//! Криптографические функции для обфускации MTProto.
//!
//! Telegram Desktop маскирует транспортный поток под случайные данные.
//! Схема работает так:
//!
//! 1. **Клиент** отправляет похожее на случайные данные рукопожатие длиной 64 байта.
//!    Байты [8..40] содержат предварительный ключ, [40..56] — вектор инициализации.
//!    Ключ расшифровки вычисляется как `SHA-256(prekey ∥ proxy_secret)`.
//!    После расшифровки AES-256-CTR байты [56..60] содержат метку протокола,
//!    а [60..62] — знаковый номер узла DC.
//!
//! 2. **Прокси** создаёт собственный начальный пакет длиной 64 байта для Telegram,
//!    используя необработанные ключи AES-256-CTR, встроенные в случайные байты.

use aes::Aes256;
use cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
use rand::RngCore;
use sha2::{Digest, Sha256};

// ─── Тип AES-256-CTR ─────────────────────────────────────────────────────────
pub type AesCtr256 = Ctr128BE<Aes256>;

// ─── Константы MTProto ────────────────────────────────────────────────────────
pub const HANDSHAKE_LEN: usize = 64;
pub const SKIP_LEN: usize = 8; // random prefix bytes before the prekey
const PREKEY_LEN: usize = 32;
const IV_LEN: usize = 16;
pub const PROTO_TAG_POS: usize = 56;
pub const DC_IDX_POS: usize = 60;

pub const PROTO_TAG_ABRIDGED: [u8; 4] = [0xef, 0xef, 0xef, 0xef];
pub const PROTO_TAG_INTERMEDIATE: [u8; 4] = [0xee, 0xee, 0xee, 0xee];
pub const PROTO_TAG_SECURE: [u8; 4] = [0xdd, 0xdd, 0xdd, 0xdd];

/// Числовые значения протоколов, которые использует разборщик сообщений.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ProtoTag {
    Abridged,
    Intermediate,
    PaddedIntermediate,
}

impl ProtoTag {
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        match b {
            x if x == PROTO_TAG_ABRIDGED => Some(Self::Abridged),
            x if x == PROTO_TAG_INTERMEDIATE => Some(Self::Intermediate),
            x if x == PROTO_TAG_SECURE => Some(Self::PaddedIntermediate),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> [u8; 4] {
        match self {
            Self::Abridged => PROTO_TAG_ABRIDGED,
            Self::Intermediate => PROTO_TAG_INTERMEDIATE,
            Self::PaddedIntermediate => PROTO_TAG_SECURE,
        }
    }
}

// ─── Разбор рукопожатия ──────────────────────────────────────────────────────

/// Результат успешного разбора клиентского рукопожатия.
pub struct HandshakeInfo {
    /// Номер узла Telegram DC (модуль: 1–5 или 203).
    pub dc_id: u32,
    /// Истина, если клиент запросил медиасервер.
    pub is_media: bool,
    /// Транспортный протокол MTProto, выбранный клиентом.
    pub proto: ProtoTag,
    /// Необработанные `prekey ∥ iv` из клиентского рукопожатия (байты [8..56]).
    /// Используются для получения ключей шифров между клиентом и прокси.
    pub prekey_and_iv: [u8; PREKEY_LEN + IV_LEN],
}

/// Разобрать рукопожатие обфускации MTProto длиной 64 байта.
///
/// Возвращает `None`, если метка протокола не распознана
/// (неверный секрет, повреждённые данные или прямая проверка соединения).
pub fn parse_handshake(handshake: &[u8; HANDSHAKE_LEN], secret: &[u8]) -> Option<HandshakeInfo> {
    let prekey = &handshake[SKIP_LEN..SKIP_LEN + PREKEY_LEN];
    let iv = &handshake[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN];

    // Ключ = SHA-256(prekey ∥ secret).
    let key = {
        let mut h = Sha256::new();
        h.update(prekey);
        h.update(secret);
        h.finalize()
    };

    // Расшифровать всё рукопожатие, чтобы получить proto_tag и dc_idx.
    let mut buf = *handshake;
    let mut cipher = make_cipher(&key, iv);
    cipher.apply_keystream(&mut buf);

    let proto = ProtoTag::from_bytes(&buf[PROTO_TAG_POS..PROTO_TAG_POS + 4])?;
    let dc_idx = i16::from_le_bytes([buf[DC_IDX_POS], buf[DC_IDX_POS + 1]]);

    let dc_id = dc_idx.unsigned_abs() as u32;
    let is_media = dc_idx < 0;

    let prekey_and_iv: [u8; PREKEY_LEN + IV_LEN] = handshake
        [SKIP_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN]
        .try_into()
        .unwrap();

    Some(HandshakeInfo {
        dc_id,
        is_media,
        proto,
        prekey_and_iv,
    })
}

// ─── Создание начального пакета прокси ───────────────────────────────────────

// Первые байты, которые Telegram отвергает как начало обфускации (HTTP, TLS…)
const RESERVED_FIRST_BYTES: &[u8] = &[0xef];
const RESERVED_STARTS: &[[u8; 4]] = &[
    [0x48, 0x45, 0x41, 0x44], // HEAD
    [0x50, 0x4f, 0x53, 0x54], // POST
    [0x47, 0x45, 0x54, 0x20], // GET
    [0xee, 0xee, 0xee, 0xee],
    [0xdd, 0xdd, 0xdd, 0xdd],
    [0x16, 0x03, 0x01, 0x02], // TLS ClientHello
];
const RESERVED_CONTINUE: [u8; 4] = [0x00, 0x00, 0x00, 0x00];

/// Создать начальный пакет обфускации длиной 64 байта для Telegram.
///
/// Прокси встраивает в случайные байты необработанные ключи AES-256-CTR,
/// поэтому Telegram может проверить пакет без знания секрета прокси.
///
/// `dc_idx` — знаковый номер DC: положительный для обычного узла,
/// отрицательный для медиасервера, как принято в Telegram.
pub fn generate_relay_init(proto: ProtoTag, dc_idx: i16) -> [u8; HANDSHAKE_LEN] {
    let proto_tag = proto.as_bytes();
    let dc_bytes = dc_idx.to_le_bytes();

    loop {
        // Сгенерировать 64 случайных байта.
        let mut rnd = [0u8; HANDSHAKE_LEN];
        rand::rng().fill_bytes(&mut rnd);

        // Исключить зарезервированные префиксы, которые Telegram или прокси
        // могут принять за начало HTTP- или TLS-соединения.
        if RESERVED_FIRST_BYTES.contains(&rnd[0]) {
            continue;
        }

        if RESERVED_STARTS.iter().any(|s| &rnd[..4] == s) {
            continue;
        }

        if rnd[4..8] == RESERVED_CONTINUE {
            continue;
        }

        // Необработанные ключ и вектор инициализации помещаются в [8..56].
        let enc_key = &rnd[SKIP_LEN..SKIP_LEN + PREKEY_LEN];
        let enc_iv = &rnd[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN];
        let mut cipher = make_cipher(enc_key, enc_iv);

        // Зашифровать копию случайных байтов, чтобы получить поток CTR.
        let mut encrypted = rnd;
        cipher.apply_keystream(&mut encrypted);

        // Для [56..64] объединить XOR-операцией открытый хвост (proto_tag ∥ dc_idx ∥ pad)
        // с соответствующими байтами потока. Telegram восстановит метаданные
        // при расшифровке тем же шифром.
        let mut tail_plain = [0u8; 8];
        tail_plain[..4].copy_from_slice(&proto_tag);
        tail_plain[4..6].copy_from_slice(&dc_bytes);
        rand::rng().fill_bytes(&mut tail_plain[6..]);

        let mut result = rnd;
        for i in 0..8 {
            // Потоковый ключ: keystream[56+i] = encrypted[56+i] XOR rnd[56+i].
            let ks = encrypted[PROTO_TAG_POS + i] ^ rnd[PROTO_TAG_POS + i];
            result[PROTO_TAG_POS + i] = tail_plain[i] ^ ks;
        }

        return result;
    }
}

// ─── Создание шифра ──────────────────────────────────────────────────────────

/// Создать шифр AES-256-CTR из ключа длиной 32 байта и вектора длиной 16 байт.
pub fn make_cipher(key: &[u8], iv: &[u8]) -> AesCtr256 {
    AesCtr256::new_from_slices(key, iv)
        .expect("ключ должен содержать 32 байта, вектор инициализации — 16 байт")
}

/// Применить поток шифра к `data` на месте.
///
/// Единая операция для вызывающих функций [`make_cipher`] и
/// [`build_connection_ciphers`]. Она не требует подключать признак `StreamCipher`
/// из crate `cipher`; его не может подключить код вне этого crate,
/// например интеграционный тест стороны сервера.
pub fn apply_keystream(cipher: &mut AesCtr256, data: &mut [u8]) {
    cipher.apply_keystream(data);
}

// ─── Создание клиентского рукопожатия для удалённого прокси ───────────────────

/// Создать рукопожатие MTProto длиной 64 байта для удалённого прокси
/// и два шифра AES-256-CTR для сеанса.
///
/// Возвращает `(handshake, enc, dec)`, где:
/// - `handshake` — 64 байта для отправки удалённому прокси;
/// - `enc` шифрует исходящие данные; поток продвинут на 64 байта;
/// - `dec` расшифровывает данные, полученные от удалённого прокси.
///
/// Удалённый прокси разбирает рукопожатие через `SHA-256(prekey ∥ upstream_secret)`
/// и направляет соединение к узлу `dc_idx`.
pub fn generate_client_handshake(
    secret: &[u8],
    dc_idx: i16,
    proto: ProtoTag,
) -> ([u8; HANDSHAKE_LEN], AesCtr256, AesCtr256) {
    let proto_bytes = proto.as_bytes();
    let dc_bytes = dc_idx.to_le_bytes();

    loop {
        let mut raw = [0u8; HANDSHAKE_LEN];
        rand::rng().fill_bytes(&mut raw);

        // Исключить зарезервированные префиксы по тем же правилам, что и в generate_relay_init.
        if RESERVED_FIRST_BYTES.contains(&raw[0]) {
            continue;
        }
        if RESERVED_STARTS.iter().any(|s| &raw[..4] == s) {
            continue;
        }
        if raw[4..8] == RESERVED_CONTINUE {
            continue;
        }

        // Получить ключ и вектор из исходных байтов до изменения, чтобы
        // удалённый прокси мог восстановить их из рукопожатия.
        let key = {
            let mut h = Sha256::new();
            h.update(&raw[SKIP_LEN..SKIP_LEN + PREKEY_LEN]);
            h.update(secret);
            h.finalize()
        };
        let iv = &raw[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN];

        // Получить полный поток шифра, зашифровав нулевой буфер.
        let mut keystream = [0u8; HANDSHAKE_LEN];
        make_cipher(&key, iv).apply_keystream(&mut keystream);

        // Встроить proto_tag и dc_idx в [56..64] через XOR с потоком,
        // чтобы после расшифровки удалённый прокси получил исходные значения.
        let mut handshake = raw;
        for i in 0..4 {
            handshake[PROTO_TAG_POS + i] = proto_bytes[i] ^ keystream[PROTO_TAG_POS + i];
        }
        for i in 0..2 {
            handshake[DC_IDX_POS + i] = dc_bytes[i] ^ keystream[DC_IDX_POS + i];
        }
        // Оставить handshake[62..64] случайными байтами: удалённый прокси
        // не интерпретирует это заполнение.

        // Создать enc для шифрования данных, отправляемых удалённому прокси.
        // Это соответствует clt_dec на удалённом прокси: тот же ключ и вектор,
        // поток продвинут на 64 байта.
        let enc_key = {
            let mut h = Sha256::new();
            h.update(&handshake[SKIP_LEN..SKIP_LEN + PREKEY_LEN]);
            h.update(secret);
            h.finalize()
        };
        let enc_iv = &handshake[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN];
        let mut enc = make_cipher(&enc_key, enc_iv);
        let mut dummy = [0u8; HANDSHAKE_LEN];
        enc.apply_keystream(&mut dummy); // пропустить байты рукопожатия в потоке

        // Создать dec для расшифровки данных от удалённого прокси.
        // Это соответствует clt_enc на удалённом прокси: обратные prekey+iv,
        // поток не продвигается.
        let reversed: Vec<u8> = handshake[SKIP_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN]
            .iter()
            .rev()
            .copied()
            .collect();
        let dec_key = {
            let mut h = Sha256::new();
            h.update(&reversed[..PREKEY_LEN]);
            h.update(secret);
            h.finalize()
        };
        let dec_iv = &reversed[PREKEY_LEN..];
        let dec = make_cipher(&dec_key, dec_iv);

        return (handshake, enc, dec);
    }
}

// ─── Шифры клиента и прокси ──────────────────────────────────────────────────

/// Четыре шифра AES-256-CTR для одного проксируемого соединения.
pub struct ConnectionCiphers {
    /// Расшифровать данные от клиента (направление клиент → прокси).
    pub clt_dec: AesCtr256,
    /// Зашифровать данные для клиента (направление прокси → клиент).
    pub clt_enc: AesCtr256,
    /// Зашифровать данные для Telegram (направление прокси → Telegram).
    pub tg_enc: AesCtr256,
    /// Расшифровать данные от Telegram (направление Telegram → прокси).
    pub tg_dec: AesCtr256,
}

/// Создать четыре шифра соединения из разобранного рукопожатия.
///
/// `prekey_and_iv` — необработанные prekey и вектор инициализации из
/// `handshake[8..56]`, встроенные клиентом в начальный пакет.
pub fn build_connection_ciphers(
    prekey_and_iv: &[u8; PREKEY_LEN + IV_LEN],
    secret: &[u8],
    relay_init: &[u8; HANDSHAKE_LEN],
) -> ConnectionCiphers {
    // ── Шифры со стороны клиента ────────────────────────────────────────────
    // Ключ расшифровки = SHA-256(client_prekey ∥ secret).
    let clt_dec_key = {
        let mut h = Sha256::new();
        h.update(&prekey_and_iv[..PREKEY_LEN]);
        h.update(secret);
        h.finalize()
    };
    let clt_dec_iv = &prekey_and_iv[PREKEY_LEN..];

    // Для шифрования используется обратная пара prekey и вектора инициализации.
    let reversed: Vec<u8> = prekey_and_iv.iter().rev().copied().collect();
    let clt_enc_key = {
        let mut h = Sha256::new();
        h.update(&reversed[..PREKEY_LEN]);
        h.update(secret);
        h.finalize()
    };
    let clt_enc_iv = &reversed[PREKEY_LEN..];

    let mut clt_dec = make_cipher(&clt_dec_key, clt_dec_iv);
    let clt_enc = make_cipher(&clt_enc_key, clt_enc_iv);

    // Продвинуть расшифровщик за уже отправленное 64-байтовое рукопожатие:
    // использованный поток CTR нельзя применять повторно.
    let mut dummy = [0u8; HANDSHAKE_LEN];
    clt_dec.apply_keystream(&mut dummy);

    // ── Шифры со стороны прокси ─────────────────────────────────────────────
    // Прокси использует необработанные ключи без хеша секрета; Telegram знает
    // их из байтов начального пакета.
    let relay_enc_key = &relay_init[SKIP_LEN..SKIP_LEN + PREKEY_LEN];
    let relay_enc_iv = &relay_init[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN];

    let relay_prekey_iv_rev: Vec<u8> = relay_init[SKIP_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN]
        .iter()
        .rev()
        .copied()
        .collect();
    let relay_dec_key = &relay_prekey_iv_rev[..PREKEY_LEN];
    let relay_dec_iv = &relay_prekey_iv_rev[PREKEY_LEN..];

    let mut tg_enc = make_cipher(relay_enc_key, relay_enc_iv);
    let tg_dec = make_cipher(relay_dec_key, relay_dec_iv);

    // Продвинуть шифровщик прокси за уже отправленный Telegram пакет длиной 64 байта.
    tg_enc.apply_keystream(&mut dummy);

    ConnectionCiphers {
        clt_dec,
        clt_enc,
        tg_enc,
        tg_dec,
    }
}
