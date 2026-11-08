use std::io::Read as _;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use cipher::StreamCipher;
use futures_util::{SinkExt, StreamExt};
use grammers_crypto::DequeBuffer;
use grammers_mtproto::authentication;
use grammers_mtproto::mtp::{Deserialization, Encrypted, Mtp, Plain};
use grammers_mtproto::transport::{Error as TransportError, Intermediate, Obfuscated, Transport};
use grammers_tl_types::{Deserializable, RemoteCall, Serializable};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::process::Command;
use tokio::sync::Mutex;
use tracing::{info, warn};
use tungstenite::Message;

use crate::config::default_dc_bootstrap_ips;
use crate::crypto::ProtoTag;
use crate::dc_map::{DcEndpoint, DcSnapshot, write_endpoint_manifest};
use crate::runtime::Runtime;
use crate::splitter::MsgSplitter;
use crate::transparent::direct_stream_ciphers;
use crate::ws_client::{
    CfDialOpts, TgWsStream, connect_cf_worker_ws_for_dc_with_outbound_opts,
    connect_cf_ws_for_dc_with_outbound_opts,
};

const TELEGRAM_TCP_PORT: u16 = 443;
/// TL `gzip_packed#3072cfa1`.
const GZIP_PACKED_CONSTRUCTOR: u32 = 0x3072_cfa1;
/// Верхний предел распакованного `help.getConfig`, как C `TG_CONFIG_MAX_UNPACKED`.
const CONFIG_MAX_UNPACKED: usize = 1024 * 1024;
/// C `TG_CONFIG_MAX_GZIP_DEPTH`.
const CONFIG_MAX_GZIP_DEPTH: usize = 4;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(6);
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(12);
const MAX_PACKET_BYTES: usize = 1024 * 1024;
const MAX_BOOTSTRAP_ATTEMPTS: usize = 3;
const MAX_DISCOVERY_WORKER_ATTEMPTS: usize = 3;
const MIN_REFRESH_SECS: u64 = 60 * 60;
const MAX_REFRESH_SECS: u64 = 7 * 24 * 60 * 60;
const PLATFORM_SYNC_RETRY_SECS: u64 = 5 * 60;
const PLATFORM_SYNC_TIMEOUT: Duration = Duration::from_secs(30);
static PLATFORM_SYNC_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
// Идентификатор официального Telegram Android; для help.getConfig api_hash и вход в аккаунт не нужны.
const TELEGRAM_CONFIG_API_ID: i32 = 4;

type TelegramTransport = Obfuscated<Intermediate>;

/// Получить `help.getConfig` на одном из проверенных встроенных DC без входа пользователя.
pub async fn fetch_config(runtime: &Runtime) -> Result<DcSnapshot, String> {
    let mut failures = Vec::new();
    let cf_domains = runtime.cf_domains();
    let bootstrap = default_dc_bootstrap_ips();
    for (dc, address) in bootstrap.iter().take(MAX_BOOTSTRAP_ATTEMPTS) {
        match fetch_from_dc(runtime, address).await {
            Ok(snapshot) => return Ok(snapshot),
            Err(error) => failures.push(format!("DC{dc} {address}: {error}")),
        }
    }

    let mut tried_dcs = Vec::new();
    for dc in bootstrap.iter().map(|(dc, _)| *dc) {
        if tried_dcs.contains(&dc) {
            continue;
        }
        tried_dcs.push(dc);
        let Some(address) = bootstrap
            .iter()
            .find_map(|(candidate_dc, address)| (*candidate_dc == dc).then_some(*address))
        else {
            continue;
        };
        for domain in worker_domains_for_discovery(runtime)
            .iter()
            .take(MAX_DISCOVERY_WORKER_ATTEMPTS)
        {
            match fetch_from_worker(runtime, domain, address, dc).await {
                Ok(snapshot) => {
                    runtime.stats().record_worker_success(domain);
                    return Ok(snapshot);
                }
                Err(error) => {
                    runtime.stats().record_worker_failure(domain, &error);
                    failures.push(format!("DC{dc} через Worker {domain}: {error}"));
                }
            }
        }
        match fetch_from_cf_dc(runtime, dc, &cf_domains.domains).await {
            Ok(snapshot) => return Ok(snapshot),
            Err(error) => failures.push(format!("DC{dc} через WSS: {error}")),
        }
    }

    Err(format!(
        "не удалось получить конфигурацию ни с одного bootstrap DC: {}",
        failures.join("; ")
    ))
}

fn worker_domains_for_discovery(runtime: &Runtime) -> &[String] {
    runtime.cf_worker_domains()
}

/// Выполнить настоящий первый обмен MTProto и вернуть время до проверенного `resPQ`.
/// Проверка не использует пользовательскую авторизацию и не сохраняет её секреты.
pub async fn probe_res_pq<S>(stream: &mut S) -> Result<u64, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let started = std::time::Instant::now();
    let deadline = tokio::time::Instant::now() + EXCHANGE_TIMEOUT;
    let mut transport = Obfuscated::new(Intermediate::new());
    let mut wire = Vec::with_capacity(16 * 1024);
    let nonce: [u8; 16] = rand::random();
    let request = grammers_tl_types::functions::ReqPqMulti { nonce }.to_bytes();
    let mut mtp = Plain::new();
    let mut packet = DequeBuffer::with_capacity(request.len() + 64, 0);
    if mtp.push(&mut packet, &request).is_none() || mtp.finalize(&mut packet).is_none() {
        return Err("req_pq_multi: не удалось сформировать plain-сообщение".to_string());
    }
    transport.pack(&mut packet);
    tokio::time::timeout_at(deadline, stream.write_all(packet.as_ref()))
        .await
        .map_err(|_| "req_pq_multi: истекло время передачи запроса".to_string())?
        .map_err(|error| format!("req_pq_multi: передача запроса: {error}"))?;
    let payload = tokio::time::timeout_at(
        deadline,
        read_transport_packet(stream, &mut transport, &mut wire),
    )
    .await
    .map_err(|_| "req_pq_multi: истекло время ожидания ответа".to_string())??;
    validate_res_pq_probe_response(&payload, nonce)?;
    Ok(started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64)
}

/// C `parse_plain_response` + `parse_res_pq`: точная длина plain-сообщения,
/// совпадение nonce, pq 1..8 байт, 1..64 fingerprint и отсутствие хвоста.
fn validate_res_pq_probe_response(payload: &[u8], nonce: [u8; 16]) -> Result<(), String> {
    if payload.len() < 20 {
        return Err("resPQ: короткий plain-ответ".to_string());
    }
    if payload[..8] != [0u8; 8] {
        return Err("resPQ: ответ не является plain-сообщением".to_string());
    }
    let message_id = i64::from_le_bytes(payload[8..16].try_into().expect("8 байт"));
    if message_id <= 0 || (message_id & 3) != 1 {
        return Err("resPQ: неверный message_id".to_string());
    }
    let length = u32::from_le_bytes(payload[16..20].try_into().expect("4 байта")) as usize;
    if length == 0 || length + 20 != payload.len() {
        return Err("resPQ: неверная длина plain-сообщения".to_string());
    }
    let body = &payload[20..];
    let response = parse_res_pq_response(body)?;
    let grammers_tl_types::enums::ResPq::Pq(parsed) = response;
    if parsed.nonce != nonce {
        return Err("resPQ: nonce не совпадает с запросом".to_string());
    }
    if parsed.pq.is_empty() || parsed.pq.len() > 8 {
        return Err("resPQ: неверный pq".to_string());
    }
    if parsed.server_public_key_fingerprints.is_empty()
        || parsed.server_public_key_fingerprints.len() > 64
    {
        return Err("resPQ: неверный список fingerprint".to_string());
    }
    let canonical = grammers_tl_types::enums::ResPq::Pq(parsed).to_bytes();
    if canonical != body {
        return Err("resPQ: лишние байты после ответа".to_string());
    }
    Ok(())
}

async fn fetch_from_dc(runtime: &Runtime, address: &str) -> Result<DcSnapshot, String> {
    let mut stream = runtime
        .outbound()
        .connect(address, TELEGRAM_TCP_PORT, CONNECT_TIMEOUT)
        .await
        .map_err(|error| format!("TCP-соединение: {error}"))?;
    stream
        .set_nodelay(true)
        .map_err(|error| format!("TCP_NODELAY: {error}"))?;

    fetch_over_stream(&mut stream).await
}

async fn fetch_from_cf_dc(
    runtime: &Runtime,
    dc: u32,
    cf_domains: &[String],
) -> Result<DcSnapshot, String> {
    if cf_domains.is_empty() {
        return Err("домены Cloudflare для WSS не настроены".to_string());
    }

    let (ws, domain, _) = connect_cf_ws_for_dc_with_outbound_opts(
        dc,
        cf_domains,
        false,
        CONNECT_TIMEOUT,
        runtime.outbound(),
        CfDialOpts {
            cf_ips: runtime.cf_ips(),
            fail_cooldown: runtime.cf_fail_cooldown(),
        },
    )
    .await;
    let ws = ws.ok_or_else(|| "Cloudflare WSS-соединение не установлено".to_string())?;
    info!(
        "Получение help.getConfig через проверенный WSS-маршрут DC{} ({})",
        dc,
        domain.as_deref().unwrap_or("домен неизвестен")
    );

    let mut stream = start_ws_byte_stream(ws);
    fetch_over_stream(&mut stream).await
}

async fn fetch_from_worker(
    runtime: &Runtime,
    worker_domain: &str,
    address: &str,
    dc: u32,
) -> Result<DcSnapshot, String> {
    let ws = connect_cf_worker_ws_for_dc_with_outbound_opts(
        worker_domain,
        address,
        dc,
        false,
        CONNECT_TIMEOUT,
        runtime.outbound(),
        CfDialOpts {
            cf_ips: runtime.cf_ips(),
            fail_cooldown: runtime.cf_fail_cooldown(),
        },
    )
    .await
    .ok_or_else(|| "Worker не установил WSS-соединение".to_string())?;
    info!(
        "Получение help.getConfig через настроенный Worker {} для DC{}",
        worker_domain, dc
    );
    let mut stream = start_ws_byte_stream(ws);
    fetch_over_stream(&mut stream).await
}

pub(crate) fn start_ws_byte_stream(ws: TgWsStream) -> DuplexStream {
    let (client, relay) = tokio::io::duplex(64 * 1024);
    tokio::spawn(bridge_ws_byte_stream(relay, ws));
    client
}

async fn bridge_ws_byte_stream(stream: DuplexStream, ws: TgWsStream) {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (sink, mut source) = ws.split();
    let sink = Arc::new(Mutex::new(sink));

    let upload_sink = Arc::clone(&sink);
    let upload = async move {
        let mut init = [0u8; crate::crypto::HANDSHAKE_LEN];
        reader
            .read_exact(&mut init)
            .await
            .map_err(|error| format!("не удалось прочитать obfuscated2 bootstrap: {error}"))?;
        upload_sink
            .lock()
            .await
            .send(Message::Binary(init.to_vec()))
            .await
            .map_err(|error| format!("не удалось передать bootstrap по WSS: {error}"))?;

        let (mut decrypt, mut encrypt) = direct_stream_ciphers(&init);
        let mut splitter = MsgSplitter::new(ProtoTag::Intermediate);
        let mut buffer = vec![0u8; 16 * 1024];
        loop {
            let length = reader
                .read(&mut buffer)
                .await
                .map_err(|error| format!("ошибка чтения bootstrap-запроса: {error}"))?;
            if length == 0 {
                break;
            }
            decrypt.apply_keystream(&mut buffer[..length]);
            let packets = splitter.split_and_encrypt(&mut buffer[..length], &mut encrypt);
            if let Some(error) = splitter.error() {
                return Err(format!("некорректный пакет help.getConfig: {error}"));
            }
            for packet in packets {
                upload_sink
                    .lock()
                    .await
                    .send(Message::Binary(packet))
                    .await
                    .map_err(|error| {
                        format!("не удалось передать пакет help.getConfig по WSS: {error}")
                    })?;
            }
        }
        for packet in splitter.flush() {
            upload_sink
                .lock()
                .await
                .send(Message::Binary(packet))
                .await
                .map_err(|error| format!("не удалось передать остаток пакета по WSS: {error}"))?;
        }
        upload_sink
            .lock()
            .await
            .close()
            .await
            .map_err(|error| format!("не удалось закрыть исходящий WSS-поток: {error}"))?;
        Ok::<(), String>(())
    };

    let download_sink = Arc::clone(&sink);
    let download = async move {
        loop {
            let message = source
                .next()
                .await
                .ok_or_else(|| "Cloudflare закрыл WSS-поток".to_string())?
                .map_err(|error| format!("ошибка чтения ответа WSS: {error}"))?;
            match message {
                Message::Binary(data) if data.len() <= MAX_PACKET_BYTES => writer
                    .write_all(&data)
                    .await
                    .map_err(|error| format!("не удалось передать ответ WSS в MTProto: {error}"))?,
                Message::Binary(_) => {
                    return Err::<(), String>("пакет ответа WSS превышает 1 MiB".to_string());
                }
                Message::Text(data) => writer
                    .write_all(data.as_bytes())
                    .await
                    .map_err(|error| format!("не удалось передать текстовый ответ WSS: {error}"))?,
                Message::Ping(data) => {
                    download_sink
                        .lock()
                        .await
                        .send(Message::Pong(data))
                        .await
                        .map_err(|error| format!("не удалось ответить на WSS ping: {error}"))?
                }
                Message::Pong(_) => {}
                Message::Close(_) => return Err("Telegram закрыл WSS-поток".to_string()),
                _ => return Err("WSS прислал неподдерживаемый тип кадра".to_string()),
            }
        }
    };

    tokio::select! {
        result = upload => {
            if let Err(error) = result {
                warn!("Ошибка отправки начального пакета через WSS: {error}");
            }
        }
        result = download => {
            if let Err(error) = result {
                warn!("Ошибка получения начального пакета через WSS: {error}");
            }
        }
    }
}

async fn fetch_over_stream<S>(stream: &mut S) -> Result<DcSnapshot, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut transport = Obfuscated::new(Intermediate::new());
    let mut wire = Vec::with_capacity(16 * 1024);

    let (request, state) =
        authentication::step1().map_err(|error| format!("начало авторизации MTProto: {error}"))?;
    let response = exchange_plain(stream, &mut transport, &mut wire, &request)
        .await
        .map_err(|error| format!("этап req_pq_multi: {error}"))?;
    let response = parse_res_pq_response(&response)?;

    let (request, state) = authentication::step2(state, response)
        .map_err(|error| format!("обработка resPQ: {error}"))?;
    let response = exchange_plain(stream, &mut transport, &mut wire, &request)
        .await
        .map_err(|error| format!("этап req_DH_params: {error}"))?;
    let response = grammers_tl_types::enums::ServerDhParams::from_bytes(&response)
        .map_err(|error| format!("разбор server_DH_params: {error}"))?;

    let (request, state) = authentication::step3(state, response)
        .map_err(|error| format!("обработка server_DH_params: {error}"))?;
    let response = exchange_plain(stream, &mut transport, &mut wire, &request)
        .await
        .map_err(|error| format!("этап set_client_DH_params: {error}"))?;
    let response = grammers_tl_types::enums::SetClientDhParamsAnswer::from_bytes(&response)
        .map_err(|error| format!("разбор set_client_DH_params_answer: {error}"))?;

    let auth = authentication::create_key(state, response)
        .map_err(|error| format!("завершение авторизации MTProto: {error}"))?;
    let mut encrypted = Encrypted::build()
        .time_offset(auth.time_offset)
        .first_salt(auth.first_salt)
        .finish(auth.auth_key);
    let request = config_request();
    let response = exchange_encrypted(stream, &mut transport, &mut wire, &mut encrypted, &request)
        .await
        .map_err(|error| format!("этап help.getConfig: {error}"))?;
    config_bytes_to_snapshot(&response, unix_time())
}

fn parse_res_pq_response(bytes: &[u8]) -> Result<grammers_tl_types::enums::ResPq, String> {
    grammers_tl_types::enums::ResPq::from_bytes(bytes)
        .map_err(|error| format!("разбор resPQ: {error}"))
}

fn config_request() -> grammers_tl_types::functions::InvokeWithLayer<
    grammers_tl_types::functions::InitConnection<grammers_tl_types::functions::help::GetConfig>,
> {
    grammers_tl_types::functions::InvokeWithLayer {
        layer: grammers_tl_types::LAYER,
        query: grammers_tl_types::functions::InitConnection {
            api_id: TELEGRAM_CONFIG_API_ID,
            device_model: "OpenWrt".to_string(),
            system_version: "OpenWrt".to_string(),
            app_version: env!("CARGO_PKG_VERSION").to_string(),
            system_lang_code: "ru".to_string(),
            lang_pack: String::new(),
            lang_code: "ru".to_string(),
            proxy: None,
            params: None,
            query: grammers_tl_types::functions::help::GetConfig {},
        },
    }
}

async fn exchange_plain<S, R>(
    stream: &mut S,
    transport: &mut TelegramTransport,
    wire: &mut Vec<u8>,
    request: &R,
) -> Result<Vec<u8>, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
    R: Serializable,
{
    let mut mtp = Plain::new();
    exchange(stream, transport, wire, &mut mtp, request).await
}

async fn exchange_encrypted<S, R>(
    stream: &mut S,
    transport: &mut TelegramTransport,
    wire: &mut Vec<u8>,
    mtp: &mut Encrypted,
    request: &R,
) -> Result<Vec<u8>, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
    R: RemoteCall,
{
    exchange(stream, transport, wire, mtp, request).await
}

async fn exchange<S, M, R>(
    stream: &mut S,
    transport: &mut TelegramTransport,
    wire: &mut Vec<u8>,
    mtp: &mut M,
    request: &R,
) -> Result<Vec<u8>, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
    M: Mtp,
    R: Serializable,
{
    let request = request.to_bytes();
    let deadline = tokio::time::Instant::now() + EXCHANGE_TIMEOUT;
    loop {
        let mut packet = DequeBuffer::with_capacity(request.len() + 64, 0);
        let request_queued = mtp.push(&mut packet, &request).is_some();
        let packet_finalized = mtp.finalize(&mut packet).is_some();
        if request_queued && !packet_finalized {
            return Err("MTProto не сформировал исходящий пакет".to_string());
        }
        if !packet.is_empty() {
            transport.pack(&mut packet);
            tokio::time::timeout_at(deadline, stream.write_all(packet.as_ref()))
                .await
                .map_err(|_| "истекло время передачи запроса Telegram".to_string())?
                .map_err(|error| format!("передача запроса Telegram: {error}"))?;
        }

        loop {
            let payload =
                tokio::time::timeout_at(deadline, read_transport_packet(stream, transport, wire))
                    .await
                    .map_err(|_| "истекло время ожидания ответа Telegram".to_string())??;
            let mut payload = payload;
            let responses = mtp
                .deserialize(&mut payload)
                .map_err(|error| format!("разбор пакета MTProto: {error}"))?;
            for response in responses {
                match response {
                    Deserialization::RpcResult(result) => return Ok(result.body),
                    Deserialization::RpcError(result) => {
                        return Err(format!(
                            "Telegram вернул RPC-ошибку {}: {}",
                            result.error.error_code, result.error.error_message
                        ));
                    }
                    Deserialization::Failure(failure) => {
                        return Err(format!("ответ MTProto не прошёл разбор: {}", failure.error));
                    }
                    Deserialization::BadMessage(message) => {
                        return Err(format!(
                            "Telegram отклонил сообщение MTProto, код {}",
                            message.code
                        ));
                    }
                    Deserialization::Update(_) | Deserialization::OwnUpdate { .. } => {}
                }
            }
            if !request_queued {
                break;
            }
        }
    }
}

async fn read_transport_packet<S>(
    stream: &mut S,
    transport: &mut TelegramTransport,
    wire: &mut Vec<u8>,
) -> Result<Vec<u8>, String>
where
    S: AsyncRead + Unpin,
{
    let mut read_buffer = [0u8; 16 * 1024];
    loop {
        if !wire.is_empty() {
            match transport.unpack(wire) {
                Ok(offset) => {
                    let payload = wire[offset.data_range].to_vec();
                    wire.drain(..offset.next_offset);
                    return Ok(payload);
                }
                Err(TransportError::MissingBytes) => {}
                Err(error) => return Err(format!("кадрирование MTProto: {error}")),
            }
        }
        if wire.len() >= MAX_PACKET_BYTES {
            return Err("пакет Telegram превысил допустимый размер".to_string());
        }
        let read_limit = read_buffer.len().min(MAX_PACKET_BYTES - wire.len());
        let read = stream
            .read(&mut read_buffer[..read_limit])
            .await
            .map_err(|error| format!("чтение ответа Telegram: {error}"))?;
        if read == 0 {
            return Err("Telegram закрыл соединение во время запроса конфигурации".to_string());
        }
        wire.extend_from_slice(&read_buffer[..read]);
    }
}

/// Удобная обёртка для unit-тестов; production разбирает TL-байты через
/// [`config_bytes_to_snapshot`], как C `tg_mtproto_config_parse`.
#[cfg(test)]
fn config_to_snapshot(config: grammers_tl_types::types::Config) -> Result<DcSnapshot, String> {
    config_to_snapshot_at(config, unix_time())
}

/// Преобразовать `help.getConfig` в snapshot на фиксированный момент времени.
/// C `tg_mtproto_config_parse` проверяет теперь-зависимые даты и покрытие DC,
/// поэтому здесь вызывается тот же `validate_snapshot`.
fn config_to_snapshot_at(
    config: grammers_tl_types::types::Config,
    now: i64,
) -> Result<DcSnapshot, String> {
    if now <= 0 {
        return Err("время разбора help.getConfig некорректно".to_string());
    }
    let mut endpoints = Vec::with_capacity(config.dc_options.len());
    for option in config.dc_options {
        let grammers_tl_types::enums::DcOption::Option(option) = option;
        let id = u32::try_from(option.id)
            .ok()
            .filter(|id| (1..=999).contains(id))
            .ok_or_else(|| format!("dcOption содержит недопустимый DC ID {}", option.id))?;
        // C `parse_dc_option`: ip_len >= INET6_ADDRSTRLEN и встроенный NUL
        // отвергаются до inet_pton.
        if option.ip_address.len() >= 46 || option.ip_address.as_bytes().contains(&0) {
            return Err(format!("dcOption DC{id} содержит неверный IP-адрес"));
        }
        let address: IpAddr = option
            .ip_address
            .parse()
            .map_err(|_| format!("dcOption DC{id} содержит неверный IP-адрес"))?;
        let port = u16::try_from(option.port)
            .ok()
            .filter(|port| *port != 0)
            .ok_or_else(|| format!("dcOption DC{id} содержит неверный TCP-порт"))?;
        // C: флаг secret требует непустой секрет не длиннее 256 байт.
        if option
            .secret
            .as_ref()
            .is_some_and(|secret| secret.is_empty() || secret.len() > 256)
        {
            return Err(format!("dcOption DC{id} содержит неверный секрет"));
        }
        endpoints.push(DcEndpoint {
            id,
            address,
            port,
            ipv6: option.ipv6,
            media_only: option.media_only,
            tcpo_only: option.tcpo_only,
            cdn: option.cdn,
            is_static: option.r#static,
            this_port_only: option.this_port_only,
            secret: option.secret.map(hex::encode),
            last_seen: now,
        });
    }
    let snapshot = DcSnapshot {
        schema_version: 1,
        fetched_at: now,
        config_date: i64::from(config.date),
        config_expires: i64::from(config.expires),
        this_dc: u32::try_from(config.this_dc)
            .map_err(|_| "help.getConfig вернул неверный текущий DC".to_string())?,
        endpoints,
    };
    crate::dc_map::validate_snapshot(&snapshot, now)?;
    Ok(snapshot)
}

/// Разобрать TL-байты `help.getConfig` как C `tg_mtproto_config_parse`:
/// поддержать `gzip_packed` до 4 уровней, канонический TL и полное покрытие DC.
pub fn config_bytes_to_snapshot(bytes: &[u8], now: i64) -> Result<DcSnapshot, String> {
    if now <= 0 {
        return Err("время разбора help.getConfig некорректно".to_string());
    }
    let mut object = bytes.to_vec();
    for _ in 0..CONFIG_MAX_GZIP_DEPTH {
        if object.len() < 4
            || u32::from_le_bytes(object[..4].try_into().expect("4 байта"))
                != GZIP_PACKED_CONSTRUCTOR
        {
            break;
        }
        object = inflate_config_gzip(&object)?;
    }
    if object.len() >= 4
        && u32::from_le_bytes(object[..4].try_into().expect("4 байта")) == GZIP_PACKED_CONSTRUCTOR
    {
        return Err("help.getConfig превышает глубину gzip_packed".to_string());
    }
    let response = grammers_tl_types::enums::Config::from_bytes(&object)
        .map_err(|error| format!("разбор help.getConfig: {error}"))?;
    let grammers_tl_types::enums::Config::Config(config) = response;
    // C требует точного потребления объекта: неизвестные флаги/хвост байтов
    // не должны молча игнорироваться. Каноническая ресериализация это ловит.
    if grammers_tl_types::enums::Config::Config(config.clone()).to_bytes() != object {
        return Err("help.getConfig содержит неизвестные поля или лишние байты".to_string());
    }
    config_to_snapshot_at(config, now)
}

/// Прочитать TL `bytes` ровно как C `read_bytes`: длина, выравнивание,
/// нулевой padding и проверка границ.
fn read_tl_bytes<'a>(data: &'a [u8], offset: &mut usize) -> Result<&'a [u8], String> {
    let remaining = data
        .len()
        .checked_sub(*offset)
        .ok_or_else(|| "gzip_packed: смещение вне объекта".to_string())?;
    if remaining == 0 {
        return Err("gzip_packed: нет длины bytes".to_string());
    }
    let first = data[*offset];
    let (prefix_len, count) = if first < 254 {
        (1usize, first as usize)
    } else if first == 254 {
        if remaining < 4 {
            return Err("gzip_packed: усечённая длина bytes".to_string());
        }
        let count = data[*offset + 1] as usize
            | (data[*offset + 2] as usize) << 8
            | (data[*offset + 3] as usize) << 16;
        if count < 254 {
            return Err("gzip_packed: неверная минимальная длина bytes".to_string());
        }
        (4usize, count)
    } else {
        return Err("gzip_packed: неверная длина bytes".to_string());
    };
    if prefix_len > remaining || count > remaining - prefix_len {
        return Err("gzip_packed: длина bytes вне объекта".to_string());
    }
    let encoded_len = prefix_len + count;
    let padding = (4 - (encoded_len & 3)) & 3;
    if padding > remaining - encoded_len {
        return Err("gzip_packed: усечённый padding".to_string());
    }
    for index in 0..padding {
        if data[*offset + encoded_len + index] != 0 {
            return Err("gzip_packed: padding не нулевой".to_string());
        }
    }
    let start = *offset + prefix_len;
    let bytes = &data[start..start + count];
    *offset += encoded_len + padding;
    Ok(bytes)
}

fn inflate_config_gzip(object: &[u8]) -> Result<Vec<u8>, String> {
    let mut offset = 4;
    let compressed = read_tl_bytes(object, &mut offset)?;
    if offset != object.len() {
        return Err("gzip_packed содержит лишние байты".to_string());
    }
    if compressed.is_empty() || compressed.len() > u32::MAX as usize {
        return Err("gzip_packed: неверная длина".to_string());
    }
    let mut cursor = std::io::Cursor::new(compressed);
    let mut expanded = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    {
        let mut decoder = flate2::read::GzDecoder::new(&mut cursor);
        loop {
            match decoder.read(&mut chunk) {
                Ok(0) => break,
                Ok(read) => {
                    if expanded.len() + read > CONFIG_MAX_UNPACKED {
                        return Err("gzip_packed превышает 1 МиБ".to_string());
                    }
                    expanded.extend_from_slice(&chunk[..read]);
                }
                Err(error) => return Err(format!("gzip_packed: {error}")),
            }
        }
    }
    if cursor.position() != compressed.len() as u64 {
        return Err("gzip_packed: поток не消费 все входные байты".to_string());
    }
    if expanded.is_empty() {
        return Err("gzip_packed пуст".to_string());
    }
    Ok(expanded)
}

/// Загружать официальную карту не чаще заданного интервала и не терять кэш при ошибке сети.
pub async fn refresh_loop(
    runtime: Arc<Runtime>,
    requested_interval: u64,
    endpoint_pairs_path: PathBuf,
    transparent_ports: Vec<u16>,
) {
    let interval = requested_interval.clamp(MIN_REFRESH_SECS, MAX_REFRESH_SECS);
    let store = Arc::clone(runtime.dc_map());
    if !transparent_ports.is_empty()
        && let Some(snapshot) = store.current()
    {
        let sync_path = std::env::var_os("R2O_TG_DC_MAP_SYNC").map(PathBuf::from);
        match write_manifest_and_sync(
            &endpoint_pairs_path,
            &snapshot,
            &transparent_ports,
            sync_path.clone(),
        )
        .await
        {
            Ok(count) if sync_path.is_some() => {
                info!("Кэш DC записан и синхронизирован платформенным адаптером: {count} пар");
            }
            Ok(count) => {
                info!("Манифест кэша Telegram DC обновлён: {count} пар; адаптер событий не задан");
            }
            Err(error) => {
                warn!("Не удалось записать manifest или синхронизировать кэш DC: {error}")
            }
        }
    }
    loop {
        if store.refresh_due(unix_time(), interval) {
            match fetch_config(&runtime).await {
                Ok(snapshot) => match store.install(snapshot, unix_time()) {
                    Ok(installed) => {
                        runtime
                            .stats()
                            .set_dc_map(installed.config_date as u64, installed.fetched_at);
                        info!(
                            "Официальная карта Telegram DC обновлена: {} адресов, конфигурация от {}, кэш проверен и сохранён атомарно",
                            installed.endpoints.len(),
                            installed.config_date
                        );
                        if !transparent_ports.is_empty() {
                            let sync_path =
                                std::env::var_os("R2O_TG_DC_MAP_SYNC").map(PathBuf::from);
                            match write_manifest_and_sync(
                                &endpoint_pairs_path,
                                &installed,
                                &transparent_ports,
                                sync_path.clone(),
                            )
                            .await
                            {
                                Ok(count) if sync_path.is_some() => {
                                    info!(
                                        "Платформенным адаптером синхронизированы проверенные пары Telegram IP+порт: {count}"
                                    );
                                }
                                Ok(count) => {
                                    info!(
                                        "Манифест проверенных пар Telegram IP+порт сохранён: {count}; адаптер событий не задан"
                                    );
                                }
                                Err(error) => warn!(
                                    "Обновлена карта DC, но платформенная синхронизация не подтверждена; listener продолжает работу: {error}"
                                ),
                            }
                        }
                    }
                    Err(error) => {
                        warn!("Не удалось сохранить официальную карту Telegram DC: {error}");
                        tokio::time::sleep(Duration::from_secs(MIN_REFRESH_SECS)).await;
                        continue;
                    }
                },
                Err(error) => {
                    warn!(
                        "Не удалось обновить карту Telegram DC; используются кэш и встроенная резервная карта: {error}"
                    );
                    tokio::time::sleep(Duration::from_secs(MIN_REFRESH_SECS)).await;
                    continue;
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(interval)).await;
    }
}

/// Каждые пять минут сверять карту DC с правилами платформы и повторять сбой.
pub async fn periodic_platform_sync_loop(
    store: Arc<crate::dc_map::DcMapStore>,
    endpoint_pairs_path: PathBuf,
    transparent_ports: Vec<u16>,
    sync_path: PathBuf,
) {
    loop {
        tokio::time::sleep(Duration::from_secs(PLATFORM_SYNC_RETRY_SECS)).await;
        if let Err(error) =
            platform_sync_tick(&store, &endpoint_pairs_path, &transparent_ports, &sync_path).await
        {
            warn!("Не удалось повторно сверить пары Telegram DC: {error}");
        }
    }
}

async fn platform_sync_tick(
    store: &crate::dc_map::DcMapStore,
    endpoint_pairs_path: &Path,
    transparent_ports: &[u16],
    sync_path: &Path,
) -> Result<usize, String> {
    if transparent_ports.is_empty() {
        return Ok(0);
    }
    let Some(snapshot) = store.current() else {
        return Ok(0);
    };
    write_manifest_and_sync(
        endpoint_pairs_path,
        &snapshot,
        transparent_ports,
        Some(sync_path.to_path_buf()),
    )
    .await
}

async fn write_manifest_and_sync(
    endpoint_pairs_path: &Path,
    snapshot: &DcSnapshot,
    transparent_ports: &[u16],
    sync_path: Option<PathBuf>,
) -> Result<usize, String> {
    let _guard = PLATFORM_SYNC_LOCK.lock().await;
    let count = write_endpoint_manifest(endpoint_pairs_path, snapshot, transparent_ports)
        .map_err(|error| format!("манифест: {error}"))?;
    sync_platform_adapter(sync_path)
        .await
        .map_err(|error| format!("синхронизация платформенного адаптера: {error}"))?;
    Ok(count)
}

/// Передать обновлённый endpoint-manifest платформенному адаптеру.
async fn sync_platform_adapter(path: Option<PathBuf>) -> Result<(), String> {
    let Some(path) = path else {
        return Ok(());
    };
    let mut child = Command::new(&path)
        .arg("sync-dc-map")
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| format!("запуск платформенного адаптера: {error}"))?;
    match tokio::time::timeout(PLATFORM_SYNC_TIMEOUT, child.wait()).await {
        Ok(Ok(status)) if status.success() => Ok(()),
        Ok(Ok(status)) => Err(format!("платформенный адаптер вернул {status}")),
        Ok(Err(error)) => Err(format!("ожидание платформенного адаптера: {error}")),
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            Err(format!(
                "платформенный адаптер превысил тайм-аут {} секунд",
                PLATFORM_SYNC_TIMEOUT.as_secs()
            ))
        }
    }
}

fn unix_time() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{
        TELEGRAM_CONFIG_API_ID, config_bytes_to_snapshot, config_request, config_to_snapshot,
        exchange_encrypted, parse_res_pq_response, probe_res_pq, sync_platform_adapter,
        worker_domains_for_discovery, write_manifest_and_sync,
    };
    use crate::outbound::OutboundConnector;
    use crate::runtime::Runtime;
    use grammers_crypto::{DequeBuffer, ObfuscatedCipher};
    use grammers_mtproto::mtp::Encrypted;
    use grammers_mtproto::transport::{Intermediate, Obfuscated, Tagged, Transport};
    use grammers_tl_types::{self as tl, Serializable};
    use std::fs;
    use std::net::IpAddr;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn valid_res_pq_bytes() -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x0516_2463_u32.to_le_bytes());
        bytes.extend_from_slice(&[1; 16]);
        bytes.extend_from_slice(&[2; 16]);
        bytes.extend_from_slice(&[3, b'p', b'q', b'q']);
        bytes.extend_from_slice(&0x1cb5_c415_u32.to_le_bytes());
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&7_i64.to_le_bytes());
        bytes
    }

    #[test]
    fn диагностика_принимает_только_корректный_res_pq() {
        assert!(parse_res_pq_response(&valid_res_pq_bytes()).is_ok());
        assert!(parse_res_pq_response(&[0; 4]).is_err());
    }

    #[test]
    fn help_get_config_получает_тот_же_список_worker_что_обычная_маршрутизация() {
        let runtime = Runtime::new(OutboundConnector::direct()).with_cf_worker_domains(vec![
            "worker-one.example".to_string(),
            "worker-two.example".to_string(),
        ]);
        assert_eq!(
            worker_domains_for_discovery(&runtime)
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec!["worker-one.example", "worker-two.example"]
        );
    }

    #[tokio::test]
    async fn dc_manifest_is_written_before_event_hook_and_hook_errors_propagate() {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let directory = std::env::temp_dir().join(format!(
            "r2o-tg-dc-sync-hook-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("r2o-check.sh");
        let manifest = PathBuf::from(format!("{}.manifest", path.display()));
        fs::write(
            &path,
            "#!/bin/sh\n[ -s \"$0.manifest\" ] || exit 10\nprintf '%s\\n' \"$1\" > \"$0.args\"\n",
        )
        .unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&path, permissions).unwrap();

        let now = super::unix_time();
        let options = crate::config::default_dc_bootstrap_ips()
            .into_iter()
            .map(|(id, address)| {
                tl::types::DcOption {
                    ipv6: address.parse::<IpAddr>().unwrap().is_ipv6(),
                    media_only: false,
                    tcpo_only: false,
                    cdn: false,
                    r#static: true,
                    this_port_only: false,
                    id: id as i32,
                    ip_address: address.to_string(),
                    port: 443,
                    secret: None,
                }
                .into()
            })
            .collect();
        let mut config = test_config(options);
        config.date = now as i32;
        config.expires = (now + 86_400) as i32;
        let snapshot = config_to_snapshot(config).unwrap();

        write_manifest_and_sync(&manifest, &snapshot, &[443, 5222], Some(path.clone()))
            .await
            .unwrap();
        assert_eq!(
            fs::read_to_string(format!("{}.args", path.display())).unwrap(),
            "sync-dc-map\n"
        );
        assert!(
            fs::read_to_string(&manifest)
                .unwrap()
                .starts_with("r2o-tg-dc-options-v1 ")
        );

        fs::write(&path, "#!/bin/sh\nexit 9\n").unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&path, permissions).unwrap();
        assert!(
            write_manifest_and_sync(&manifest, &snapshot, &[443], Some(path.clone()))
                .await
                .unwrap_err()
                .contains("синхронизация платформенного адаптера")
        );
        assert!(fs::metadata(&manifest).is_ok());
        assert!(sync_platform_adapter(None).await.is_ok());
        fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn периодическая_сверка_повторяет_ошибочную_синхронизацию() {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let directory = std::env::temp_dir().join(format!(
            "r2o-tg-periodic-sync-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&directory).unwrap();

        let now = super::unix_time();
        let options = crate::config::default_dc_bootstrap_ips()
            .into_iter()
            .map(|(id, address)| {
                tl::types::DcOption {
                    ipv6: address.parse::<IpAddr>().unwrap().is_ipv6(),
                    media_only: false,
                    tcpo_only: false,
                    cdn: false,
                    r#static: true,
                    this_port_only: false,
                    id: id as i32,
                    ip_address: address.to_string(),
                    port: 443,
                    secret: None,
                }
                .into()
            })
            .collect();
        let mut config = test_config(options);
        config.date = now as i32;
        config.expires = (now + 86_400) as i32;
        let snapshot = config_to_snapshot(config).unwrap();
        let store = std::sync::Arc::new(crate::dc_map::DcMapStore::without_cache(
            directory.join("карта.json"),
        ));
        store.install(snapshot, now).unwrap();

        let adapter = directory.join("сверка.sh");
        fs::write(
            &adapter,
            "#!/bin/sh\ncount=0\n[ ! -f \"$0.calls\" ] || count=$(wc -c < \"$0.calls\")\nprintf x >> \"$0.calls\"\n[ \"$count\" -ge 1 ]\n",
        )
        .unwrap();
        let mut permissions = fs::metadata(&adapter).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&adapter, permissions).unwrap();

        let manifest = directory.join("пары.tsv");
        assert_eq!(super::PLATFORM_SYNC_RETRY_SECS, 300);
        assert!(
            super::platform_sync_tick(&store, &manifest, &[443], &adapter)
                .await
                .is_err()
        );
        assert!(
            super::platform_sync_tick(&store, &manifest, &[443], &adapter)
                .await
                .is_ok()
        );
        assert_eq!(
            fs::read_to_string(format!("{}.calls", adapter.display())).unwrap(),
            "xx",
            "повторная сверка должна повторить вызов адаптера после ошибки"
        );

        fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn probe_res_pq_completes_real_obfuscated_intermediate_exchange_with_mock_dc() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let mock = tokio::spawn(async move {
            let mut init = [0u8; 64];
            server.read_exact(&mut init).await.unwrap();
            let mut server_init = init;
            server_init.reverse();
            let mut cipher = ObfuscatedCipher::new(&server_init);
            // Grammers шифрует все 64 байта заголовка, хотя заменяет в сети
            // только последние восемь. Входящий ключ должен пропустить весь
            // этот поток; ответный ключ начинается с нулевого смещения.
            cipher.decrypt(&mut [0u8; 64]);

            let mut frame_header = [0u8; 4];
            server.read_exact(&mut frame_header).await.unwrap();
            cipher.decrypt(&mut frame_header);
            let request_len = u32::from_le_bytes(frame_header) as usize;
            assert!((24..4096).contains(&request_len));
            let mut request = vec![0u8; request_len];
            server.read_exact(&mut request).await.unwrap();
            cipher.decrypt(&mut request);
            assert_eq!(
                &request[..8],
                &[0; 8],
                "req_pq_multi должен быть plain MTProto"
            );
            assert_eq!(i64::from_le_bytes(request[8..16].try_into().unwrap()), 0);
            assert_eq!(
                u32::from_le_bytes(request[20..24].try_into().unwrap()),
                0xbe7e_8ef1,
                "клиент должен отправить Telegram req_pq_multi"
            );

            let mut response_body = valid_res_pq_bytes();
            // resPQ обязан вернуть nonce исходного req_pq_multi.
            response_body[4..20].copy_from_slice(&request[24..40]);
            let mut response = Vec::with_capacity(response_body.len() + 20);
            response.extend_from_slice(&0_i64.to_le_bytes());
            response.extend_from_slice(&1_i64.to_le_bytes());
            response.extend_from_slice(&(response_body.len() as i32).to_le_bytes());
            response.extend_from_slice(&response_body);
            let mut packet = DequeBuffer::with_capacity(response.len() + 8, 0);
            packet.extend(response);
            let mut response_transport = Intermediate::new();
            response_transport.init_tag();
            response_transport.pack(&mut packet);
            cipher.encrypt(packet.as_mut());
            server.write_all(packet.as_ref()).await.unwrap();
        });

        let elapsed = probe_res_pq(&mut client).await.unwrap();
        mock.await.unwrap();
        assert!(elapsed < 5_000, "mock MTProto response must be bounded");
    }

    #[test]
    fn converts_all_official_dc_option_flags_without_merging_cdn_and_media() {
        let option = tl::types::DcOption {
            ipv6: true,
            media_only: true,
            tcpo_only: true,
            cdn: false,
            r#static: true,
            this_port_only: true,
            id: 2,
            ip_address: "2001:67c:4e8:f002::a".to_string(),
            port: 5222,
            secret: Some(vec![0xaa, 0xbb]),
        };
        let mut options = primary_options();
        options.push(option.into());
        let config = test_config(options);
        let snapshot = config_to_snapshot(config).unwrap();
        let endpoint = snapshot
            .endpoints
            .iter()
            .find(|endpoint| endpoint.id == 2 && endpoint.media_only)
            .expect("медиа-опция DC2");
        assert_eq!(endpoint.id, 2);
        assert!(endpoint.ipv6);
        assert!(endpoint.media_only);
        assert!(endpoint.tcpo_only);
        assert!(!endpoint.cdn);
        assert!(endpoint.is_static);
        assert!(endpoint.this_port_only);
        assert_eq!(endpoint.port, 5222);
        assert_eq!(endpoint.secret.as_deref(), Some("aabb"));
    }

    fn tl_bytes_field(value: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        if value.len() < 254 {
            out.push(value.len() as u8);
        } else {
            out.push(254);
            out.push(value.len() as u8);
            out.push((value.len() >> 8) as u8);
            out.push((value.len() >> 16) as u8);
        }
        out.extend_from_slice(value);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out
    }

    fn gzip_packed(payload: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        std::io::Write::write_all(&mut encoder, payload).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut out = 0x3072_cfa1_u32.to_le_bytes().to_vec();
        out.extend_from_slice(&tl_bytes_field(&compressed));
        out
    }

    #[test]
    fn config_bytes_accepts_full_tl_and_gzip_and_rejects_unknown_flags() {
        let config = test_config(primary_options());
        let bytes = tl::enums::Config::Config(config).to_bytes();
        let now = super::unix_time();
        let snapshot = config_bytes_to_snapshot(&bytes, now).unwrap();
        assert_eq!(snapshot.endpoints.len(), 5);
        assert_eq!(snapshot.this_dc, 2);

        let gzipped = gzip_packed(&bytes);
        let snapshot = config_bytes_to_snapshot(&gzipped, now).unwrap();
        assert_eq!(snapshot.endpoints.len(), 5);

        let nested = gzip_packed(&gzipped);
        assert_eq!(
            config_bytes_to_snapshot(&nested, now)
                .unwrap()
                .endpoints
                .len(),
            5
        );

        let mut unknown = bytes.clone();
        let flags = u32::from_le_bytes(unknown[4..8].try_into().unwrap());
        unknown[4..8].copy_from_slice(&(flags | (1 << 5)).to_le_bytes());
        assert!(config_bytes_to_snapshot(&unknown, now).is_err());

        let mut trailing = bytes;
        trailing.extend_from_slice(&[0, 0, 0, 0]);
        assert!(config_bytes_to_snapshot(&trailing, now).is_err());
    }

    #[test]
    fn rejects_invalid_official_address_instead_of_guessing_a_dc() {
        let option = tl::types::DcOption {
            ipv6: false,
            media_only: false,
            tcpo_only: false,
            cdn: false,
            r#static: false,
            this_port_only: false,
            id: 2,
            ip_address: "not-an-ip".to_string(),
            port: 443,
            secret: None,
        };
        assert!(config_to_snapshot(test_config(vec![option.into()])).is_err());
    }

    #[test]
    fn config_request_initializes_api_layer_without_user_auth() {
        let request = config_request();

        assert_eq!(request.layer, tl::LAYER);
        assert_eq!(request.query.api_id, TELEGRAM_CONFIG_API_ID);
        assert_eq!(request.query.device_model, "OpenWrt");
        assert_eq!(request.query.system_version, "OpenWrt");
        assert_eq!(request.query.app_version, env!("CARGO_PKG_VERSION"));
        assert_eq!(request.query.system_lang_code, "ru");
        assert_eq!(request.query.lang_code, "ru");
        assert!(request.query.proxy.is_none());
        assert!(request.query.params.is_none());
        assert_eq!(
            request.query.query.to_bytes(),
            tl::functions::help::GetConfig {}.to_bytes()
        );
    }

    #[tokio::test]
    async fn encrypted_exchange_sends_internal_request_when_push_returns_none() {
        let (mut client, mut peer) = tokio::io::duplex(16 * 1024);
        let peer_task = tokio::spawn(async move {
            let mut bytes = vec![0; 16 * 1024];
            let length = peer.read(&mut bytes).await.unwrap();
            bytes.truncate(length);
            bytes
        });
        let mut transport = Obfuscated::new(Intermediate::new());
        let mut wire = Vec::new();
        let mut encrypted = Encrypted::build()
            .time_offset(0)
            .first_salt(1)
            .finish([0; 256]);

        let result = exchange_encrypted(
            &mut client,
            &mut transport,
            &mut wire,
            &mut encrypted,
            &tl::functions::help::GetConfig {},
        )
        .await;
        drop(client);
        let sent = peer_task.await.unwrap();

        assert!(sent.len() > crate::crypto::HANDSHAKE_LEN);
        assert!(
            !result
                .unwrap_err()
                .contains("MTProto не принял запрос в исходящий пакет")
        );
    }

    /// Основные IPv4-адреса DC1–5, нужные `validate_snapshot`.
    fn primary_options() -> Vec<tl::enums::DcOption> {
        [
            (1, "149.154.175.50"),
            (2, "149.154.167.51"),
            (3, "149.154.175.100"),
            (4, "149.154.167.91"),
            (5, "149.154.171.5"),
        ]
        .into_iter()
        .map(|(id, address)| {
            tl::types::DcOption {
                ipv6: false,
                media_only: false,
                tcpo_only: false,
                cdn: false,
                r#static: true,
                this_port_only: false,
                id,
                ip_address: address.to_string(),
                port: 443,
                secret: None,
            }
            .into()
        })
        .collect()
    }

    fn test_config(dc_options: Vec<tl::enums::DcOption>) -> tl::types::Config {
        let now = super::unix_time();
        tl::types::Config {
            default_p2p_contacts: false,
            preload_featured_stickers: false,
            revoke_pm_inbox: false,
            blocked_mode: false,
            force_try_ipv6: false,
            date: now as i32,
            expires: (now + 86_400) as i32,
            test_mode: false,
            this_dc: 2,
            dc_options,
            dc_txt_domain_name: String::new(),
            chat_size_max: 0,
            megagroup_size_max: 0,
            forwarded_count_max: 0,
            online_update_period_ms: 0,
            offline_blur_timeout_ms: 0,
            offline_idle_timeout_ms: 0,
            online_cloud_timeout_ms: 0,
            notify_cloud_delay_ms: 0,
            notify_default_delay_ms: 0,
            push_chat_period_ms: 0,
            push_chat_limit: 0,
            edit_time_limit: 0,
            revoke_time_limit: 0,
            revoke_pm_time_limit: 0,
            rating_e_decay: 0,
            stickers_recent_limit: 0,
            channels_read_media_period: 0,
            tmp_sessions: None,
            call_receive_timeout_ms: 0,
            call_ring_timeout_ms: 0,
            call_connect_timeout_ms: 0,
            call_packet_timeout_ms: 0,
            me_url_prefix: String::new(),
            autoupdate_url_prefix: None,
            gif_search_username: None,
            venue_search_username: None,
            img_search_username: None,
            static_maps_provider: None,
            caption_length_max: 0,
            message_length_max: 0,
            webfile_dc_id: 2,
            suggested_lang_code: None,
            lang_pack_version: None,
            base_lang_pack_version: None,
            reactions_default: None,
            autologin_token: None,
        }
    }
}
