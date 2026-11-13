//! C `say`/`fail`: запись текста ошибки в буфер вызывающего.
//!
//! Контракт C: `cap == 0` — молчание; иначе `snprintf(err, cap, "%s", msg)`,
//! то есть не больше `cap - 1` байт и завершающий NUL. Обрезка побайтная —
//! UTF-8 может разрезаться, как в C.

/// Записать `text` в `buffer` по правилам `snprintf`. Возвращает число
/// записанных байт без NUL.
pub fn write_error_text(buffer: &mut [u8], text: &str) -> usize {
    if buffer.is_empty() {
        return 0;
    }
    let bytes = text.as_bytes();
    let take = bytes.len().min(buffer.len() - 1);
    buffer[..take].copy_from_slice(&bytes[..take]);
    buffer[take] = 0;
    take
}

/// Собрать строку ошибки с пределом `cap` байт (включая NUL в C-смысле).
pub fn error_text(cap: usize, text: &str) -> String {
    if cap == 0 {
        return String::new();
    }
    let mut buffer = vec![0_u8; cap];
    let written = write_error_text(&mut buffer, text);
    String::from_utf8_lossy(&buffer[..written]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::{error_text, write_error_text};

    #[test]
    fn error_text_matches_snprintf_semantics() {
        let mut empty: [u8; 0] = [];
        assert_eq!(write_error_text(&mut empty, "текст"), 0);

        let mut one = [0xAA_u8; 1];
        assert_eq!(write_error_text(&mut one, "abcdef"), 0);
        assert_eq!(one, [0]);

        let mut short = [0xAA_u8; 5];
        assert_eq!(write_error_text(&mut short, "abcdef"), 4);
        assert_eq!(&short, b"abcd\0");

        let mut exact = [0xAA_u8; 7];
        assert_eq!(write_error_text(&mut exact, "abcdef"), 6);
        assert_eq!(&exact, b"abcdef\0");

        let mut roomy = [0xAA_u8; 16];
        assert_eq!(write_error_text(&mut roomy, "ошибка"), 12);
        assert_eq!(&roomy[..12], "ошибка".as_bytes());
        assert_eq!(roomy[12], 0);

        assert_eq!(error_text(0, "x"), "");
        assert_eq!(error_text(4, "abcdef"), "abc");
        assert_eq!(error_text(16, "ok"), "ok");
    }
}
