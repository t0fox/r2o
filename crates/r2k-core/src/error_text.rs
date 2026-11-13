//! C `fail` (`datapath/plan_parse.c:32-36`): запись текста ошибки в буфер.
//!
//! `cap == 0` — молчание; иначе не больше `cap - 1` байт и завершающий NUL.
//! Обрезка побайтная, как `snprintf`.

/// Записать `text` в `buffer` по правилам `snprintf`. Возвращает число байт
/// без NUL.
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

#[cfg(test)]
mod tests {
    use super::write_error_text;

    #[test]
    fn fail_buffer_matches_snprintf() {
        let mut empty: [u8; 0] = [];
        assert_eq!(write_error_text(&mut empty, "x"), 0);

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
    }
}
