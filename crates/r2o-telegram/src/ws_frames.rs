//! Проверка серверных WebSocket-кадров перед tungstenite.
//!
//! tungstenite 0.24 не отвергает неканоническую length-кодировку и новый data-кадр
//! внутри фрагментированного сообщения, которые C `tg_ws_reassembly_feed`
//! считает ошибкой протокола. Guard пропускает байты без изменений, но
//! отслеживает заголовки кадров и возвращает I/O-ошибку до их разбора.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// C `TG_WS_MAX_MESSAGE`.
const MAX_MESSAGE: u64 = 4 * 1024 * 1024;

#[derive(Default)]
struct FrameState {
    header: [u8; 10],
    header_len: usize,
    remaining: u64,
    fragmented: bool,
}

pub struct FrameGuard<S> {
    inner: S,
    prefix: Vec<u8>,
    prefix_offset: usize,
    state: FrameState,
}

impl<S> std::fmt::Debug for FrameGuard<S> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FrameGuard")
            .field("prefix_len", &self.prefix.len())
            .field("remaining", &self.state.remaining)
            .field("fragmented", &self.state.fragmented)
            .finish()
    }
}

impl<S> FrameGuard<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            prefix: Vec::new(),
            prefix_offset: 0,
            state: FrameState::default(),
        }
    }

    /// Байты, уже прочитанные вместе с upgrade-заголовком.
    pub fn with_prefix(inner: S, prefix: Vec<u8>) -> Self {
        Self {
            inner,
            prefix,
            prefix_offset: 0,
            state: FrameState::default(),
        }
    }

    fn invalid(reason: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, reason)
    }

    fn feed_header(state: &mut FrameState) -> Result<(), io::Error> {
        let first = state.header[0];
        let second = state.header[1];
        if first & 0x70 != 0 {
            return Err(Self::invalid("RSV-биты без расширения"));
        }
        let opcode = first & 0x0f;
        let fin = first & 0x80 != 0;
        if !matches!(opcode, 0 | 1 | 2 | 8 | 9 | 10) {
            return Err(Self::invalid("неизвестный opcode WebSocket"));
        }
        if second & 0x80 != 0 {
            return Err(Self::invalid("замаскированный кадр сервера"));
        }
        let marker = second & 0x7f;
        let length = match marker {
            126 => {
                let value = (u64::from(state.header[2]) << 8) | u64::from(state.header[3]);
                if value < 126 {
                    return Err(Self::invalid("неканоническая 16-bit length"));
                }
                value
            }
            127 => {
                if state.header[2] & 0x80 != 0 {
                    return Err(Self::invalid("length WebSocket с установленным MSB"));
                }
                let mut value = 0u64;
                for byte in &state.header[2..10] {
                    value = (value << 8) | u64::from(*byte);
                }
                if value <= u64::from(u16::MAX) {
                    return Err(Self::invalid("неканоническая 64-bit length"));
                }
                value
            }
            value => u64::from(value),
        };
        if length > MAX_MESSAGE {
            return Err(Self::invalid("кадр WebSocket больше 4 МиБ"));
        }
        if opcode >= 8 {
            if length > 125 {
                return Err(Self::invalid("управляющий кадр больше 125 байт"));
            }
            if !fin {
                return Err(Self::invalid("фрагментированный управляющий кадр"));
            }
        } else {
            match opcode {
                0 => {
                    if !state.fragmented {
                        return Err(Self::invalid("continuation без начала сообщения"));
                    }
                    if fin {
                        state.fragmented = false;
                    }
                }
                1 | 2 => {
                    if state.fragmented {
                        return Err(Self::invalid("новый data-кадр внутри фрагментации"));
                    }
                    if !fin {
                        state.fragmented = true;
                    }
                }
                _ => unreachable!(),
            }
        }
        state.remaining = length;
        state.header_len = 0;
        Ok(())
    }

    fn consume(&mut self, mut data: &[u8]) -> Result<(), io::Error> {
        loop {
            if self.state.remaining > 0 {
                let skip = usize::try_from(self.state.remaining.min(data.len() as u64))
                    .unwrap_or(data.len());
                self.state.remaining -= skip as u64;
                data = &data[skip..];
                if data.is_empty() {
                    return Ok(());
                }
            }
            while self.state.header_len < 2 && !data.is_empty() {
                self.state.header[self.state.header_len] = data[0];
                self.state.header_len += 1;
                data = &data[1..];
            }
            if self.state.header_len < 2 {
                return Ok(());
            }
            let marker = self.state.header[1] & 0x7f;
            let extension = if marker < 126 {
                0
            } else if marker == 126 {
                2
            } else {
                8
            };
            let needed = 2 + extension;
            while self.state.header_len < needed && !data.is_empty() {
                self.state.header[self.state.header_len] = data[0];
                self.state.header_len += 1;
                data = &data[1..];
            }
            if self.state.header_len < needed {
                return Ok(());
            }
            Self::feed_header(&mut self.state)?;
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for FrameGuard<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.prefix_offset < this.prefix.len() {
            let available = &this.prefix[this.prefix_offset..];
            let take = available.len().min(buf.remaining());
            let chunk = available[..take].to_vec();
            buf.put_slice(&chunk);
            this.prefix_offset += take;
            if this.prefix_offset == this.prefix.len() {
                this.prefix.clear();
                this.prefix_offset = 0;
            }
            return match this.consume(&chunk) {
                Ok(()) => Poll::Ready(Ok(())),
                Err(error) => Poll::Ready(Err(error)),
            };
        }
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let chunk = buf.filled()[before..].to_vec();
                match this.consume(&chunk) {
                    Ok(()) => Poll::Ready(Ok(())),
                    Err(error) => Poll::Ready(Err(error)),
                }
            }
            other => other,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FrameGuard<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
