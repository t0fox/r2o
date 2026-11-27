//! Двунаправленная передача transparent MTProto потока через WSS.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cipher::StreamCipher;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Mutex as AsyncMutex, Notify};
use tracing::{info, warn};
use tungstenite::Message;

use crate::crypto::ProtoTag;
use crate::memory_budget::{BudgetReservation, MemoryBudget};
use crate::response_observer::MtprotoResponseObserver;
use crate::routing::{RouteFeedback, WsFraming};
use crate::splitter::MsgSplitter;
use crate::stats::ConnectionTelemetry;
use crate::transparent;
use crate::ws_client::{TgWsStream, WsTcpStream, media_tag};

const RELAY_BUF_SIZE: usize = 16 * 1024;
const RELAY_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
const FIRST_RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const MEDIA_RESPONSE_TIMEOUT: Duration = Duration::from_secs(20);
pub(crate) const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Default)]
pub(crate) struct ResponseProgress {
    pending_since: Mutex<Option<tokio::time::Instant>>,
    changed: Notify,
}

impl ResponseProgress {
    pub(crate) fn sent(&self) {
        let mut pending = self.pending_since.lock().unwrap();
        if pending.is_none() {
            *pending = Some(tokio::time::Instant::now());
            self.changed.notify_one();
        }
    }

    pub(crate) fn received(&self) {
        if self.pending_since.lock().unwrap().take().is_some() {
            self.changed.notify_one();
        }
    }

    pub(crate) async fn stalled(&self, timeout: Duration) {
        self.stalled_while_reading(timeout, None).await;
    }

    async fn stalled_while_reading(
        &self,
        timeout: Duration,
        read_progress: Option<&Mutex<Option<tokio::time::Instant>>>,
    ) {
        loop {
            let changed = self.changed.notified();
            let pending = *self.pending_since.lock().unwrap();
            let Some(sent) = pending else {
                changed.await;
                continue;
            };
            let deadline = recent_read_or(sent, read_progress) + timeout;
            tokio::select! {
                biased;
                _ = changed => {}
                _ = tokio::time::sleep_until(deadline) => {
                    if *self.pending_since.lock().unwrap() == Some(sent)
                        && recent_read_or(sent, read_progress).elapsed() >= timeout
                    {
                        return;
                    }
                }
            }
        }
    }
}

enum MtprotoResponseState {
    NotSent,
    Awaiting {
        started: tokio::time::Instant,
        last_delivery: tokio::time::Instant,
    },
    Confirmed,
    Failed,
}

async fn send_application_frame<S>(
    ws_write: &Arc<AsyncMutex<S>>,
    response_state: &Arc<AsyncMutex<MtprotoResponseState>>,
    feedback: &RouteFeedback,
    first_request: &Notify,
    frame: Vec<u8>,
) -> Result<(), String>
where
    S: futures_util::Sink<Message> + Unpin + Send,
    S::Error: std::fmt::Display,
{
    let mut state = response_state.lock().await;
    let first_application_frame = matches!(&*state, MtprotoResponseState::NotSent);
    if first_application_frame {
        let now = tokio::time::Instant::now();
        *state = MtprotoResponseState::Awaiting {
            started: now,
            last_delivery: now,
        };
        first_request.notify_one();
    }

    drop(state);
    match ws_write.lock().await.send(Message::Binary(frame)).await {
        Ok(()) => Ok(()),
        Err(error) => {
            record_mtproto_failure_if_pending(response_state, feedback).await;
            Err(format!("ошибка отправки кадра WSS: {error}"))
        }
    }
}

async fn record_first_mtproto_response(
    response_state: &Arc<AsyncMutex<MtprotoResponseState>>,
) -> Option<Duration> {
    let mut state = response_state.lock().await;
    if let MtprotoResponseState::Awaiting { started, .. } = &*state {
        let latency = started.elapsed();
        *state = MtprotoResponseState::Confirmed;
        Some(latency)
    } else {
        None
    }
}

async fn record_first_response_progress(response_state: &AsyncMutex<MtprotoResponseState>) {
    if let MtprotoResponseState::Awaiting { last_delivery, .. } = &mut *response_state.lock().await
    {
        *last_delivery = tokio::time::Instant::now();
    }
}

fn recent_read_or(
    baseline: tokio::time::Instant,
    read_progress: Option<&Mutex<Option<tokio::time::Instant>>>,
) -> tokio::time::Instant {
    read_progress
        .and_then(|progress| *progress.lock().unwrap())
        .map_or(baseline, |read| read.max(baseline))
}

async fn wait_for_first_response_stall(
    response_state: &AsyncMutex<MtprotoResponseState>,
    first_request: &Notify,
    read_progress: Option<&Mutex<Option<tokio::time::Instant>>>,
) {
    loop {
        let deadline = match *response_state.lock().await {
            MtprotoResponseState::Awaiting { last_delivery, .. } => {
                Some(recent_read_or(last_delivery, read_progress) + FIRST_RESPONSE_TIMEOUT)
            }
            MtprotoResponseState::NotSent => None,
            _ => return std::future::pending().await,
        };
        let Some(deadline) = deadline else {
            first_request.notified().await;
            continue;
        };
        if tokio::time::Instant::now() >= deadline {
            return;
        }
        tokio::time::sleep_until(deadline).await;
    }
}

async fn observe_and_record_first_mtproto_response(
    observer: &mut MtprotoResponseObserver,
    payload: &[u8],
    response_state: &Arc<AsyncMutex<MtprotoResponseState>>,
) -> Result<Option<Duration>, ()> {
    if observer.observe(payload)? {
        Ok(record_first_mtproto_response(response_state).await)
    } else {
        Ok(None)
    }
}

async fn record_mtproto_failure_if_pending(
    response_state: &Arc<AsyncMutex<MtprotoResponseState>>,
    feedback: &RouteFeedback,
) {
    let mut state = response_state.lock().await;
    if matches!(&*state, MtprotoResponseState::Awaiting { .. }) {
        *state = MtprotoResponseState::Failed;
        crate::routing::record_mtproto_failure(feedback);
    }
}

#[derive(Clone)]
pub(crate) struct PayloadActivity {
    started: tokio::time::Instant,
    last_payload_ms: Arc<AtomicUsize>,
}

impl PayloadActivity {
    pub(crate) fn new() -> Self {
        Self {
            started: tokio::time::Instant::now(),
            last_payload_ms: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub(crate) fn touch(&self) {
        self.last_payload_ms.store(
            self.started.elapsed().as_millis() as usize,
            Ordering::Relaxed,
        );
    }

    pub(crate) async fn idle_reached(&self, idle_timeout: Duration) {
        let idle_ms = idle_timeout.as_millis().min(usize::MAX as u128) as usize;
        loop {
            let elapsed_ms = self.started.elapsed().as_millis() as usize;
            let last_payload_ms = self.last_payload_ms.load(Ordering::Relaxed);
            let idle_for_ms = elapsed_ms.wrapping_sub(last_payload_ms);
            if idle_for_ms >= idle_ms {
                return;
            }

            let remaining_ms = (idle_ms - idle_for_ms) as u64;
            tokio::time::sleep(Duration::from_millis(remaining_ms)).await;
        }
    }
}

enum UploadEnd {
    Fin,
    Aborted(String),
}

enum DownloadEnd {
    ResponseTimeout { media: bool },
    PeerClose(String),
    ClientError(String),
    UpstreamError(String),
}

// Pending I/O owns both stream halves in Open. TCP FIN enters Draining;
// a WebSocket Close or a bounded drain transitions to Closing. I/O errors
// enter Aborted without waiting for a peer that can no longer complete Close.
enum RelayCompletion {
    ResponseTimeout { media: bool },
    ClientFin,
    PeerClose(String),
    Aborted { side: &'static str, reason: String },
    Idle,
}

impl From<DownloadEnd> for RelayCompletion {
    fn from(value: DownloadEnd) -> Self {
        match value {
            DownloadEnd::ResponseTimeout { media } => Self::ResponseTimeout { media },
            DownloadEnd::PeerClose(reason) => Self::PeerClose(reason),
            DownloadEnd::ClientError(reason) => Self::Aborted {
                side: "клиент",
                reason,
            },
            DownloadEnd::UpstreamError(reason) => Self::Aborted {
                side: "upstream",
                reason,
            },
        }
    }
}

async fn race_directions(
    upload: impl Future<Output = UploadEnd>,
    download: impl Future<Output = DownloadEnd>,
    drain_timeout: Duration,
) -> RelayCompletion {
    tokio::pin!(upload, download);
    tokio::select! {
        result = &mut download => result.into(),
        result = &mut upload => match result {
            UploadEnd::Fin => match tokio::time::timeout(drain_timeout, download).await {
                Ok(result) => result.into(),
                Err(_) => RelayCompletion::ClientFin,
            },
            UploadEnd::Aborted(reason) => RelayCompletion::Aborted { side: "передача в upstream", reason },
        },
    }
}

async fn supervise_directions(
    upload: impl Future<Output = UploadEnd>,
    download: impl Future<Output = DownloadEnd>,
    activity: &PayloadActivity,
    idle_timeout: Duration,
    drain_timeout: Duration,
) -> RelayCompletion {
    tokio::select! {
        ended = race_directions(upload, download, drain_timeout) => ended,
        _ = activity.idle_reached(idle_timeout) => RelayCompletion::Idle,
    }
}

async fn complete_ws_close<S, R>(
    write: &mut S,
    read: &mut R,
    peer_started: bool,
) -> Result<(), tungstenite::Error>
where
    S: futures_util::Sink<Message, Error = tungstenite::Error> + Unpin,
    R: futures_util::Stream<Item = Result<Message, tungstenite::Error>> + Unpin,
{
    if peer_started {
        // tungstenite queues the matching Close as soon as Stream yields it.
        return write.flush().await;
    }
    write.send(Message::Close(None)).await?;
    while let Some(message) = read.next().await {
        if matches!(message?, Message::Close(_)) {
            return write.flush().await;
        }
    }
    Err(tungstenite::Error::Protocol(
        tungstenite::error::ProtocolError::ResetWithoutClosingHandshake,
    ))
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn bridge_transparent_ws(
    stream: TcpStream,
    mut ws: TgWsStream,
    init: [u8; crate::crypto::HANDSHAKE_LEN],
    label: SocketAddr,
    destination: SocketAddr,
    dc: u32,
    is_media: bool,
    proto: ProtoTag,
    framing: WsFraming,
    route_type: &'static str,
    feedback: RouteFeedback,
    telemetry: ConnectionTelemetry,
    memory_budget: Option<Arc<MemoryBudget>>,
    watch_media_progress: bool,
) {
    info!(
        "[{}] прозрачный маршрут: {} → DC{}{} через {} (кадрирование: {})",
        label,
        destination,
        dc,
        media_tag(is_media),
        route_type,
        framing.as_str()
    );
    // C epoll_proxy резервирует базовый буфер соединения в общем бюджете.
    // R2O удерживает тот же RELAY_BUF_SIZE на всё время моста.
    let _relay_reservation = match memory_budget.as_ref() {
        Some(budget) => match BudgetReservation::acquire(budget, RELAY_BUF_SIZE) {
            Some(reservation) => Some(reservation),
            None => {
                warn!(
                    "[{}] бюджет памяти Telegram исчерпан до старта моста",
                    label
                );
                return;
            }
        },
        None => None,
    };
    let (mut client_read, mut client_write) = stream.into_split();
    let read_progress = WsTcpStream::track_read_progress(&mut ws);
    let (ws_write, mut ws_read) = ws.split();
    let ws_write = Arc::new(AsyncMutex::new(ws_write));
    let bytes_up = Arc::new(AtomicUsize::new(0));
    let bytes_down = Arc::new(AtomicUsize::new(0));
    let activity = PayloadActivity::new();
    let progress = watch_media_progress.then(ResponseProgress::default);
    let progress = progress.as_ref();
    let response_state = Arc::new(AsyncMutex::new(MtprotoResponseState::NotSent));
    let response_observer = MtprotoResponseObserver::new(&init, proto);
    let first_request = Notify::new();
    let first_request_signal = &first_request;

    let upload = {
        let ws_write = Arc::clone(&ws_write);
        let bytes_up = Arc::clone(&bytes_up);
        let activity = activity.clone();
        let response_state = Arc::clone(&response_state);
        let feedback = feedback.clone();
        let telemetry = telemetry.clone();
        let memory_budget = memory_budget.clone();
        async move {
            let init_reservation = match memory_budget.as_ref() {
                Some(budget) => match BudgetReservation::acquire(budget, init.len()) {
                    Some(reservation) => Some(reservation),
                    None => {
                        return UploadEnd::Aborted(
                            "бюджет памяти Telegram исчерпан для init".into(),
                        );
                    }
                },
                None => None,
            };
            if ws_write
                .lock()
                .await
                .send(Message::Binary(init.to_vec()))
                .await
                .is_err()
            {
                return UploadEnd::Aborted("не удалось отправить init по WSS".into());
            }
            drop(init_reservation);
            bytes_up.fetch_add(init.len(), Ordering::Relaxed);
            activity.touch();

            let (mut decrypt, mut encrypt) = transparent::direct_stream_ciphers(&init);
            let mut splitter = (framing == WsFraming::Packets).then(|| MsgSplitter::new(proto));
            let mut buffer = vec![0u8; RELAY_BUF_SIZE];
            loop {
                let length = match client_read.read(&mut buffer).await {
                    Ok(0) => break,
                    Err(error) => {
                        return UploadEnd::Aborted(format!("ошибка чтения TCP клиента: {error}"));
                    }
                    Ok(length) => length,
                };
                telemetry.record_client_bytes(length as u64);

                if let Some(splitter) = splitter.as_mut() {
                    decrypt.apply_keystream(&mut buffer[..length]);
                    let frames = splitter.split_and_encrypt(&mut buffer[..length], &mut encrypt);
                    if let Some(error) = splitter.error() {
                        return UploadEnd::Aborted(format!("ошибка кадрирования MTProto: {error}"));
                    }
                    for frame in frames {
                        let frame_len = frame.len();
                        let _frame_reservation = match memory_budget.as_ref() {
                            Some(budget) => match BudgetReservation::acquire(budget, frame_len) {
                                Some(reservation) => Some(reservation),
                                None => {
                                    return UploadEnd::Aborted(
                                        "бюджет памяти Telegram исчерпан для кадра WSS".into(),
                                    );
                                }
                            },
                            None => None,
                        };
                        if let Some(progress) = progress {
                            progress.sent();
                        }
                        if let Err(error) = send_application_frame(
                            &ws_write,
                            &response_state,
                            &feedback,
                            first_request_signal,
                            frame,
                        )
                        .await
                        {
                            return UploadEnd::Aborted(error);
                        }
                        bytes_up.fetch_add(frame_len, Ordering::Relaxed);
                        activity.touch();
                    }
                } else {
                    let _frame_reservation = match memory_budget.as_ref() {
                        Some(budget) => match BudgetReservation::acquire(budget, length) {
                            Some(reservation) => Some(reservation),
                            None => {
                                return UploadEnd::Aborted(
                                    "бюджет памяти Telegram исчерпан для кадра WSS".into(),
                                );
                            }
                        },
                        None => None,
                    };
                    if let Some(progress) = progress {
                        progress.sent();
                    }
                    if let Err(error) = send_application_frame(
                        &ws_write,
                        &response_state,
                        &feedback,
                        first_request_signal,
                        buffer[..length].to_vec(),
                    )
                    .await
                    {
                        return UploadEnd::Aborted(error);
                    }
                    bytes_up.fetch_add(length, Ordering::Relaxed);
                    activity.touch();
                }
            }

            if let Some(splitter) = splitter.as_mut() {
                let pending = splitter.pending_len();
                if pending > 0 {
                    warn!(
                        "[{}] ошибка кадрирования MTProto: при закрытии осталось {} байт неполного пакета",
                        label, pending
                    );
                }
                // A partial MTProto frame cannot be carried as a valid packet.
            }
            UploadEnd::Fin
        }
    };

    let download = {
        let ws_read = &mut ws_read;
        let ws_write = Arc::clone(&ws_write);
        let bytes_down = Arc::clone(&bytes_down);
        let activity = activity.clone();
        let response_state = Arc::clone(&response_state);
        let feedback = feedback.clone();
        let telemetry = telemetry.clone();
        let memory_budget = memory_budget.clone();
        let mut response_observer = response_observer;
        async move {
            let mut response_observer_enabled = true;
            let mut first_response_seen = false;
            loop {
                // Пока tungstenite собирает один кадр, учитываем частичные
                // чтения. Завершённый Ping/Pong не считается ответом MTProto.
                *read_progress.lock().unwrap() = None;
                let media_timeout = async {
                    if let Some(progress) = progress {
                        progress
                            .stalled_while_reading(MEDIA_RESPONSE_TIMEOUT, Some(&read_progress))
                            .await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                };
                let message = tokio::select! {
                    biased;
                    message = ws_read.next() => message,
                    _ = wait_for_first_response_stall(&response_state, first_request_signal, Some(&read_progress)) => {
                        return DownloadEnd::ResponseTimeout { media: false };
                    }
                    _ = media_timeout => return DownloadEnd::ResponseTimeout { media: true },
                };
                let Some(message) = message else {
                    break;
                };
                match message {
                    Ok(Message::Binary(data)) => {
                        let length = data.len();
                        let _message_reservation = match memory_budget.as_ref() {
                            Some(budget) => match BudgetReservation::acquire(budget, length) {
                                Some(reservation) => Some(reservation),
                                None => {
                                    return DownloadEnd::ClientError(
                                        "бюджет памяти Telegram исчерпан для ответа WSS".into(),
                                    );
                                }
                            },
                            None => None,
                        };
                        telemetry.record_upstream_bytes(length as u64);
                        if response_observer_enabled {
                            match observe_and_record_first_mtproto_response(
                                &mut response_observer,
                                &data,
                                &response_state,
                            )
                            .await
                            {
                                Ok(Some(latency)) => {
                                    response_observer_enabled = false;
                                    first_response_seen = true;
                                    telemetry.mark_mtproto_response(latency);
                                    info!(
                                        "[{}] первый MTProto ответ DC{}{} через {} получен за {} мс",
                                        label,
                                        dc,
                                        media_tag(is_media),
                                        route_type,
                                        latency.as_millis()
                                    );
                                    crate::routing::record_mtproto_response_with_client_latency(
                                        &feedback,
                                        latency,
                                        telemetry.client_elapsed_us(),
                                    );
                                }
                                Ok(None) => {}
                                Err(()) => response_observer_enabled = false,
                            }
                        }
                        if let Err(error) = client_write.write_all(&data).await {
                            return DownloadEnd::ClientError(format!(
                                "ошибка записи в TCP клиента: {error}"
                            ));
                        }
                        if !data.is_empty()
                            && let Some(progress) = progress
                        {
                            progress.received();
                        }
                        if !first_response_seen && !data.is_empty() {
                            // Прогресс продлевает ожидание, но сам по себе не подтверждает MTProto.
                            record_first_response_progress(&response_state).await;
                        }
                        bytes_down.fetch_add(length, Ordering::Relaxed);
                        activity.touch();
                    }
                    Ok(Message::Text(data)) => {
                        let length = data.len();
                        let _message_reservation = match memory_budget.as_ref() {
                            Some(budget) => match BudgetReservation::acquire(budget, length) {
                                Some(reservation) => Some(reservation),
                                None => {
                                    return DownloadEnd::ClientError(
                                        "бюджет памяти Telegram исчерпан для ответа WSS".into(),
                                    );
                                }
                            },
                            None => None,
                        };
                        telemetry.record_upstream_bytes(length as u64);
                        if let Err(error) = client_write.write_all(data.as_bytes()).await {
                            return DownloadEnd::ClientError(format!(
                                "ошибка записи текста WSS в TCP клиента: {error}"
                            ));
                        }
                        bytes_down.fetch_add(length, Ordering::Relaxed);
                        activity.touch();
                    }
                    Ok(Message::Ping(_)) => {
                        // tungstenite has already queued a Pong with the same payload.
                        if let Err(error) = ws_write.lock().await.flush().await {
                            return DownloadEnd::UpstreamError(format!(
                                "ошибка ответа на WSS ping: {error}"
                            ));
                        }
                    }
                    Ok(Message::Pong(_)) => {}
                    Ok(Message::Close(frame)) => {
                        record_mtproto_failure_if_pending(&response_state, &feedback).await;
                        return DownloadEnd::PeerClose(match frame {
                            Some(frame) => format!(
                                "upstream закрыл WSS: код={:?}, причина={}",
                                frame.code, frame.reason
                            ),
                            None => "upstream закрыл WSS без кода".to_string(),
                        });
                    }
                    Err(error) => {
                        record_mtproto_failure_if_pending(&response_state, &feedback).await;
                        return DownloadEnd::UpstreamError(format!("ошибка чтения WSS: {error}"));
                    }
                    _ => {
                        record_mtproto_failure_if_pending(&response_state, &feedback).await;
                        return DownloadEnd::UpstreamError(
                            "upstream прислал неподдерживаемый кадр WSS".into(),
                        );
                    }
                }
            }
            record_mtproto_failure_if_pending(&response_state, &feedback).await;
            DownloadEnd::UpstreamError("upstream завершил WSS без Close".into())
        }
    };

    let completion = supervise_directions(
        upload,
        download,
        &activity,
        SESSION_IDLE_TIMEOUT,
        RELAY_DRAIN_TIMEOUT,
    )
    .await;
    let (closed_by, reason, closing) = match completion {
        RelayCompletion::ResponseTimeout { media: false } => {
            record_mtproto_failure_if_pending(&response_state, &feedback).await;
            telemetry.set_stage("mtproto_timeout");
            (
                "таймер MTProto",
                "нет входящих данных перед подтверждением MTProto".into(),
                Some(false),
            )
        }
        RelayCompletion::ResponseTimeout { media: true } => {
            crate::routing::record_mtproto_failure(&feedback);
            telemetry.set_stage("media_stall");
            (
                "таймер медиа",
                "после запроса нет данных от сервера".into(),
                Some(false),
            )
        }
        RelayCompletion::ClientFin => ("клиент", "клиент закрыл TCP".into(), Some(false)),
        RelayCompletion::PeerClose(reason) => ("upstream", reason, Some(true)),
        RelayCompletion::Aborted { side, reason } => (side, reason, None),
        RelayCompletion::Idle => (
            "таймер простоя",
            format!("нет MTProto-данных {SESSION_IDLE_TIMEOUT:?}"),
            Some(false),
        ),
    };
    let close_state = if let Some(peer_started) = closing {
        let handshake = async {
            complete_ws_close(&mut *ws_write.lock().await, &mut ws_read, peer_started).await
        };
        match tokio::time::timeout(RELAY_DRAIN_TIMEOUT, handshake).await {
            Ok(Ok(())) => "CLOSED",
            Ok(Err(error)) => {
                warn!("[{}] ошибка завершения WSS Close: {}", label, error);
                "ABORTED"
            }
            Err(_) => {
                warn!(
                    "[{}] нет подтверждения WSS Close за {:?}",
                    label, RELAY_DRAIN_TIMEOUT
                );
                "ABORTED"
            }
        }
    } else {
        "ABORTED"
    };
    info!(
        "[{}] сессия DC{}{} через {} закрыта стороной {}: состояние={}, причина={}, вверх {} байт, вниз {} байт",
        label,
        dc,
        media_tag(is_media),
        route_type,
        closed_by,
        close_state,
        reason,
        bytes_up.load(Ordering::Relaxed),
        bytes_down.load(Ordering::Relaxed)
    );
}

#[cfg(test)]
mod tests {
    use super::{
        DownloadEnd, FIRST_RESPONSE_TIMEOUT, MtprotoResponseState, PayloadActivity,
        RelayCompletion, ResponseProgress, UploadEnd, observe_and_record_first_mtproto_response,
        race_directions, record_first_mtproto_response, record_first_response_progress,
        send_application_frame, supervise_directions, wait_for_first_response_stall,
    };
    use cipher::StreamCipher;
    use std::future;
    use std::io;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll};
    use std::time::Duration;
    use tokio::sync::oneshot;
    use tungstenite::Message;

    use crate::crypto::{HANDSHAKE_LEN, ProtoTag, direct_server_stream_cipher};
    use crate::response_observer::MtprotoResponseObserver;
    use crate::routing::RouteFeedback;

    #[tokio::test(start_paused = true)]
    async fn media_stall_requires_upload_without_download_progress() {
        let progress = ResponseProgress::default();
        let timeout = Duration::from_secs(20);
        let stalled = progress.stalled(timeout);
        tokio::pin!(stalled);
        assert!(
            tokio::time::timeout(timeout * 2, &mut stalled)
                .await
                .is_err()
        );

        progress.sent();
        assert!(
            tokio::time::timeout(timeout / 2, &mut stalled)
                .await
                .is_err()
        );
        progress.received();
        assert!(
            tokio::time::timeout(timeout * 2, &mut stalled)
                .await
                .is_err()
        );

        progress.sent();
        assert!(
            tokio::time::timeout(timeout / 2, &mut stalled)
                .await
                .is_err()
        );
        progress.sent();
        stalled.await;
    }

    struct TestSink {
        fail_send: bool,
    }

    impl futures_util::Sink<Message> for TestSink {
        type Error = io::Error;

        fn poll_ready(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, _: Message) -> Result<(), Self::Error> {
            if self.fail_send {
                Err(io::Error::other("ошибка отправки"))
            } else {
                Ok(())
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    struct DropCount(Arc<AtomicUsize>);

    impl Drop for DropCount {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn здоровье_маршрута_ждёт_первый_ответ_mtproto_после_запроса() {
        let response_state = Arc::new(tokio::sync::Mutex::new(MtprotoResponseState::NotSent));
        let sink = Arc::new(tokio::sync::Mutex::new(TestSink { fail_send: false }));
        let feedback = RouteFeedback::direct(997, false, "149.154.167.50", Duration::from_secs(1));

        assert!(
            record_first_mtproto_response(&response_state)
                .await
                .is_none()
        );
        send_application_frame(
            &sink,
            &response_state,
            &feedback,
            &tokio::sync::Notify::new(),
            vec![1, 2, 3],
        )
        .await
        .unwrap();
        assert!(
            record_first_mtproto_response(&response_state)
                .await
                .is_some()
        );
        assert!(
            record_first_mtproto_response(&response_state)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn ошибка_отправки_не_подтверждает_здоровье_mtproto() {
        let response_state = Arc::new(tokio::sync::Mutex::new(MtprotoResponseState::NotSent));
        let sink = Arc::new(tokio::sync::Mutex::new(TestSink { fail_send: true }));
        let feedback = RouteFeedback::direct(998, false, "149.154.167.51", Duration::from_secs(1));

        assert!(
            send_application_frame(
                &sink,
                &response_state,
                &feedback,
                &tokio::sync::Notify::new(),
                vec![1, 2, 3]
            )
            .await
            .is_err()
        );
        assert!(
            record_first_mtproto_response(&response_state)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn непустая_некорректная_binary_рамка_не_подтверждает_маршрут() {
        let response_state = Arc::new(tokio::sync::Mutex::new(MtprotoResponseState::NotSent));
        let sink = Arc::new(tokio::sync::Mutex::new(TestSink { fail_send: false }));
        let feedback = RouteFeedback::direct(996, false, "149.154.167.52", Duration::from_secs(1));
        send_application_frame(
            &sink,
            &response_state,
            &feedback,
            &tokio::sync::Notify::new(),
            vec![1, 2, 3],
        )
        .await
        .unwrap();

        let init = [0_u8; HANDSHAKE_LEN];
        let mut encrypt = direct_server_stream_cipher(&init);
        let mut observer = MtprotoResponseObserver::new(&init, ProtoTag::Intermediate);
        let mut ack = [0_u8, 0, 0, 0x80];
        encrypt.apply_keystream(&mut ack);
        assert!(matches!(
            observe_and_record_first_mtproto_response(&mut observer, &ack, &response_state,).await,
            Ok(None)
        ));

        let mut invalid = [0_u8; 4];
        encrypt.apply_keystream(&mut invalid);

        assert!(
            observe_and_record_first_mtproto_response(&mut observer, &invalid, &response_state,)
                .await
                .is_err()
        );
        assert!(matches!(
            &*response_state.lock().await,
            MtprotoResponseState::Awaiting { .. }
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn данные_сдвигают_таймер_wss_без_подтверждения_маршрута() {
        let state = Arc::new(tokio::sync::Mutex::new(MtprotoResponseState::NotSent));
        let sink = Arc::new(tokio::sync::Mutex::new(TestSink { fail_send: false }));
        let first_request = tokio::sync::Notify::new();
        let feedback = RouteFeedback::direct(997, false, "149.154.167.50", Duration::from_secs(1));
        send_application_frame(&sink, &state, &feedback, &first_request, vec![1, 2, 3])
            .await
            .unwrap();
        let stalled = wait_for_first_response_stall(&state, &first_request, None);
        tokio::pin!(stalled);

        let gap = FIRST_RESPONSE_TIMEOUT - Duration::from_secs(1);
        for _ in 0..2 {
            assert!(tokio::time::timeout(gap, &mut stalled).await.is_err());
            record_first_response_progress(&state).await;
        }
        assert!(matches!(
            *state.lock().await,
            MtprotoResponseState::Awaiting { .. }
        ));
        let last_delivery = tokio::time::Instant::now();
        stalled.await;
        assert_eq!(last_delivery.elapsed(), FIRST_RESPONSE_TIMEOUT);
    }

    #[tokio::test(start_paused = true)]
    async fn partial_ws_frames_extend_response_deadline_until_message_arrives() {
        use tokio::io::AsyncWriteExt;
        use tokio::net::{TcpListener, TcpStream};
        use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
        use tungstenite::protocol::Role;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut peer, _) = listener.accept().await.unwrap();
        let mut ws = WebSocketStream::from_raw_socket(
            MaybeTlsStream::Plain(crate::ws_client::WsTcpStream::new(tcp)),
            Role::Client,
            None,
        )
        .await;
        let progress = crate::ws_client::WsTcpStream::track_read_progress(&mut ws);
        let now = tokio::time::Instant::now();
        let state = tokio::sync::Mutex::new(MtprotoResponseState::Awaiting {
            started: now,
            last_delivery: now,
        });
        let first_request = tokio::sync::Notify::new();
        let gap = FIRST_RESPONSE_TIMEOUT - Duration::from_secs(1);
        let send = async move {
            // Frame start, then the second payload byte from a partial TCP read,
            // then the final continuation frame.
            peer.write_all(&[0x02, 2, 0x11]).await.unwrap();
            tokio::time::sleep(gap).await;
            peer.write_all(&[0x22]).await.unwrap();
            tokio::time::sleep(gap).await;
            peer.write_all(&[0x80, 1, 0x33]).await.unwrap();
        };
        let receive = async {
            use futures_util::StreamExt;
            tokio::select! {
                message = ws.next() => assert_eq!(message.unwrap().unwrap(), Message::Binary(vec![0x11, 0x22, 0x33])),
                _ = wait_for_first_response_stall(&state, &first_request, Some(&progress)) => panic!("partial frame timed out"),
            }
        };
        tokio::join!(send, receive);
        assert!(now.elapsed() > FIRST_RESPONSE_TIMEOUT);
    }

    #[tokio::test]
    async fn полный_валидный_mtproto_пакет_подтверждает_маршрут() {
        let response_state = Arc::new(tokio::sync::Mutex::new(MtprotoResponseState::NotSent));
        let sink = Arc::new(tokio::sync::Mutex::new(TestSink { fail_send: false }));
        let feedback = RouteFeedback::direct(995, false, "149.154.167.53", Duration::from_secs(1));
        send_application_frame(
            &sink,
            &response_state,
            &feedback,
            &tokio::sync::Notify::new(),
            vec![1, 2, 3],
        )
        .await
        .unwrap();

        let init = [0_u8; HANDSHAKE_LEN];
        let mut encrypt = direct_server_stream_cipher(&init);
        let mut valid = vec![40, 0, 0, 0];
        valid.extend(1_u8..=40);
        encrypt.apply_keystream(&mut valid);
        let mut observer = MtprotoResponseObserver::new(&init, ProtoTag::Intermediate);

        assert!(
            observe_and_record_first_mtproto_response(&mut observer, &valid, &response_state,)
                .await
                .unwrap()
                .is_some()
        );
        assert!(matches!(
            &*response_state.lock().await,
            MtprotoResponseState::Confirmed
        ));
    }

    #[tokio::test]
    async fn close_handshake_works_in_both_directions_over_tcp() {
        use futures_util::{SinkExt, StreamExt};
        use tokio::net::{TcpListener, TcpStream};
        use tokio_tungstenite::{accept_async, client_async};

        for server_starts in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = async {
                let (tcp, _) = listener.accept().await.unwrap();
                let mut ws = accept_async(tcp).await.unwrap();
                if server_starts {
                    ws.send(Message::Close(None)).await.unwrap();
                }
                assert!(matches!(ws.next().await, Some(Ok(Message::Close(_)))));
                if !server_starts {
                    ws.flush().await.unwrap();
                }
            };
            let client = async {
                let tcp = TcpStream::connect(address).await.unwrap();
                let (ws, _) = client_async(format!("ws://{address}/"), tcp).await.unwrap();
                let (mut write, mut read) = ws.split();
                if server_starts {
                    assert!(matches!(read.next().await, Some(Ok(Message::Close(_)))));
                }
                super::complete_ws_close(&mut write, &mut read, server_starts)
                    .await
                    .unwrap();
            };
            tokio::time::timeout(Duration::from_secs(2), async {
                tokio::join!(server, client);
            })
            .await
            .unwrap();
        }
    }

    #[tokio::test]
    async fn cancelling_bridge_drops_both_direction_futures() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(AtomicUsize::new(0));
        let upload_drop = Arc::clone(&dropped);
        let download_drop = Arc::clone(&dropped);
        let upload_started = Arc::clone(&started);
        let download_started = Arc::clone(&started);
        let task = tokio::spawn(race_directions(
            async move {
                upload_started.fetch_add(1, Ordering::SeqCst);
                let _drop_count = DropCount(upload_drop);
                future::pending().await
            },
            async move {
                download_started.fetch_add(1, Ordering::SeqCst);
                let _drop_count = DropCount(download_drop);
                future::pending().await
            },
            Duration::from_millis(10),
        ));

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while started.load(Ordering::SeqCst) != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        task.abort();
        let _ = task.await;

        assert_eq!(dropped.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn completed_direction_drains_its_peer_before_teardown() {
        let activity = PayloadActivity::new();
        let (finish_tx, finish_rx) = oneshot::channel();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let _ = finish_tx.send(DownloadEnd::PeerClose("upstream завершён".to_string()));
        });

        let result = supervise_directions(
            async { UploadEnd::Fin },
            async move { finish_rx.await.unwrap() },
            &activity,
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .await;

        assert!(matches!(
            result,
            RelayCompletion::PeerClose(reason) if reason == "upstream завершён"
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn idle_session_cancels_both_relay_directions() {
        let activity = PayloadActivity::new();
        let dropped = Arc::new(AtomicUsize::new(0));
        let upload_drop = Arc::clone(&dropped);
        let download_drop = Arc::clone(&dropped);
        let (upload_started_tx, upload_started_rx) = tokio::sync::oneshot::channel();
        let (download_started_tx, download_started_rx) = tokio::sync::oneshot::channel();

        let task = tokio::spawn(async move {
            supervise_directions(
                async move {
                    let _drop_count = DropCount(upload_drop);
                    let _ = upload_started_tx.send(());
                    future::pending().await
                },
                async move {
                    let _drop_count = DropCount(download_drop);
                    let _ = download_started_tx.send(());
                    future::pending().await
                },
                &activity,
                Duration::from_millis(10),
                Duration::from_millis(10),
            )
            .await
        });

        upload_started_rx.await.unwrap();
        download_started_rx.await.unwrap();
        tokio::time::advance(Duration::from_millis(10)).await;
        let result = task.await.unwrap();

        assert!(matches!(result, RelayCompletion::Idle));
        assert_eq!(dropped.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn activity_resets_the_idle_deadline() {
        let activity = PayloadActivity::new();
        let touched = activity.clone();
        let (touch_tx, touch_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            touched.touch();
            let _ = touch_tx.send(());
        });
        let started = tokio::time::Instant::now();
        let idle = activity.idle_reached(Duration::from_millis(30));
        tokio::pin!(idle);

        tokio::select! {
            _ = &mut idle => panic!("тайм-аут простоя истёк до запланированных данных"),
            result = touch_rx => result.expect("задача передачи должна сообщать о своей активности"),
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(29), &mut idle)
                .await
                .is_err()
        );
        tokio::time::advance(Duration::from_millis(1)).await;
        idle.await;

        assert_eq!(started.elapsed(), Duration::from_millis(40));
    }
}
