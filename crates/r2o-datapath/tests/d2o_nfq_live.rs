use r2o_datapath::netlink::{MessageIter, NF_ACCEPT, QueuePacket};
use r2o_datapath::nfqueue::{QueueSocket, ReceiveError};

fn fnv(bytes: &[u8]) -> u64 {
    let mut hash = 1469598103934665603_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(1099511628211);
    }
    hash
}

#[test]
#[ignore = "run through scripts/test-datapath-nfq-live-differential.sh in unshare -Urn"]
fn nfqueue_live_open_recv_verdict_matches_c() {
    let queue: u16 = std::env::var("R2O_NFQ_LIVE_QUEUE")
        .expect("R2O_NFQ_LIVE_QUEUE")
        .parse()
        .expect("queue number");
    let mut output = String::new();
    let mut socket = match QueueSocket::open(
        queue,
        libc::AF_INET as u16,
        65535,
        1024,
        true,
        4 * 1024 * 1024,
    ) {
        Ok(socket) => socket,
        Err(error) => {
            output.push_str("open=0\n");
            write_output(&output);
            panic!("NFQUEUE open: {error}");
        }
    };
    output.push_str("open=1\n");
    if let Ok(path) = std::env::var("R2O_NFQ_LIVE_READY") {
        std::fs::write(path, &output).unwrap();
    }

    let mut bytes = Vec::new();
    match socket.receive_timeout(&mut bytes, 5000) {
        Ok(true) => {}
        Ok(false) => {
            output.push_str("recv=0\n");
            write_output(&output);
            panic!("NFQUEUE не получил пакет");
        }
        Err(ReceiveError::LostPackets) => {
            output.push_str("recv=-2\n");
            write_output(&output);
            panic!("NFQUEUE lost packets");
        }
        Err(error) => {
            output.push_str(&format!("recv=error {error}\n"));
            write_output(&output);
            panic!("NFQUEUE recv: {error}");
        }
    }

    let message = MessageIter::new(&bytes).next().expect("netlink message");
    let packet = QueuePacket::parse(&message).expect("NFQUEUE packet");
    let payload = packet.payload.expect("NFQUEUE payload");
    let ihl = if payload.is_empty() {
        0
    } else {
        usize::from(payload[0] & 0x0f) * 4
    };
    let hash = if ihl != 0 && ihl <= payload.len() {
        fnv(&payload[ihl..])
    } else {
        0
    };
    let id = packet.id.unwrap_or(0);
    output.push_str(&format!(
        "recv=1 hook={} hw={} outdev={} mark={} have_id={} id_nonzero={} payload_len={} l4hash={hash:016x} cap={} trunc={} ts={} lost={}\n",
        packet.hook.unwrap_or(0),
        packet.hardware_protocol.unwrap_or(0),
        packet.output_device.unwrap_or(0),
        packet.mark.unwrap_or(0),
        u8::from(packet.id.is_some()),
        u8::from(id != 0),
        payload.len(),
        packet.cap_len.unwrap_or(0),
        u8::from(packet.truncated),
        u8::from(packet.timestamp_ns.is_some()),
        socket.lost_packets()
    ));
    socket.send_verdict(id, NF_ACCEPT).expect("NFQUEUE verdict");
    write_output(&output);
    assert!(output.contains("hook=3"), "{output}");
}

fn write_output(output: &str) {
    if let Ok(path) = std::env::var("R2O_NFQ_LIVE_DIFF_OUTPUT") {
        std::fs::write(path, output).unwrap();
    }
}
