use r2o_datapath::raw::RawSocket;
use std::ffi::CString;

fn interface_index(name: &str) -> u32 {
    let name = CString::new(name).expect("имя интерфейса без NUL");
    unsafe { libc::if_nametoindex(name.as_ptr()) }
}

#[test]
#[ignore = "requires an isolated Linux network namespace with CAP_NET_RAW and dummy links"]
fn raw_socket_tracks_egress_mtu_and_respects_explicit_interface() {
    let output = interface_index("d2kout");
    let low = interface_index("d2klow");
    assert_ne!(output, 0, "интерфейс d2kout отсутствует в namespace");
    assert_ne!(low, 0, "интерфейс d2klow отсутствует в namespace");

    let raw = RawSocket::open(libc::AF_INET, 0x5252, None).expect("открыть raw socket");
    assert_eq!(raw.maxlen(), 1280);
    assert_eq!(raw.r2o_adopt_egress(&[output]), Some(1500));
    assert_eq!(raw.maxlen(), 1500);
    assert_eq!(raw.r2o_adopt_egress(&[output]), None);
    assert_eq!(raw.maxlen(), 1500);

    assert_eq!(raw.r2o_adopt_egress(&[output, low]), Some(1280));
    assert_eq!(raw.maxlen(), 1280);
    assert_eq!(raw.r2o_adopt_egress(&[0x7fff_fff0]), None);
    assert_eq!(raw.maxlen(), 1280);
    assert_eq!(raw.r2o_adopt_egress(&[output]), Some(1500));
    assert_eq!(raw.maxlen(), 1500);

    let explicit = RawSocket::open(libc::AF_INET, 0x5252, Some("d2klow"))
        .expect("открыть raw socket на заданном интерфейсе");
    assert_eq!(explicit.maxlen(), 1280);
    assert_eq!(explicit.r2o_adopt_egress(&[output]), None);
    assert_eq!(explicit.maxlen(), 1280);
}
