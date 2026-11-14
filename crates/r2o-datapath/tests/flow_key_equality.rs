//! C `d2k_key_equal` (`datapath/track.h:76-83`): равенство ключа потока
//! сравнивает протокол, порты, семейство и адреса. В R2O протокол TCP
//! закодирован типом `TcpFlowKey`, семейство — вариантом `Address`, поэтому
//! проверяем все поля, которые могут различаться.

use r2k_core::addr::Address;
use r2o_datapath::capture::TcpFlowKey;

fn key(low_address: &str, high_address: &str, low_port: u16, high_port: u16) -> TcpFlowKey {
    TcpFlowKey {
        low_address: Address::parse(low_address).unwrap(),
        high_address: Address::parse(high_address).unwrap(),
        low_port,
        high_port,
    }
}

#[test]
fn tcp_flow_key_equality_сравнивает_все_поля_как_c() {
    let base = key("192.0.2.10", "198.51.100.20", 41000, 443);
    assert_eq!(base, key("192.0.2.10", "198.51.100.20", 41000, 443));
    assert_ne!(base, key("192.0.2.11", "198.51.100.20", 41000, 443));
    assert_ne!(base, key("192.0.2.10", "198.51.100.21", 41000, 443));
    assert_ne!(base, key("192.0.2.10", "198.51.100.20", 41001, 443));
    assert_ne!(base, key("192.0.2.10", "198.51.100.20", 41000, 444));

    let v6 = key("2001:db8::1", "2001:db8::2", 41000, 443);
    assert_eq!(v6, key("2001:db8::1", "2001:db8::2", 41000, 443));
    assert_ne!(v6, key("2001:db8::1", "2001:db8::3", 41000, 443));
    // C `(a->family == 6) != (b->family == 6)` отвергает смешанные семейства;
    // в R2O IPv4 и IPv6 — разные варианты `Address`.
    assert_ne!(base, v6);
}
