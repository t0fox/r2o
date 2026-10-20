use r2k_core::plan::Plan;
use r2o_controller::http_search::{candidate_keys, candidate_text};
use r2o_controller::plan_text::compile_text;

#[test]
fn compiles_the_canonical_http_split_plan_to_the_r2o_tlv_layout() {
    let text = candidate_text("split", None).unwrap();
    let actual = compile_text(&text).unwrap();
    let actual_hex: String = actual.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(
        actual_hex,
        "52324f500001000b00000004000100100000000000000000000000000000000000020002060401000004000500000103000100"
    );
}

#[test]
fn compiles_payload_poison_fake_and_split_with_the_c_record_order() {
    let id = r2o_controller::http_search::stable_id("fake-badsum");
    let text = candidate_text("fake-badsum", Some(&id)).unwrap();
    let actual = compile_text(&text).unwrap();
    let actual_hex: String = actual.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(
        actual_hex,
        "52324f500001000b00000007000100109675c64e2dc20a91e63456c43c817f41000200020604001000270001474554202f20485454502f312e310d0a486f73743a206469736b2e727a642e72750d0a0d0a00110008000100010000000001000004000500000101000a000100010100000000000103000100"
    );
}

#[test]
fn refuses_unknown_plan_directives_instead_of_dropping_them() {
    let text = "r2o-plan 1 1\nproto tcp tls\nunknown-guard x\n";
    assert!(
        compile_text(text)
            .unwrap_err()
            .to_string()
            .contains("unknown")
    );
}

#[test]
fn compiles_every_supported_http_search_candidate() {
    for key in candidate_keys() {
        let text = candidate_text(key, Some(&r2o_controller::http_search::stable_id(key))).unwrap();
        let plan = Plan::parse(&compile_text(&text).unwrap()).unwrap();
        assert_eq!(plan.transport, 6, "{key}");
        assert_eq!(plan.proto, 4, "{key}");
    }
}

#[test]
fn r2o_compiles_quic_ttl_probe_and_datapath_accepts_only_its_shape() {
    let payload = r2k_core::plan::R2K_QUIC_TTL_PROBE_PAYLOAD
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let text = format!(
        "r2o-plan 1 10\nproto udp quic\npayload 1 {payload}\npoison 1 ttl=3\nfake payload=1 poison=1 repeats=2 gap_us=0 place=before\n"
    );
    let plan = Plan::parse(&compile_text(&text).unwrap()).unwrap();

    assert!(plan.r2k_is_quic_ttl_probe());
    assert!(plan.r2k_is_quic_address_plan());
    assert!(r2o_datapath::engine::validate_runtime_plan(&plan).is_ok());
}

#[test]
fn plan_words_only_split_on_ascii_space_and_tab() {
    let text = "r2o-plan 1 1\nproto\u{000b}tcp tls\n";
    assert!(compile_text(text).is_err());
}

#[test]
fn rejects_measured_input_lengths_larger_than_the_c_text_parser_limit() {
    let text = "r2o-plan 1 3\nproto tcp tls\ninput 65536 0 0\n";
    assert!(compile_text(text).is_err());
}

#[test]
fn compiles_supported_directives_to_r2o_tlv_bytes() {
    let cases = [
        (
            "r2o-plan 1 12\nid 00112233445566778899aabbccddeeff\nproto tcp tls\npayload 1 4869\npoison 1 badsum ttl=64 seqshift=-1\nsplit sni_middle -2\nfake payload=1 poison=1 repeats=2 gap_us=25 place=before tlsmod=rnd\nseqovl payload=1 poison=1\norder reverse\npace 1000\ninput 100 20 10\nsettle 2000\nsegment 512\nwire detect-tcp-v1\ninput tls-sni\ndelay 15\n",
            "52324f500001000c0000000f0001001000112233445566778899aabbccddeeff00020002060100100004000148690011000800014001ffffffff010000040005fffe0101000b00010001020000000019010102000400010001010300010101050004000003e80106000c00000064000000140000000a01070004000007d00108000400000200010a0000010b00040000000f0109000101",
        ),
        (
            "r2o-plan 1 8\nproto tcp tls\nwire tcp-template-v1\ninput tls-sni\noob sni_middle 7f\n",
            "52324f50000100080000000600010010000000000000000000000000000000000002000206010103000100010a00000109000102010d000300057f",
        ),
        (
            "r2o-plan 1 7\nproto udp quic\nipfrag 3\n",
            "52324f50000100070000000400010010000000000000000000000000000000000002000211020103000100010c000103",
        ),
        (
            "r2o-plan 1 9\nproto udp quic\nudplen 200\n",
            "52324f50000100090000000400010010000000000000000000000000000000000002000211020103000100010e000200c8",
        ),
        (
            "r2o-plan 1 10\nproto udp quic\nquicsplit 1\n",
            "52324f500001000a0000000400010010000000000000000000000000000000000002000211020103000100010f000101",
        ),
        (
            "r2o-plan 1 11\nproto udp quic\nquicdeny 1\n",
            "52324f500001000b00000004000100100000000000000000000000000000000000020002110201030001000110000101",
        ),
        (
            "r2o-plan 1 12\nproto tcp tls\npayload-pad 1 8 170 010203\npayload-pad64 2 8 0 YWJjZA==\npayload-slice 3 1 2 3\nguard rst_alien\n",
            "52324f500001000c0000000700010010000000000000000000000000000000000002000206010010000a0001010203aaaaaaaaaa0010000a0002616263640000000000100005000303aaaa01030001000104000101",
        ),
    ];

    for (text, expected_hex) in cases {
        let actual = compile_text(text).unwrap();
        let actual_hex: String = actual.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(actual_hex, expected_hex, "plan text: {text}");
    }
}
