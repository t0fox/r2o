# Полный индекс production C-функций D2O

Срез: локальное дерево `E:\d2o` (HEAD main `a378e230947ebfd011439e1cac0f1e994d883aae`).
Индекс построен механически по определениям функций; тестовые файлы (`test_*`), `planlab.c`, `ctlprobe.c`, `probe_mtproto.c` и `telegram/differential` исключены.
Столбец «static» означает внутреннюю функцию без внешней линкуемости. Наличие строки здесь не означает паритет.

## core — 1207 функций

### catalog.c — 60

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `set_err` | 56 | да |
| 2 | `jpeek` | 80 | да |
| 3 | `jeat` | 93 | да |
| 4 | `jeat_null_if_present` | 111 | да |
| 5 | `floor_div` | 149 | да |
| 6 | `days_from_civil` | 157 | да |
| 7 | `civil_from_days` | 167 | да |
| 8 | `format_rfc3339` | 186 | да |
| 9 | `jparse_raw_int` | 208 | да |
| 10 | `jparse_i32` | 242 | да |
| 11 | `jparse_u8` | 253 | да |
| 12 | `jparse_u16` | 264 | да |
| 13 | `jparse_bool_i` | 275 | да |
| 14 | `jparse_string_dyn` | 306 | да |
| 15 | `jparse_string_fixed` | 409 | да |
| 16 | `read_fixed_digits` | 429 | да |
| 17 | `eat_lit` | 448 | да |
| 18 | `jparse_rfc3339` | 463 | да |
| 19 | `jskip_value` | 546 | да |
| 20 | `parse_object` | 630 | да |
| 21 | `grow` | 668 | да |
| 22 | `parse_array` | 693 | да |
| 23 | `handle_signal_key` | 724 | да |
| 24 | `parse_signal` | 744 | да |
| 25 | `handle_fp_key` | 757 | да |
| 26 | `parse_fp` | 790 | да |
| 27 | `handle_plan_key` | 799 | да |
| 28 | `parse_plan` | 818 | да |
| 29 | `elem_plan` | 822 | да |
| 30 | `handle_binding_key` | 835 | да |
| 31 | `parse_binding` | 887 | да |
| 32 | `elem_binding` | 892 | да |
| 33 | `d2k_cat_shape_fits` | 906 |  |
| 34 | `handle_box_key` | 919 | да |
| 35 | `parse_box` | 941 | да |
| 36 | `elem_box` | 945 | да |
| 37 | `handle_domain_observation` | 954 | да |
| 38 | `parse_domain_observations` | 973 | да |
| 39 | `handle_net_whitelist_key` | 992 | да |
| 40 | `handle_catalog_key` | 1002 | да |
| 41 | `parse_catalog_obj` | 1029 | да |
| 42 | `prune_unavailable_domain_groups` | 1037 | да |
| 43 | `free_box` | 1063 | да |
| 44 | `d2k_catalog_free` | 1073 |  |
| 45 | `d2k_catalog_memory_bytes` | 1085 |  |
| 46 | `read_whole_file` | 1104 | да |
| 47 | `d2k_catalog_load` | 1146 |  |
| 48 | `write_json_string` | 1199 | да |
| 49 | `wr_indent` | 1221 | да |
| 50 | `write_json_array` | 1231 | да |
| 51 | `write_signal_elem` | 1243 | да |
| 52 | `write_fp` | 1260 | да |
| 53 | `write_plan_elem` | 1269 | да |
| 54 | `write_binding_elem` | 1283 | да |
| 55 | `write_box_elem` | 1335 | да |
| 56 | `write_domain_key` | 1354 | да |
| 57 | `write_domain_observation` | 1360 | да |
| 58 | `write_domain_group` | 1368 | да |
| 59 | `d2k_catalog_save` | 1375 |  |
| 60 | `d2k_catalog_save_atomic` | 1446 |  |

### compose.c — 53

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `d2k_net_whitelist_count` | 108 |  |
| 2 | `d2k_net_whitelist_name` | 111 |  |
| 3 | `wr16be` | 151 | да |
| 4 | `rd16be` | 152 | да |
| 5 | `wr32be` | 153 | да |
| 6 | `tlv_rec` | 163 | да |
| 7 | `tlv_header` | 187 | да |
| 8 | `plan_tlv_stamp_ident` | 219 |  |
| 9 | `overlap_plan_tlv` | 259 |  |
| 10 | `reorder_plan_tlv` | 278 |  |
| 11 | `badsum_fake_plan_tlv` | 297 |  |
| 12 | `checksum_plan_tlv` | 323 |  |
| 13 | `to_hex` | 332 | да |
| 14 | `ev_matches_flow` | 352 |  |
| 15 | `wait_for_event3` | 398 | да |
| 16 | `wait_for_event` | 424 | да |
| 17 | `props_bind_any` | 495 | да |
| 18 | `d2k_props_bind` | 527 |  |
| 19 | `d2k_props_bind_family` | 531 |  |
| 20 | `d2k_props_bind_udp` | 535 |  |
| 21 | `d2k_props_bind_udp_family` | 539 |  |
| 22 | `d2k_props_contact` | 543 |  |
| 23 | `d2k_props_contact_on` | 548 |  |
| 24 | `d2k_props_contact_on_family` | 554 |  |
| 25 | `tcp_timestamps_read` | 568 | да |
| 26 | `tcp_timestamps_write` | 581 | да |
| 27 | `connect_with_tcp_profile` | 592 | да |
| 28 | `d2k_props_contact_on_family_tcp_profile` | 639 |  |
| 29 | `build_fake_body` | 787 | да |
| 30 | `d2k_props_question_plan` | 799 |  |
| 31 | `d2k_props_question_passed` | 846 |  |
| 32 | `question_retire` | 875 | да |
| 33 | `d2k_props_ask` | 882 |  |
| 34 | `step_rc` | 890 | да |
| 35 | `d2k_props_ask_traced` | 901 |  |
| 36 | `append_fmt` | 1204 | да |
| 37 | `emit_header_proto` | 1222 | да |
| 38 | `emit_header` | 1230 | да |
| 39 | `append_hex` | 1234 | да |
| 40 | `overlap_plan_text` | 1246 |  |
| 41 | `reorder_plan_text` | 1272 |  |
| 42 | `badsum_fake_plan_text` | 1289 |  |
| 43 | `checksum_plan_text` | 1313 |  |
| 44 | `build_decoy_hello` | 1347 | да |
| 45 | `parse_protocol_plan_text` | 1357 | да |
| 46 | `duplicates_plan_text` | 1368 | да |
| 47 | `body_room` | 1385 | да |
| 48 | `everything_plan_text` | 1398 | да |
| 49 | `d2k_fallback_arms` | 1500 |  |
| 50 | `fb_arm_at` | 1505 | да |
| 51 | `d2k_fallback_plan` | 1544 |  |
| 52 | `d2k_arm_plan` | 1553 |  |
| 53 | `d2k_compose` | 1764 |  |

### crypto.c — 28

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `xtime` | 34 | да |
| 2 | `d2k_aes_sbox_byte` | 71 |  |
| 3 | `aes128_key_expand` | 81 | да |
| 4 | `sub_bytes` | 113 | да |
| 5 | `shift_rows` | 122 | да |
| 6 | `mix_columns` | 132 | да |
| 7 | `add_round_key` | 143 | да |
| 8 | `aes128_encrypt_block` | 152 | да |
| 9 | `d2k_aes128_ecb` | 168 |  |
| 10 | `rotr32` | 176 | да |
| 11 | `sha256_compress` | 202 | да |
| 12 | `sha256_init` | 231 | да |
| 13 | `sha256_update` | 243 | да |
| 14 | `sha256_final` | 268 | да |
| 15 | `d2k_sha256` | 293 |  |
| 16 | `d2k_hmac_sha256` | 302 |  |
| 17 | `d2k_hkdf_extract` | 332 |  |
| 18 | `d2k_hkdf_expand_label` | 351 |  |
| 19 | `d2k_hkdf_expand_label_ctx` | 356 |  |
| 20 | `gf128_h_table` | 450 | да |
| 21 | `gf128_mul_fast` | 464 | да |
| 22 | `ghash` | 480 | да |
| 23 | `d2k_ghash_for_test` | 539 |  |
| 24 | `inc32` | 548 | да |
| 25 | `gctr` | 561 | да |
| 26 | `consttime_eq16` | 585 | да |
| 27 | `d2k_aes128_gcm_encrypt` | 597 |  |
| 28 | `d2k_aes128_gcm_decrypt` | 628 |  |

### d2kask.c — 24

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `need_value` | 121 | да |
| 2 | `parse_flag_u16` | 135 | да |
| 3 | `parse_flag_u32` | 158 | да |
| 4 | `parse_flag_ms` | 180 | да |
| 5 | `parse_args` | 203 | да |
| 6 | `hex_nibble` | 316 | да |
| 7 | `save_hex` | 330 | да |
| 8 | `read_hex_file` | 362 | да |
| 9 | `wait_shape` | 425 | да |
| 10 | `pval_str` | 463 | да |
| 11 | `print_header` | 471 | да |
| 12 | `print_snapshot` | 483 | да |
| 13 | `pos_decided` | 520 | да |
| 14 | `pos_value` | 531 | да |
| 15 | `step_rc_str` | 548 | да |
| 16 | `ack_code_str` | 566 | да |
| 17 | `print_seen_types` | 580 | да |
| 18 | `print_step` | 598 | да |
| 19 | `print_question` | 633 | да |
| 20 | `all_unknown` | 677 | да |
| 21 | `print_not_asked_at_all` | 685 | да |
| 22 | `print_vector` | 699 | да |
| 23 | `print_plans` | 708 | да |
| 24 | `main` | 737 |  |

### d2kc.c — 28

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `on_signal` | 112 | да |
| 2 | `now_ms` | 114 | да |
| 3 | `save_atomic` | 123 | да |
| 4 | `self_mem` | 137 | да |
| 5 | `sched_say` | 151 | да |
| 6 | `http_search_portal` | 169 | да |
| 7 | `hs_open_port` | 177 | да |
| 8 | `hs_close_port` | 211 | да |
| 9 | `hs_hex` | 213 | да |
| 10 | `hs_set_probe` | 222 | да |
| 11 | `hs_del_probe` | 236 | да |
| 12 | `hs_set_plan` | 247 | да |
| 13 | `hs_del_plan` | 260 | да |
| 14 | `hs_start` | 272 | да |
| 15 | `hs_changed` | 278 | да |
| 16 | `http_portal` | 289 | да |
| 17 | `http_push` | 311 | да |
| 18 | `http_save` | 318 | да |
| 19 | `http_probe_done` | 325 | да |
| 20 | `hs_say` | 358 | да |
| 21 | `poison_cmp` | 366 | да |
| 22 | `hs_measured_poisons` | 369 | да |
| 23 | `usage` | 395 | да |
| 24 | `offline_self_check` | 407 | да |
| 25 | `diagnostic_event` | 416 | да |
| 26 | `diagnostic_limit` | 419 | да |
| 27 | `diagnostic_tick` | 422 | да |
| 28 | `main` | 471 |  |

### d2kfetch.c — 6

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `json_string` | 42 | да |
| 2 | `vol_verdict_code` | 65 | да |
| 3 | `usage` | 75 | да |
| 4 | `resolve_first` | 105 | да |
| 5 | `snapshot_wire` | 118 | да |
| 6 | `main` | 158 |  |

### d2kvoice.c — 4

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `usage` | 23 | да |
| 2 | `split_hostport` | 40 | да |
| 3 | `verdict_word` | 51 | да |
| 4 | `main` | 64 |  |

### diagnostics.c — 41

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `copy` | 99 | да |
| 2 | `js` | 106 | да |
| 3 | `number` | 132 | да |
| 4 | `d2k_diag_new` | 133 |  |
| 5 | `d2k_diag_free` | 134 |  |
| 6 | `d2k_diag_bytes` | 135 |  |
| 7 | `d2k_diag_event_count` | 136 |  |
| 8 | `d2k_diag_sample_count` | 137 |  |
| 9 | `d2k_diag_memory_history_count` | 138 |  |
| 10 | `d2k_diag_memory_enable` | 139 |  |
| 11 | `d2k_diag_memory_active` | 140 |  |
| 12 | `atomic_read` | 141 | да |
| 13 | `atomic_peak` | 142 | да |
| 14 | `d2k_diag_memory_acquire` | 146 |  |
| 15 | `d2k_diag_memory_release` | 153 |  |
| 16 | `d2k_diag_memory_alloc_failure` | 158 |  |
| 17 | `d2k_diag_memory_snapshot` | 162 |  |
| 18 | `d2k_diag_memory_counts` | 171 |  |
| 19 | `d2k_diag_set_madvise` | 181 |  |
| 20 | `record_anomaly` | 182 | да |
| 21 | `d2k_diag_record_write_error` | 189 |  |
| 22 | `d2k_diag_record` | 193 |  |
| 23 | `d2k_diag_record_limit` | 203 |  |
| 24 | `value` | 214 | да |
| 25 | `compact_kib` | 219 | да |
| 26 | `compact_bytes_kib` | 222 | да |
| 27 | `compact_bytes` | 223 | да |
| 28 | `compact_count` | 224 | да |
| 29 | `proc_pid_dir_present` | 226 | да |
| 30 | `optional_proc_status` | 231 | да |
| 31 | `read_proc` | 239 | да |
| 32 | `read_detail` | 261 | да |
| 33 | `read_status` | 306 | да |
| 34 | `write_detail` | 311 | да |
| 35 | `write_limit_reason` | 330 | да |
| 36 | `write_limit_reason_state` | 345 | да |
| 37 | `write_memory_tracking` | 358 | да |
| 38 | `write_madvise` | 371 | да |
| 39 | `write_anomalies` | 383 | да |
| 40 | `d2k_diag_sample` | 396 |  |
| 41 | `d2k_diag_write` | 470 |  |

### domain.c — 4

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `d2k_domain_normalize` | 7 |  |
| 2 | `rule_exists` | 32 | да |
| 3 | `d2k_domain_base` | 43 |  |
| 4 | `d2k_domain_member` | 67 |  |

### groups.c — 14

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `d2k_group_key_make` | 10 |  |
| 2 | `d2k_group_key_same` | 20 |  |
| 3 | `valid` | 25 | да |
| 4 | `member` | 39 | да |
| 5 | `votes` | 46 | да |
| 6 | `failures` | 62 | да |
| 7 | `add_group` | 73 | да |
| 8 | `rebuild` | 104 | да |
| 9 | `cover` | 123 | да |
| 10 | `d2k_group_learn` | 134 |  |
| 11 | `d2k_group_restore` | 247 |  |
| 12 | `d2k_group_match` | 275 |  |
| 13 | `d2k_group_forget` | 295 |  |
| 14 | `d2k_group_expire` | 312 |  |

### h3.c — 9

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `d2k_h3_control` | 20 |  |
| 2 | `prefix_int` | 31 | да |
| 3 | `prefix_int_read` | 52 | да |
| 4 | `d2k_h3_request` | 74 |  |
| 5 | `huff_status` | 127 | да |
| 6 | `static_status` | 149 | да |
| 7 | `name_is_status` | 172 | да |
| 8 | `decode_section` | 177 | да |
| 9 | `d2k_h3_status` | 263 |  |

### hello.c — 19

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `rd16` | 52 | да |
| 2 | `rd24` | 55 | да |
| 3 | `wr16` | 58 | да |
| 4 | `wr24` | 62 | да |
| 5 | `skip_u8_vec` | 70 | да |
| 6 | `skip_u16_vec` | 81 | да |
| 7 | `parse_hello` | 129 | да |
| 8 | `d2k_hello_complete` | 275 |  |
| 9 | `d2k_hello_shape` | 284 |  |
| 10 | `d2k_hello_sni` | 309 |  |
| 11 | `d2k_hello_ech_offer` | 323 |  |
| 12 | `d2k_hello_alpn` | 350 |  |
| 13 | `d2k_alpn_is_http` | 378 |  |
| 14 | `splice_sni` | 410 | да |
| 15 | `hex_nibble` | 463 | да |
| 16 | `hex_decode` | 481 | да |
| 17 | `d2k_hello_rename` | 501 |  |
| 18 | `d2k_hello_without_sni` | 538 |  |
| 19 | `d2k_hello_from_profile` | 579 |  |

### httpsearch.c — 66

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `mono_ms` | 38 | да |
| 2 | `d2k_hs_answer_name` | 44 |  |
| 3 | `d2k_hs_judge` | 62 |  |
| 4 | `hs_path_ok` | 100 | да |
| 5 | `hs_read` | 111 | да |
| 6 | `d2k_hs_probe_run` | 133 |  |
| 7 | `d2k_hs_candidate_count` | 254 |  |
| 8 | `d2k_hs_candidate_key` | 255 |  |
| 9 | `poison_key_spec` | 259 | да |
| 10 | `known_key` | 290 | да |
| 11 | `d2k_hs_candidate_text` | 297 |  |
| 12 | `stable_id` | 330 | да |
| 13 | `fresh_id` | 337 | да |
| 14 | `say` | 445 | да |
| 15 | `host_ok` | 455 | да |
| 16 | `rec_find` | 471 | да |
| 17 | `rec_get` | 480 | да |
| 18 | `same_program` | 503 | да |
| 19 | `failed_live` | 513 | да |
| 20 | `remember_live_failure` | 523 | да |
| 21 | `d2k_httpsearch_test_add_failures` | 556 |  |
| 22 | `d2k_httpsearch_test_add_records` | 570 |  |
| 23 | `d2k_httpsearch_measured_poison` | 582 |  |
| 24 | `d2k_hs_plan_poisons` | 611 |  |
| 25 | `d2k_httpsearch_new` | 647 |  |
| 26 | `drop_socket` | 655 | да |
| 27 | `drop_probe` | 662 | да |
| 28 | `d2k_httpsearch_free` | 669 |  |
| 29 | `d2k_httpsearch_busy` | 679 |  |
| 30 | `d2k_httpsearch_plan_of` | 683 |  |
| 31 | `d2k_httpsearch_diagnostic_counts` | 690 |  |
| 32 | `d2k_httpsearch_diagnostics` | 710 |  |
| 33 | `diagnostic_end` | 713 | да |
| 34 | `finish` | 725 | да |
| 35 | `open_job` | 733 | да |
| 36 | `revoke_owned` | 755 | да |
| 37 | `all_failed` | 762 | да |
| 38 | `install` | 807 | да |
| 39 | `d2k_httpsearch_install_ack` | 821 |  |
| 40 | `confirmed` | 846 | да |
| 41 | `trial_executed` | 897 | да |
| 42 | `judge_trial` | 905 | да |
| 43 | `next_candidate` | 958 | да |
| 44 | `add_cand` | 1008 | да |
| 45 | `build_cands` | 1015 | да |
| 46 | `build_fallback` | 1044 | да |
| 47 | `start` | 1057 | да |
| 48 | `start_next` | 1096 | да |
| 49 | `live_owner` | 1106 | да |
| 50 | `d2k_httpsearch_bound_failure` | 1116 |  |
| 51 | `d2k_httpsearch_control` | 1136 |  |
| 52 | `d2k_httpsearch_cut` | 1173 |  |
| 53 | `d2k_httpsearch_portal` | 1193 |  |
| 54 | `d2k_httpsearch_ack` | 1232 |  |
| 55 | `d2k_httpsearch_applied` | 1265 |  |
| 56 | `d2k_httpsearch_result` | 1292 |  |
| 57 | `d2k_httpsearch_tick` | 1400 |  |
| 58 | `d2k_httpsearch_push_all` | 1432 |  |
| 59 | `d2k_httpsearch_save` | 1447 |  |
| 60 | `d2k_httpsearch_load` | 1476 |  |
| 61 | `runner_main` | 1528 | да |
| 62 | `d2k_hs_runner_new` | 1542 |  |
| 63 | `d2k_hs_runner_free` | 1558 |  |
| 64 | `d2k_hs_runner_wake_fd` | 1567 |  |
| 65 | `d2k_hs_runner_start` | 1569 |  |
| 66 | `d2k_hs_runner_done` | 1584 |  |

### httpsprobe.c — 22

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `d2k_https_classify` | 33 |  |
| 2 | `d2k_https_upgrade` | 43 |  |
| 3 | `d2k_https_ttl` | 47 |  |
| 4 | `d2k_https_state_name` | 58 |  |
| 5 | `mono_ms` | 70 | да |
| 6 | `https_connect` | 78 | да |
| 7 | `https_tls` | 149 | да |
| 8 | `first_flight` | 172 | да |
| 9 | `d2k_https_probe_real` | 204 |  |
| 10 | `host_ok` | 275 | да |
| 11 | `cache_find` | 286 | да |
| 12 | `cache_put` | 293 | да |
| 13 | `worker` | 315 | да |
| 14 | `d2k_httpsprobe_new` | 352 |  |
| 15 | `d2k_httpsprobe_free` | 378 |  |
| 16 | `d2k_httpsprobe_wake_fd` | 394 |  |
| 17 | `d2k_httpsprobe_portal` | 398 |  |
| 18 | `d2k_httpsprobe_done` | 431 |  |
| 19 | `d2k_httpsprobe_state` | 452 |  |
| 20 | `d2k_httpsprobe_lost` | 461 |  |
| 21 | `d2k_httpsprobe_save` | 477 |  |
| 22 | `d2k_httpsprobe_load` | 508 |  |

### httpup_logic.c — 15

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `ascii_alnum` | 17 | да |
| 2 | `dns_host` | 22 | да |
| 3 | `host_equal` | 38 | да |
| 4 | `known_portal_host` | 47 | да |
| 5 | `find_crlf` | 54 | да |
| 6 | `parse_request` | 61 | да |
| 7 | `d2k_httpup_request_safe` | 133 |  |
| 8 | `build_redirect` | 138 | да |
| 9 | `portal_marker` | 152 | да |
| 10 | `redirect_location_host` | 173 | да |
| 11 | `portal_answer` | 194 | да |
| 12 | `d2k_httpup_portal_response` | 228 |  |
| 13 | `d2k_httpup_request_target` | 241 |  |
| 14 | `d2k_httpup_portal_location` | 254 |  |
| 15 | `d2k_httpup_redirect_https` | 265 |  |

### ipfrag.c — 8

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `d2k_ipfrag_shape` | 6 |  |
| 2 | `d2k_ipfrag_cuts` | 19 |  |
| 3 | `wr16` | 47 | да |
| 4 | `sum16` | 48 | да |
| 5 | `fold` | 52 | да |
| 6 | `d2k_udpfrag_build_ex` | 53 |  |
| 7 | `d2k_udpfrag_build` | 86 |  |
| 8 | `d2k_udpfrag6_build_ex` | 92 |  |

### link.c — 43

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `execution_context` | 46 | да |
| 2 | `say` | 57 | да |
| 3 | `wait_readable` | 71 | да |
| 4 | `read_exact` | 93 | да |
| 5 | `write_all` | 109 | да |
| 6 | `hex_nibble` | 134 | да |
| 7 | `hex_decode` | 145 | да |
| 8 | `d2k_link_open` | 162 |  |
| 9 | `d2k_link_close` | 192 |  |
| 10 | `d2k_link_peer_closed` | 198 |  |
| 11 | `d2k_link_next` | 224 |  |
| 12 | `d2k_link_set_name` | 525 |  |
| 13 | `d2k_link_set_name_probe` | 532 |  |
| 14 | `send_name_plan` | 539 | да |
| 15 | `d2k_link_set_name_family` | 633 |  |
| 16 | `d2k_link_set_name_bound` | 640 |  |
| 17 | `d2k_link_del_name_bound` | 646 |  |
| 18 | `d2k_link_set_name_probe_trial` | 660 |  |
| 19 | `area_context_valid` | 671 | да |
| 20 | `d2k_link_set_suffix_family` | 678 |  |
| 21 | `d2k_link_set_https` | 687 |  |
| 22 | `d2k_link_set_stall_budgets` | 708 |  |
| 23 | `send_area_key` | 732 | да |
| 24 | `d2k_link_del_suffix_family` | 755 |  |
| 25 | `d2k_link_set_bypass_family` | 759 |  |
| 26 | `d2k_link_del_bypass_family` | 763 |  |
| 27 | `d2k_link_area_identified` | 768 |  |
| 28 | `addr_shape_ok` | 784 | да |
| 29 | `d2k_link_set_addr` | 790 |  |
| 30 | `d2k_link_set_addr_family` | 795 |  |
| 31 | `addr_probe_flow_bytes` | 853 | да |
| 32 | `d2k_link_set_addr_probe` | 869 |  |
| 33 | `d2k_link_set_addr_probe_family` | 878 |  |
| 34 | `d2k_link_del_addr_probe` | 912 |  |
| 35 | `d2k_link_del_addr_probe_family` | 920 |  |
| 36 | `d2k_link_arm_shape` | 940 |  |
| 37 | `d2k_link_arm_shape_family` | 945 |  |
| 38 | `d2k_link_del_name_family` | 982 |  |
| 39 | `d2k_link_del_name_probe` | 1015 |  |
| 40 | `d2k_link_del_name_probe_family` | 1021 |  |
| 41 | `d2k_link_del_addr` | 1052 |  |
| 42 | `d2k_link_del_addr_family` | 1057 |  |
| 43 | `d2k_ev_outer_appdata` | 1080 |  |

### match.c — 3

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `same_evidence` | 39 | да |
| 2 | `d2k_fp_same` | 76 |  |
| 3 | `d2k_catalog_match` | 128 |  |

### meas.c — 13

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `nap_us` | 53 | да |
| 2 | `d2k_mark_real` | 62 | да |
| 3 | `d2k_accept_serverhello` | 88 |  |
| 4 | `d2k_accept_tls_record` | 97 |  |
| 5 | `d2k_accept_any` | 102 |  |
| 6 | `cuts_valid` | 110 | да |
| 7 | `send_all` | 125 | да |
| 8 | `connect_bounded` | 143 | да |
| 9 | `d2k_meas_once` | 176 |  |
| 10 | `d2k_meas` | 270 |  |
| 11 | `udp_now_ms` | 308 | да |
| 12 | `d2k_udp_port_claim` | 314 |  |
| 13 | `d2k_udp_port_forget_all` | 342 |  |

### measured.c — 11

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `append_fmt` | 11 | да |
| 2 | `append_hex` | 23 | да |
| 3 | `d2k_white_decoy_hello` | 34 |  |
| 4 | `template_plan` | 58 | да |
| 5 | `d2k_rx_volume_plan_named` | 85 |  |
| 6 | `d2k_rx_volume_plan_client` | 91 |  |
| 7 | `d2k_rx_volume_plan` | 115 |  |
| 8 | `measured_payload` | 122 | да |
| 9 | `d2k_tcp_split_plan` | 141 |  |
| 10 | `d2k_arm_plan_measured_cap` | 154 |  |
| 11 | `d2k_arm_plan_measured` | 388 |  |

### net4.c — 4

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `d2k_ip4_parse` | 8 |  |
| 2 | `d2k_ip4_text` | 33 |  |
| 3 | `d2k_ip4_private` | 41 |  |
| 4 | `d2k_ip6_private` | 54 |  |

### p256.c — 22

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `fe_copy` | 32 | да |
| 2 | `ge` | 35 | да |
| 3 | `is_zero` | 42 | да |
| 4 | `sub_raw` | 49 | да |
| 5 | `add_raw` | 60 | да |
| 6 | `fe_add` | 70 | да |
| 7 | `fe_sub` | 77 | да |
| 8 | `fe_mul` | 85 | да |
| 9 | `fe_sqr` | 116 | да |
| 10 | `to_mont` | 125 | да |
| 11 | `from_mont` | 126 | да |
| 12 | `fe_inv` | 132 | да |
| 13 | `fe_from_be` | 144 | да |
| 14 | `fe_to_be` | 151 | да |
| 15 | `pt_double` | 162 | да |
| 16 | `pt_add` | 193 | да |
| 17 | `pt_mul` | 236 | да |
| 18 | `pt_affine` | 250 | да |
| 19 | `scalar_ok` | 263 | да |
| 20 | `d2k_p256_public` | 269 |  |
| 21 | `d2k_p256_keypair` | 283 |  |
| 22 | `d2k_p256_ecdh` | 292 |  |

### plantlv.c — 20

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `b64_value` | 127 | да |
| 2 | `parse_base64` | 134 | да |
| 3 | `say` | 164 | да |
| 4 | `hex_nib` | 172 | да |
| 5 | `parse_hex` | 181 | да |
| 6 | `anchor_by_name` | 207 | да |
| 7 | `split_fields` | 222 | да |
| 8 | `parse_uint` | 238 | да |
| 9 | `parse_int` | 249 | да |
| 10 | `kv_u32` | 260 | да |
| 11 | `str_u32` | 269 | да |
| 12 | `plan_free` | 273 | да |
| 13 | `parse_text` | 278 | да |
| 14 | `put` | 692 | да |
| 15 | `put_u8` | 697 | да |
| 16 | `put_u16` | 698 | да |
| 17 | `put_u32` | 699 | да |
| 18 | `put_rec` | 703 | да |
| 19 | `d2k_plan_text_to_tlv` | 710 |  |
| 20 | `d2k_plan_text_to_hex` | 848 |  |

### props.c — 5

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `original_probe` | 36 | да |
| 2 | `original_data` | 48 | да |
| 3 | `wire_measure` | 53 | да |
| 4 | `d2k_quic_original_measure` | 81 |  |
| 5 | `d2k_quic_strategy_measure` | 89 |  |

### quic.c — 21

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `rd16` | 98 | да |
| 2 | `read_varint` | 111 | да |
| 3 | `parse_initial_header` | 150 | да |
| 4 | `d2k_quic_is_initial` | 183 |  |
| 5 | `decrypt_initial` | 192 | да |
| 6 | `collect_crypto_frames` | 240 | да |
| 7 | `skip_u8_vec` | 435 | да |
| 8 | `skip_u16_vec` | 447 | да |
| 9 | `find_sni` | 459 | да |
| 10 | `find_client_hello_sni` | 504 | да |
| 11 | `crypto_stream_of` | 553 | да |
| 12 | `d2k_quic_client_hello` | 568 |  |
| 13 | `d2k_quic_dgrams_hello` | 608 |  |
| 14 | `d2k_quic_hello_name` | 662 |  |
| 15 | `d2k_quic_hello_incomplete` | 673 |  |
| 16 | `d2k_quic_sni` | 688 |  |
| 17 | `d2k_quic_assembly_init` | 709 |  |
| 18 | `d2k_quic_assembly_feed` | 713 |  |
| 19 | `d2k_quic_assembly_complete` | 781 |  |
| 20 | `put_split_frame` | 825 | да |
| 21 | `d2k_quic_initial_split_crypto` | 842 |  |

### quicarms.c — 9

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `d2k_quic_original_blob` | 13 |  |
| 2 | `ask_q` | 31 | да |
| 3 | `refusal` | 59 |  |
| 4 | `ask_frag` | 113 | да |
| 5 | `ask` | 126 | да |
| 6 | `d2k_quic_original_arms` | 143 |  |
| 7 | `strategy_ask` | 228 | да |
| 8 | `prop_word` | 245 | да |
| 9 | `d2k_quic_strategy_arms` | 249 |  |

### quicconn.c — 36

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `qc_dispose` | 210 | да |
| 2 | `say` | 219 | да |
| 3 | `now_ms` | 227 | да |
| 4 | `crypto_put` | 244 | да |
| 5 | `crypto_ready` | 255 | да |
| 6 | `build_ack` | 266 | да |
| 7 | `seal_level` | 282 | да |
| 8 | `send_level` | 353 | да |
| 9 | `tp_put_int` | 368 | да |
| 10 | `tp_build` | 381 | да |
| 11 | `tp_server_parse` | 419 | да |
| 12 | `tp_server_ee` | 461 | да |
| 13 | `frames_in` | 480 | да |
| 14 | `recv_dgram` | 703 | да |
| 15 | `crypto_frame` | 821 | да |
| 16 | `first_flight` | 837 | да |
| 17 | `prepare_retry` | 899 | да |
| 18 | `d2k_qc_first_initial` | 929 |  |
| 19 | `qc_no_sigpipe` | 957 | да |
| 20 | `d2k_qc_connect` | 967 |  |
| 21 | `d2k_qc_stream_send` | 1289 |  |
| 22 | `d2k_qc_stream_recv` | 1378 |  |
| 23 | `d2k_qc_app_progress` | 1426 |  |
| 24 | `d2k_qc_peer_name` | 1431 |  |
| 25 | `d2k_qc_rx_wire_bytes` | 1432 |  |
| 26 | `d2k_qc_datagrams` | 1433 |  |
| 27 | `d2k_qc_handshake_done` | 1437 |  |
| 28 | `d2k_qc_rtt_ms` | 1438 |  |
| 29 | `d2k_qc_dgrams` | 1439 |  |
| 30 | `d2k_qc_outbound` | 1444 |  |
| 31 | `d2k_qc_ping` | 1455 |  |
| 32 | `d2k_qc_fd` | 1460 |  |
| 33 | `d2k_qc_local` | 1462 |  |
| 34 | `d2k_qc_local_addr` | 1471 |  |
| 35 | `d2k_qc_release` | 1479 |  |
| 36 | `d2k_qc_close` | 1487 |  |

### quichello.c — 13

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `select_probe_profile` | 35 | да |
| 2 | `split_point` | 70 | да |
| 3 | `put_crypto` | 81 | да |
| 4 | `prepare` | 125 | да |
| 5 | `seal_one` | 184 | да |
| 6 | `probe_initial_sized` | 236 | да |
| 7 | `d2k_quic_probe_initial` | 277 |  |
| 8 | `d2k_quic_probe_initial_longer` | 282 |  |
| 9 | `d2k_quic_prepare_target` | 288 |  |
| 10 | `d2k_quic_hello_rename` | 313 |  |
| 11 | `d2k_quic_hello_ask` | 331 |  |
| 12 | `d2k_quic_hello_split` | 413 |  |
| 13 | `d2k_quic_hello_recid` | 458 |  |

### quicprobe.c — 56

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `qp_addr_parse` | 174 | да |
| 2 | `resolve_family` | 182 | да |
| 3 | `resolve_real` | 210 | да |
| 4 | `d2k_quic_build_pool` | 255 |  |
| 5 | `qp_varint` | 321 | да |
| 6 | `qp_parse_hdr` | 338 | да |
| 7 | `qp_dcid_of` | 412 | да |
| 8 | `qp_donor_unauth_reply` | 457 | да |
| 9 | `qp_verify_server_response` | 495 | да |
| 10 | `qp_build_vn_trigger` | 575 | да |
| 11 | `nap_us` | 623 | да |
| 12 | `qp_open_fresh` | 638 | да |
| 13 | `qp_send_one` | 717 | да |
| 14 | `qp_head_of` | 807 | да |
| 15 | `qp_verify_aead` | 816 | да |
| 16 | `qp_verify_bound` | 836 | да |
| 17 | `d2k_quic_verify_bound` | 881 |  |
| 18 | `d2k_quic_verify_response` | 891 |  |
| 19 | `qp_verify_vn` | 899 | да |
| 20 | `qp_recv_ttl` | 938 | да |
| 21 | `qp_send_fragmented` | 1005 | да |
| 22 | `qp_neutral_control_sni` | 1046 | да |
| 23 | `quic_ask_core` | 1065 | да |
| 24 | `quic_ask_ex` | 1406 | да |
| 25 | `quic_fragment` | 1419 | да |
| 26 | `qp_progress` | 1433 | да |
| 27 | `quic_ask_arm` | 1438 | да |
| 28 | `qp_arm_first_send` | 1501 | да |
| 29 | `qp_now_ms` | 1511 | да |
| 30 | `quic_arm_data` | 1517 | да |
| 31 | `d2k_quic_data_stage` | 1592 |  |
| 32 | `quic_ask` | 1833 | да |
| 33 | `qp_ask_vn` | 1856 | да |
| 34 | `quic_ask_ttl` | 1870 | да |
| 35 | `quic_ask_copies` | 1887 | да |
| 36 | `quic_ask_srcport` | 1899 | да |
| 37 | `quic_ask_split` | 1910 | да |
| 38 | `quic_ask_longer` | 1925 | да |
| 39 | `quic_ask_frames` | 1932 | да |
| 40 | `quic_ask_control` | 1943 | да |
| 41 | `reason_set` | 1958 | да |
| 42 | `reason_append` | 1965 | да |
| 43 | `budget_left` | 1985 | да |
| 44 | `qp_pinned_or_next` | 2019 | да |
| 45 | `qp_dyn_wait` | 2090 | да |
| 46 | `d2k_quic_budget_ms` | 2097 |  |
| 47 | `qp_outcome` | 2112 | да |
| 48 | `qp_questions_step` | 2119 | да |
| 49 | `d2k_quic_props_findings` | 2276 |  |
| 50 | `arm_budget_left` | 2327 | да |
| 51 | `arm_budget_spent` | 2330 | да |
| 52 | `classify_run` | 2338 | да |
| 53 | `d2k_quic_classify` | 2921 |  |
| 54 | `d2k_quic_base` | 2925 |  |
| 55 | `d2k_quic_run_seeded` | 2929 |  |
| 56 | `d2k_quic_run` | 2934 |  |

### quicsnap_reseal.c — 2

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `reseal_one` | 25 | да |
| 2 | `d2k_qsnap_recid` | 76 |  |

### quicsnap.c — 6

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `d2k_qsnap_is` | 14 |  |
| 2 | `d2k_qsnap_parse` | 18 |  |
| 3 | `d2k_qsnap_pack` | 50 |  |
| 4 | `d2k_qsnap_client_hello` | 76 |  |
| 5 | `d2k_qsnap_sni` | 83 |  |
| 6 | `d2k_qsnap_form` | 92 |  |

### quicwire.c — 28

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `salt_for` | 42 | да |
| 2 | `label_key` | 45 | да |
| 3 | `label_iv` | 48 | да |
| 4 | `label_hp` | 51 | да |
| 5 | `d2k_qw_varint_read` | 57 |  |
| 6 | `d2k_qw_varint_len` | 70 |  |
| 7 | `d2k_qw_varint_write_w` | 78 |  |
| 8 | `d2k_qw_varint_write` | 108 |  |
| 9 | `long_type_v1` | 120 | да |
| 10 | `long_type_wire` | 133 | да |
| 11 | `d2k_qw_long_hdr_token_w` | 143 |  |
| 12 | `d2k_qw_long_hdr_w` | 177 |  |
| 13 | `d2k_qw_long_hdr_token` | 187 |  |
| 14 | `d2k_qw_long_hdr` | 197 |  |
| 15 | `d2k_qw_hdr_parse` | 205 |  |
| 16 | `d2k_qw_pn_len` | 278 |  |
| 17 | `d2k_qw_pn_decode` | 296 |  |
| 18 | `d2k_qw_initial_secret` | 318 |  |
| 19 | `d2k_qw_keys_from_secret` | 328 |  |
| 20 | `nonce_of` | 345 | да |
| 21 | `d2k_qw_seal` | 352 |  |
| 22 | `d2k_qw_open` | 397 |  |
| 23 | `d2k_qw_retry_verify` | 455 |  |
| 24 | `d2k_qw_retry_build` | 482 |  |
| 25 | `d2k_qw_ranges_reset` | 526 |  |
| 26 | `d2k_qw_ranges_add` | 530 |  |
| 27 | `d2k_qw_ranges_bytes` | 561 |  |
| 28 | `d2k_qw_ranges_complete` | 567 |  |

### sched.c — 282

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `refuse_is_permanent` | 302 | да |
| 2 | `refuse_is_damage` | 321 | да |
| 3 | `verify_default` | 389 | да |
| 4 | `bind_default` | 416 | да |
| 5 | `verify_rx_default` | 421 | да |
| 6 | `verify_rx_gzip_default` | 430 | да |
| 7 | `mark_default` | 439 | да |
| 8 | `classify_unconfigured` | 452 | да |
| 9 | `voice_default` | 483 | да |
| 10 | `d2k_sched_cpu_parse` | 489 |  |
| 11 | `cpu_read_proc` | 514 | да |
| 12 | `meminfo_field` | 532 | да |
| 13 | `d2k_sched_meminfo_parse` | 552 |  |
| 14 | `mem_read_proc` | 563 | да |
| 15 | `read_u64_file` | 574 | да |
| 16 | `ct_read_proc` | 585 | да |
| 17 | `client_alpn_nonhttp` | 1115 | да |
| 18 | `fresh_trial_id` | 1140 | да |
| 19 | `addr_probe_remove` | 1517 | да |
| 20 | `question_retire` | 1558 | да |
| 21 | `candidate_retire` | 1573 | да |
| 22 | `trial_retire` | 1593 | да |
| 23 | `say` | 1604 | да |
| 24 | `say_quiet` | 1616 | да |
| 25 | `d2k_sched_set_send_cap` | 1635 |  |
| 26 | `d2k_sched_set_say` | 1640 |  |
| 27 | `verdict_name` | 1648 | да |
| 28 | `signal_of` | 1673 | да |
| 29 | `is_rx_volume_kind` | 1700 | да |
| 30 | `fp_add` | 1704 | да |
| 31 | `volume_bucket` | 1747 | да |
| 32 | `is_volume_kind` | 1754 | да |
| 33 | `box_volume_bucket_agrees` | 1761 | да |
| 34 | `server_is_low` | 1799 | да |
| 35 | `client_ip_of` | 1808 | да |
| 36 | `server_of` | 1814 | да |
| 37 | `same_flow` | 1825 | да |
| 38 | `remember` | 1842 | да |
| 39 | `recall` | 1865 | да |
| 40 | `cooldown_find_endpoint` | 1872 | да |
| 41 | `cooldown_find_challenge` | 1887 | да |
| 42 | `dead_find` | 1900 | да |
| 43 | `dead_step` | 1916 | да |
| 44 | `dead_clear` | 1938 | да |
| 45 | `is_late_volume_suspicion` | 1943 | да |
| 46 | `cooldown_blocks` | 1949 | да |
| 47 | `cooldown_clear_endpoint` | 1976 | да |
| 48 | `cooldown_clear_nonchallenge` | 1983 | да |
| 49 | `clear_backoff_ms` | 2001 | да |
| 50 | `cooldown_victim` | 2013 | да |
| 51 | `cooldown_record` | 2033 | да |
| 52 | `late_close_what` | 2101 | да |
| 53 | `box_stall_budget` | 2115 | да |
| 54 | `budget_listed` | 2125 | да |
| 55 | `name_stall_budgets` | 2132 | да |
| 56 | `tcp_stall_in_name_band` | 2154 | да |
| 57 | `stall_budgets_push` | 2171 | да |
| 58 | `task_of` | 2194 | да |
| 59 | `task_free_slot` | 2205 | да |
| 60 | `task_watching_slot` | 2218 | да |
| 61 | `tcp_hello_kind` | 2241 | да |
| 62 | `hello_fits_client` | 2246 | да |
| 63 | `quic_pack_ech` | 2257 | да |
| 64 | `quic_named_find` | 2269 | да |
| 65 | `client_offers_ts` | 2287 | да |
| 66 | `client_tcp_profile` | 2304 | да |
| 67 | `flowkey_same` | 2321 | да |
| 68 | `take_shape_opts` | 2329 | да |
| 69 | `drop_client_opts` | 2343 | да |
| 70 | `fill_hellos` | 2348 | да |
| 71 | `worker_arg_alloc` | 2520 | да |
| 72 | `worker_arg_free` | 2530 | да |
| 73 | `d2k_sched_ech_baseline_result` | 2539 |  |
| 74 | `worker_volume` | 2562 | да |
| 75 | `worker_volume_cut` | 2633 | да |
| 76 | `seed_input_of` | 2668 | да |
| 77 | `d2k_sched_progress_note` | 2681 |  |
| 78 | `ask_settle` | 2701 | да |
| 79 | `sched_quic_yield` | 2708 | да |
| 80 | `sched_quic_progress` | 2732 | да |
| 81 | `sched_mono_ms` | 2736 | да |
| 82 | `worker_run_body` | 2742 | да |
| 83 | `worker_run` | 3256 | да |
| 84 | `quic_text_is_split` | 3277 | да |
| 85 | `quic_client_multi` | 3281 | да |
| 86 | `quic_split_unfit` | 3294 | да |
| 87 | `task_budget` | 3307 | да |
| 88 | `note_worker_start_failure` | 3332 | да |
| 89 | `start_worker` | 3340 | да |
| 90 | `join_worker` | 3406 | да |
| 91 | `box_ensure` | 3431 | да |
| 92 | `wall_s` | 3460 | да |
| 93 | `bind_confirmed` | 3464 | да |
| 94 | `fnv1a` | 3575 | да |
| 95 | `tried_add` | 3594 | да |
| 96 | `plan_ident` | 3599 | да |
| 97 | `is_hex_digit` | 3608 | да |
| 98 | `question_shape` | 3636 | да |
| 99 | `probe_shape` | 3643 | да |
| 100 | `task_wire_shape` | 3675 | да |
| 101 | `binding_wire_shape` | 3679 | да |
| 102 | `stamp_plan_id` | 3685 | да |
| 103 | `prop_close` | 3728 | да |
| 104 | `contact_close` | 3739 | да |
| 105 | `ver_close` | 3750 | да |
| 106 | `task_reset` | 3763 | да |
| 107 | `box_injects_rst` | 3835 | да |
| 108 | `rst_guard_wanted` | 3843 | да |
| 109 | `plan_arm_rst_guard` | 3854 | да |
| 110 | `prop_send_next` | 3865 | да |
| 111 | `prop_finish` | 3975 | да |
| 112 | `task_fail` | 3994 | да |
| 113 | `quic_deny_find` | 4033 | да |
| 114 | `quic_deny_install` | 4041 | да |
| 115 | `quic_deny_active` | 4115 | да |
| 116 | `quic_deny_recheck` | 4130 | да |
| 117 | `quic_deny_tick` | 4156 | да |
| 118 | `task_done` | 4184 | да |
| 119 | `rx_decoy_name` | 4196 | да |
| 120 | `net_whitelist_undecided` | 4202 | да |
| 121 | `net_whitelist_needs_probe` | 4212 | да |
| 122 | `sched_probe_cap` | 4221 | да |
| 123 | `vol_cut_measured` | 4225 | да |
| 124 | `vol_cut_kb` | 4228 | да |
| 125 | `rx_ladder_pending` | 4234 | да |
| 126 | `next_rx_volume_plan` | 4243 | да |
| 127 | `refill_from_fallback` | 4293 | да |
| 128 | `claim_early_refusal` | 4395 | да |
| 129 | `ack_reason_text` | 4413 | да |
| 130 | `candidate_trial_matches` | 4425 | да |
| 131 | `exec_refusal` | 4438 | да |
| 132 | `ech_witness_transport_proof` | 4469 | да |
| 133 | `ech_witness_rx_cut` | 4477 | да |
| 134 | `local_refusal_verdict` | 4486 | да |
| 135 | `install_next` | 4540 | да |
| 136 | `binding_for` | 4761 | да |
| 137 | `known_plans` | 4778 | да |
| 138 | `budget_rank` | 4867 | да |
| 139 | `binding_beats` | 4870 | да |
| 140 | `bound_plan_here` | 4882 | да |
| 141 | `own_rank_before` | 4907 | да |
| 142 | `own_first_plans` | 4915 | да |
| 143 | `verdict_proves_block` | 5058 | да |
| 144 | `clear_measured_shape` | 5075 | да |
| 145 | `clear_binding_matches` | 5083 | да |
| 146 | `forget_clear_target_bindings` | 5124 | да |
| 147 | `props_text` | 5179 | да |
| 148 | `probes_word` | 5192 | да |
| 149 | `verdict_to_plans` | 5210 | да |
| 150 | `d2k_sched_new` | 5567 |  |
| 151 | `d2k_sched_set_measure_mark` | 5613 |  |
| 152 | `json_str` | 5625 | да |
| 153 | `json_time` | 5635 | да |
| 154 | `level_name` | 5651 | да |
| 155 | `signal_human` | 5664 | да |
| 156 | `task_phase` | 5686 | да |
| 157 | `live_binding_for` | 5708 | да |
| 158 | `live_autopick_status` | 5724 | да |
| 159 | `d2k_sched_diagnostics` | 5812 |  |
| 160 | `d2k_sched_limit_diagnostics` | 5815 |  |
| 161 | `worker_type` | 5818 | да |
| 162 | `d2k_sched_diagnostic_counts` | 5827 |  |
| 163 | `d2k_sched_diagnostic_madvise` | 5877 |  |
| 164 | `d2k_sched_diagnostic_madvise_reset` | 5878 |  |
| 165 | `d2k_sched_write_live` | 5880 |  |
| 166 | `d2k_sched_free` | 6052 |  |
| 167 | `wake_loop` | 6078 | да |
| 168 | `d2k_sched_wake_fd` | 6083 |  |
| 169 | `d2k_sched_active` | 6085 |  |
| 170 | `plan_by_id` | 6097 | да |
| 171 | `d2k_sched_sync` | 6113 |  |
| 172 | `d2k_sched_sync_pending` | 6128 |  |
| 173 | `addr_binding_shape` | 6145 | да |
| 174 | `newer_name_binding` | 6172 | да |
| 175 | `area_key_same` | 6196 | да |
| 176 | `area_find` | 6201 | да |
| 177 | `area_store` | 6207 | да |
| 178 | `area_retry_delay` | 6215 | да |
| 179 | `area_failure` | 6224 | да |
| 180 | `area_ack_reason` | 6240 | да |
| 181 | `area_reason_name` | 6249 | да |
| 182 | `area_retry_due` | 6261 | да |
| 183 | `area_plan` | 6268 | да |
| 184 | `own_exact_confirmed` | 6279 | да |
| 185 | `desired_area` | 6298 | да |
| 186 | `desired_has_key` | 6335 | да |
| 187 | `write_live_groups` | 6348 | да |
| 188 | `sync_area_send` | 6443 | да |
| 189 | `area_exceptions_ready` | 6521 | да |
| 190 | `area_exception_groups_suspended` | 6535 | да |
| 191 | `group_exception_status` | 6554 | да |
| 192 | `sync_areas` | 6589 | да |
| 193 | `plan_text_max_emit` | 6649 | да |
| 194 | `d2k_sched_sync_step` | 6661 |  |
| 195 | `has_other_family_target_plan` | 6916 | да |
| 196 | `remember_resources` | 6940 | да |
| 197 | `remember_measured_path` | 6970 | да |
| 198 | `public_resource_peer` | 6986 | да |
| 199 | `select_resource_path` | 6996 | да |
| 200 | `ech_rr_known` | 7053 | да |
| 201 | `ech_rr_store` | 7062 | да |
| 202 | `ech_chal_has` | 7075 | да |
| 203 | `ech_chal_add` | 7082 | да |
| 204 | `ech_pick_witness` | 7089 | да |
| 205 | `ech_witness_untried` | 7119 | да |
| 206 | `ech_witness_reject` | 7131 | да |
| 207 | `ech_witness_add` | 7141 | да |
| 208 | `start_search` | 7153 | да |
| 209 | `box_id_for` | 7333 | да |
| 210 | `voice_trial_send` | 7425 | да |
| 211 | `voice_ip_fmt` | 7447 | да |
| 212 | `voice_ip_text` | 7451 | да |
| 213 | `voice_ip_text2` | 7455 | да |
| 214 | `voice_trial_owned` | 7462 | да |
| 215 | `voice_trial_same_context` | 7470 | да |
| 216 | `voice_start` | 7482 | да |
| 217 | `voice_finish_measure` | 7513 | да |
| 218 | `quic_addr_start` | 7617 | да |
| 219 | `measurements_in_flight` | 7629 | да |
| 220 | `queued_measurements` | 7636 | да |
| 221 | `res_sample` | 7650 | да |
| 222 | `res_valid` | 7697 | да |
| 223 | `cpu_free_pct` | 7699 | да |
| 224 | `mem_reserve_kb` | 7703 | да |
| 225 | `mem_short` | 7708 | да |
| 226 | `ct_short` | 7712 | да |
| 227 | `ct_pct` | 7718 | да |
| 228 | `meas_state` | 7722 | да |
| 229 | `measure_slots` | 7742 | да |
| 230 | `limiter_text` | 7751 | да |
| 231 | `measure_started` | 7768 | да |
| 232 | `measure_limit_update` | 7772 | да |
| 233 | `installed_family_ready` | 7843 | да |
| 234 | `binding_covering` | 7877 | да |
| 235 | `watch_shape` | 7900 | да |
| 236 | `queued_family_ready` | 7906 | да |
| 237 | `family_recovery_eligible` | 7911 | да |
| 238 | `group_path` | 7920 | да |
| 239 | `family_recovery_start` | 7924 | да |
| 240 | `launch_task` | 8000 | да |
| 241 | `launch_or_queue` | 8030 | да |
| 242 | `voice_observe` | 8071 | да |
| 243 | `voice_confirm` | 8091 | да |
| 244 | `voice_fail` | 8154 | да |
| 245 | `is_voice_class` | 8161 | да |
| 246 | `is_telegram_tunnel_domain` | 8168 | да |
| 247 | `on_suspect` | 8182 | да |
| 248 | `quic_own_initial` | 8608 | да |
| 249 | `remeasure_snapped` | 8624 | да |
| 250 | `quic_note_multi` | 8691 | да |
| 251 | `on_shape` | 8733 | да |
| 252 | `group_record` | 9014 | да |
| 253 | `record_shape` | 9036 | да |
| 254 | `budget_uncountable_note` | 9044 | да |
| 255 | `budget_cut_reject` | 9073 | да |
| 256 | `say_question_trace` | 9160 | да |
| 257 | `ladder_candidate_at` | 9176 | да |
| 258 | `ladder_candidate` | 9186 | да |
| 259 | `candidate_path` | 9190 | да |
| 260 | `search_report` | 9208 | да |
| 261 | `verify_confirm` | 9263 | да |
| 262 | `partial_finish` | 9669 | да |
| 263 | `plan_id_is_ours` | 9692 | да |
| 264 | `applied_trial_is_ours` | 9701 | да |
| 265 | `applied_of_candidate` | 9709 | да |
| 266 | `on_applied` | 9740 | да |
| 267 | `on_refused_foreign` | 9901 | да |
| 268 | `on_refused_unfit` | 9961 | да |
| 269 | `on_refused` | 10054 | да |
| 270 | `note_clean_handshake` | 10177 | да |
| 271 | `clean_handshake_recent` | 10203 | да |
| 272 | `on_exchange` | 10218 | да |
| 273 | `d2k_sched_event` | 10326 |  |
| 274 | `own_first_continue` | 10466 | да |
| 275 | `rx_saved_bootstrap` | 10529 | да |
| 276 | `layered_rx_result` | 10575 | да |
| 277 | `queued_before` | 10659 | да |
| 278 | `quic_yield_tick` | 10667 | да |
| 279 | `queued_pick` | 10704 | да |
| 280 | `queued_release` | 10729 | да |
| 281 | `voice_pending_dispatch` | 10757 | да |
| 282 | `d2k_sched_tick` | 10785 |  |

### stun.c — 5

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `rd16` | 20 | да |
| 2 | `rd32` | 24 | да |
| 3 | `d2k_stun_request` | 28 |  |
| 4 | `parse_xor_mapped` | 53 | да |
| 5 | `d2k_stun_parse_response` | 86 |  |

### tls12.c — 26

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `tls12_dispose` | 99 | да |
| 2 | `say` | 103 | да |
| 3 | `now_ms` | 111 | да |
| 4 | `put16` | 117 | да |
| 5 | `get16` | 118 | да |
| 6 | `read_exact` | 120 | да |
| 7 | `write_all` | 156 | да |
| 8 | `prf` | 184 | да |
| 9 | `d2k_tls12_prf_for_test` | 215 |  |
| 10 | `tr_add` | 221 | да |
| 11 | `nonce_of` | 229 | да |
| 12 | `aad_of` | 236 | да |
| 13 | `send_plain` | 247 | да |
| 14 | `send_sealed` | 259 | да |
| 15 | `read_record` | 288 | да |
| 16 | `hs_next` | 356 | да |
| 17 | `ch12_build` | 416 | да |
| 18 | `d2k_tls12_connect` | 493 |  |
| 19 | `d2k_tls12_resume` | 533 |  |
| 20 | `tls12_finish` | 557 | да |
| 21 | `d2k_tls12_write` | 751 |  |
| 22 | `d2k_tls12_read` | 757 |  |
| 23 | `d2k_tls12_peer_name` | 796 |  |
| 24 | `d2k_tls12_free` | 798 |  |
| 25 | `d2k_tls12_rx_wire_bytes` | 800 |  |
| 26 | `d2k_tls12_rx_record_missing` | 801 |  |

### tls13.c — 23

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `tls_dispose` | 84 | да |
| 2 | `say` | 88 | да |
| 3 | `now_ms` | 96 | да |
| 4 | `read_exact` | 103 | да |
| 5 | `write_all` | 139 | да |
| 6 | `put16` | 161 | да |
| 7 | `get16` | 162 | да |
| 8 | `nonce_of` | 166 | да |
| 9 | `read_record` | 176 | да |
| 10 | `write_record` | 237 | да |
| 11 | `traffic_keys` | 261 | да |
| 12 | `tls_connect_internal` | 266 | да |
| 13 | `d2k_tls_connect` | 526 |  |
| 14 | `d2k_tls_connect_alpn` | 532 |  |
| 15 | `d2k_tls_connect_ech` | 539 |  |
| 16 | `d2k_tls_ech_accepted` | 549 |  |
| 17 | `d2k_tls_write` | 551 |  |
| 18 | `d2k_tls_read` | 563 |  |
| 19 | `d2k_tls_peer_name` | 604 |  |
| 20 | `d2k_tls_free` | 606 |  |
| 21 | `d2k_tls_rx_wire_bytes` | 611 |  |
| 22 | `d2k_tls_rx_record_missing` | 612 |  |
| 23 | `d2k_tls_version` | 614 |  |

### tls13core.c — 24

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `put16` | 17 | да |
| 2 | `get16` | 18 | да |
| 3 | `d2k_t13_random` | 22 |  |
| 4 | `der_len` | 54 | да |
| 5 | `ascii_lower` | 65 | да |
| 6 | `name_matches` | 74 | да |
| 7 | `cert_name_ok` | 107 | да |
| 8 | `d2k_t13_cert_name_ok12` | 167 |  |
| 9 | `d2k_t13_cert_name_ok` | 178 |  |
| 10 | `d2k_t13_ch_build` | 198 |  |
| 11 | `d2k_t13_derive_secret` | 362 |  |
| 12 | `d2k_t13_schedule_hs` | 369 |  |
| 13 | `d2k_t13_schedule_ap` | 384 |  |
| 14 | `d2k_t13_finished_mac` | 397 |  |
| 15 | `d2k_t13_sh_version` | 408 |  |
| 16 | `d2k_t13_sh_parse` | 429 |  |
| 17 | `d2k_t13_flight_next` | 480 |  |
| 18 | `ech_host_ok` | 493 | да |
| 19 | `d2k_ech_config_parse` | 511 |  |
| 20 | `hpke_extract` | 571 | да |
| 21 | `hpke_expand` | 584 | да |
| 22 | `ech_hpke` | 599 | да |
| 23 | `d2k_t13_ech_build` | 622 |  |
| 24 | `d2k_t13_ech_accepted` | 685 |  |

### udpplan.c — 12

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `append_fmt` | 11 | да |
| 2 | `emit_header_proto` | 29 | да |
| 3 | `append_hex` | 37 | да |
| 4 | `quic_arm_found` | 51 | да |
| 5 | `quic_split_plan_text` | 60 | да |
| 6 | `quic_plan_text` | 70 | да |
| 7 | `d2k_quic_arm_plan` | 174 |  |
| 8 | `d2k_quic_compose_plan` | 189 |  |
| 9 | `d2k_quic_delay_plan` | 206 |  |
| 10 | `d2k_voice_arm_plan` | 220 |  |
| 11 | `d2k_voice_plan` | 242 |  |
| 12 | `d2k_quic_question_plan` | 248 |  |

### udpruntime.c — 8

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `udp_next_fragment_id` | 23 | да |
| 2 | `d2k_udp_batch_free` | 33 |  |
| 3 | `d2k_udp_plan_build` | 34 |  |
| 4 | `udp_raw_init` | 102 | да |
| 5 | `udp_raw_close` | 108 | да |
| 6 | `udp_raw_prepare` | 114 | да |
| 7 | `udp_raw_send` | 132 | да |
| 8 | `d2k_udp_plan_send` | 148 |  |

### verdict.c — 7

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `looks_like_tls` | 34 | да |
| 2 | `reverse_note` | 54 | да |
| 3 | `pause_note` | 75 | да |
| 4 | `stop_requested` | 93 | да |
| 5 | `classify_cancelled` | 97 | да |
| 6 | `d2k_classify_cancelable` | 105 |  |
| 7 | `d2k_classify` | 337 |  |

### verify_quic_replay.c — 2

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `replay_now_ms` | 24 | да |
| 2 | `d2k_verify_quic_replay_on` | 30 |  |

### verify.c — 74

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `verify_now_ms` | 53 | да |
| 2 | `dns16` | 59 | да |
| 3 | `ech_dns_name` | 63 | да |
| 4 | `d2k_ech_resolve` | 91 |  |
| 5 | `find_hdr_end` | 194 | да |
| 6 | `find_eol` | 204 | да |
| 7 | `lower_ascii` | 211 | да |
| 8 | `span_eq_ascii_ci` | 215 | да |
| 9 | `has_cf_challenge` | 228 | да |
| 10 | `read13` | 274 | да |
| 11 | `read12` | 279 | да |
| 12 | `body_read_reason` | 299 | да |
| 13 | `body_say` | 305 | да |
| 14 | `body_feed` | 309 | да |
| 15 | `body_byte` | 318 | да |
| 16 | `body_exact` | 332 | да |
| 17 | `body_line` | 353 | да |
| 18 | `read_http_body` | 381 | да |
| 19 | `read_status_buf` | 458 | да |
| 20 | `read_status_rd` | 700 | да |
| 21 | `d2k_http_read_response` | 731 |  |
| 22 | `d2k_verify_probe` | 740 |  |
| 23 | `write13` | 751 | да |
| 24 | `write12` | 756 | да |
| 25 | `redirect_path` | 763 | да |
| 26 | `https_redirect_response` | 800 | да |
| 27 | `d2k_verify_budget_set` | 823 |  |
| 28 | `d2k_verify_budget_get` | 824 |  |
| 29 | `d2k_verify_tcp_timestamps_set` | 827 |  |
| 30 | `d2k_verify_tcp_timestamps_get` | 830 |  |
| 31 | `d2k_verify_quic_form_set` | 838 |  |
| 32 | `d2k_verify_tcp_data_packets` | 851 |  |
| 33 | `budget_say` | 878 | да |
| 34 | `gateway_header_end` | 886 | да |
| 35 | `gateway_header_value` | 893 | да |
| 36 | `gateway_connection_upgrade` | 906 | да |
| 37 | `gateway_json_hello` | 918 | да |
| 38 | `gateway_fill` | 977 | да |
| 39 | `request_gateway_websocket` | 1001 | да |
| 40 | `read_eof` | 1133 | да |
| 41 | `budget_tcp` | 1147 | да |
| 42 | `fd_peer_spoke` | 1218 | да |
| 43 | `fd_packets` | 1224 | да |
| 44 | `request_complete_page` | 1239 | да |
| 45 | `request_page_budget` | 1248 | да |
| 46 | `verify_contact` | 1350 | да |
| 47 | `d2k_props_contact_on_family_tcp_profile` | 1361 |  |
| 48 | `verify_probe13_internal` | 1366 | да |
| 49 | `verify_probe13_on` | 1445 | да |
| 50 | `ech_http_denial` | 1452 | да |
| 51 | `d2k_verify_probe_ech_on` | 1463 |  |
| 52 | `d2k_verify_probe_ech_origin_on` | 1479 |  |
| 53 | `d2k_verify_replay_on` | 1500 |  |
| 54 | `d2k_verify_probe_on` | 1565 |  |
| 55 | `d2k_verify_probe_alpn_on` | 1579 |  |
| 56 | `verify_probe12_internal` | 1637 | да |
| 57 | `d2k_verify_probe12_on` | 1704 |  |
| 58 | `d2k_verify_probe_identity_on` | 1711 |  |
| 59 | `d2k_verify_probe_gzip_on` | 1718 |  |
| 60 | `d2k_verify_probe_baseline` | 1725 |  |
| 61 | `d2k_verify_probe_path_on` | 1745 |  |
| 62 | `d2k_verify_close` | 1760 |  |
| 63 | `d2k_verify_probe_quic` | 1769 |  |
| 64 | `quic_app_silent` | 1781 | да |
| 65 | `h3_read_headers` | 1800 | да |
| 66 | `quic_recv_chunk` | 1817 | да |
| 67 | `budget_quic` | 1837 | да |
| 68 | `qb_request` | 1954 | да |
| 69 | `qb_recv` | 1961 | да |
| 70 | `qb_progress` | 1965 | да |
| 71 | `qb_packets` | 1968 | да |
| 72 | `d2k_verify_probe_quic_on` | 1976 |  |
| 73 | `d2k_verify_probe_quic_path_on` | 1984 |  |
| 74 | `d2k_verify_probe_quic_path_mark_on` | 1992 |  |

### voice_discovery.c — 7

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `nibble` | 17 | да |
| 2 | `d2k_voice_discovery_prefix` | 23 |  |
| 3 | `d2k_discovery_response` | 42 |  |
| 4 | `milliseconds` | 50 | да |
| 5 | `discovery_probe` | 55 | да |
| 6 | `local_failure` | 103 | да |
| 7 | `d2k_voice_discovery_search` | 111 |  |

### voice.c — 14

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `is_voice_port` | 43 | да |
| 2 | `field_val` | 66 | да |
| 3 | `d2k_voice_targets` | 85 |  |
| 4 | `send_one` | 174 | да |
| 5 | `ms_since` | 206 | да |
| 6 | `voice_ask` | 215 | да |
| 7 | `voice_resolve` | 300 | да |
| 8 | `voice_blob_load` | 324 | да |
| 9 | `voice_alive` | 350 | да |
| 10 | `voice_ask_real` | 366 |  |
| 11 | `voice_ask_arms` | 372 | да |
| 12 | `say_reason` | 404 | да |
| 13 | `add_reason` | 411 | да |
| 14 | `d2k_voice_run` | 435 |  |

### volume.c — 19

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `rx_wire_partial` | 59 | да |
| 2 | `d2k_volume_rx_partial` | 67 |  |
| 3 | `d2k_volume_rx_pair_agrees` | 79 |  |
| 4 | `d2k_volume_rx_needs_repeat` | 104 |  |
| 5 | `d2k_volume_rx_evidence` | 112 |  |
| 6 | `d2k_vol_verdict_name` | 216 |  |
| 7 | `now_ms` | 225 | да |
| 8 | `nap_ms` | 231 | да |
| 9 | `clamp_ms` | 238 | да |
| 10 | `fill_pad` | 248 | да |
| 11 | `connect_bounded` | 260 | да |
| 12 | `drain_head_tls` | 326 | да |
| 13 | `drain_head_plain` | 352 | да |
| 14 | `resource_retry_path` | 394 | да |
| 15 | `rx_probe` | 412 | да |
| 16 | `measure_response_volume` | 441 | да |
| 17 | `probe_response_volume` | 559 | да |
| 18 | `d2k_volume_probe_path` | 596 |  |
| 19 | `d2k_volume_probe` | 730 |  |

### x25519.c — 11

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `car25519` | 33 | да |
| 2 | `sel25519` | 55 | да |
| 3 | `pack25519` | 64 | да |
| 4 | `unpack25519` | 85 | да |
| 5 | `A` | 92 | да |
| 6 | `Z` | 93 | да |
| 7 | `M` | 95 | да |
| 8 | `S` | 107 | да |
| 9 | `inv25519` | 110 | да |
| 10 | `d2k_x25519` | 120 |  |
| 11 | `d2k_x25519_base` | 171 |  |

## datapath — 567 функций

### addr.c — 3

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `d2k_addr_parse` | 6 |  |
| 2 | `d2k_addr_text` | 21 |  |
| 3 | `d2k_addr_equal` | 33 |  |

### capture.c — 6

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `same` | 5 | да |
| 2 | `d2k_capture_forget` | 9 |  |
| 3 | `reject` | 17 | да |
| 4 | `d2k_capture_feed_ready` | 23 |  |
| 5 | `tls_ready` | 110 | да |
| 6 | `d2k_capture_feed` | 120 |  |

### ctl.c — 14

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `say` | 67 | да |
| 2 | `set_nonblock` | 77 | да |
| 3 | `d2k_ctl_open` | 82 |  |
| 4 | `d2k_ctl_close` | 130 |  |
| 5 | `d2k_ctl_listen_fd` | 144 |  |
| 6 | `d2k_ctl_peer_fd` | 145 |  |
| 7 | `d2k_ctl_set_disconnect_hook` | 147 |  |
| 8 | `d2k_ctl_accept` | 153 |  |
| 9 | `drop_peer` | 180 | да |
| 10 | `d2k_ctl_flush` | 191 |  |
| 11 | `d2k_ctl_event` | 218 |  |
| 12 | `d2k_ctl_poll` | 258 |  |
| 13 | `d2k_ctl_dropped` | 316 |  |
| 14 | `d2k_ctl_sent` | 317 |  |

### ctlsrv.c — 12

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `put_key` | 24 | да |
| 2 | `d2k_plan_fits` | 40 |  |
| 3 | `ack` | 85 | да |
| 4 | `ack_trial` | 113 | да |
| 5 | `d2k_ctlsrv_greet` | 126 |  |
| 6 | `d2k_ctlsrv_peer_closed` | 148 |  |
| 7 | `canonical_address` | 153 | да |
| 8 | `addr_shape_valid` | 164 | да |
| 9 | `read_probe_flow` | 170 | да |
| 10 | `d2k_ctlsrv_command` | 190 |  |
| 11 | `d2k_ctlsrv_pump` | 512 |  |
| 12 | `d2k_ctlsrv_http80_event` | 698 |  |

### ctq.c — 20

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `align4` | 17 | да |
| 2 | `wr16h` | 19 | да |
| 3 | `wr32h` | 20 | да |
| 4 | `rd16h` | 21 | да |
| 5 | `rd64be` | 22 | да |
| 6 | `rd32be` | 27 | да |
| 7 | `put` | 32 | да |
| 8 | `open_nest` | 44 | да |
| 9 | `close_nest` | 49 | да |
| 10 | `d2k_ct_get_req` | 53 |  |
| 11 | `counter` | 85 | да |
| 12 | `tcp_state` | 100 | да |
| 13 | `d2k_ct_info_parse` | 123 |  |
| 14 | `d2k_ct_counters_parse` | 159 |  |
| 15 | `d2k_ct_query_info_fd` | 170 |  |
| 16 | `d2k_ct_query_fd` | 189 |  |
| 17 | `reply_errno` | 202 | да |
| 18 | `d2k_ct_probe_fd` | 215 |  |
| 19 | `d2k_ct_open` | 244 |  |
| 20 | `d2k_ct_open` | 256 |  |

### d2kd.c — 44

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `on_signal` | 63 | да |
| 2 | `self_cost` | 69 | да |
| 3 | `now_ns` | 113 | да |
| 4 | `tls_route_segment_cap` | 124 | да |
| 5 | `count_reason` | 166 | да |
| 6 | `icmp_step` | 221 | да |
| 7 | `log_send_fail` | 254 | да |
| 8 | `routes_routed` | 279 | да |
| 9 | `describe_oifs` | 283 | да |
| 10 | `routes_refresh` | 303 | да |
| 11 | `cap_refresh` | 373 | да |
| 12 | `send_original_verdict` | 418 | да |
| 13 | `send_delayed_verdict` | 430 | да |
| 14 | `delayed_verdict_done` | 434 | да |
| 15 | `hold_owns` | 485 | да |
| 16 | `resend_original` | 494 | да |
| 17 | `resend_originals` | 511 | да |
| 18 | `release_original` | 519 | да |
| 19 | `ct_query` | 562 | да |
| 20 | `ct_probe` | 579 | да |
| 21 | `out_verdict` | 598 | да |
| 22 | `out_fail` | 604 | да |
| 23 | `out_marked` | 616 | да |
| 24 | `out_defer` | 641 | да |
| 25 | `out_resend_failed` | 652 | да |
| 26 | `out_send_now` | 674 | да |
| 27 | `out_send_at` | 687 | да |
| 28 | `out_send_at_owned` | 700 | да |
| 29 | `http80_log` | 718 | да |
| 30 | `http80_io_payload` | 734 | да |
| 31 | `http80_io_accept` | 746 | да |
| 32 | `http80_io_rst` | 758 | да |
| 33 | `http80_cut` | 777 | да |
| 34 | `http80_step` | 787 | да |
| 35 | `usage` | 835 | да |
| 36 | `arg_u32` | 864 | да |
| 37 | `port_of` | 874 | да |
| 38 | `print_stats` | 879 | да |
| 39 | `proto_name` | 1040 | да |
| 40 | `jrn_kind` | 1051 | да |
| 41 | `print_journal` | 1071 | да |
| 42 | `refuse_of_errno` | 1115 | да |
| 43 | `offline_self_check` | 1119 | да |
| 44 | `main` | 1126 |  |

### hold.c — 12

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `r32` | 18 | да |
| 2 | `same` | 19 | да |
| 3 | `d2k_hold_parse` | 22 |  |
| 4 | `d2k_hold_new` | 42 |  |
| 5 | `d2k_hold_free` | 43 |  |
| 6 | `release_slot` | 44 | да |
| 7 | `d2k_hold_flush` | 53 |  |
| 8 | `d2k_hold_next` | 74 |  |
| 9 | `d2k_hold_get_stats` | 82 |  |
| 10 | `d2k_hold_verdicts` | 86 |  |
| 11 | `http_ready` | 94 | да |
| 12 | `d2k_hold_feed` | 102 |  |

### http_trace.c — 1

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `d2k_http_trace` | 10 |  |

### http80.c — 30

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `d2k_http80_new` | 68 |  |
| 2 | `d2k_http80_free` | 72 |  |
| 3 | `d2k_http80_get_stats` | 76 |  |
| 4 | `name_norm` | 84 | да |
| 5 | `d2k_http80_set_https` | 98 |  |
| 6 | `d2k_http80_https` | 121 |  |
| 7 | `wr16` | 134 | да |
| 8 | `wr32` | 135 | да |
| 9 | `sum16` | 139 | да |
| 10 | `fold` | 145 | да |
| 11 | `build` | 157 | да |
| 12 | `rd32` | 191 | да |
| 13 | `stale` | 197 | да |
| 14 | `find` | 201 | да |
| 15 | `make` | 218 | да |
| 16 | `d2k_http80_executed` | 239 |  |
| 17 | `request_result` | 257 | да |
| 18 | `d2k_http80_delivered` | 268 |  |
| 19 | `seq_after` | 282 | да |
| 20 | `delivered` | 286 | да |
| 21 | `cut_pending` | 290 | да |
| 22 | `cut_result` | 296 | да |
| 23 | `d2k_http80_sweep` | 306 |  |
| 24 | `request_prefix` | 328 | да |
| 25 | `request_feed` | 343 | да |
| 26 | `d2k_http80_packet` | 350 |  |
| 27 | `d2k_http80_swap` | 528 |  |
| 28 | `lc` | 550 | да |
| 29 | `d2k_http_request` | 552 |  |
| 30 | `d2k_http_hello` | 635 |  |

### icmpguard.c — 7

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `d2k_icmpguard_init` | 7 |  |
| 2 | `u16` | 11 | да |
| 3 | `parse_ip` | 22 | да |
| 4 | `d2k_icmpguard_note` | 50 |  |
| 5 | `d2k_icmpguard_check` | 72 |  |
| 6 | `d2k_icmpguard_dropped` | 113 |  |
| 7 | `d2k_icmpguard_noted` | 114 |  |

### journal.c — 14

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `d2k_journal_new` | 17 |  |
| 2 | `d2k_journal_free` | 34 |  |
| 3 | `d2k_suspect_text` | 42 |  |
| 4 | `d2k_refuse_text` | 56 |  |
| 5 | `add_entry` | 77 | да |
| 6 | `d2k_journal_add` | 133 |  |
| 7 | `d2k_journal_add_applied` | 140 |  |
| 8 | `d2k_journal_add_refused` | 152 |  |
| 9 | `d2k_journal_add_fate_bound` | 161 |  |
| 10 | `d2k_journal_add_fate` | 179 |  |
| 11 | `d2k_journal_count` | 185 |  |
| 12 | `d2k_journal_at` | 189 |  |
| 13 | `d2k_journal_dropped` | 199 |  |
| 14 | `d2k_journal_added` | 203 |  |

### nat.c — 5

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `parse_ip4` | 21 | да |
| 2 | `field_after` | 47 | да |
| 3 | `d2k_nat_outside` | 68 |  |
| 4 | `parse_address` | 76 | да |
| 5 | `d2k_nat_outside_family` | 85 |  |

### nfq.c — 12

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `say` | 34 | да |
| 2 | `nl_write` | 44 | да |
| 3 | `await_ack` | 62 | да |
| 4 | `send_and_ack` | 112 | да |
| 5 | `set_rcvbuf` | 128 | да |
| 6 | `d2k_nfq_open` | 148 |  |
| 7 | `d2k_nfq_close` | 233 |  |
| 8 | `d2k_nfq_fd` | 251 |  |
| 9 | `d2k_nfq_recv` | 255 |  |
| 10 | `d2k_nfq_verdict` | 277 |  |
| 11 | `d2k_nfq_verdict_payload` | 295 |  |
| 12 | `d2k_nfq_lost` | 314 |  |

### nl.c — 19

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `align4` | 11 | да |
| 2 | `h16` | 17 | да |
| 3 | `h32` | 18 | да |
| 4 | `wh16` | 19 | да |
| 5 | `wh32` | 20 | да |
| 6 | `n16` | 23 | да |
| 7 | `n32` | 26 | да |
| 8 | `wn16` | 30 | да |
| 9 | `wn32` | 33 | да |
| 10 | `d2k_nl_iter_init` | 38 |  |
| 11 | `d2k_nl_next` | 46 |  |
| 12 | `d2k_nl_packet` | 80 |  |
| 13 | `d2k_nl_errno` | 164 |  |
| 14 | `hdr_init` | 182 | да |
| 15 | `put_attr` | 201 | да |
| 16 | `d2k_nl_verdict` | 219 |  |
| 17 | `d2k_nl_verdict_payload` | 237 |  |
| 18 | `d2k_nl_cfg_cmd` | 255 |  |
| 19 | `d2k_nl_cfg_params` | 276 |  |

### plan_apply.c — 15

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `anchor_offset` | 27 | да |
| 2 | `cmp_size` | 83 | да |
| 3 | `split_points` | 91 | да |
| 4 | `tls_ch_layout` | 121 | да |
| 5 | `random_bytes` | 157 | да |
| 6 | `wr16` | 166 | да |
| 7 | `wr24` | 169 | да |
| 8 | `fake_tls_bytes` | 174 | да |
| 9 | `emit_fake` | 240 | да |
| 10 | `emit_vec_free` | 269 | да |
| 11 | `emit_overhead` | 286 | да |
| 12 | `d2k_plan_max_emit` | 298 |  |
| 13 | `d2k_plan_apply` | 344 |  |
| 14 | `d2k_actions_cancel` | 892 |  |
| 15 | `d2k_actions_free` | 924 |  |

### plan_parse.c — 17

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `rd16` | 24 | да |
| 2 | `rd32` | 28 | да |
| 3 | `fail` | 33 | да |
| 4 | `scan` | 46 | да |
| 5 | `check_refs` | 225 | да |
| 6 | `d2k_find_payload` | 328 |  |
| 7 | `d2k_find_poison` | 337 |  |
| 8 | `d2k_plan_load` | 346 |  |
| 9 | `d2k_plan_free` | 569 |  |
| 10 | `d2k_plan_poison_used` | 584 |  |
| 11 | `d2k_plan_flow_needs` | 595 |  |
| 12 | `d2k_plan_quic_deny` | 602 |  |
| 13 | `d2k_plan_guards` | 606 |  |
| 14 | `d2k_plan_transport` | 610 |  |
| 15 | `d2k_plan_proto` | 614 |  |
| 16 | `d2k_plan_stream_input` | 618 |  |
| 17 | `d2k_plan_id` | 624 |  |

### plans.c — 75

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `bind_context` | 95 | да |
| 2 | `d2k_plantab_new` | 105 |  |
| 3 | `d2k_plantab_free` | 133 |  |
| 4 | `name_eq` | 155 | да |
| 5 | `shape_transport` | 170 | да |
| 6 | `area_name_valid` | 178 | да |
| 7 | `suffix_member` | 194 | да |
| 8 | `area_exact` | 200 | да |
| 9 | `area_set` | 210 | да |
| 10 | `d2k_plantab_set_suffix_family` | 229 |  |
| 11 | `d2k_plantab_set_bypass_family` | 240 |  |
| 12 | `area_del` | 247 | да |
| 13 | `d2k_plantab_del_suffix_family` | 256 |  |
| 14 | `d2k_plantab_del_bypass_family` | 261 |  |
| 15 | `area_bypassed` | 266 | да |
| 16 | `area_match` | 276 | да |
| 17 | `d2k_plantab_revision` | 287 |  |
| 18 | `d2k_plantab_has_ech_target` | 289 |  |
| 19 | `d2k_plantab_stream_candidate` | 317 |  |
| 20 | `d2k_plantab_stream_candidate_family` | 322 |  |
| 21 | `d2k_plantab_stream_candidate_target` | 328 |  |
| 22 | `find_name_skip` | 358 | да |
| 23 | `find_name` | 370 | да |
| 24 | `find_name_shape_port` | 386 | да |
| 25 | `find_name_port` | 402 | да |
| 26 | `d2k_plantab_http_candidate` | 415 |  |
| 27 | `d2k_plantab_find_http` | 425 |  |
| 28 | `find_addr_shape` | 440 | да |
| 29 | `find_addr` | 453 | да |
| 30 | `modern_shape_for_ech` | 466 | да |
| 31 | `scan_name` | 472 | да |
| 32 | `scan_addr` | 489 | да |
| 33 | `oldest` | 519 | да |
| 34 | `take_free_or_evict` | 542 | да |
| 35 | `d2k_plantab_set_name_shaped` | 572 |  |
| 36 | `d2k_plantab_set_name_probe` | 577 |  |
| 37 | `probe_transport` | 585 | да |
| 38 | `d2k_plantab_set_name_family` | 591 |  |
| 39 | `d2k_plantab_set_name` | 673 |  |
| 40 | `d2k_plantab_set_addr` | 679 |  |
| 41 | `d2k_plantab_set_addr_family` | 687 |  |
| 42 | `d2k_plantab_set_addr_shaped` | 693 |  |
| 43 | `drop` | 729 | да |
| 44 | `d2k_plantab_del_name` | 744 |  |
| 45 | `d2k_plantab_del_name_family` | 748 |  |
| 46 | `d2k_plantab_del_name_shaped` | 774 |  |
| 47 | `d2k_plantab_del_name_bound` | 793 |  |
| 48 | `d2k_plantab_del_name_probe` | 809 |  |
| 49 | `d2k_plantab_del_name_probe_family` | 814 |  |
| 50 | `d2k_plantab_del_addr` | 831 |  |
| 51 | `d2k_plantab_del_addr_family` | 838 |  |
| 52 | `d2k_plantab_del_addr_shaped` | 845 |  |
| 53 | `trial_id_valid` | 851 | да |
| 54 | `probe_flow_valid` | 861 | да |
| 55 | `probe_flow_equal` | 877 | да |
| 56 | `probe_drop` | 890 | да |
| 57 | `d2k_plantab_clear_probes` | 898 |  |
| 58 | `d2k_plantab_set_addr_probe` | 913 |  |
| 59 | `d2k_plantab_del_addr_probe` | 964 |  |
| 60 | `find_probe` | 979 | да |
| 61 | `d2k_plantab_find_addr_probe` | 1009 |  |
| 62 | `d2k_plantab_find_voice_probe` | 1015 |  |
| 63 | `d2k_plantab_probe_count` | 1021 |  |
| 64 | `shape_fits` | 1045 | да |
| 65 | `shape_is_udp` | 1055 | да |
| 66 | `d2k_plantab_shape_misses` | 1059 |  |
| 67 | `d2k_plantab_find` | 1063 |  |
| 68 | `d2k_plantab_find_sport` | 1069 |  |
| 69 | `d2k_plantab_find_family` | 1075 |  |
| 70 | `d2k_plantab_find_target` | 1082 |  |
| 71 | `d2k_plantab_count` | 1239 |  |
| 72 | `d2k_plantab_capacity` | 1243 |  |
| 73 | `d2k_plantab_binding` | 1247 |  |
| 74 | `d2k_plantab_set_name_trial` | 1260 |  |
| 75 | `d2k_plantab_trial` | 1269 |  |

### raw.c — 17

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `if_mtu` | 65 | да |
| 2 | `pick_maxlen` | 93 | да |
| 3 | `route_mtu` | 141 | да |
| 4 | `say` | 182 | да |
| 5 | `d2k_raw_open` | 194 |  |
| 6 | `d2k_raw_close` | 259 |  |
| 7 | `d2k_raw_limits` | 272 |  |
| 8 | `d2k_raw_maxlen` | 276 |  |
| 9 | `d2k_raw_adopt_egress` | 282 |  |
| 10 | `blend` | 307 | да |
| 11 | `d2k_raw_route_maxlen` | 312 |  |
| 12 | `d2k_raw_route_maxlen_family` | 316 |  |
| 13 | `d2k_raw_prepare` | 342 |  |
| 14 | `d2k_raw_send` | 407 |  |
| 15 | `d2k_raw_sent` | 515 |  |
| 16 | `d2k_raw_errors` | 519 |  |
| 17 | `d2k_raw_busy` | 523 |  |

### routemark_nl.c — 8

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `parse_rules` | 19 | да |
| 2 | `dump` | 28 | да |
| 3 | `dump_rules` | 62 | да |
| 4 | `lookup_route` | 73 | да |
| 5 | `dump_socket` | 116 | да |
| 6 | `d2k_routemark_load` | 131 |  |
| 7 | `d2k_routemark_watch_open` | 180 |  |
| 8 | `d2k_routemark_watch_drain` | 212 |  |

### routemark.c — 23

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `rd16h` | 28 | да |
| 2 | `rd32h` | 29 | да |
| 3 | `wr16h` | 30 | да |
| 4 | `wr32h` | 31 | да |
| 5 | `d2k_routemark_init` | 33 |  |
| 6 | `d2k_routemark_request` | 37 |  |
| 7 | `nl_error` | 50 | да |
| 8 | `d2k_routemark_parse` | 54 |  |
| 9 | `d2k_routemark_lookup_request` | 104 |  |
| 10 | `add_oif` | 123 | да |
| 11 | `route_oifs` | 133 | да |
| 12 | `d2k_routemark_lookup_parse` | 155 |  |
| 13 | `d2k_routemark_watch_relevant` | 176 |  |
| 14 | `d2k_routemark_clear_oifs` | 193 |  |
| 15 | `d2k_routemark_set_oifs` | 202 |  |
| 16 | `d2k_routemark_set` | 216 |  |
| 17 | `d2k_routemark_merge` | 230 |  |
| 18 | `d2k_routemark_set_policy` | 270 |  |
| 19 | `policy_match` | 278 | да |
| 20 | `d2k_routemark_routed` | 283 |  |
| 21 | `d2k_routemark_client` | 299 |  |
| 22 | `d2k_routemark_gate` | 305 |  |
| 23 | `d2k_routemark_describe` | 328 |  |

### sched.c — 16

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `d2k_sched_new` | 44 |  |
| 2 | `d2k_sched_grow_slot_size` | 74 |  |
| 3 | `d2k_sched_free` | 91 |  |
| 4 | `earlier` | 103 | да |
| 5 | `sift_up` | 110 | да |
| 6 | `sift_down` | 123 | да |
| 7 | `d2k_sched_push` | 142 |  |
| 8 | `d2k_sched_push_serial` | 150 |  |
| 9 | `d2k_sched_push_owned` | 155 |  |
| 10 | `push` | 160 | да |
| 11 | `d2k_sched_pop_due` | 193 |  |
| 12 | `d2k_sched_pop_due_serial` | 199 |  |
| 13 | `d2k_sched_pop_due_ex` | 205 |  |
| 14 | `d2k_sched_next_ns` | 270 |  |
| 15 | `d2k_sched_count` | 274 |  |
| 16 | `d2k_sched_refusals` | 278 |  |

### session.c — 107

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `initial_dcid` | 203 | да |
| 2 | `init_ring_add` | 216 | да |
| 3 | `init_ring_drop` | 240 | да |
| 4 | `init_ring_pack` | 254 | да |
| 5 | `slot_of` | 289 | да |
| 6 | `shape_slot` | 290 | да |
| 7 | `next_fragment_id` | 294 | да |
| 8 | `d2k_session_new` | 307 |  |
| 9 | `d2k_session_free` | 347 |  |
| 10 | `d2k_session_set_plan` | 359 |  |
| 11 | `name_same` | 370 | да |
| 12 | `rd16` | 385 | да |
| 13 | `refuse_coded` | 403 | да |
| 14 | `refuse` | 416 | да |
| 15 | `tcp_options_timestamp_profile` | 423 | да |
| 16 | `tcp_options_have_timestamp` | 436 | да |
| 17 | `plan_handed_off` | 447 | да |
| 18 | `table_of` | 478 | да |
| 19 | `suspect_num` | 487 | да |
| 20 | `suspect` | 506 | да |
| 21 | `on_flow_expire` | 522 | да |
| 22 | `rd32` | 533 | да |
| 23 | `is_discord_ip_discovery` | 545 | да |
| 24 | `is_discord_ip_discovery_response` | 553 | да |
| 25 | `is_stun_binding` | 570 | да |
| 26 | `is_stun_request` | 581 | да |
| 27 | `is_stun_response_for` | 585 | да |
| 28 | `d2k_session_nat_stats` | 651 |  |
| 29 | `plan_fits_transport` | 673 | да |
| 30 | `flow_tracked` | 679 | да |
| 31 | `handle_udp` | 780 | да |
| 32 | `note_tcp_hello` | 1574 | да |
| 33 | `routed_flow` | 1594 | да |
| 34 | `session_packet` | 1629 | да |
| 35 | `d2k_session_packet` | 2604 |  |
| 36 | `d2k_session_packet_mtu` | 2609 |  |
| 37 | `d2k_session_packet_probe` | 2616 |  |
| 38 | `d2k_session_packet_probe_mtu` | 2622 |  |
| 39 | `d2k_session_observe_tcp` | 2629 |  |
| 40 | `d2k_session_plan_revision` | 2634 |  |
| 41 | `d2k_session_stream_anchor` | 2638 |  |
| 42 | `d2k_session_set_hook` | 2648 |  |
| 43 | `d2k_session_set_route_mark` | 2652 |  |
| 44 | `d2k_session_route_mark` | 2656 |  |
| 45 | `d2k_session_routed_flows` | 2660 |  |
| 46 | `d2k_session_set_udp_reverse_hook` | 2664 |  |
| 47 | `d2k_session_set_ct_query` | 2668 |  |
| 48 | `d2k_session_udp_hold_begin` | 2672 |  |
| 49 | `d2k_session_udp_opening` | 2714 |  |
| 50 | `d2k_session_udp_hold_end` | 2739 |  |
| 51 | `d2k_session_udp_hold_replay` | 2745 |  |
| 52 | `d2k_session_note_unassembled` | 2754 |  |
| 53 | `d2k_session_hold_candidate` | 2795 |  |
| 54 | `d2k_session_want_shape` | 2927 |  |
| 55 | `d2k_session_want_shape_family` | 2932 |  |
| 56 | `d2k_session_shape` | 2963 |  |
| 57 | `d2k_session_shape_family` | 2967 |  |
| 58 | `d2k_session_shape_tcp_options_family` | 2983 |  |
| 59 | `d2k_session_plans` | 2993 |  |
| 60 | `d2k_session_plan_count` | 2997 |  |
| 61 | `d2k_session_plan_capacity` | 3001 |  |
| 62 | `silence_deadline` | 3019 | да |
| 63 | `tcp_silence_observe` | 3035 | да |
| 64 | `fin_retry_window` | 3064 | да |
| 65 | `fin_window_over` | 3070 | да |
| 66 | `sweep_one` | 3085 | да |
| 67 | `sweep_udp_one` | 3113 | да |
| 68 | `quic_watch` | 3165 | да |
| 69 | `flow_tuple` | 3175 | да |
| 70 | `ct_flow` | 3198 | да |
| 71 | `tcp_watch` | 3258 | да |
| 72 | `tcp_in_band` | 3264 | да |
| 73 | `tcp_band_top` | 3272 | да |
| 74 | `ct_tcp_flow` | 3280 | да |
| 75 | `d2k_session_set_stall_budgets` | 3331 |  |
| 76 | `d2k_session_stall_budgets` | 3346 |  |
| 77 | `d2k_session_sweep` | 3354 |  |
| 78 | `d2k_session_expire` | 3373 |  |
| 79 | `d2k_session_flows` | 3398 |  |
| 80 | `d2k_session_send_pending` | 3402 |  |
| 81 | `d2k_session_sent` | 3408 |  |
| 82 | `d2k_session_exec_failed` | 3450 |  |
| 83 | `d2k_session_guards` | 3504 |  |
| 84 | `d2k_session_client_shape` | 3510 |  |
| 85 | `d2k_session_damaged` | 3516 |  |
| 86 | `d2k_session_unsent` | 3526 |  |
| 87 | `d2k_session_applied` | 3542 |  |
| 88 | `d2k_session_done` | 3546 |  |
| 89 | `d2k_session_damaged_count` | 3550 |  |
| 90 | `d2k_session_sent_lost` | 3554 |  |
| 91 | `d2k_session_refusals` | 3558 |  |
| 92 | `d2k_session_capacity` | 3562 |  |
| 93 | `d2k_session_flows_tcp` | 3566 |  |
| 94 | `d2k_session_flows_udp` | 3570 |  |
| 95 | `d2k_session_capacity_tcp` | 3574 |  |
| 96 | `d2k_session_capacity_udp` | 3578 |  |
| 97 | `d2k_session_refusals_tcp` | 3582 |  |
| 98 | `d2k_session_refusals_udp` | 3586 |  |
| 99 | `d2k_session_hellos` | 3590 |  |
| 100 | `d2k_session_with_sni` | 3594 |  |
| 101 | `d2k_session_suspects` | 3598 |  |
| 102 | `d2k_session_rst_dropped` | 3602 |  |
| 103 | `d2k_session_exchanges` | 3606 |  |
| 104 | `d2k_session_reply_hidden` | 3610 |  |
| 105 | `d2k_session_tcp_hello_flows` | 3614 |  |
| 106 | `d2k_session_payload_stats` | 3618 |  |
| 107 | `d2k_session_journal` | 3641 |  |

### tls.c — 7

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `rd16` | 31 | да |
| 2 | `skip_u8_vec` | 37 | да |
| 3 | `skip_u16_vec` | 49 | да |
| 4 | `has_ech_offer` | 73 | да |
| 5 | `has_tls13` | 106 | да |
| 6 | `find_sni` | 132 | да |
| 7 | `d2k_tls_parse` | 180 |  |

### track.c — 18

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `d2k_key_make` | 19 |  |
| 2 | `d2k_key_make_addr` | 56 |  |
| 3 | `round_pow2` | 85 | да |
| 4 | `key_eq` | 93 | да |
| 5 | `key_hash` | 109 | да |
| 6 | `d2k_track_new` | 118 |  |
| 7 | `d2k_track_free` | 136 |  |
| 8 | `d2k_track_find` | 145 |  |
| 9 | `remove_at` | 166 | да |
| 10 | `d2k_track_get` | 194 |  |
| 11 | `d2k_track_new_connection` | 232 |  |
| 12 | `d2k_track_remove` | 260 |  |
| 13 | `d2k_track_walk` | 270 |  |
| 14 | `d2k_track_expire` | 281 |  |
| 15 | `d2k_track_remove_if` | 311 |  |
| 16 | `d2k_track_count` | 328 |  |
| 17 | `d2k_track_capacity` | 332 |  |
| 18 | `d2k_track_refusals` | 336 |  |

### udp_hold.c — 10

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `same_key` | 15 | да |
| 2 | `clear_slot` | 19 | да |
| 3 | `release_slot` | 23 | да |
| 4 | `d2k_udp_hold_new` | 32 |  |
| 5 | `d2k_udp_hold_free` | 34 |  |
| 6 | `d2k_udp_hold_flush` | 42 |  |
| 7 | `d2k_udp_hold_feed` | 55 |  |
| 8 | `d2k_udp_hold_feed_marked` | 61 |  |
| 9 | `d2k_udp_hold_take` | 99 |  |
| 10 | `d2k_udp_hold_next_ns` | 116 |  |

### udp_path.c — 7

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `d2k_udp_path_release` | 7 |  |
| 2 | `d2k_udp_path_pre` | 16 |  |
| 3 | `d2k_udp_path_post` | 36 |  |
| 4 | `d2k_udp_path_read` | 63 |  |
| 5 | `d2k_udp_path_expire` | 70 |  |
| 6 | `d2k_udp_path_passed` | 77 |  |
| 7 | `d2k_udp_path_planned` | 91 |  |

### udp_release.c — 34

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `d2k_udp_release_new` | 30 |  |
| 2 | `d2k_udp_release_free` | 54 |  |
| 3 | `d2k_udp_release_enqueue` | 62 |  |
| 4 | `next_due` | 84 | да |
| 5 | `d2k_udp_release_flush` | 97 |  |
| 6 | `d2k_udp_release_next_ns` | 125 |  |
| 7 | `d2k_udp_replay_fates` | 136 |  |
| 8 | `plain_verdict` | 175 | да |
| 9 | `plain_resend` | 179 | да |
| 10 | `d2k_udp_release_batch` | 185 |  |
| 11 | `release_batch` | 195 | да |
| 12 | `follow_stale` | 273 | да |
| 13 | `follow_drop` | 278 | да |
| 14 | `d2k_udp_follow_age` | 283 |  |
| 15 | `d2k_udp_follow_live` | 290 |  |
| 16 | `d2k_udp_follow_busy` | 291 |  |
| 17 | `d2k_udp_follow_queue_full` | 292 |  |
| 18 | `d2k_udp_follow_refused` | 293 |  |
| 19 | `d2k_udp_send_busy` | 295 |  |
| 20 | `d2k_udp_follow_new` | 299 |  |
| 21 | `d2k_udp_follow_free` | 301 |  |
| 22 | `follow_tuple` | 303 | да |
| 23 | `same_tuple` | 322 | да |
| 24 | `d2k_udp_follow_mark` | 330 |  |
| 25 | `follow_put` | 335 | да |
| 26 | `follow_find` | 358 | да |
| 27 | `d2k_udp_follow_match` | 373 |  |
| 28 | `out_resend` | 389 | да |
| 29 | `d2k_udp_out_owned_emit` | 418 |  |
| 30 | `refused_flow` | 426 | да |
| 31 | `out_verdict` | 433 | да |
| 32 | `d2k_udp_out_neutral` | 438 |  |
| 33 | `d2k_udp_out_batch` | 443 |  |
| 34 | `d2k_udp_out_late` | 476 |  |

### wire_udp.c — 5

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `wr16` | 23 | да |
| 2 | `sum16` | 32 | да |
| 3 | `fold` | 43 | да |
| 4 | `pseudo_sum` | 58 | да |
| 5 | `d2k_wire_build_udp` | 68 |  |

### wire.c — 9

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `wr16` | 24 | да |
| 2 | `wr32` | 29 | да |
| 3 | `rd16` | 36 | да |
| 4 | `auto_ttl` | 55 | да |
| 5 | `sum16` | 74 | да |
| 6 | `fold` | 85 | да |
| 7 | `pseudo_sum` | 100 | да |
| 8 | `d2k_wire_build` | 110 |  |
| 9 | `d2k_wire_tcp_checksum_ok` | 280 |  |

## detect — 158 функций

### bridge.c — 17

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `d2k_detect_stop_all` | 46 |  |
| 2 | `stop_asked` | 51 | да |
| 3 | `plannable_hit` | 77 | да |
| 4 | `map_verdict` | 96 | да |
| 5 | `bridge_input` | 117 | да |
| 6 | `progress_seen` | 262 | да |
| 7 | `trace_questions` | 285 | да |
| 8 | `retry_base_timeout` | 315 | да |
| 9 | `sched_tcp` | 321 | да |
| 10 | `d2k_detect_sched_tcp` | 467 |  |
| 11 | `d2k_detect_sched_tcp_white` | 479 |  |
| 12 | `d2k_detect_sched_tcp_seeded` | 489 |  |
| 13 | `d2k_detect_sched_tcp_seeded_white` | 504 |  |
| 14 | `base_seen` | 532 | да |
| 15 | `base_stop` | 538 | да |
| 16 | `d2k_detect_sched_tcp_ack` | 549 |  |
| 17 | `d2k_detect_sched_tcp_base` | 576 |  |

### classify.c — 36

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `d2k_verdict_name` | 58 |  |
| 2 | `d2k_resp_name` | 75 |  |
| 3 | `d2k_now_ms` | 87 |  |
| 4 | `d2k_sleep_ms` | 97 |  |
| 5 | `d2k_trigger_accepts` | 110 |  |
| 6 | `d2k_trigger_sni` | 127 |  |
| 7 | `d2k_detect_stopped` | 137 |  |
| 8 | `d2k_opts_defaults` | 142 |  |
| 9 | `d2k_opts_acceptable` | 165 |  |
| 10 | `d2k_opts_skipped` | 173 |  |
| 11 | `d2k_trace_add` | 184 |  |
| 12 | `obs_done` | 211 | да |
| 13 | `d2k_note` | 218 |  |
| 14 | `note_gap_loss` | 239 | да |
| 15 | `d2k_split_offsets` | 254 |  |
| 16 | `dial_marked_mode` | 293 | да |
| 17 | `d2k_dial_deadline_err` | 369 |  |
| 18 | `dial_marked` | 377 | да |
| 19 | `once_probe` | 386 | да |
| 20 | `unacked_bytes` | 500 | да |
| 21 | `d2k_probe_data_ack` | 521 |  |
| 22 | `measure` | 609 | да |
| 23 | `bind_decoy` | 718 | да |
| 24 | `answered_by_props` | 733 | да |
| 25 | `fam_ix` | 767 | да |
| 26 | `self_ix` | 770 | да |
| 27 | `selftest_cached_age` | 775 | да |
| 28 | `selftest_store` | 792 | да |
| 29 | `d2k_raw_note_rc` | 802 |  |
| 30 | `raw_selftest` | 828 | да |
| 31 | `raw_doubted` | 861 | да |
| 32 | `raw_recheck` | 868 | да |
| 33 | `sweep_poisons` | 888 | да |
| 34 | `cross_check_tls12` | 1085 | да |
| 35 | `d2k_classify_run` | 1096 |  |
| 36 | `d2k_send_nosig` | 1482 |  |

### main.c — 8

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `usage` | 20 | да |
| 2 | `print_json_str` | 52 | да |
| 3 | `print_tri` | 68 | да |
| 4 | `print_json` | 76 | да |
| 5 | `print_progress` | 194 | да |
| 6 | `tri_word` | 202 | да |
| 7 | `print_human` | 208 | да |
| 8 | `main` | 278 |  |

### poison.c — 12

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `d2k_poison_supports_family` | 18 |  |
| 2 | `d2k_poison_has_fake` | 25 |  |
| 3 | `add` | 48 | да |
| 4 | `d2k_poison_same` | 63 |  |
| 5 | `already_listed` | 74 | да |
| 6 | `init_poisons` | 85 | да |
| 7 | `d2k_poisons` | 183 |  |
| 8 | `d2k_note_props_hit` | 195 |  |
| 9 | `d2k_note_props_miss` | 217 |  |
| 10 | `d2k_strategy_for_poison` | 227 |  |
| 11 | `d2k_strategy_for` | 402 |  |
| 12 | `d2k_arm_from_poison` | 414 |  |

### props.c — 7

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `prop_probes` | 50 | да |
| 2 | `apply_set` | 199 | да |
| 3 | `d2k_run_properties` | 262 |  |
| 4 | `d2k_run_properties_family` | 268 |  |
| 5 | `tri_no` | 419 | да |
| 6 | `tri_yes` | 420 | да |
| 7 | `d2k_compose_from_props` | 427 |  |

### raw.c — 62

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `parse_long_exact` | 64 | да |
| 2 | `d2k_parse_rst_rule` | 80 |  |
| 3 | `d2k_parse_stale_rst_rule` | 122 |  |
| 4 | `pid_alive` | 129 | да |
| 5 | `d2k_rst_rule_stale` | 138 |  |
| 6 | `d2k_raw_supported` | 165 |  |
| 7 | `raw_rule_system` | 225 | да |
| 8 | `d2k_raw_rst_fail_count` | 263 |  |
| 9 | `d2k_raw_dial_count` | 264 |  |
| 10 | `seed_init` | 266 | да |
| 11 | `seed_once` | 272 | да |
| 12 | `next_source_port` | 284 | да |
| 13 | `rst_nft` | 314 | да |
| 14 | `sweep_stale_rst_rules` | 320 | да |
| 15 | `rst_rule_cmd_form` | 383 | да |
| 16 | `rst_rule_cmd` | 403 | да |
| 17 | `rc_exit1` | 408 | да |
| 18 | `rst_delete_once` | 417 | да |
| 19 | `rst_abandon` | 425 | да |
| 20 | `register_atexit` | 438 | да |
| 21 | `rst_remember` | 441 | да |
| 22 | `retry_pending_releases` | 455 | да |
| 23 | `rst_release_locked` | 472 | да |
| 24 | `d2k_raw_flush_pending` | 482 |  |
| 25 | `d2k_raw_pending_count` | 489 |  |
| 26 | `raw_atexit` | 498 | да |
| 27 | `rst_key_of` | 507 | да |
| 28 | `suppress_kernel_rst` | 518 | да |
| 29 | `release_kernel_rst` | 548 | да |
| 30 | `local_addr_for` | 557 | да |
| 31 | `rd16` | 599 | да |
| 32 | `rd32` | 601 | да |
| 33 | `wr16` | 607 | да |
| 34 | `wr32` | 609 | да |
| 35 | `checksum` | 615 | да |
| 36 | `tcp_checksum` | 631 | да |
| 37 | `build_ipv4_tcp` | 653 | да |
| 38 | `tcp_checksum_family` | 739 | да |
| 39 | `build_ip_tcp` | 751 | да |
| 40 | `raw_sendto` | 774 | да |
| 41 | `d2k_raw_set_segment_max` | 815 |  |
| 42 | `raw_send` | 831 | да |
| 43 | `raw_send_syn` | 865 | да |
| 44 | `raw_recv` | 901 | да |
| 45 | `raw_read_payload` | 953 | да |
| 46 | `raw_close` | 991 | да |
| 47 | `raw_handshake` | 1009 | да |
| 48 | `raw_dial` | 1093 | да |
| 49 | `d2k_raw_probe_handshake_as` | 1188 |  |
| 50 | `raw_send_plan` | 1210 | да |
| 51 | `d2k_raw_probe_poison_family` | 1273 |  |
| 52 | `d2k_raw_supported` | 1329 |  |
| 53 | `d2k_raw_set_segment_max` | 1330 |  |
| 54 | `d2k_raw_rst_fail_count` | 1331 |  |
| 55 | `d2k_raw_dial_count` | 1332 |  |
| 56 | `d2k_raw_flush_pending` | 1333 |  |
| 57 | `d2k_raw_pending_count` | 1334 |  |
| 58 | `d2k_raw_probe_poison_family` | 1336 |  |
| 59 | `d2k_raw_probe_handshake_as` | 1346 |  |
| 60 | `d2k_raw_probe_handshake` | 1358 |  |
| 61 | `d2k_raw_probe_handshake_family` | 1365 |  |
| 62 | `d2k_raw_probe_poison` | 1373 |  |

### response.c — 7

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `resp_timeout` | 65 | да |
| 2 | `d2k_resp_scan12` | 84 |  |
| 3 | `d2k_resp_handshake12` | 124 |  |
| 4 | `count_handshakes` | 216 | да |
| 5 | `d2k_neutral_sni` | 234 |  |
| 6 | `d2k_resp_decide` | 275 |  |
| 7 | `d2k_probe_response` | 311 |  |

### trigger.c — 9

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `d2k_trigger_tls` | 22 |  |
| 2 | `hexval` | 53 | да |
| 3 | `d2k_trigger_raw_hex` | 68 |  |
| 4 | `d2k_trigger_control` | 119 |  |
| 5 | `d2k_opts_decoy` | 131 |  |
| 6 | `d2k_trigger_host_ts_override` | 157 |  |
| 7 | `host_offers_ts` | 159 | да |
| 8 | `d2k_trigger_offers_ts` | 181 |  |
| 9 | `d2k_trigger_allows_poison` | 202 |  |

## panel — 68 функций

### main.c — 18

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `on_signal` | 43 | да |
| 2 | `say` | 48 | да |
| 3 | `usage` | 56 | да |
| 4 | `trim` | 64 | да |
| 5 | `known_key` | 72 | да |
| 6 | `valid_mode` | 92 | да |
| 7 | `remember_unknown` | 97 | да |
| 8 | `copy_value` | 107 | да |
| 9 | `normalize_shell_value` | 115 | да |
| 10 | `config_unsigned` | 139 | да |
| 11 | `read_config` | 152 | да |
| 12 | `split_listen` | 212 | да |
| 13 | `listen_socket` | 236 | да |
| 14 | `is_loopback_addr` | 270 | да |
| 15 | `set_state_note` | 277 | да |
| 16 | `serve` | 288 | да |
| 17 | `offline_self_check` | 397 | да |
| 18 | `main` | 405 |  |

### server.c — 50

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `d2k_panel_control_tick` | 48 |  |
| 2 | `d2k_panel_ignore_sigpipe` | 59 |  |
| 3 | `json_ws` | 69 | да |
| 4 | `json_string` | 74 | да |
| 5 | `json_compound` | 97 | да |
| 6 | `json_number` | 121 | да |
| 7 | `json_value` | 145 | да |
| 8 | `json_valid_object` | 159 | да |
| 9 | `json_top_value` | 167 | да |
| 10 | `json_top_true` | 198 | да |
| 11 | `json_top_nonempty_string` | 205 | да |
| 12 | `pid_path_running` | 212 | да |
| 13 | `engine_pid_running` | 234 | да |
| 14 | `controller_pid_running` | 238 | да |
| 15 | `write_all` | 242 | да |
| 16 | `response_ex` | 262 | да |
| 17 | `response` | 288 | да |
| 18 | `header_value` | 293 | да |
| 19 | `d2k_panel_same_origin` | 317 |  |
| 20 | `run_service_action` | 330 | да |
| 21 | `telegram_config_flags` | 377 | да |
| 22 | `telegram_status_value` | 406 | да |
| 23 | `telegram_stats_number` | 421 | да |
| 24 | `telegram_stats_optional_number` | 435 | да |
| 25 | `telegram_stats_value` | 446 | да |
| 26 | `worker_domain_normalize` | 548 | да |
| 27 | `worker_domain_add` | 589 | да |
| 28 | `worker_line` | 602 | да |
| 29 | `worker_domains_from_config` | 615 | да |
| 30 | `worker_domains_from_json` | 671 | да |
| 31 | `worker_config_write` | 712 | да |
| 32 | `worker_request_body` | 785 | да |
| 33 | `api_telegram_workers` | 823 | да |
| 34 | `api_control` | 896 | да |
| 35 | `api_update` | 981 | да |
| 36 | `read_request` | 1009 | да |
| 37 | `json_object_file` | 1031 | да |
| 38 | `buf_add` | 1066 | да |
| 39 | `buf_puts` | 1073 | да |
| 40 | `buf_printf` | 1075 | да |
| 41 | `buf_json_string` | 1092 | да |
| 42 | `catalog_revision` | 1111 | да |
| 43 | `buf_live_knowledge` | 1130 | да |
| 44 | `append_stage` | 1156 | да |
| 45 | `append_snapshot` | 1166 | да |
| 46 | `api_status` | 1250 | да |
| 47 | `static_file` | 1315 | да |
| 48 | `diagnostic_response` | 1362 | да |
| 49 | `api_diagnostics` | 1365 | да |
| 50 | `d2k_panel_handle_fd` | 1398 |  |

## relay-enroll — 45 функций

### main.c — 45

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `rate_allow` | 113 | да |
| 2 | `shared_limits_create` | 124 | да |
| 3 | `dead` | 132 |  |
| 4 | `shared_unlock` | 149 | да |
| 5 | `limits_lock` | 152 | да |
| 6 | `limits_unlock` | 153 | да |
| 7 | `conn_admit` | 157 | да |
| 8 | `conn_set_pid` | 171 | да |
| 9 | `conn_release_slot` | 175 | да |
| 10 | `conn_release_pid` | 180 | да |
| 11 | `conn_route` | 188 | да |
| 12 | `route_status` | 201 | да |
| 13 | `valid_proof` | 211 | да |
| 14 | `parse_headers` | 222 | да |
| 15 | `system_resolve` | 259 | да |
| 16 | `monotonic_ms` | 271 | да |
| 17 | `monotonic_seconds` | 276 | да |
| 18 | `clock_now` | 277 | да |
| 19 | `dns_build_query` | 281 | да |
| 20 | `dns16` | 294 | да |
| 21 | `dns_read_name` | 298 | да |
| 22 | `dns_parse_reply` | 322 | да |
| 23 | `udp_open` | 374 | да |
| 24 | `udp_send` | 386 | да |
| 25 | `udp_recv` | 390 | да |
| 26 | `udp_close` | 403 | да |
| 27 | `addr_add` | 410 | да |
| 28 | `answer_cache_create` | 417 | да |
| 29 | `cache_get` | 422 | да |
| 30 | `cache_put` | 431 | да |
| 31 | `public_phase` | 440 | да |
| 32 | `json_space` | 475 | да |
| 33 | `json_char` | 478 | да |
| 34 | `json_name` | 482 | да |
| 35 | `allowed_host` | 493 | да |
| 36 | `handle_resolve` | 503 | да |
| 37 | `socket_write_all` | 555 | да |
| 38 | `forward_registration` | 561 | да |
| 39 | `ssl_write_all` | 588 | да |
| 40 | `reply_json` | 593 | да |
| 41 | `reply` | 601 | да |
| 42 | `serve_client` | 612 | да |
| 43 | `stop_server` | 659 | да |
| 44 | `child_exited` | 660 | да |
| 45 | `main` | 662 |  |

## relay-gate — 18 функций

### main.c — 18

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `host_allowed` | 94 | да |
| 2 | `host_syntax_ok` | 107 | да |
| 3 | `parse_port` | 117 | да |
| 4 | `split_hostport` | 130 | да |
| 5 | `parse_head` | 144 | да |
| 6 | `request_allowed` | 188 | да |
| 7 | `header_is` | 195 | да |
| 8 | `build_origin_request` | 203 | да |
| 9 | `v4_public` | 239 | да |
| 10 | `addr_public` | 249 | да |
| 11 | `rate_allow` | 279 | да |
| 12 | `write_all` | 301 | да |
| 13 | `reply` | 310 | да |
| 14 | `connect_timeout` | 316 | да |
| 15 | `dial` | 334 | да |
| 16 | `relay` | 348 | да |
| 17 | `serve` | 376 | да |
| 18 | `main` | 442 |  |

## src — 460 функций

### cf_domains.c — 19

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `normalize_domain` | 30 | да |
| 2 | `add_unique` | 60 | да |
| 3 | `decode_domain` | 71 | да |
| 4 | `tg_cf_domain_pool_parse_remote` | 98 |  |
| 5 | `merge_domains` | 131 | да |
| 6 | `parse_timestamp` | 142 | да |
| 7 | `load_cache` | 156 | да |
| 8 | `write_all` | 202 | да |
| 9 | `create_parent_directories` | 213 | да |
| 10 | `write_cache` | 233 | да |
| 11 | `load_fallback` | 271 | да |
| 12 | `tg_cf_domain_pool_init` | 283 |  |
| 13 | `tg_cf_domain_pool_install_remote` | 312 |  |
| 14 | `tg_cf_domain_pool_count` | 340 |  |
| 15 | `tg_cf_domain_pool_copy_at` | 349 |  |
| 16 | `tg_cf_domain_pool_fetched_at` | 363 |  |
| 17 | `tg_cf_domain_pool_refresh_due` | 372 |  |
| 18 | `tg_cf_domain_pool_refresh` | 384 |  |
| 19 | `tg_cf_domain_pool_destroy` | 424 |  |

### config.c — 9

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `trim` | 13 | да |
| 2 | `copy_value` | 19 | да |
| 3 | `normalize_domain` | 23 | да |
| 4 | `parse_domain_list` | 64 | да |
| 5 | `parse_boolean` | 92 | да |
| 6 | `parse_bounded_uint` | 99 | да |
| 7 | `normalize_shell_value` | 111 | да |
| 8 | `tg_config_read` | 124 |  |
| 9 | `tg_config_clean` | 228 |  |

### dc_map_json.c — 16

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `appendf` | 21 | да |
| 2 | `skip_space` | 64 | да |
| 3 | `take` | 71 | да |
| 4 | `hex_value` | 78 | да |
| 5 | `read_string` | 85 | да |
| 6 | `read_integer` | 123 | да |
| 7 | `read_u32` | 154 | да |
| 8 | `read_port` | 163 | да |
| 9 | `read_bool` | 170 | да |
| 10 | `read_nullable_secret` | 187 | да |
| 11 | `read_endpoint` | 210 | да |
| 12 | `read_endpoints` | 257 | да |
| 13 | `tg_dc_snapshot_parse_json` | 281 |  |
| 14 | `tg_dc_snapshot_destroy` | 328 |  |
| 15 | `bool_text` | 334 | да |
| 16 | `tg_dc_snapshot_encode_json` | 338 |  |

### dc_map_store.c — 27

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `copy_snapshot` | 30 | да |
| 2 | `same_address_port` | 40 | да |
| 3 | `same_address` | 47 | да |
| 4 | `same_route` | 54 | да |
| 5 | `same_identity` | 61 | да |
| 6 | `replaced_by_incoming` | 71 | да |
| 7 | `endpoint_order` | 84 | да |
| 8 | `append_builtin_endpoints` | 99 | да |
| 9 | `merge_snapshot` | 125 | да |
| 10 | `read_snapshot_file` | 161 | да |
| 11 | `make_parent_dirs` | 191 | да |
| 12 | `write_all` | 213 | да |
| 13 | `atomic_write` | 224 | да |
| 14 | `save_snapshot` | 254 | да |
| 15 | `tg_dc_map_store_init` | 264 |  |
| 16 | `tg_dc_map_store_destroy` | 271 |  |
| 17 | `tg_dc_map_store_load` | 277 |  |
| 18 | `tg_dc_map_store_current` | 300 |  |
| 19 | `tg_dc_map_store_refresh_due` | 304 |  |
| 20 | `tg_dc_map_store_install` | 313 |  |
| 21 | `snapshot_is_fresh` | 339 | да |
| 22 | `tg_dc_map_store_resolve` | 344 |  |
| 23 | `destination_equals` | 354 | да |
| 24 | `tg_dc_handshake_secrets` | 369 |  |
| 25 | `pair_order` | 404 | да |
| 26 | `port_is_allowed` | 414 | да |
| 27 | `tg_dc_write_endpoint_manifest` | 421 |  |

### dc_map.c — 13

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `tg_dc_builtin_endpoint_count` | 43 |  |
| 2 | `tg_dc_builtin_endpoint_at` | 47 |  |
| 3 | `ipv4_non_global` | 62 | да |
| 4 | `ipv6_v4_mapped` | 74 | да |
| 5 | `public_address` | 79 | да |
| 6 | `not_future` | 92 | да |
| 7 | `tg_dc_snapshot_validate` | 97 |  |
| 8 | `normalized_destination` | 129 | да |
| 9 | `endpoint_matches` | 141 | да |
| 10 | `resolve_official` | 148 | да |
| 11 | `resolve_builtin` | 183 | да |
| 12 | `tg_dc_resolve` | 207 |  |
| 13 | `tg_dc_lookup_result_text` | 232 |  |

### enroll.c — 1

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `tg_enroll_proof` | 6 |  |

### epoll_proxy.c — 101

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `monotonic_ms` | 214 | да |
| 2 | `monotonic_us` | 220 | да |
| 3 | `record_client_response_latency` | 227 | да |
| 4 | `add_bytes` | 244 | да |
| 5 | `add_u64` | 249 | да |
| 6 | `route_session_owner` | 254 | да |
| 7 | `route_session_add_bytes` | 259 | да |
| 8 | `route_session_transport_for` | 269 | да |
| 9 | `route_session_append` | 284 | да |
| 10 | `route_session_event` | 301 | да |
| 11 | `route_session_selected` | 322 | да |
| 12 | `route_session_first_response` | 346 | да |
| 13 | `read_le32` | 360 | да |
| 14 | `read_le64` | 365 | да |
| 15 | `set_nonblocking` | 370 | да |
| 16 | `set_tcp_nodelay` | 375 | да |
| 17 | `set_tcp_quickack` | 380 | да |
| 18 | `default_original_destination` | 389 | да |
| 19 | `queue_append_grow` | 395 | да |
| 20 | `queue_prepend` | 434 | да |
| 21 | `queue_release` | 465 | да |
| 22 | `queue_flush` | 478 | да |
| 23 | `client_events` | 500 | да |
| 24 | `upstream_events` | 519 | да |
| 25 | `watch_update` | 539 | да |
| 26 | `watch_remove` | 558 | да |
| 27 | `connection_close` | 565 | да |
| 28 | `collect_retired` | 595 | да |
| 29 | `route_health_key_matches` | 609 | да |
| 30 | `route_health_in_use` | 630 | да |
| 31 | `route_health_get` | 643 | да |
| 32 | `route_failure_record` | 674 | да |
| 33 | `route_health_cooldown_at` | 689 | да |
| 34 | `route_health_failed_at` | 705 | да |
| 35 | `route_health_failed` | 717 | да |
| 36 | `route_health_preferred_step` | 742 | да |
| 37 | `route_plan_prioritize` | 811 | да |
| 38 | `route_plan_prioritize_kind` | 826 | да |
| 39 | `target_sockaddr` | 839 | да |
| 40 | `ipv4_public` | 863 | да |
| 41 | `public_route_target` | 877 | да |
| 42 | `resolve_route_domain` | 901 | да |
| 43 | `route_worker_count` | 912 | да |
| 44 | `route_worker_domain` | 917 | да |
| 45 | `route_cf_domain_count` | 924 | да |
| 46 | `route_cf_domain` | 931 | да |
| 47 | `set_direct_hostname` | 944 | да |
| 48 | `set_worker_path` | 955 | да |
| 49 | `prepare_wss_tls` | 966 | да |
| 50 | `begin_upstream` | 980 | да |
| 51 | `clear_wss_state` | 1040 | да |
| 52 | `clear_route_attempt` | 1068 | да |
| 53 | `hedge_retire_candidate` | 1108 | да |
| 54 | `hedge_cancel_candidates` | 1122 | да |
| 55 | `setup_route_attempt` | 1133 | да |
| 56 | `start_next_route` | 1186 | да |
| 57 | `advance_route` | 1315 | да |
| 58 | `hedge_candidate_count` | 1324 | да |
| 59 | `hedge_connection_count` | 1329 | да |
| 60 | `hedge_launch_next` | 1337 | да |
| 61 | `hedge_fill` | 1439 | да |
| 62 | `hedge_fail_candidate` | 1467 | да |
| 63 | `connection_update` | 1474 | да |
| 64 | `hedge_promote_candidate` | 1493 | да |
| 65 | `advance_half_closes` | 1590 | да |
| 66 | `route_after_handshake` | 1622 | да |
| 67 | `receive_client` | 1718 | да |
| 68 | `receive_upstream` | 1806 | да |
| 69 | `socket_error` | 1835 | да |
| 70 | `queue_wss_packet` | 1842 | да |
| 71 | `process_client_payload` | 1849 | да |
| 72 | `clear_wss_replay` | 1870 | да |
| 73 | `disable_wss_replay_after_payload_write` | 1875 | да |
| 74 | `queue_wss_replay_payload` | 1885 | да |
| 75 | `flush_wss_replay` | 1904 | да |
| 76 | `hedge_candidate_flush_buffered_payload` | 1924 | да |
| 77 | `response_packet_valid` | 1943 | да |
| 78 | `observe_mtproto_response` | 1972 | да |
| 79 | `queue_wss_response` | 2090 | да |
| 80 | `establish_wss_stream` | 2140 | да |
| 81 | `set_tls_want` | 2181 | да |
| 82 | `progress_wss` | 2194 | да |
| 83 | `handle_pending_dns_client_event` | 2323 | да |
| 84 | `client_event` | 2349 | да |
| 85 | `upstream_event` | 2381 | да |
| 86 | `accept_clients` | 2520 | да |
| 87 | `wss_waiting_for_first_response` | 2581 | да |
| 88 | `timeout_until_expiry` | 2586 | да |
| 89 | `expire_connections` | 2630 | да |
| 90 | `tg_epoll_proxy_create` | 2725 |  |
| 91 | `tg_epoll_proxy_step` | 2812 |  |
| 92 | `tg_epoll_proxy_destroy` | 2839 |  |
| 93 | `tg_epoll_proxy_active_connections` | 2848 |  |
| 94 | `tg_epoll_proxy_max_connections` | 2852 |  |
| 95 | `tg_epoll_proxy_get_stats` | 2856 |  |
| 96 | `tg_epoll_proxy_create` | 2975 |  |
| 97 | `tg_epoll_proxy_step` | 2980 |  |
| 98 | `tg_epoll_proxy_destroy` | 2986 |  |
| 99 | `tg_epoll_proxy_active_connections` | 2987 |  |
| 100 | `tg_epoll_proxy_max_connections` | 2991 |  |
| 101 | `tg_epoll_proxy_get_stats` | 2995 |  |

### identity.c — 12

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `read_all` | 19 | да |
| 2 | `write_all` | 30 | да |
| 3 | `set_hex_id` | 41 | да |
| 4 | `save_identity` | 49 | да |
| 5 | `identity_error` | 78 | да |
| 6 | `load_identity` | 87 | да |
| 7 | `tg_identity_load_or_mint` | 122 |  |
| 8 | `tg_identity_cleanup` | 155 |  |
| 9 | `tg_identity_public_key` | 161 |  |
| 10 | `tg_identity_sign` | 169 |  |
| 11 | `tg_identity_verify` | 184 |  |
| 12 | `tg_register_hmac_hex` | 199 |  |

### limits.c — 3

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `tg_limits_soft_nofile` | 14 |  |
| 2 | `tg_limits_auto_max_connections` | 22 |  |
| 3 | `tg_limits_runtime_memory_budget` | 42 |  |

### listener.c — 8

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `tg_listener_decode_original_dst` | 10 |  |
| 2 | `tg_listener_is_self_dial` | 19 |  |
| 3 | `tg_listener_get_original_dst` | 28 |  |
| 4 | `tg_listener_decode_original_dst_any` | 39 |  |
| 5 | `original_dst_option` | 69 | да |
| 6 | `tg_listener_get_original_dst_any` | 79 |  |
| 7 | `ipv4_non_global` | 106 | да |
| 8 | `tg_listener_is_self_dial_addr` | 118 |  |

### main.c — 29

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `memory_bytes_from_sysinfo` | 55 | да |
| 2 | `proxy_memory_budget` | 63 | да |
| 3 | `on_signal` | 80 | да |
| 4 | `log_msg` | 82 | да |
| 5 | `write_status` | 88 | да |
| 6 | `create_local_listener` | 97 | да |
| 7 | `monotonic_ms` | 168 | да |
| 8 | `discovery_cancelled` | 174 | да |
| 9 | `discover_wss_host` | 181 | да |
| 10 | `refresh_local_dc_map` | 230 | да |
| 11 | `dc_refresh_worker` | 296 | да |
| 12 | `start_dc_refresh` | 305 | да |
| 13 | `finish_dc_refresh` | 325 | да |
| 14 | `stop_dc_refresh` | 338 | да |
| 15 | `run_local_daemon` | 346 | да |
| 16 | `check_config` | 501 | да |
| 17 | `redirect_log` | 510 | да |
| 18 | `meta_verify_name` | 537 | да |
| 19 | `check_instagram_ip` | 547 | да |
| 20 | `offline_self_check` | 560 | да |
| 21 | `parse_unsigned_arg` | 564 | да |
| 22 | `check_telegram_dc` | 577 | да |
| 23 | `telegram_probe_stage_name` | 613 | да |
| 24 | `telegram_probe_error_name` | 625 | да |
| 25 | `check_telegram_wss_matrix` | 642 | да |
| 26 | `discover_telegram_dc` | 672 | да |
| 27 | `check_telegram_dc_matrix` | 714 | да |
| 28 | `discover_telegram_dc_matrix` | 723 | да |
| 29 | `main` | 732 |  |

### memory_budget.c — 2

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `tg_memory_budget_reserve` | 6 |  |
| 2 | `tg_memory_budget_release` | 17 |  |

### mtproto_auth.c — 27

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `read_le32` | 41 | да |
| 2 | `read_le64` | 46 | да |
| 3 | `write_bytes` | 51 | да |
| 4 | `write_u32` | 60 | да |
| 5 | `write_u64` | 67 | да |
| 6 | `write_tl_bytes` | 74 | да |
| 7 | `read_tl_bytes` | 98 | да |
| 8 | `read_fixed` | 129 | да |
| 9 | `read_tl_u32` | 138 | да |
| 10 | `sha1_pair` | 147 | да |
| 11 | `sha1_triple` | 160 | да |
| 12 | `parse_res_pq` | 175 | да |
| 13 | `add_mod` | 201 | да |
| 14 | `mul_mod` | 205 | да |
| 15 | `gcd_u64` | 216 | да |
| 16 | `pow_mod` | 225 | да |
| 17 | `is_prime_u64` | 236 | да |
| 18 | `rho_next` | 272 | да |
| 19 | `factorize_pq` | 276 | да |
| 20 | `u64_to_be_min` | 306 | да |
| 21 | `sha256_pair` | 318 | да |
| 22 | `rsa_modulus` | 331 | да |
| 23 | `rsa_encrypt_hashed` | 339 | да |
| 24 | `tg_mtproto_auth_step2` | 398 |  |
| 25 | `tg_mtproto_auth_step3` | 467 |  |
| 26 | `tg_mtproto_auth_step4` | 666 |  |
| 27 | `tg_mtproto_auth_clear` | 718 |  |

### mtproto_config.c — 11

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `load_le32` | 25 | да |
| 2 | `read_u32` | 30 | да |
| 3 | `read_bytes` | 39 | да |
| 4 | `skip_bytes` | 72 | да |
| 5 | `skip_string` | 78 | да |
| 6 | `skip_ints` | 82 | да |
| 7 | `parse_reaction` | 90 | да |
| 8 | `parse_dc_option` | 101 | да |
| 9 | `parse_uncompressed_config` | 150 | да |
| 10 | `inflate_config_gzip` | 219 | да |
| 11 | `tg_mtproto_config_parse` | 251 |  |

### mtproto_crypto.c — 12

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `proto_from_bytes` | 10 | да |
| 2 | `reserved_handshake_prefix` | 25 | да |
| 3 | `tg_mtproto_ctr_init` | 39 |  |
| 4 | `tg_mtproto_ctr_xor` | 51 |  |
| 5 | `tg_mtproto_ctr_destroy` | 65 |  |
| 6 | `tg_mtproto_direct_stream_ciphers` | 71 |  |
| 7 | `tg_mtproto_direct_server_stream_cipher` | 94 |  |
| 8 | `tg_mtproto_aes_ige` | 106 |  |
| 9 | `parse_with_key` | 160 | да |
| 10 | `tg_mtproto_parse_obfuscated2` | 188 |  |
| 11 | `tg_mtproto_parse_secret` | 194 |  |
| 12 | `tg_mtproto_make_obfuscated2_init` | 216 |  |

### mtproto_encrypted.c — 4

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `digest_parts` | 8 | да |
| 2 | `derive_v2_key_iv` | 25 | да |
| 3 | `tg_mtproto_v2_encrypt` | 49 |  |
| 4 | `tg_mtproto_v2_decrypt` | 96 |  |

### mtproto_probe.c — 39

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `monotonic_ms` | 41 | да |
| 2 | `wait_fd` | 47 | да |
| 3 | `transfer_all` | 74 | да |
| 4 | `collect_discovery_wss_bytes` | 107 | да |
| 5 | `discovery_wss_pump` | 139 | да |
| 6 | `discovery_transfer_all` | 181 | да |
| 7 | `read_le32` | 211 | да |
| 8 | `write_le32` | 216 | да |
| 9 | `read_le64` | 220 | да |
| 10 | `write_le64` | 225 | да |
| 11 | `make_message_id` | 229 | да |
| 12 | `read_tl_bytes` | 250 | да |
| 13 | `parse_res_pq` | 278 | да |
| 14 | `parse_plain_response` | 310 | да |
| 15 | `set_probe_socket_mark` | 327 | да |
| 16 | `make_address` | 338 | да |
| 17 | `connect_numeric_until` | 359 | да |
| 18 | `tg_mtproto_probe_res_pq` | 396 |  |
| 19 | `connect_hostname` | 526 | да |
| 20 | `ssl_wait` | 586 | да |
| 21 | `ssl_handshake_until` | 602 | да |
| 22 | `ssl_transfer_until` | 612 | да |
| 23 | `wss_upgrade_until` | 635 | да |
| 24 | `collect_wss_probe_response` | 672 | да |
| 25 | `wss_wait_for_res_pq` | 719 | да |
| 26 | `tg_mtproto_probe_res_pq_wss` | 758 |  |
| 27 | `discovery_write` | 886 | да |
| 28 | `discovery_write_u32` | 896 | да |
| 29 | `discovery_write_u64` | 902 | да |
| 30 | `discovery_write_tl_bytes` | 908 | да |
| 31 | `discovery_write_string` | 932 | да |
| 32 | `send_frame` | 939 | да |
| 33 | `read_frame` | 964 | да |
| 34 | `exchange_plain` | 996 | да |
| 35 | `build_config_query` | 1033 | да |
| 36 | `tg_mtproto_parse_rpc_result` | 1050 |  |
| 37 | `discover_config_common` | 1106 | да |
| 38 | `tg_mtproto_discover_config` | 1257 |  |
| 39 | `tg_mtproto_discover_config_wss` | 1277 |  |

### mtproto_splitter.c — 12

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `grow_packet` | 10 | да |
| 2 | `append_encrypted` | 37 | да |
| 3 | `required_header` | 49 | да |
| 4 | `parse_total_length` | 57 | да |
| 5 | `tg_mtproto_splitter_init` | 89 |  |
| 6 | `tg_mtproto_splitter_init_accounted` | 94 |  |
| 7 | `tg_mtproto_splitter_destroy` | 106 |  |
| 8 | `emit_packet` | 113 | да |
| 9 | `tg_mtproto_splitter_feed` | 130 |  |
| 10 | `tg_mtproto_splitter_flush` | 214 |  |
| 11 | `tg_mtproto_splitter_error` | 226 |  |
| 12 | `tg_mtproto_split_result_text` | 230 |  |

### net.c — 2

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `tg_nip_host_to_ipv4` | 17 |  |
| 2 | `tg_tcp_connect_ipv4` | 44 |  |

### route_dns.c — 49

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `tg_route_dns_test_doh_endpoint_count` | 71 |  |
| 2 | `tg_route_dns_test_doh_endpoint` | 75 |  |
| 3 | `monotonic_ms` | 88 | да |
| 4 | `ipv4_public` | 94 | да |
| 5 | `public_target` | 108 | да |
| 6 | `system_dns_error_is_negative` | 136 | да |
| 7 | `system_lookup` | 144 | да |
| 8 | `dns_skip_name` | 189 | да |
| 9 | `tg_route_dns_parse_response` | 218 |  |
| 10 | `wait_socket` | 272 | да |
| 11 | `set_route_socket_mark` | 285 | да |
| 12 | `https_connect` | 296 | да |
| 13 | `dns_encode_question` | 387 | да |
| 14 | `ssl_write_all` | 425 | да |
| 15 | `ssl_read_exact` | 444 | да |
| 16 | `h2_write_frame` | 466 | да |
| 17 | `h2_read_frame` | 483 | да |
| 18 | `hpack_encode_integer` | 502 | да |
| 19 | `hpack_encode_string` | 524 | да |
| 20 | `hpack_encode_header` | 534 | да |
| 21 | `h2_encode_doh_headers` | 542 | да |
| 22 | `tg_route_dns_test_h2_encode_headers` | 569 |  |
| 23 | `hpack_read_integer` | 577 | да |
| 24 | `hpack_skip_string` | 603 | да |
| 25 | `h2_response_is_ok` | 617 | да |
| 26 | `tg_route_dns_test_h2_response_is_ok` | 664 |  |
| 27 | `h2_response_body` | 670 | да |
| 28 | `tg_route_dns_https2_request` | 753 | да |
| 29 | `http_response_has_explicit_framing` | 791 | да |
| 30 | `ssl_read_response` | 820 | да |
| 31 | `decode_chunked_body` | 849 | да |
| 32 | `tg_route_dns_parse_http_response` | 894 |  |
| 33 | `contains_http_control` | 950 | да |
| 34 | `tg_route_dns_https_request` | 957 |  |
| 35 | `doh_query_endpoint` | 1005 | да |
| 36 | `doh_lookup` | 1033 | да |
| 37 | `system_then_doh_lookup` | 1064 | да |
| 38 | `tg_route_dns_lookup_now` | 1075 |  |
| 39 | `find_entry` | 1083 | да |
| 40 | `get_entry` | 1090 | да |
| 41 | `enqueue` | 1113 | да |
| 42 | `resolver_worker` | 1126 | да |
| 43 | `tg_route_dns_create` | 1188 |  |
| 44 | `tg_route_dns_destroy` | 1218 |  |
| 45 | `valid_domain` | 1230 | да |
| 46 | `tg_route_dns_prefetch` | 1254 |  |
| 47 | `tg_route_dns_prefetch_cf_pool` | 1264 |  |
| 48 | `tg_route_dns_resolve_status` | 1286 |  |
| 49 | `tg_route_dns_resolve` | 1313 |  |

### route_plan.c — 6

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `tg_route_websocket_dc` | 7 |  |
| 2 | `tg_route_cf_proxy_hostname` | 11 |  |
| 3 | `append_step` | 23 | да |
| 4 | `append_direct` | 32 | да |
| 5 | `append_cloudflare` | 40 | да |
| 6 | `tg_route_plan_build` | 55 |  |

### stats_socket.c — 10

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `route_stage_name` | 17 | да |
| 2 | `route_state_name` | 27 | да |
| 3 | `route_transport_name` | 35 | да |
| 4 | `stats_append` | 46 | да |
| 5 | `append_active_sessions` | 58 | да |
| 6 | `set_socket_flags` | 131 | да |
| 7 | `remove_stale_socket` | 141 | да |
| 8 | `tg_stats_socket_open` | 170 |  |
| 9 | `tg_stats_socket_serve` | 234 |  |
| 10 | `tg_stats_socket_close` | 323 |  |

### tls.c — 4

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `tg_tls_client_context` | 9 |  |
| 2 | `tg_tls_connect_fd` | 24 |  |
| 3 | `tg_tls_prepare_client_fd` | 28 |  |
| 4 | `tg_tls_connect_fd_sni` | 55 |  |

### transparent.c — 6

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `prefix_matches` | 15 | да |
| 2 | `cidr_matches` | 26 | да |
| 3 | `destination_allowed` | 51 | да |
| 4 | `parse_client_handshake` | 69 | да |
| 5 | `tg_transparent_select_route` | 102 |  |
| 6 | `tg_transparent_select_target` | 137 |  |

### ws_pump.c — 20

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `release_frames` | 16 | да |
| 2 | `tg_ws_pump_init` | 25 |  |
| 3 | `tg_ws_pump_init_accounted` | 29 |  |
| 4 | `reserve_rx` | 50 | да |
| 5 | `trim_idle_buffers` | 68 | да |
| 6 | `tg_ws_pump_destroy` | 98 |  |
| 7 | `queue_opcode` | 105 | да |
| 8 | `tg_ws_pump_queue_binary` | 129 |  |
| 9 | `tg_ws_pump_queue_mtproto_payload` | 130 |  |
| 10 | `tg_ws_pump_queue_ping` | 132 |  |
| 11 | `tg_ws_pump_queue_close` | 133 |  |
| 12 | `tg_ws_pump_fd` | 134 |  |
| 13 | `tg_ws_pump_events` | 135 |  |
| 14 | `append_fragment` | 142 | да |
| 15 | `tg_ws_reassembly_destroy` | 171 |  |
| 16 | `valid_utf8` | 178 | да |
| 17 | `tg_ws_reassembly_feed` | 204 |  |
| 18 | `dispatch_frames` | 294 | да |
| 19 | `flush_tx` | 314 | да |
| 20 | `tg_ws_pump_process` | 330 |  |

### ws.c — 18

| # | Функция | Строка | static |
|---:|---|---:|---|
| 1 | `valid_opcode` | 12 | да |
| 2 | `tg_ws_encode_client_frame` | 17 |  |
| 3 | `tg_ws_decode_server_frame` | 48 |  |
| 4 | `ssl_read_all` | 83 | да |
| 5 | `ssl_write_all` | 93 | да |
| 6 | `header_has_token` | 103 | да |
| 7 | `get_header` | 117 | да |
| 8 | `has_http_control` | 138 | да |
| 9 | `tg_ws_upgrade_start_ex` | 145 |  |
| 10 | `tg_ws_upgrade_start` | 208 |  |
| 11 | `tg_ws_upgrade_pending` | 213 |  |
| 12 | `tg_ws_upgrade_advance` | 225 |  |
| 13 | `validate_upgrade_response` | 234 | да |
| 14 | `tg_ws_upgrade_feed` | 266 |  |
| 15 | `tg_ws_upgrade` | 301 |  |
| 16 | `write_frame` | 320 | да |
| 17 | `tg_ws_write_binary` | 330 |  |
| 18 | `tg_ws_read_binary` | 335 |  |

**Всего: 2523 функций.**

