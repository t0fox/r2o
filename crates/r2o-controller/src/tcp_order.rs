use crate::catalog::{Binding, Catalog};
use crate::discovery::DiscoveryTarget;
use r2k_core::control::{self, SHAPE_LEGACY, SHAPE_MODERN};
use r2k_core::plan::{Plan, TCP_ORDER_EXEC, TCP_ORDER_MAX_PARTS};
use std::fmt::Write;
use std::net::SocketAddr;

pub fn valid_shape(shape: u8) -> bool {
    control::is_tcp_context_shape(shape)
        && matches!(
            control::r2k_link_shape_tcp_base(shape),
            SHAPE_LEGACY | SHAPE_MODERN
        )
}

pub struct Experiment<'a> {
    target: &'a DiscoveryTarget,
    hello: &'a [u8],
    sni: std::ops::Range<usize>,
    cuts: Vec<usize>,
    segment: usize,
    pace: u32,
}

impl<'a> Experiment<'a> {
    pub fn from_measured(
        target: &'a DiscoveryTarget,
        hello: &'a [u8],
        measured: &str,
        send_cap: usize,
    ) -> Option<Self> {
        let tls = r2k_core::tls::parse(hello);
        let sni = r2k_core::tls::complete_sni(hello)?;
        let endpoint = target.endpoint.parse::<SocketAddr>().ok()?;
        if !matches!(
            control::r2k_link_shape_tcp_base(target.shape),
            SHAPE_LEGACY | SHAPE_MODERN
        ) || tls.ech_offer
            || tls.is_tls13 != (control::r2k_link_shape_tcp_base(target.shape) == SHAPE_MODERN)
            || !hello[sni.clone()].eq_ignore_ascii_case(target.host.as_bytes())
            || endpoint.is_ipv4() != (target.family == 4)
            || hello.len() > 16_384
        {
            return None;
        }
        let base = Plan::parse(&crate::plan_text::compile_text(measured).ok()?).ok()?;
        if base.transport != 6
            || base.proto != 1
            || base.splits.is_empty()
            || base.tcp_order.is_some()
            || !base.fakes.is_empty()
            || !base.seq_overlays.is_empty()
            || base.oob_enabled
            || base.settle_us != 0
            || base.delay_us != 0
            || base.input_tcp_flags.is_some()
        {
            return None;
        }
        let mut cuts = Vec::with_capacity(base.splits.len() + 1);
        for split in &base.splits {
            let anchor = match split.anchor {
                0 => 0,
                1 => sni.start,
                2 => sni.end,
                5 => sni.start + sni.len() / 2,
                _ => return None,
            };
            let cut = anchor.checked_add_signed(isize::from(split.offset))?;
            if cut == 0 || cut >= hello.len() {
                return None;
            }
            cuts.push(cut);
        }
        cuts.sort_unstable();
        if cuts.windows(2).any(|pair| pair[0] == pair[1]) || cuts.len() >= TCP_ORDER_MAX_PARTS {
            return None;
        }
        if cuts.len() == 1 && !(sni.start < cuts[0] && cuts[0] < sni.end && sni.end < hello.len()) {
            return None;
        }
        let advertised = if send_cap == 0 {
            1400
        } else {
            send_cap.checked_sub(100)?
        };
        let segment = if base.segment_size == 0 {
            advertised
        } else {
            advertised.min(base.segment_size as usize)
        };
        (segment > 0).then_some(Self {
            target,
            hello,
            sni,
            cuts,
            segment,
            pace: base.pace_us,
        })
    }

    pub fn control(&self, reverse: bool) -> Option<String> {
        let mut order: Vec<_> = (1..=self.cuts.len() + 1).collect();
        if reverse {
            order.reverse();
        }
        self.text(&self.cuts, &order)
    }

    pub fn mixed(&self) -> Option<String> {
        let mut cuts = self.cuts.clone();
        if cuts.len() == 1 {
            cuts.push(self.sni.end);
        }
        let mut order: Vec<_> = (1..=cuts.len() + 1).collect();
        order.swap(cuts.len() - 1, cuts.len());
        self.text(&cuts, &order)
    }

    fn text(&self, cuts: &[usize], order: &[usize]) -> Option<String> {
        let mut text = format!(
            "r2o-plan 1 {TCP_ORDER_EXEC}\nid 00000000000000000000000000000000\nproto tcp tls\nwire tcp-template-v1\ninput tls-sni\ninput {} {} {}\nsegment {}\nscope {} {}\n",
            self.hello.len(),
            self.sni.start,
            self.sni.len(),
            self.segment,
            self.target.endpoint,
            self.target.host
        );
        for cut in cuts {
            writeln!(text, "split payload_start +{cut}").ok()?;
        }
        write!(text, "order {}", order[0]).ok()?;
        for part in &order[1..] {
            write!(text, ",{part}").ok()?;
        }
        text.push('\n');
        if self.pace != 0 {
            writeln!(text, "pace {}", self.pace).ok()?;
        }
        // Check the entire physical batch before the verifier reserves a socket.
        let count = cuts
            .iter()
            .copied()
            .chain([self.hello.len()])
            .scan(0, |start, end| {
                let length = end - *start;
                *start = end;
                Some(length.div_ceil(self.segment))
            })
            .sum::<usize>();
        (count <= r2k_core::plan::WIRE_BATCH_MAX).then_some(text)
    }
}

pub fn catalog_key(binding: &Binding, plan: &Plan) -> Option<String> {
    let order = plan.tcp_order.as_ref()?;
    if binding.kind != "tcpord"
        || binding.target != order.host
        || binding.port != order.endpoint.port()
        || binding.family != if order.endpoint.is_ipv4() { 4 } else { 6 }
        || binding.transport != 6
        || !valid_shape(binding.shape)
        || binding.tcp_profile != control::r2k_link_shape_tcp_profile(binding.shape)
        || binding.verified_by != 1
    {
        return None;
    }
    control::tcp_order_plan_key(order.endpoint, order.host.as_bytes())
}

pub(crate) fn save(
    catalog: &mut Catalog,
    target: &DiscoveryTarget,
    canonical_text: &str,
    now: i64,
    input: u8,
) -> Result<String, String> {
    use crate::discovery::{bind_confirmed, stable_plan_id, text_with_id};
    let id = stable_plan_id(target.family, target.shape, canonical_text);
    let text = text_with_id(canonical_text, &id)?;
    let plan =
        Plan::parse(&crate::plan_text::compile_text(&text)?).map_err(|error| error.to_string())?;
    let endpoint = target
        .endpoint
        .parse::<SocketAddr>()
        .map_err(|error| error.to_string())?;
    let binding = Binding {
        kind: "tcpord".into(),
        target: target.host.clone(),
        port: endpoint.port(),
        family: target.family,
        shape: target.shape,
        transport: 6,
        tcp_profile: target.tcp_profile(),
        verified_by: 1,
        ..Binding::default()
    };
    let key = catalog_key(&binding, &plan)
        .filter(|_| {
            plan.tcp_order
                .as_ref()
                .is_some_and(|order| order.endpoint == endpoint)
        })
        .ok_or("invalid measured TCP scope")?;
    let box_id = format!(
        "order-{}",
        stable_plan_id(target.family, target.shape, &key)
    );
    if let Some(record) = catalog.boxes.iter_mut().find(|record| record.id == box_id) {
        if record
            .bindings
            .iter()
            .any(|binding| binding.kind != "tcpord")
        {
            return Err("measured TCP scope collides with an existing box".into());
        }
        record.plans.retain(|saved| saved.id == id);
    } else {
        let scoped = catalog.boxes.iter().enumerate().filter(|(_, record)| {
            !record.bindings.is_empty() && record.bindings.iter().all(|b| b.kind == "tcpord")
        });
        if scoped.clone().count() >= 64
            && let Some((index, _)) = scoped.min_by_key(|(_, record)| record.updated)
        {
            catalog.boxes.remove(index);
        }
    }
    bind_confirmed(
        catalog,
        &box_id,
        &id,
        &text,
        "tls",
        &target.host,
        "tcpord",
        6,
        target.family,
        target.shape,
        target.tcp_profile(),
        1,
        input,
        now,
        endpoint.port(),
        None,
    )?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use r2k_core::plan::PacketInput;

    #[test]
    fn permutation_keeps_byte_ranges_and_validates_complete_layout_and_limits() {
        let host = "order.example";
        let (hello, sni) = (0..16)
            .find_map(|_| {
                let mut connection = crate::r2o_tls::r2o_tls_client_connection(
                    host,
                    false,
                    Some(640),
                    rustls::RootCertStore::empty(),
                )
                .unwrap();
                let mut hello = Vec::new();
                connection.write_tls(&mut hello).unwrap();
                let sni = r2k_core::tls::complete_sni(&hello).unwrap();
                (sni.end < hello.len()).then_some((hello, sni))
            })
            .unwrap();
        let mut shaped =
            crate::r2o_tls::tcp_order_connection(host, false, hello.len(), sni.start).unwrap();
        let mut actual = Vec::new();
        shaped.write_tls(&mut actual).unwrap();
        assert_eq!(actual.len(), hello.len());
        assert_eq!(r2k_core::tls::complete_sni(&actual), Some(sni.clone()));
        let cut = sni.start + 1;
        let seed = format!(
            "r2o-plan 1 5\nid 00000000000000000000000000000000\nproto tcp tls\nwire detect-tcp-v1\nsegment 1400\nsplit payload_start +{cut}\norder forward\n"
        );
        let target = DiscoveryTarget {
            host: host.into(),
            endpoint: "198.51.100.2:8443".into(),
            family: 4,
            shape: control::SHAPE_MODERN,
            tcp_profile: control::TCP_PROFILE_TS,
        };
        let experiment = Experiment::from_measured(&target, &hello, &seed, 1500).unwrap();
        let text = experiment.mixed().unwrap();
        let wire = crate::plan_text::compile_text(&text).unwrap();
        assert_eq!(
            u16::from_be_bytes(wire[6..8].try_into().unwrap()),
            TCP_ORDER_EXEC
        );
        assert!(Plan::to_wire(&wire, true).is_err());
        for wrong in ["1,1,2", "1,2", "1,3,4", "0,3,2"] {
            assert!(
                crate::plan_text::compile_text(&text.replace("1,3,2", wrong)).is_err(),
                "{wrong}"
            );
        }
        let plan = Plan::parse(&wire).unwrap();
        let seq = u32::MAX - 150;
        let mut input = PacketInput::new(&actual, seq);
        input.tcp_flags = Some(0x18);
        input.segment_cap = 80;
        let result = plan.apply(&input).unwrap();
        assert!(result.emits.iter().all(|emit| emit.bytes.len() <= 80));
        let offsets: Vec<_> = result
            .emits
            .iter()
            .map(|emit| emit.seq.wrapping_sub(seq) as usize)
            .collect();
        assert_eq!(offsets[cut.div_ceil(80)], sni.end);
        assert_eq!(offsets.last(), Some(&cut));
        for (emit, offset) in result.emits.iter().zip(offsets) {
            assert_eq!(&emit.bytes, &actual[offset..offset + emit.bytes.len()]);
        }
        input.segment_cap = 1;
        assert_eq!(plan.apply(&input).unwrap_err().kind(), "too-many-emissions");
        input.segment_cap = 80;
        input.tcp_flags = Some(0x14);
        assert_eq!(plan.apply(&input).unwrap_err().kind(), "mixed-input");
        input.tcp_flags = Some(0x18);
        input.payload = &actual[..actual.len() - 1];
        assert_eq!(plan.apply(&input).unwrap_err().kind(), "mixed-input");
        let mut other = actual.clone();
        other[sni.start] = b'x';
        input.payload = &other;
        assert_eq!(plan.apply(&input).unwrap_err().kind(), "mixed-input");
        let mut moved = actual.clone();
        let following_len = usize::from(u16::from_be_bytes(
            actual[sni.end + 2..sni.end + 4].try_into().unwrap(),
        ));
        moved[sni.start - 9..sni.end + 4 + following_len].rotate_left(sni.len() + 9);
        let moved_sni = r2k_core::tls::complete_sni(&moved).unwrap();
        assert_eq!(&moved[moved_sni.clone()], host.as_bytes());
        assert_ne!(moved_sni.start, sni.start);
        input.payload = &moved;
        assert_eq!(plan.apply(&input).unwrap_err().kind(), "mixed-input");
    }
}
