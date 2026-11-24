use super::*;
use r2k_core::packet::PacketView;

const RTA_SRC: u16 = 2;
const RTA_IIF: u16 = 3;
const RTA_GATEWAY: u16 = 5;
const RTA_PREFSRC: u16 = 7;
const RTA_MARK: u16 = 16;
const RTA_VIA: u16 = 18;
const RTA_NEWDST: u16 = 19;
const RTA_ENCAP_TYPE: u16 = 21;
const RTA_ENCAP: u16 = 22;
const RTA_NH_ID: u16 = 30;
const RTN_LOCAL: u8 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum R2oEffectiveRoute {
    Equivalent,
    Different,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct R2oRouteCheck {
    source: Address,
    destination: Address,
    output: u32,
    client_mark: u32,
    probe_mark: u32,
    measure_mark: u32,
    raw_mark: u32,
    tos: u8,
    local: bool,
}

impl R2oRouteCheck {
    pub fn new(packet: &[u8], context: R2oRoutePacket, measure_mark: u32) -> Option<Self> {
        let view = PacketView::parse(packet)?;
        let client_mark = context.mark.unwrap_or(0);
        Some(Self {
            source: view.src,
            destination: view.dst,
            output: context.output_ifindex.filter(|&index| index != 0)?,
            client_mark,
            probe_mark: if context.probe_mark != 0 {
                context.probe_mark
            } else {
                context.datapath_mark
            },
            measure_mark,
            raw_mark: context.datapath_mark,
            tos: view.traffic_class & 0xfc,
            local: client_mark != 0 && [context.probe_mark, measure_mark].contains(&client_mark),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NextHop {
    interface: u32,
    gateway: Option<Address>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Lookup {
    Route(NextHop, Option<Address>),
    Local,
    Unreachable,
    Unavailable,
}

impl R2oRouteMonitor {
    pub fn r2o_check_effective_route(&mut self, query: R2oRouteCheck) -> R2oEffectiveRoute {
        let result = self.r2o_compare_paths(query);
        result.unwrap_or(R2oEffectiveRoute::Unavailable)
    }

    fn r2o_compare_paths(&mut self, query: R2oRouteCheck) -> Option<R2oEffectiveRoute> {
        if query.destination.family() == 4
            && std::fs::read_to_string("/proc/sys/net/ipv4/fib_multipath_hash_policy")
                .is_ok_and(|value| value.trim() != "0")
        {
            // Старое ядро не принимает порты в RTM_GETROUTE.
            return None;
        }
        let input = if query.local {
            None
        } else {
            // POSTROUTING не передаёт iif. При правилах, независимых от iif,
            // используем непосредственно подключённую сеть источника.
            match self.r2o_effective_lookup(query.source, None, None, 0, 0) {
                Lookup::Local => None,
                Lookup::Route(lan, _) if lan.gateway.is_none() && lan.interface != query.output => {
                    Some(lan.interface)
                }
                _ => return None,
            }
        };
        let Lookup::Route(original, _) = self.r2o_effective_lookup(
            query.destination,
            Some(query.source),
            input,
            query.client_mark,
            query.tos,
        ) else {
            return None;
        };
        if original.interface != query.output {
            return None;
        }

        if query.destination.family() == 6 {
            // IPv6-фрагменты идут через AF_PACKET с поиском по адресу пакета.
            match self.r2o_effective_lookup(
                query.destination,
                Some(query.source),
                None,
                query.raw_mark,
                0,
            ) {
                Lookup::Route(path, _) if path == original => (),
                Lookup::Route(..) | Lookup::Local | Lookup::Unreachable => {
                    return Some(R2oEffectiveRoute::Different);
                }
                Lookup::Unavailable => return None,
            }
        }

        let mut checked = [None; 3];
        for (index, mark) in [
            Some(query.raw_mark),
            Some(query.probe_mark),
            (query.measure_mark != 0).then_some(query.measure_mark),
        ]
        .into_iter()
        .enumerate()
        {
            let Some(mark) = mark else {
                continue;
            };
            let first = self.r2o_effective_lookup(query.destination, None, None, mark, 0);
            let Lookup::Route(path, source) = first else {
                return matches!(first, Lookup::Local | Lookup::Unreachable)
                    .then_some(R2oEffectiveRoute::Different);
            };
            if path != original {
                return Some(R2oEffectiveRoute::Different);
            }
            if index != 0 && !checked.contains(&Some(mark)) {
                // Зонд TCP/UDP выбирает локальный адрес до последующих посылок.
                let selected =
                    self.r2o_effective_lookup(query.destination, Some(source?), None, mark, 0);
                match selected {
                    Lookup::Route(path, _) if path == original => (),
                    Lookup::Route(..) | Lookup::Local | Lookup::Unreachable => {
                        return Some(R2oEffectiveRoute::Different);
                    }
                    Lookup::Unavailable => return None,
                }
                checked[index] = Some(mark);
            }
        }
        Some(R2oEffectiveRoute::Equivalent)
    }

    fn r2o_effective_lookup(
        &mut self,
        destination: Address,
        source: Option<Address>,
        input: Option<u32>,
        mark: u32,
        tos: u8,
    ) -> Lookup {
        let sequence = self.r2o_next_sequence();
        let request = request(sequence, destination, source, input, mark, tos);
        let mut result = Lookup::Unavailable;
        if self
            .r2o_receive_request(request, R2O_LOOKUP_BUFFER, R2O_LOOKUP_ROUNDS, |bytes| {
                for message in r2o_route_messages(bytes).map_err(r2o_parse_io_error)? {
                    match message.kind {
                        R2O_NLMSG_ERROR => {
                            let error =
                                r2o_kernel_error(message.body).map_err(r2o_parse_io_error)?;
                            // На MIPS номера сетевых errno отличаются от x86.
                            result = if [-libc::EACCES, -libc::ENETUNREACH, -libc::EHOSTUNREACH]
                                .contains(&error)
                            {
                                Lookup::Unreachable
                            } else {
                                Lookup::Unavailable
                            };
                            return Ok(true);
                        }
                        R2O_RTM_NEWROUTE => {
                            result = parse_path(message.body, destination)
                                .unwrap_or(Lookup::Unavailable);
                            return Ok(true);
                        }
                        _ => (),
                    }
                }
                Ok(false)
            })
            .is_err()
        {
            return Lookup::Unavailable;
        }
        result
    }
}

fn request(
    sequence: u32,
    destination: Address,
    source: Option<Address>,
    input: Option<u32>,
    mark: u32,
    tos: u8,
) -> Vec<u8> {
    let family = if destination.family() == 4 {
        R2oRouteFamily::Ipv4
    } else {
        R2oRouteFamily::Ipv6
    };
    let width = family.r2o_probe().len();
    let mut request = r2o_route_lookup_request(family, sequence);
    let dst_start = R2O_NLMSG_HEADER_LEN + R2O_ROUTE_HEADER_LEN + R2O_NLA_HEADER_LEN;
    request[dst_start..].copy_from_slice(&destination.bytes()[..width]);
    request[R2O_NLMSG_HEADER_LEN + 3] = tos;
    let mut add = |kind: u16, value: &[u8]| {
        let length = R2O_NLA_HEADER_LEN + value.len();
        request.extend_from_slice(&(length as u16).to_ne_bytes());
        request.extend_from_slice(&kind.to_ne_bytes());
        request.extend_from_slice(value);
    };
    if let Some(source) = source {
        add(RTA_SRC, &source.bytes()[..width]);
    }
    if let Some(input) = input {
        add(RTA_IIF, &input.to_ne_bytes());
    }
    if mark != 0 {
        add(RTA_MARK, &mark.to_ne_bytes());
    }
    if source.is_some() {
        request[R2O_NLMSG_HEADER_LEN + 2] = (width * 8) as u8;
    }
    let size = request.len() as u32;
    request[..4].copy_from_slice(&size.to_ne_bytes());
    request
}

fn parse_path(body: &[u8], destination: Address) -> Option<Lookup> {
    let header = body.get(..R2O_ROUTE_HEADER_LEN)?;
    let mut interface = None;
    let mut gateway = None;
    let mut preferred_source = None;
    let mut dst_matches = false;
    let family = if destination.family() == 4 { 2 } else { 10 };
    if header[0] != family {
        return None;
    }
    if header[7] != R2O_RTN_UNICAST {
        return match header[7] {
            RTN_LOCAL => Some(Lookup::Local),
            6..=9 => Some(Lookup::Unreachable),
            _ => None,
        };
    }
    for (kind, value) in r2o_route_attributes(body, R2O_ROUTE_HEADER_LEN).ok()? {
        match kind {
            R2O_RTA_DST => {
                dst_matches =
                    r2o_route_key_address(destination.family(), Some(value))? == destination
            }
            R2O_RTA_OIF => interface = Some(u32::from_ne_bytes(value.try_into().ok()?)),
            RTA_GATEWAY => {
                gateway = Some(r2o_route_key_address(destination.family(), Some(value))?)
            }
            RTA_PREFSRC => {
                preferred_source = Some(r2o_route_key_address(destination.family(), Some(value))?)
            }
            // Via, multipath, LWT, новый объект nexthop. Скалярный снимок недостаточен.
            R2O_RTA_MULTIPATH | RTA_VIA | RTA_NEWDST | RTA_ENCAP_TYPE | RTA_ENCAP | RTA_NH_ID => {
                return None;
            }
            _ => (),
        }
    }
    let interface = interface.filter(|&value| value != 0)?;
    dst_matches.then_some(Lookup::Route(
        NextHop { interface, gateway },
        preferred_source,
    ))
}
