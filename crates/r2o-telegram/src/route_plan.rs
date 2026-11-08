//! Порт `telegram/src/route_plan.c`: DC→WSS, Cloudflare hostname и план
//! маршрутов. Порядок шагов и границы полностью совпадают с C.

use crate::config::WsRoutingPolicy;

/// C `TG_CONFIG_MAX_CF_WORKER_DOMAINS`.
pub const MAX_CF_WORKER_DOMAINS: usize = 8;
/// C `TG_CF_POOL_MAX` (32 remote + 32 manual).
pub const MAX_CF_POOL: usize = 64;
/// C `TG_ROUTE_PLAN_MAX`.
pub const MAX_ROUTE_STEPS: usize = 2 + MAX_CF_WORKER_DOMAINS + 2 * MAX_CF_POOL + 1;
/// C `TG_CF_DOMAIN_LEN`.
pub const CF_DOMAIN_LEN: usize = 254;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteKind {
    DirectWss = 1,
    CfWorker = 2,
    CfProxy = 3,
    DirectTcp = 4,
}

impl RouteKind {
    pub fn number(self) -> u8 {
        self as u8
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteStep {
    pub kind: RouteKind,
    pub index: u8,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RoutePlan {
    pub steps: Vec<RouteStep>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoutingPolicy {
    Adaptive = 0,
    Sequential = 1,
    CfFirst = 2,
    Hedged = 3,
}

impl RoutingPolicy {
    pub fn from_number(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Adaptive),
            1 => Some(Self::Sequential),
            2 => Some(Self::CfFirst),
            3 => Some(Self::Hedged),
            _ => None,
        }
    }

    pub fn number(self) -> u32 {
        self as u32
    }
}

impl From<WsRoutingPolicy> for RoutingPolicy {
    fn from(policy: WsRoutingPolicy) -> Self {
        match policy {
            WsRoutingPolicy::Adaptive => Self::Adaptive,
            WsRoutingPolicy::Sequential => Self::Sequential,
            WsRoutingPolicy::CfFirst => Self::CfFirst,
            WsRoutingPolicy::Hedged => Self::Hedged,
        }
    }
}

/// C `tg_route_websocket_dc`: тестовый DC 203 использует WS DC2.
pub fn websocket_dc(dc_id: u32) -> u32 {
    if dc_id == 203 { 2 } else { dc_id }
}

/// C `tg_route_cf_proxy_hostname`: `kws{dc}[-1].{domain}` без нормализации.
pub fn cf_proxy_hostname(
    dc_id: u32,
    media_variant: u8,
    domain: &str,
    hostname_size: usize,
) -> Option<String> {
    if !(1..=999).contains(&dc_id) || media_variant > 1 || domain.is_empty() || hostname_size == 0 {
        return None;
    }
    let hostname = format!(
        "kws{dc_id}{}.{domain}",
        if media_variant == 1 { "-1" } else { "" }
    );
    (hostname.len() < hostname_size).then_some(hostname)
}

/// C `set_direct_hostname`: индекс 0 — `kwsN`, 1 — `kwsN-1`.
pub fn direct_wss_hostname(dc_id: u32, variant: u8) -> Option<String> {
    let dc = websocket_dc(dc_id);
    if !(1..=5).contains(&dc) || variant > 1 {
        return None;
    }
    Some(if variant == 1 {
        format!("kws{dc}-1.web.telegram.org")
    } else {
        format!("kws{dc}.web.telegram.org")
    })
}

fn append_step(plan: &mut RoutePlan, kind: RouteKind, index: usize) -> Result<(), ()> {
    if plan.steps.len() >= MAX_ROUTE_STEPS || index > u8::MAX as usize {
        return Err(());
    }
    plan.steps.push(RouteStep {
        kind,
        index: index as u8,
    });
    Ok(())
}

fn append_direct(plan: &mut RoutePlan, dc_id: u32, is_media: bool) -> Result<(), ()> {
    let websocket_dc = websocket_dc(dc_id);
    if !(1..=5).contains(&websocket_dc) {
        return Ok(());
    }
    let first = usize::from(is_media);
    append_step(plan, RouteKind::DirectWss, first)?;
    append_step(plan, RouteKind::DirectWss, 1 - first)?;
    Ok(())
}

fn append_cloudflare(
    plan: &mut RoutePlan,
    worker_count: usize,
    cf_domain_count: usize,
    is_media: bool,
) -> Result<(), ()> {
    for index in 0..worker_count {
        append_step(plan, RouteKind::CfWorker, index)?;
    }
    for index in 0..cf_domain_count {
        // Индекс кодирует базовый домен и его media-вариант (-1).
        if is_media {
            append_step(plan, RouteKind::CfProxy, 2 * index + 1)?;
        }
        append_step(plan, RouteKind::CfProxy, 2 * index)?;
    }
    Ok(())
}

/// C `tg_route_plan_build`. `None` соответствует `-1` (невалидные параметры).
#[allow(clippy::too_many_arguments)]
pub fn build_plan(
    dc_id: u32,
    is_media: bool,
    policy: RoutingPolicy,
    prefer_cf: bool,
    worker_count: usize,
    cf_domain_count: usize,
    diagnostic_direct_tcp: bool,
) -> Option<RoutePlan> {
    if dc_id > 999 || worker_count > MAX_CF_WORKER_DOMAINS || cf_domain_count > MAX_CF_POOL {
        return None;
    }
    let mut plan = RoutePlan::default();
    let cf_first =
        policy == RoutingPolicy::CfFirst || (policy == RoutingPolicy::Adaptive && prefer_cf);
    let result = if cf_first {
        append_cloudflare(&mut plan, worker_count, cf_domain_count, is_media)
            .and_then(|()| append_direct(&mut plan, dc_id, is_media))
    } else {
        append_direct(&mut plan, dc_id, is_media)
            .and_then(|()| append_cloudflare(&mut plan, worker_count, cf_domain_count, is_media))
    };
    result.ok()?;
    if diagnostic_direct_tcp {
        append_step(&mut plan, RouteKind::DirectTcp, 0).ok()?;
    }
    Some(plan)
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_CF_WORKER_DOMAINS, RouteKind, RoutingPolicy, build_plan, cf_proxy_hostname,
        websocket_dc,
    };

    /// Зеркало D2O `telegram/test_route_plan.c`.
    #[test]
    fn d2o_test_route_plan_cases() {
        let plan = build_plan(4, true, RoutingPolicy::Adaptive, false, 2, 3, false).unwrap();
        assert_eq!(plan.steps.len(), 10);
        assert_eq!(
            (plan.steps[0].kind, plan.steps[0].index),
            (RouteKind::DirectWss, 1)
        );
        assert_eq!(
            (plan.steps[1].kind, plan.steps[1].index),
            (RouteKind::DirectWss, 0)
        );
        assert_eq!(
            (plan.steps[2].kind, plan.steps[2].index),
            (RouteKind::CfWorker, 0)
        );
        assert_eq!(
            (plan.steps[4].kind, plan.steps[4].index),
            (RouteKind::CfProxy, 1)
        );
        assert_eq!(
            (plan.steps[5].kind, plan.steps[5].index),
            (RouteKind::CfProxy, 0)
        );
        assert_eq!(
            (plan.steps[6].kind, plan.steps[6].index),
            (RouteKind::CfProxy, 3)
        );
        assert_eq!(
            (plan.steps[9].kind, plan.steps[9].index),
            (RouteKind::CfProxy, 4)
        );
        assert!(
            plan.steps
                .iter()
                .all(|step| step.kind != RouteKind::DirectTcp)
        );

        let plan = build_plan(4, true, RoutingPolicy::Adaptive, false, 2, 3, true).unwrap();
        assert_eq!(plan.steps.len(), 11);
        assert_eq!(plan.steps[10].kind, RouteKind::DirectTcp);

        let plan = build_plan(2, false, RoutingPolicy::CfFirst, false, 1, 2, false).unwrap();
        assert_eq!(plan.steps[0].kind, RouteKind::CfWorker);
        assert_eq!(plan.steps[1].kind, RouteKind::CfProxy);
        assert_eq!(plan.steps[3].kind, RouteKind::DirectWss);

        let plan = build_plan(2, false, RoutingPolicy::Adaptive, true, 1, 2, false).unwrap();
        assert_eq!(plan.steps[0].kind, RouteKind::CfWorker);
        assert_eq!(plan.steps[1].kind, RouteKind::CfProxy);
        assert_eq!(plan.steps[3].kind, RouteKind::DirectWss);
    }

    #[test]
    fn d2o_hostname_and_bounds() {
        assert_eq!(
            cf_proxy_hostname(2, 0, "example.co.uk", 254).as_deref(),
            Some("kws2.example.co.uk")
        );
        assert_eq!(
            cf_proxy_hostname(2, 1, "example.co.uk", 254).as_deref(),
            Some("kws2-1.example.co.uk")
        );
        assert_eq!(
            cf_proxy_hostname(203, 0, "example.co.uk", 254).as_deref(),
            Some("kws203.example.co.uk")
        );
        assert_eq!(
            cf_proxy_hostname(203, 1, "example.co.uk", 254).as_deref(),
            Some("kws203-1.example.co.uk")
        );
        assert_eq!(
            cf_proxy_hostname(6, 0, "example.co.uk", 254).as_deref(),
            Some("kws6.example.co.uk")
        );
        assert!(cf_proxy_hostname(1000, 0, "example.co.uk", 254).is_none());
        assert!(cf_proxy_hostname(2, 2, "example.co.uk", 254).is_none());
        assert!(cf_proxy_hostname(2, 0, "", 254).is_none());
        assert!(cf_proxy_hostname(2, 0, "example.co.uk", 4).is_none());

        let plan = build_plan(2, false, RoutingPolicy::Adaptive, false, 0, 2, false).unwrap();
        assert_eq!(plan.steps.len(), 4);
        assert_eq!(
            (plan.steps[2].kind, plan.steps[2].index),
            (RouteKind::CfProxy, 0)
        );
        assert_eq!(
            (plan.steps[3].kind, plan.steps[3].index),
            (RouteKind::CfProxy, 2)
        );

        assert_eq!(websocket_dc(203), 2);
        assert_eq!(websocket_dc(5), 5);
        assert_eq!(websocket_dc(999), 999);
        assert_eq!(
            build_plan(6, false, RoutingPolicy::Adaptive, false, 0, 0, false)
                .unwrap()
                .steps
                .len(),
            0
        );
        let plan = build_plan(6, false, RoutingPolicy::Adaptive, false, 0, 0, true).unwrap();
        assert_eq!(plan.steps.len(), 1);
        assert_eq!(plan.steps[0].kind, RouteKind::DirectTcp);
        assert!(
            build_plan(
                2,
                false,
                RoutingPolicy::Adaptive,
                false,
                MAX_CF_WORKER_DOMAINS + 1,
                0,
                false
            )
            .is_none()
        );
        assert!(
            build_plan(
                2,
                false,
                RoutingPolicy::Adaptive,
                false,
                0,
                super::MAX_CF_POOL + 1,
                false
            )
            .is_none()
        );
        assert!(build_plan(1000, false, RoutingPolicy::Adaptive, false, 0, 0, false).is_none());
    }
}
