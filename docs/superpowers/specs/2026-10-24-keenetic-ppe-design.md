# Keenetic PPE visibility support

## Intent

Preserve the donor's optional Keenetic PPE behavior so R2O can see the opening packets of TCP, QUIC, and voice flows while keeping the router's global hardware acceleration enabled.

## Goals

- Import donor `D2K_PPE_DEOFFLOAD` into `R2O_PPE_DEOFFLOAD` and expose the setting in Lava.
- Install, report, heal, and remove only R2O-owned PPE rules through `iptables`/`ip6tables`.
- On Keenetic, restore R2O firewall/PPE rules through the existing NDM netfilter hook mechanism when that hook directory is present.
- Keep the PPE adapter a no-op when the PPE target is absent; the independent OpenWrt fw4 flow-offload guard follows D2O and restores the owner's setting on stop.
- Package the adapter in every release and cover it with mock-command lifecycle tests.

## Non-goals

- Change proprietary Keenetic PPE settings globally or alter router-wide offload settings outside D2O's temporary `nf_conntrack_fastnat` and fw4 `flow_offloading` lifecycles.
- Promise visibility after the configured connskip window or for flows already bound before a rule is installed.
- Claim real Keenetic acceptance; that still requires the target hardware.

## Approaches

1. Import the setting only. Rejected because it would conceal a nonfunctional option.
2. Port the donor lifecycle adapter with R2O-owned rule tags. Chosen because it preserves donor behavior, isolates cleanup from D2O/NDM rules, and no-ops when PPE is unavailable.
3. Disable all PPE in firmware. Rejected because it changes unrelated router traffic and the donor explicitly avoids it.

## Behavior and safety

The adapter uses the donor's paired TCP/UDP rules for PREROUTING and FORWARD plus client-only HTTP keep-alive rules. It tags rules `r2o-ppe`, uses connskip 30 and the donor's HTTP window, checks for the PPE target before insertion, and removes rules by its own tag. `R2O_PPE_DEOFFLOAD=0` removes owned rules. Missing PPE support is an informational no-op; incomplete insertion is reported but does not prevent ordinary NFQUEUE operation.

The service invokes the adapter after firewall installation, during reapply/heal, on stop, and in status. The installer adds a small NDM hook only when the standard hook directory already exists; uninstall removes it only when its content still matches the R2O-owned hook. The same checked setting is editable in Lava and maps from the donor on first install. Releases include the adapter and hook. Mock tests exercise exact commands, idempotence, owner isolation, disabled mode, absence of PPE, and NDM event filtering; no command is run on a physical router.

The service also mirrors D2O's separate offload lifecycles: it saves and temporarily disables writable `nf_conntrack_fastnat`, then restores it after firewall teardown; for OpenWrt, it saves `1` and sets fw4 `flow_offloading` to `0` only when that option is enabled, restoring `1` on stop. The PPE adapter remains per-flow and does not change the firmware's proprietary PPE setting. Service mock differentials cover persistence across restart; kernel behavior is not claimed without a router fixture.

## Review focus

- Foreign PPE rules must survive ensure/remove; test rules with a different owner tag.
- A disabled setting must clean up R2O rules without inserting replacements.
- A firmware without PPE must leave the service functional and install no rules.
- IPv6 must only be touched when `ip6tables` advertises PPE.
- Partial rule failure must be visible in status and all R2O-owned rules removable.
- NDM events outside `nat`/`mangle` must not restart or mutate R2O services.
