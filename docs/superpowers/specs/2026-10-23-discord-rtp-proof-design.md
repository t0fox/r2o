# Discord RTP proof design

## Intent

Do not save a permanent Discord voice address plan on STUN or IP Discovery alone.
Save it only after the temporary plan's exact IPv4 UDP flow has a valid STUN or
Discovery response and at least three forward-moving RTP sequence numbers have
been accepted in each direction. Report this as bidirectional RTP observed; it
does not prove decoded or audible audio.

## Constraints

- Keep trial state bounded by the existing voice trial limit and 120-second TTL.
- Match the exact client/server IPv4 addresses and ports and the temporary trial ID.
- Count only packets that the datapath accepts for forwarding.
- Reject malformed RTP, duplicate/out-of-order sequence numbers, other flows, and
  packets from a different client SSRC when Discovery supplied one.
- A prior catalog binding verified only by STUN or Discovery must not be activated
  as RTP-confirmed.

## Approaches

1. Keep saving after STUN/Discovery and retain the disclaimer. This preserves
   current behavior but does not meet the RTP confirmation requirement.
2. Emit a separate bounded datapath RTP proof after bidirectional accepted RTP
   progression, then persist the binding. **Chosen:** uses the already observed
   NFQUEUE flow and keeps proof attached to the exact trial.
3. Decode media or validate audio quality. The payload is encrypted and this
   would add unrelated protocol dependencies; it is outside this proof boundary.

## Design

After STUN/Discovery response, the datapath keeps the pending trial and observes
RTP headers for the same five-tuple. The client SSRC must match the Discovery
request when known; STUN-only trials learn it from the first accepted client RTP
packet. A bounded counter accepts three monotonically advancing sequence numbers
from the client and three from the server. A new control event carries the exact
flow, trial ID, and directional counts. The controller treats STUN/Discovery as
preconditions only, and writes the catalog and permanent datapath binding only
after that RTP event. Legacy voice bindings whose verification is only STUN or
Discovery are left in the catalog but not installed.

## Verification

Unit tests cover RTP header validity, SSRC and tuple matching, sequence progress,
per-direction thresholds, proof expiry, and the rule that STUN/Discovery alone
cannot save a binding. The datapath acceptance path is exercised with synthetic
IPv4/UDP/RTP packets, then the workspace, NFQUEUE, differential, and QEMU suites
run before release work continues.
