# Master host requirements

The central server and its web UI must run on Linux, FreeBSD, OpenBSD, and Solaris primary master profiles. A separate agent monitors that machine using the same protocol as other hosts.

## Placement and network boundary

- **MST-001:** Preflight must verify that the selected master address is reachable from both jumpbox and agent networks, that the jumpbox can initiate the UI connection, and that listeners do not conflict with scored services. No public DNS, internet, or jumpbox inbound access may be assumed.
- **MST-002:** Serve HTTPS UI/administrator API on configurable TCP 8443 and enrollment/telemetry on configurable TCP 9443, using separately constructed handlers. Requests to administrator routes on the telemetry listener must fail regardless of certificate or URL.
- **MST-003:** Bind only explicitly selected addresses plus loopback where required. The UI must enforce an exact source-address/CIDR allowlist for the jumpbox at the application layer and host firewall. Require explicit expansion of that allowlist; never infer a trusted subnet from one address.
- **MST-004:** Use the TCP peer address, normalize IPv4-mapped IPv6, and reject access outside the allowlist before login or asset delivery. Ignore forwarded-address headers unless an explicitly configured trusted proxy is part of the deployment. If NAT aggregates sources, explain the resulting loss of IP isolation and retain login authentication.
- **MST-005:** The local agent uses a loopback telemetry endpoint with the correct certificate SAN/trust mapping. It must have a distinct agent identity. Master startup must not depend on that agent already being healthy, and vice versa; use retry to avoid a dependency cycle.

## Administration

- **MST-006:** Create the first administrator through the local bootstrap process with no default password. Store passwords using a current, parameterized password hash qualified on the target. Rate-limit authentication, use secure/HttpOnly/SameSite cookies, expire sessions, protect cookie-authenticated writes against CSRF, and provide explicit logout.
- **MST-007:** Bundle UI assets locally; use no required external fonts, analytics, scripts, or CDN. Escape event text and use a restrictive content security policy. Logs, usernames, hostnames, and evidence are untrusted UI data.
- **MST-008:** Provide host overview, last contact/coverage, OS/service/firewall capability details, searchable events, baseline differences, alert acknowledgment, enrollment/revocation, deployment status, and a visible master-health indicator. Display collection failure separately from no changes.
- **MST-009:** Filter events by host, time range, category, severity, and text; show original evidence and parser status. Enforce pagination and query bounds. Operator acknowledgment must not delete evidence or imply remediation.
- **MST-010:** Record administrator login, policy/baseline changes, enrollment, revocation, exports, maintenance, and deployment actions in an append-oriented audit history. Redact tokens and passwords. Do not implement a browser-accessible root terminal in the initial product.

## Enrollment and ingestion

- **MST-011:** Generate short-lived, single-use enrollment tokens bound to an expected host record and allowed source profile. Proposed lifetime is ten minutes. Enrollment must atomically consume a token, prove possession of the submitted key, and issue an agent certificate from a dedicated agent CA.
- **MST-012:** A telemetry client certificate must map to an enabled enrollment record. Revocation must reject subsequent requests and terminate/recheck existing authenticated sessions within 60 seconds. Merely chaining to the CA is insufficient.
- **MST-013:** Reject oversized, malformed, unknown-critical-version, or identity-mismatched input before storage. Authoritative agent identity comes from authentication, not a submitted JSON field. Limit connections, pending enrollment, request duration, decompression, batch counts, and bytes per agent; disable request compression initially unless bounded decoding is implemented.
- **MST-014:** Commit events durably before acknowledgment. Deduplicate by authenticated agent, stream, and sequence/event identity. Conflicting duplicates must produce an audit/error event rather than overwrite history. Protocol and cursor semantics follow AGT-023/024.
- **MST-015:** Support overlapping old/new certificates during bounded renewal, CA rotation with a staged trust overlap, and explicit host re-enrollment. Proposed agent certificate lifetime is seven days with renewal attempted before half-life. Disconnected expiry must produce a repair path over authenticated management; never bypass expiration validation.

## Storage and resilience

- **MST-016:** Use local persistent storage with restrictive permissions and a portable backend qualified on all primary master platforms. Version database schemas, serialize migrations, take a recoverable backup before migration, and refuse unsupported downgrade paths.
- **MST-017:** Proposed defaults: retain events for 72 hours subject to a 2 GiB event-store cap, with separately bounded 128 MiB audit storage and reserved free space. Report impending eviction, actual retention, and dropped/rejected event counts. Audit storage exhaustion must be visible and must not silently authorize unrecorded administrative changes.
- **MST-018:** On low disk, preserve recoverable storage and publish degraded health; do not acknowledge events that were not durably accepted. Agents must back off/buffer. A master restart must not duplicate enrollment, corrupt identity, or lose committed acknowledgments.
- **MST-019:** Support encrypted exports/backups pulled by the jumpbox, including a manifest, integrity checks, and a documented restore sequence. Certificate authority/private-key backup must be separately protected. Restore tests must include database and identity state, not just readable event files.
- **MST-020:** Keep server authority and network permissions separate from local root collection. Master service runs as a dedicated account on high ports; installation/firewall helpers handle privileged mutations. Sandbox capabilities must be reported per OS.

## Alerts and independent checks

- **MST-021:** Mark a host stale after three missed default heartbeats (45 seconds), and offline after 90 seconds, using master receive time. Maintenance suppression must have an expiry and retain raw events. Master downtime itself requires an observer outside the master.
- **MST-022:** Alert on new privileged accounts/keys, selected configuration changes, service failures, new listeners, disabled collection, certificate problems, queue loss, and agent integrity changes. Provide evidence and deduplication/suppression windows, not only severity labels.
- **MST-023:** Perform configurable bounded TCP/HTTP(S)/DNS service checks from the master. Clearly label this observation point; availability from the master is not proof that a scoring engine can reach the service.
- **MST-024:** Supply a jumpbox-initiated master/UI health probe and export command so loss of the master is observable without inbound jumpbox traffic. Agents retain local bounded data during an outage; automatic failover to another master is an extension.

## Capacity target

- **MST-025:** On a documented 2-vCPU/2-GiB lab host, qualify 25 agents producing an aggregate 250 events/second for 30 minutes, plus a 60-second burst of 1,000 events/second. Target receipt-to-search visibility below 5 seconds at steady load, under 1 GiB combined server RSS, and no unexplained loss. Keep actual results per OS; permit explicit backpressure rather than unbounded memory under overload.
