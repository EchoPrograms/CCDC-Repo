# Agent requirements

Applies to agents on all required OS families, including the master host. OS-specific mechanisms are defined in [compatibility.md](compatibility.md) and the platform documents.

## Identity and configuration

- **AGT-001:** Generate a unique agent ID and private key on the destination. Bind its enrolled identity to a master-assigned host record. Hostname and IP are attributes, not authentication identities. Detect duplicate identities caused by image cloning and require deliberate re-enrollment.
- **AGT-002:** Load a versioned, validated configuration containing master endpoints, trust anchors, collector policy, intervals, resource limits, and writable state paths. Reject unknown security-critical fields and unsafe paths. Support a non-mutating config check and machine-readable capability report.
- **AGT-003:** Keep private keys and state readable only by the service identity and authorized administrators. Use a restrictive creation mask. Do not include deployment credentials in agent configuration.
- **AGT-004:** Agents MUST NOT expose a TCP/UDP management listener. Local helper IPC must authenticate the peer using platform facilities and restrict both socket location and permissions.

## Core collection

| ID | Required collector | Required behavior |
| --- | --- | --- |
| AGT-005 | Inventory | OS/version/patch, kernel, architecture and ABI, hostname, addresses, boot identity when available, virtualization boundary, init and firewall capabilities |
| AGT-006 | Authentication | Available login/SSH/sudo/doas/su failures and successes from configured journal/syslog sources; retain original evidence and parser confidence |
| AGT-007 | Accounts and access | Local users/groups, UID/GID and privileged memberships, SSH authorized-key metadata/fingerprints, sudo/doas policy metadata and selected hashes; distinguish local from directory identities |
| AGT-008 | Processes and sessions | PID, parent, UID, executable identity when available, start identity, sessions, and bounded command metadata; redact configured secrets from arguments |
| AGT-009 | Network | Listening sockets, local addresses/ports, protocol and process attribution when available; optionally bounded established connections; never imply missing attribution means no process |
| AGT-010 | Services and startup | Native service enabled/running/failed state, selected definition hashes, cron and at jobs, init/supervisor startup entries; include manager identity |
| AGT-011 | File integrity | Selected file content hash, owner, mode, size, timestamps, symlink target, ACL/flags when supported; distinguish missing, denied, unstable, and changed |
| AGT-012 | Host health | CPU/memory summaries, filesystems and free space, uptime, agent queue/drop counters, collector failures, configured limits, and current policy version |
| AGT-013 | Agent integrity | Executable/config/service-definition hashes and permissions, supervisor state, identity/certificate metadata, and detected changes to owned firewall objects |

- **AGT-014:** Every collector must implement availability probing and report `ok`, `partial`, `permission_denied`, `unsupported`, or `error` with a stable reason code. An empty successful result must be distinguishable from failed collection. A missing critical collector degrades host coverage in the master.
- **AGT-015:** Use authenticated effective SSH configuration where a supported native check exists; account for Include/Match and per-user authorized-key locations. Never upload private SSH keys, password hashes, or complete secret-bearing configurations by default. Flag an unreadable/evaluated-outside-scope rule rather than guess.
- **AGT-016:** Directory-service enumeration, kernel audit streams, package integrity databases, SELinux/AppArmor events, BSM audit, and process-to-socket attribution are conditional facilities. Their absence must not disable unrelated core collectors. Kernel audit must not be enabled or reconfigured automatically.
- **AGT-017:** Initial baselines must be labeled observations, not trusted clean state. Baseline approval is explicit. Preserve before/after metadata and the approving operator; never automatically bless an attacker-induced change.

## Portability and input handling

- **AGT-018:** Use native APIs or exact per-OS command adapters. Execute fixed argument vectors with absolute verified paths, bounded runtime/output, a restricted environment, and locale control. Do not interpolate inventory values or collected text into shell commands.
- **AGT-019:** Bound every collection by time, bytes, file count, recursion, and concurrency. Do not follow arbitrary symlinks or recurse through device/pseudo/network filesystems by default. Detect file replacement during hashing and report an unstable observation.
- **AGT-020:** Log readers must handle rename rotation, truncation, restart, missing journal cursors, partial lines, non-UTF-8 bytes, and dropped history. Persist cursors with the spool; report gaps. Detect duplicate journal/syslog ingestion or identify duplicate sources.
- **AGT-021:** Inspect only the current jail/zone/container view unless separately authorized host visibility exists. Label that boundary on every inventory and coverage report.

## Telemetry and buffering

- **AGT-022:** Initiate HTTPS telemetry to the master; TLS 1.2 minimum, prefer TLS 1.3, validate the pinned master trust anchor and endpoint identity. Use a one-use enrollment token followed by individual mutual TLS. Do not fall back to plaintext or skip verification.
- **AGT-023:** Use a versioned JSON event envelope: `schema_version`, `agent_id`, `host_id`, `event_id`, `boot_id` when available, `stream_id`, durable `sequence`, `observed_at`, `sent_at`, `category`, `source`, `collector_status`, `payload`, and optional bounded original evidence. Master adds `received_at` and authenticated identity. Generate IDs/keys with OS cryptographic randomness.
- **AGT-024:** Provide at-least-once delivery with durable acknowledgments, retry with jitter/backoff, and master deduplication. Delete acknowledged spool segments only after durable acknowledgment; sequence/cursor checkpoints must recover safely after a crash. Version incompatibility must be actionable, not an infinite hot retry loop.
- **AGT-025:** Proposed defaults: heartbeat every 15 seconds; incremental log batches at most every 5 seconds; health every 30 seconds; access/service/network snapshots every 60 seconds; selected file checks every 5 minutes. Intervals are configurable with jitter and per-collector budgets.
- **AGT-026:** Proposed limits: 64 KiB encoded event, 1 MiB encoded batch, 128 MiB disk spool, bounded 16 MiB in-memory queue, and 10-second command timeout. Large evidence must truncate with metadata; reject rather than split invalid JSON. Maintain space for health/loss reporting.
- **AGT-027:** When full, evict oldest low-priority telemetry before critical events according to a documented policy. If only critical data remains, drop oldest with explicit counts and sequence ranges. Disk-full behavior must not crash-loop or fill an unrelated filesystem. Resend a loss summary after recovery.
- **AGT-028:** Measure durations using monotonic time where available; preserve wall-clock observations and report suspected clock skew. Do not set system time automatically or weaken certificate checks because the clock is wrong.

## Privilege and availability

- **AGT-029:** Install a root-owned service and binary. The full-visibility collection component may run as root when required by the OS. Prefer a separate unprivileged network/spool worker with narrow, validated local IPC; if a single privileged process is used initially, label that mode and restrict its filesystem, syscall, and network access as supported.
- **AGT-030:** The collector/helper interface must allow only declared read operations and typed configuration. It must not accept arbitrary commands, executable paths, shell fragments, or unrestricted file reads from the master.
- **AGT-031:** Use native service supervision or an explicit portable supervisor where the native startup framework lacks it. Restart with delay and a crash budget, publish permanent failure state, and keep intentional operator stops effective. No hidden respawning jobs or mutually restarting services.
- **AGT-032:** Provide graceful stop, config validation/reload with last-known-good retention, health reporting, explicit maintenance mode, upgrade, and uninstall. Reload must not partially activate invalid settings. Agent installation must not change host-wide securelevel, kernel module policy, or unrelated security settings.
- **AGT-033:** Immutable/append-only flags are an optional hardening profile for supported filesystems, scoped to binaries and static definitions. Never mark live queues, databases, certificates needing renewal, or writable logs immutable. Record original flags and document how the authorized operator enters maintenance and restores them.
- **AGT-034:** Detect accidental process death and report missing telemetry centrally; do not claim to prevent a root attacker from stopping, disconnecting, or forging local collection. Agent integrity events are useful evidence, not proof of a clean kernel.

## Performance target

- **AGT-035:** On a documented 1-vCPU/512-MiB lab guest with 25 configured integrity files and 5 new log lines/second, target combined agent/helper steady RSS below 96 MiB, under 5% of one vCPU averaged over ten minutes after baseline, and spool bounded by AGT-026. Record actual values separately on every OS; missing a target requires tuning or a documented profile limitation before qualification.
