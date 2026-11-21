# Deployment requirements

Deployment is an explicit, resumable workflow over supplied hosts. All four requested OS families must be first-class installation targets, including the master role. Refer to platform documents for native paths and commands.

## Inputs and credentials

- **DEP-001:** Accept a versioned inventory with host ID/address, configured management ports, credential-profile reference, expected SSH key/fingerprint or bootstrap trust choice, role, desired collectors, and optional platform hints. Collect master addresses, jumpbox source addresses as seen by the master, agent source/NAT addresses, listener ports, and artifact bundle path during setup.
- **DEP-002:** Prompt for credential profiles using hidden input. Support SSH keys/agent, key passphrases, passwords, keyboard-interactive authentication, and separate elevation credentials where permitted. Keep secrets in memory by default; never include them in process arguments, inventory output, logs, history, world-readable files, or generated service definitions.
- **DEP-003:** Bind each credential profile to its selected hosts. Default to one authentication attempt per selected method/profile/host with explicit retry controls. Do not spray all credentials across all hosts. Serialize interactive MFA/elevation prompts without mixing host context.
- **DEP-004:** Verify SSH server identity. First-use trust must display and record the fingerprint for operator verification; changed keys block automatic reuse. Automatic host-key collection is not independent verification. Retain known hosts separately from general inventory.

## Read-only discovery

- **DEP-005:** Probe only the given hosts and configured candidate management ports using timeouts and low concurrency. Confirm the protocol through a bounded handshake. Implement SSH transport initially; identify unsupported/plaintext protocols as unavailable deployment routes, without sending credentials to them. Service/OS banners are advisory.
- **DEP-006:** After authentication, detect OS family/release/patch level, kernel and userland architecture/bitness, executable ABI, shell path, libc/runtime dependencies, active init/supervisor, firewall owner/backend, filesystem constraints, free space, effective UID/privileges, and jail/zone/container boundary. Run the shared adapter probes and retain sanitized evidence.
- **DEP-007:** Detect sudo, doas, Solaris pfexec/RBAC and role assumption as separate elevation adapters. Test the exact required actions non-destructively where possible. Never assume membership in wheel grants passwordless root. Report insufficient privilege by operation.
- **DEP-008:** Verify selected listener addresses and route observations. A host cannot reliably infer the source IP another machine observes through NAT; use an authenticated probe and compare with inventory. Do not broaden an allowlist automatically after a failed probe.
- **DEP-009:** Select artifacts only using a signed manifest of OS/release floor, architecture/ABI, build/runtime dependencies, crypto support, and digest. Verify signature using a pretrusted release public key, then digest, before privileged installation. Unsigned checksums alone do not authenticate a bundle.
- **DEP-010:** If no exact qualified artifact/adapter combination exists, produce a per-host compatibility report and remediation plan. Do not execute a Linux binary on BSD/Solaris or install an old vulnerable runtime silently. Partial collection/manual installation must be labeled explicitly.

## Installation transaction

| Stage | Required outcome |
| --- | --- |
| Discover | Authenticated facts and selected adapters; no configuration mutation |
| Plan | Paths, identities, service definitions, firewall diff, dependencies, required privilege, and rollback steps |
| Stage | Private unique temporary directory; uploaded verified artifact/configuration; disk and executable checks |
| Prepare | Save owned-object prior state; verify dependency availability; arm independent firewall rollback |
| Install | Root-owned versioned binaries/configuration; service account and native service definition |
| Connect | Required narrow firewall rules; enrollment; local/remote health and new SSH-session checks |
| Commit | Durable installation receipt, native firewall persistence, canceled rollback, removed enrollment secrets/staging |
| Recover | Stop at failing stage, revert owned mutations, revoke orphan enrollment where reachable, publish remaining cleanup |

- **DEP-011:** Every stage must have a stable machine-readable status, timestamps, sanitized evidence, and compensating actions. Rerunning after interruption must inspect receipts/current state, converge without duplicate services/users/rules, and never overwrite unrelated administrator edits.
- **DEP-012:** Bootstrap must work with POSIX shell semantics or a verified OS-specific shell. Do not assume Bash, GNU tar/sed/find, Python, curl, wget, systemctl, `/proc`, or writable `/tmp`. Prefer SFTP; if unavailable, use bounded binary-safe transfer through the authenticated SSH exec channel. Never use a world-readable temporary secret or download-and-pipe-to-shell installation.
- **DEP-013:** Use private temporary directories, reject archive path traversal/symlink escapes, check ownership of destination parents, and atomically activate verified files on the same filesystem where possible. Record original modes/owners/flags. Do not replace files via attacker-controlled symlinks.
- **DEP-014:** Default to offline bundled dependencies. Package installation, if selected as a dependency strategy, must appear in the plan with exact names/versions and offline source. Do not change global repositories or upgrade the host. Existing crypto libraries must be checked for minimum protocol/algorithm support.
- **DEP-015:** Install the master before dependent agents: trust/administrator initialization, validated listener configuration, narrow firewall integration, server start, then its distinct local agent. Install other agents with individual token/key handling. Do not embed a shared permanent fleet secret in bundles.
- **DEP-016:** Verify process/service state and an authenticated first heartbeat, collector coverage, correct identity, protected key permissions, expected listeners, UI access from jumpbox, rejection of unauthorized UI access when a test source exists, and preserved management/scored-service access. Treat untested negative reachability as unverified, not passed.
- **DEP-017:** Do not reboot competition hosts automatically. Lab qualification must test boot persistence; production receipts must distinguish configured persistence from persistence verified by an actual reboot.

## Firewall and connectivity

- **DEP-018:** Use [firewall.md](firewall.md) for every automatic firewall mutation. UI source filtering in the application must be active before exposing the listener. Source allowlists must account for jumpbox, agent NAT, loopback, and IPv6 explicitly.
- **DEP-019:** If master-to-agent management is unavailable, retain jumpbox-originated deployment and probe reporting. A master server does not need to hold all SSH credentials or initiate agent sessions after enrollment. Firewall verification may coordinate authenticated probes through the controller.
- **DEP-020:** Rollback must survive controller disconnect and installer exit. Use a platform-qualified local job/supervisor with a durable deadline and transaction receipt; if such recovery cannot be armed, firewall automation must stop before mutation. If the host reboots mid-transaction, an early recovery hook must resolve pending changes before activating tool-managed persistent policy; firewall mutations must not be made persistent before verification.

## Update, maintenance, and removal

- **DEP-021:** Stage updates beside the active version; check signature, ABI, configuration, available storage, migration compatibility, and service definition before switching. Keep the last working version and sanitized receipt. Roll back if local health/first heartbeat fails within the bounded deadline.
- **DEP-022:** Updating/removing an immutable installation must use its documented maintenance sequence. Do not globally disable file protections or lower securelevel. Report when a reboot/offline maintenance session is necessary rather than circumvent a protection.
- **DEP-023:** Uninstall must stop/disable only owned services/supervisors, remove only owned firewall objects and binaries, and revoke the identity when the master is reachable. Preserve telemetry/configuration evidence by default. Purging retained data/keys is a separate explicit option with an exact-target preview.
- **DEP-024:** Removing a shared account, dependency, CA, directory, or rule is allowed only if the receipt proves ownership and no remaining installation uses it. Changed administrator files cause a conflict report rather than blind restoration. Report any unreverted partial change.
- **DEP-025:** Support a local rescue command using a saved receipt for status, stopping services, reversing owned firewall changes, and restoring the prior version without needing the master. Recovery instructions must be available in the offline bundle for each OS.

## Proposed operator interface

The following command names describe required workflows, not existing executables: `discover`, `plan`, `install-master`, `install-agents`, `verify`, `status`, `update`, `maintenance`, `rollback`, `uninstall`, and `export`. Each must offer structured output; mutating workflows must print the resolved target set and execute the reviewed plan without silently broadening it.
