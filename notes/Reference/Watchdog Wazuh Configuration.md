---
updated: 2026-11-20
tags: [ccdc, monitoring, wazuh]
---
# Watchdog Wazuh configuration

Follow [[Service Watchdogs and Alerts]] for monitoring and the two-phase recovery workflow. Repository directory `watchdog/wazuh/` contains the local rules, agent collection fragment, opt-in Active Response and notification examples.

On a Wazuh 4.14 manager, add the contents of `watchdog/wazuh/rules.xml` to a local rules file under `/var/ossec/etc/rules/`, checking for ID conflicts. Validate representative JSON with `/var/ossec/bin/wazuh-logtest`. Add `watchdog/wazuh/agent-localfile.xml` inside each agent's `ossec_config` to collect `/var/log/hunter-watch.jsonl`, then restart manager and agents using their service managers and verify alerts arrive.

DOWN is rule 100710 at level 10; recovery exhaustion 100714 and failure 100715 are level 10; RECOVERED 100711 is level 5. The manager's installed `email_alert_level` is often 12, which suppresses all of these. Configure global email/SMTP settings, set the global threshold and granular recipient level to 5, and filter the recipient to those rule IDs as shown in `watchdog/wazuh/notifications.xml`. Lowering the global threshold affects other email routing. Test delivery and review [Wazuh email thresholds](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/alerts.html) and [granular email](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/email-alerts.html). Slack needs a configured hook; custom webhook integration requires a separately implemented manager executable, which this repository does not supply. See [integration settings](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/integration.html).

Active Response is optional and independently enabled. Install the supplied wrapper in the agent's Active Response bin directory, configure the manager's supplied `active-response.xml`, and explicitly set the host recovery owner to `wazuh` only after testing. Local ownership supports bounded retries; Wazuh's transition-only DOWN trigger gives one automatic attempt per outage. See the repository's `watchdog/README.md` for the allowlist and prerequisites.
