#!/usr/bin/env python3
"""Generate Lecture 02 (SIEM tools) as index.html. Render to PDF with chromium afterwards."""
import html, json, pathlib

e = html.escape
here = pathlib.Path(__file__).parent
shared = here.parent / "shared"
TITLE = "SIEM Tools: Splunk, Wazuh & More"

SH = ("analyst@soc", ":~$")          # default lab shell
SPL = ("splunk", " › search")
KIB = ("kibana", " ›")
KQL = ("sentinel", " › KQL")
AQL = ("qradar", " › AQL")

# Topic: key (for `man`), title, module, desc, headline, points[(term, meaning)], tip, terminal lines, prompt, task.
# Terminal lines: "$ x" = typed command/query, "# x" = comment, anything else = output.
T = []
def topic(key, title, mod, desc, headline, points, tip, term, task, prompt=SH):
    T.append(dict(key=key, title=title, mod=mod, desc=desc, headline=headline, points=points, tip=tip, term=term, task=task, prompt=prompt))

M1, M2, M3, M4, M5 = "SIEM Fundamentals", "Splunk", "Wazuh", "Elastic, Sentinel, QRadar & Sigma", "Hands-on SOC Lab"
MODS = [M1, M2, M3, M4, M5]
COLOR = {M1: "#58a6ff", M2: "#ffa657", M3: "#56d4dd", M4: "#d2a8ff", M5: "#ff7b72"}

# ---------- Module 1: Fundamentals ----------
topic("siem", "What is a SIEM?", M1,
      "Security Information and Event Management: one place that collects logs from everything, makes them searchable, and raises alerts when activity looks malicious.",
      "collect → normalize → correlate → alert → retain",
      [("Collect", "pull logs from servers, endpoints, network devices and cloud"), ("Normalize", "turn many formats into common field names"),
       ("Correlate", "link related events across sources and time"), ("Alert", "notify analysts when a rule matches"), ("Retain", "keep history for investigations and compliance")],
      "Without a SIEM an analyst must log into every machine one by one. With it, one query covers the whole estate.",
      ["# the slow way: one server at a time",
       "$ ssh web01 \"grep -c 'Failed password' /var/log/auth.log\"", "214",
       "$ ssh db01 \"grep -c 'Failed password' /var/log/auth.log\"", "3",
       "# ...and 200 more servers. In a SIEM it is one search:",
       "$ siem-search 'event.outcome:failure' --last 24h --by host.name",
       "host.name     count", "web01           214", "vpn01            57", "db01               3",
       "# (siem-search is a teaching stand-in for any SIEM's search box)"],
      "List five log sources in your own lab you would send to a SIEM, and one attack each would reveal.")
topic("logsources", "Log sources", M1,
      "A SIEM is only as good as the data it receives. These sources give the most security value per byte.",
      "endpoints · identity · network · applications · cloud",
      [("Linux", "/var/log/auth.log, journald, auditd"), ("Windows", "Security log: 4624 logon, 4625 failed, 4688 process, 4720 user created"),
       ("Sysmon", "Event 1 process create, 3 network connect, 11 file create"), ("Network", "firewall, DNS, proxy, IDS (Suricata/Zeek)"),
       ("Cloud / SaaS", "AWS CloudTrail, Entra ID sign-ins, M365 audit")],
      "Start with authentication logs everywhere: most intrusions involve logging in somewhere.",
      ["$ sudo tail -1 /var/log/auth.log", "Oct 24 08:51:02 web01 sshd[2210]: Failed password for root from 192.168.56.23 port 50412 ssh2",
       "$ tail -1 /var/log/apache2/access.log", "192.168.56.23 - - [24/Oct/2026:08:55:10 +0000] \"GET /admin HTTP/1.1\" 403 492",
       "$ jq -r '.EventID, .TargetUserName, .IpAddress' event-4625.json", "4625", "administrator", "192.168.56.23"],
      "For each Windows event ID on this slide, write one sentence on what an attacker action would create it.")
topic("normalize", "Parsing & normalization", M1,
      "Every product writes logs differently. The SIEM extracts fields and maps them to a common schema so one query works across all sources.",
      "raw text → fields → common schema → enrichment",
      [("Field extraction", "regex or decoders pull out user, IP, action"), ("Schemas", "Splunk CIM, Elastic ECS, Sentinel ASIM, OCSF"),
       ("Time", "normalize timestamps to UTC or correlation breaks"), ("Enrichment", "add GeoIP, asset owner, threat-intel matches")],
      "If two sources call the same thing 'src', 'SourceIP' and 'client_ip', your rule silently misses two of them. Normalization fixes that.",
      ["$ head -1 raw/auth.log", "Oct 24 08:51:02 web01 sshd[2210]: Failed password for root from 192.168.56.23 port 50412 ssh2",
       "$ head -1 normalized/auth.json | jq", "{", '  "@timestamp": "2026-10-24T08:51:02Z",', '  "host.name": "web01",',
       '  "event.category": "authentication",', '  "event.outcome": "failure",', '  "user.name": "root",',
       '  "source.ip": "192.168.56.23",', '  "source.geo.country_iso_code": "private"', "}"],
      "Take three different log lines from your lab and write the ECS field names you would map them to.")
topic("correlation", "Correlation rules", M1,
      "A correlation rule links several events into one meaningful alert, so analysts see incidents instead of noise.",
      "threshold · sequence · first-seen · indicator match",
      [("Threshold", "N events within T minutes (e.g. 10 failed logins in 5 min)"), ("Sequence", "A then B (many failures, then a success)"),
       ("First-seen / rarity", "new admin account, new country, new process"), ("Indicator match", "IP, domain or hash on a threat-intel list")],
      "Correlation turns thousands of raw events into the one alert worth a human's time.",
      ["$ cat rules/bruteforce_then_success.yml", "name: Brute force followed by successful login", "severity: high",
       "group_by: [source.ip, user.name]", "window: 10m", "sequence:", "  - match: {event.category: authentication, event.outcome: failure}",
       "    count: '>= 10'", "  - match: {event.category: authentication, event.outcome: success}", "mitre: [T1110, T1078]",
       "# generic pseudo-rule: every SIEM writes this in its own language"],
      "Write in plain English one threshold rule and one sequence rule for your lab web server.")
topic("triage", "Alert triage & SOC workflow", M1,
      "Every alert follows the same path. Good notes at each step make the next analyst faster.",
      "triage → investigate → contain → close",
      [("Triage", "real or noise? how severe? which asset?"), ("Investigate", "scope it: which hosts, users, time range"),
       ("Contain", "block IP, disable account, isolate host"), ("Close", "true positive, false positive or benign; document it")],
      "A false positive is still useful: tune the rule so it doesn't fire again for the same benign reason.",
      ["$ cat cases/case-0142.md", "# Case 0142: SSH brute force on web01", "Alert:    5712 sshd brute force (level 10)", "Source:   192.168.56.23 (lab attacker VM)",
       "Scope:    29 failures, 0 successes, web01 only", "Action:   IP blocked by active response for 10 min", "Verdict:  True positive (authorized lab test)",
       "Tuning:   none needed"],
      "Write a case note like this for one alert you generate in your lab this week.")
topic("mitre", "MITRE ATT&CK mapping", M1,
      "ATT&CK is a public catalogue of attacker techniques. Tagging rules with technique IDs shows what you detect and where the gaps are.",
      "tactic (why) → technique (how) → your detection",
      [("T1110", "Brute Force"), ("T1078", "Valid Accounts"), ("T1059", "Command and Scripting Interpreter"),
       ("T1136", "Create Account"), ("T1053", "Scheduled Task/Job")],
      "Build an ATT&CK coverage map from your rule tags; uncovered techniques become your detection backlog.",
      ["$ grep -H 'attack.t' rules/*.yml", "rules/ssh_bruteforce.yml:    - attack.t1110", "rules/new_local_admin.yml:   - attack.t1136",
       "rules/cron_modified.yml:     - attack.t1053", "$ grep -h 'attack.t' rules/*.yml | sort | uniq -c", "      1 - attack.t1053",
       "      1 - attack.t1110", "      1 - attack.t1136"],
      "Open attack.mitre.org, pick one technique, and describe which log source would detect it.")

# ---------- Module 2: Splunk ----------
topic("splunk", "Splunk overview", M2,
      "A commercial data platform widely used as a SIEM. Data is indexed on arrival and searched with SPL, the Search Processing Language.",
      "forwarder → indexer → search head",
      [("Universal Forwarder", "lightweight agent that ships logs"), ("Indexer", "parses, indexes and stores events"),
       ("Search head", "web UI and search engine"), ("Ports", "8000 web · 8089 management · 9997 forwarder input"),
       ("Enterprise Security", "premium SIEM app: notables, risk-based alerting")],
      "Splunk offers a trial and a limited free license for learning; check splunk.com for current terms before building a lab.",
      ["$ sudo /opt/splunk/bin/splunk status", "splunkd is running (PID: 1874).", "splunk helpers are running (PIDs: 1880 1902).",
       "$ sudo /opt/splunk/bin/splunk enable listen 9997", "Listening for Splunk data on TCP port 9997.",
       "$ sudo ss -tln | grep -E ':(8000|8089|9997)'", "LISTEN 0  128  0.0.0.0:8000  0.0.0.0:*", "LISTEN 0  128  0.0.0.0:8089  0.0.0.0:*",
       "LISTEN 0  128  0.0.0.0:9997  0.0.0.0:*"],
      "Install Splunk on a lab VM, open port 9997 for receiving, and log in at http://<vm-ip>:8000.", prompt=("analyst@splunk01", ":~$"))
topic("forwarder", "Universal Forwarder", M2,
      "Installed on each source host, the forwarder watches files and sends new lines to the indexer.",
      "splunk add forward-server · splunk add monitor",
      [("add forward-server", "where to send data (indexer:9997)"), ("add monitor", "which file or folder to watch"),
       ("-index", "destination index (create it on the indexer first)"), ("-sourcetype", "tells Splunk how to parse it"),
       ("outputs.conf / inputs.conf", "the config files these commands write")],
      "Use a dedicated index per data type (linux, wineventlog, web) so searches and retention stay manageable.",
      ["# on web01", "$ sudo /opt/splunkforwarder/bin/splunk add forward-server 192.168.56.20:9997", "Added forwarding to: 192.168.56.20:9997.",
       "$ sudo /opt/splunkforwarder/bin/splunk add monitor /var/log/auth.log -index linux -sourcetype linux_secure",
       "Added monitor of '/var/log/auth.log'.", "$ sudo /opt/splunkforwarder/bin/splunk list forward-server", "Active forwards:",
       "\t192.168.56.20:9997", "Configured but inactive forwards:", "\tNone"],
      "Forward /var/log/auth.log from a second VM and confirm events arrive with index=linux.", prompt=("analyst@web01", ":~$"))
topic("spl", "SPL basics", M2,
      "SPL searches start by choosing data, then pipe results through commands, like a Linux pipeline.",
      'index=… sourcetype=… "text" | command | command',
      [("index= / sourcetype=", "where to look (always set them, it's faster)"), ("|", "pipe results into the next command"),
       ("rex", "extract a field with a regex"), ("stats count by", "group and count"), ("sort -count", "sort descending")],
      "Same idea as Lecture 01's grep | awk | sort | uniq -c, but across every host at once.",
      ['$ index=linux sourcetype=linux_secure "Failed password" | head 2',
       "Oct 24 08:51:05 web01 sshd[2210]: Failed password for root from 192.168.56.23 port 50418 ssh2",
       "Oct 24 08:51:02 web01 sshd[2210]: Failed password for root from 192.168.56.23 port 50412 ssh2",
       r'$ index=linux "Failed password" | rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)" | stats count by src_ip | sort -count',
       "src_ip            count", "192.168.56.23        29", "192.168.56.41         6", "192.168.56.7          2"],
      "Write a search that counts failed logins per user instead of per source IP.", prompt=SPL)
topic("spl2", "SPL toolkit", M2,
      "A handful of commands cover most day-to-day hunting and reporting.",
      "timechart · table · top · where · eval · dedup",
      [("timechart", "counts over time (spot spikes)"), ("table", "choose columns to display"), ("top", "most common values"),
       ("where", "filter on calculated values"), ("eval", "create or transform fields"), ("dedup", "keep one event per value")],
      "timechart is the fastest way to see when an attack started and stopped.",
      ['$ index=linux "Failed password" | timechart span=10m count', "_time               count", "2026-10-24 08:40       0",
       "2026-10-24 08:50      31", "2026-10-24 09:00       6",
       r'$ index=linux "Accepted" | rex "for (?<user>\S+) from (?<src_ip>\S+)" | table _time user src_ip',
       "_time                user     src_ip", "2026-10-24 09:14:10  kali     192.168.56.1",
       '$ index=linux "Failed password" | top limit=2 user', "user      count  percent", "root         31  83.8", "admin         6  16.2"],
      "Build a timechart of successful logins per user over the last 7 days.", prompt=SPL)
topic("wineventlog", "Windows events in Splunk", M2,
      "Windows Security events are the core of most enterprise detections. Know the key IDs by heart.",
      "index=wineventlog EventCode=…",
      [("4624 / 4625", "successful / failed logon"), ("4672", "special privileges assigned (admin logon)"), ("4688", "new process created"),
       ("4720", "user account created"), ("4732", "member added to a security-enabled local group")],
      "A new account (4720) quickly added to Administrators (4732) is a classic persistence pattern worth an alert.",
      ["$ index=wineventlog EventCode=4625 | stats count by Account_Name, Source_Network_Address | where count > 10",
       "Account_Name   Source_Network_Address  count", "administrator  192.168.56.23              18",
       "$ index=wineventlog (EventCode=4720 OR EventCode=4732) | table _time EventCode user src_user",
       "_time                EventCode  user       src_user", "2026-10-24 10:02:11  4720       svc_backup  labadmin",
       "2026-10-24 10:02:40  4732       svc_backup  labadmin"],
      "Search for 4672 events and list which accounts logged on with admin rights today.", prompt=SPL)
topic("splunkalerts", "Splunk alerts", M2,
      "Any search can be saved as an alert that runs on a schedule and acts when results appear.",
      "search → schedule → trigger condition → action",
      [("Schedule", "cron, e.g. */5 * * * * (every 5 minutes)"), ("Time range", "last 15 minutes, overlapping the schedule"),
       ("Trigger", "number of results > 0"), ("Actions", "email, webhook, notable event (ES)"), ("Throttle", "suppress repeats per src_ip")],
      "This search is the sequence rule from Module 1, written in SPL.",
      [r'$ index=linux sourcetype=linux_secure ("Failed password" OR "Accepted password") | rex "(?<action>Failed|Accepted) password for (invalid user )?(?<user>\S+) from (?<src_ip>\S+)" | stats count(eval(action="Failed")) as failures count(eval(action="Accepted")) as successes by src_ip user | where failures>=10 AND successes>=1',
       "src_ip          user      failures  successes", "192.168.56.23   analyst         29          1",
       "# save as alert: every 5 min, last 15 min, trigger if results > 0"],
      "Save this search as an alert in your lab and trigger it from your attacker VM.", prompt=SPL)

# ---------- Module 3: Wazuh ----------
topic("wazuh", "Wazuh overview", M3,
      "A free, open-source security platform (SIEM + XDR): endpoint agents, rule-based detection, file integrity monitoring, vulnerability detection and compliance.",
      "agent → server (manager) → indexer → dashboard",
      [("Agent", "runs on endpoints, collects logs and checks"), ("Server", "decoders + rules analyse events, raise alerts"),
       ("Indexer", "stores and searches alerts (OpenSearch-based)"), ("Dashboard", "web UI on 443"),
       ("Ports", "1514 agent events · 1515 enrollment · 55000 API")],
      "Wazuh is the easiest full SIEM to run at home: one VM, one install script, all features.",
      ["$ curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh", "$ sudo bash ./wazuh-install.sh -a",
       "INFO: Starting Wazuh installation assistant.", "INFO: --- Wazuh indexer ---", "INFO: --- Wazuh server ---", "INFO: --- Wazuh dashboard ---",
       "INFO: You can access the web interface https://<wazuh-dashboard-ip>:443", "    User: admin", "    Password: <generated, also saved in wazuh-install-files.tar>",
       "$ systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard", "active", "active", "active"],
      "Run the all-in-one install on a lab VM (the docs recommend 4 vCPU / 8 GB RAM) and log into the dashboard.", prompt=("analyst@wazuh", ":~$"))
topic("agents", "Deploying Wazuh agents", M3,
      "Each monitored host runs an agent that enrolls with the manager and streams events over an encrypted channel.",
      "WAZUH_MANAGER=… apt-get install wazuh-agent",
      [("WAZUH_MANAGER", "manager IP, set at install time"), ("WAZUH_AGENT_NAME", "how the host appears in the dashboard"),
       ("agent_control -l", "list agents and their status (on the manager)"), ("ossec.conf", "agent config: /var/ossec/etc/ossec.conf")],
      "An agent showing 'Disconnected' is itself a signal: on a server it may mean someone stopped it.",
      ["# on web01 (after adding the Wazuh apt repository)", "$ sudo WAZUH_MANAGER='192.168.56.20' WAZUH_AGENT_NAME='web01' apt-get install -y wazuh-agent",
       "Setting up wazuh-agent ...", "$ sudo systemctl enable --now wazuh-agent", "# on the manager", "$ sudo /var/ossec/bin/agent_control -l",
       "Wazuh agent_control. List of available agents:", "   ID: 000, Name: wazuh (server), IP: 127.0.0.1, Active/Local",
       "   ID: 001, Name: web01, IP: any, Active"],
      "Enroll two agents (Linux and, if you can, Windows) and confirm both show as Active.", prompt=("analyst@lab", ":~$"))
topic("logtest", "Decoders & rules", M3,
      "Decoders extract fields from a log line; rules match those fields and assign an ID and a level from 0 to 15.",
      "/var/ossec/bin/wazuh-logtest",
      [("5716", "sshd: authentication failed (level 5)"), ("5720", "sshd: multiple authentication failures (level 10)"),
       ("5710 / 5712", "non-existent user / brute force with non-existent users"), ("5715", "sshd: authentication success"),
       ("wazuh-logtest", "paste a log line, see decoding and the matching rule")],
      "Always test a new log format with wazuh-logtest before relying on it in production.",
      ["$ sudo /var/ossec/bin/wazuh-logtest", "Type one log per line", "Oct 24 08:51:02 web01 sshd[2210]: Failed password for root from 192.168.56.23 port 50412 ssh2",
       "**Phase 2: Completed decoding.", "        name: 'sshd'", "        srcip: '192.168.56.23'", "        srcuser: 'root'",
       "**Phase 3: Completed filtering (rules).", "        id: '5716'", "        level: '5'", "        description: 'sshd: authentication failed.'",
       "**Alert to be generated."],
      "Paste a successful SSH login line into wazuh-logtest. Which rule ID matches?", prompt=("analyst@wazuh", ":~$"))
topic("localrules", "Custom rules", M3,
      "Add your own detections in local_rules.xml. They build on built-in rules and survive upgrades.",
      "/var/ossec/etc/rules/local_rules.xml",
      [("id", "use 100000–120000 for custom rules"), ("level", "0 (ignore) to 15 (critical)"), ("if_sid", "only evaluate when a parent rule fired"),
       ("frequency / timeframe", "threshold correlation"), ("mitre", "tag with an ATT&CK technique")],
      "This rule escalates a successful SSH login from outside the lab subnet to level 12.",
      ["$ sudo cat /var/ossec/etc/rules/local_rules.xml", '<group name="local,sshd,">', '  <rule id="100100" level="12">',
       "    <if_sid>5715</if_sid>", "    <srcip>!192.168.56.0/24</srcip>", "    <description>SSH login from outside the lab subnet</description>",
       "    <mitre><id>T1078</id></mitre>", "  </rule>", "</group>", "$ sudo systemctl restart wazuh-manager"],
      "Write a rule that raises level 12 when root logs in successfully over SSH.", prompt=("analyst@wazuh", ":~$"))
topic("fim", "File Integrity Monitoring", M3,
      "Syscheck hashes watched files and alerts when they are added, changed or deleted.",
      "<syscheck><directories …>",
      [("realtime", "alert immediately instead of on a schedule"), ("report_changes", "include a diff of text files"),
       ("550", "integrity checksum changed"), ("554", "file added to the system"), ("553", "file deleted")],
      "Watch /etc, web roots and startup locations: attackers change them to persist.",
      ["$ sudo grep -A2 '<syscheck>' /var/ossec/etc/ossec.conf", "<syscheck>",
       '  <directories check_all="yes" realtime="yes" report_changes="yes">/etc,/var/www/html</directories>',
       "  <frequency>43200</frequency>", "$ echo '10.0.0.66 bank.example' | sudo tee -a /etc/hosts", "10.0.0.66 bank.example",
       "# on the manager", "$ sudo tail -1 /var/ossec/logs/alerts/alerts.json | jq -r '.rule.id, .rule.description, .syscheck.path'",
       "550", "Integrity checksum changed.", "/etc/hosts"],
      "Enable realtime FIM on /var/www/html, edit index.html, and find the alert with its diff.", prompt=("analyst@web01", ":~$"))
topic("activeresponse", "Active response", M3,
      "Wazuh can run a script automatically when a rule fires, for example blocking the source IP for a few minutes.",
      "<active-response> in the manager's ossec.conf",
      [("command", "firewall-drop, host-deny, disable-account …"), ("location", "local (the agent that saw it) or all"),
       ("rules_id", "which rules trigger it"), ("timeout", "seconds before the action is undone"), ("white_list", "IPs never to block (your admin IP!)")],
      "Automation cuts response time, but a bad rule can lock you out. Whitelist yourself and start with short timeouts.",
      ["$ sudo grep -A5 '<active-response>' /var/ossec/etc/ossec.conf", "<active-response>", "  <command>firewall-drop</command>",
       "  <location>local</location>", "  <rules_id>5712,5720</rules_id>", "  <timeout>600</timeout>",
       "# on web01, after a lab brute-force test", "$ sudo iptables -L INPUT -n | grep 192.168.56.23",
       "DROP       all  --  192.168.56.23        0.0.0.0/0"],
      "Enable firewall-drop for rule 5720, trigger it from your attacker VM, and watch the block expire.", prompt=("analyst@wazuh", ":~$"))
topic("wazuhapi", "Dashboard & API", M3,
      "The dashboard groups features into modules; the REST API lets scripts query and manage everything.",
      "https://<manager>:55000",
      [("Threat Hunting", "search all alerts"), ("FIM", "file changes per agent"), ("Vulnerability Detection", "CVEs in installed packages"),
       ("SCA", "configuration checks against CIS benchmarks"), ("MITRE ATT&CK", "alerts mapped to techniques")],
      "Never hard-code API credentials in scripts you share. Read them from environment variables.",
      ["$ TOKEN=$(curl -sk -u \"$WAZUH_USER:$WAZUH_PASS\" -X POST 'https://192.168.56.20:55000/security/user/authenticate?raw=true')",
       "$ curl -sk -H \"Authorization: Bearer $TOKEN\" 'https://192.168.56.20:55000/agents?select=name,status' | jq -c '.data.affected_items[]'",
       '{"name":"wazuh","status":"active","id":"000"}', '{"name":"web01","status":"active","id":"001"}'],
      "Open the SCA module for one agent. Pick a failed CIS check and fix it on the VM.", prompt=("analyst@soc", ":~$"))

# ---------- Module 4: other platforms ----------
topic("elastic", "Elastic Security", M4,
      "Built on the Elastic Stack: Elasticsearch stores data, Kibana is the UI, and Elastic Agent or Beats collect logs. Data follows ECS.",
      "KQL · EQL · ES|QL",
      [("KQL", "quick filters in Kibana"), ("ES|QL", "piped query language for aggregation"), ("EQL", "event sequences across time"),
       ("Elastic Agent + Fleet", "centrally managed collection"), ("Detection rules", "prebuilt rules mapped to ATT&CK")],
      "EQL sequences express 'A then B by the same user' directly, which is ideal for multi-step attacks.",
      ["$ event.category:authentication and event.outcome:failure and source.ip:192.168.56.23", "29 hits",
       '$ FROM logs-* | WHERE event.outcome == "failure" | STATS attempts = COUNT(*) BY source.ip | SORT attempts DESC | LIMIT 3',
       "attempts  source.ip", "      29  192.168.56.23", "       6  192.168.56.41", "       2  192.168.56.7",
       '$ sequence by user.name with maxspan=5m [authentication where event.outcome == "failure"] with runs=5 [authentication where event.outcome == "success"]',
       "1 sequence found · user.name: analyst"],
      "Rewrite the Splunk brute-force search from Module 2 in ES|QL.", prompt=KIB)
topic("sentinel", "Microsoft Sentinel", M4,
      "A cloud-native SIEM on Azure. Data lands in a Log Analytics workspace and is queried with KQL (Kusto Query Language).",
      "Table | where … | summarize … by …",
      [("Data connectors", "Entra ID, M365, Defender, Syslog, CEF"), ("Analytics rules", "scheduled KQL that creates incidents"),
       ("Workbooks", "dashboards"), ("Playbooks", "Logic Apps automation (SOAR)"), ("Hunting", "saved KQL hunting queries")],
      "Note: this KQL (Kusto) is a different language from Elastic's KQL (Kibana) despite the same acronym.",
      ["$ SecurityEvent | where TimeGenerated > ago(1h) and EventID == 4625 | summarize Attempts = count() by IpAddress, TargetAccount | sort by Attempts desc | take 2",
       "IpAddress       TargetAccount         Attempts", "192.168.56.23   LAB\\administrator         18", "192.168.56.41   LAB\\backup                 4",
       '$ SigninLogs | where ResultType != "0" | summarize Failures = count() by UserPrincipalName, Location | take 2',
       "UserPrincipalName        Location  Failures", "student1@lab.example    IQ              7", "student2@lab.example    DE              3"],
      "Use Microsoft's free KQL training data (the Log Analytics demo workspace) to run a summarize query.", prompt=KQL)
topic("qradar", "IBM QRadar", M4,
      "A commercial SIEM that groups related events into 'offenses'. Searches use AQL, an SQL-like language.",
      "SELECT … FROM events WHERE … LAST n HOURS",
      [("Log sources / DSMs", "parsers for each product"), ("Offenses", "correlated incidents with a magnitude score"),
       ("Flows", "network flow records alongside events"), ("AQL", "SQL-style searching"), ("Reference sets", "watchlists of IPs, users, hashes")],
      "If you know SQL, AQL feels familiar: SELECT, WHERE, GROUP BY, ORDER BY, plus a time clause.",
      ["$ SELECT sourceip, username, COUNT(*) AS attempts FROM events WHERE QIDNAME(qid) ILIKE '%failed%' GROUP BY sourceip, username ORDER BY attempts DESC LAST 1 HOURS",
       "sourceip        username       attempts", "192.168.56.23   root                 29", "192.168.56.41   admin                 6",
       "$ SELECT DATEFORMAT(starttime,'HH:mm') AS t, sourceip, destinationport FROM events WHERE sourceip = '192.168.56.23' LAST 10 MINUTES",
       "t      sourceip        destinationport", "08:51  192.168.56.23   22", "08:55  192.168.56.23   80"],
      "Translate the AQL query above into SPL and into Sentinel KQL.", prompt=AQL)
topic("sigma", "Sigma: one rule, any SIEM", M4,
      "Sigma is an open, YAML-based format for detection rules. Write a rule once and convert it to SPL, KQL, ES|QL and more.",
      "sigma convert -t <backend> rule.yml",
      [("logsource", "what data the rule needs"), ("detection", "selections and a condition"), ("tags", "ATT&CK mapping"),
       ("sigma-cli + backends", "pip install sigma-cli pySigma-backend-splunk"), ("SigmaHQ", "thousands of community rules on GitHub")],
      "Sigma keeps detections portable when your organisation changes SIEM vendor.",
      ["$ cat ssh_failed.yml", "title: SSH Failed Password", "status: experimental", "logsource:", "  product: linux", "  service: auth",
       "detection:", "  keywords:", "    - 'Failed password'", "  condition: keywords", "tags:", "  - attack.t1110", "level: low",
       "$ sigma convert -t splunk --without-pipeline ssh_failed.yml", "\"Failed password\""],
      "Browse github.com/SigmaHQ/sigma, pick one Linux rule, and convert it for your SIEM.", prompt=("analyst@soc", ":~$"))

# ---------- Module 5: hands-on ----------
topic("lab", "Build a home SIEM lab", M5,
      "Three VMs on a host-only network are enough to practise the full detect-and-respond loop safely.",
      "SIEM VM · target VM · attacker VM",
      [("192.168.56.20", "Wazuh all-in-one (or Splunk)"), ("192.168.56.10", "Ubuntu web server with agent / forwarder"),
       ("192.168.56.23", "Kali, used to generate test activity"), ("Snapshots", "take one before every experiment")],
      "Only generate test activity against machines you own. These events are harmless but real.",
      ["# from Kali: write a harmless marker event into syslog on the target", "$ ssh analyst@192.168.56.10 \"logger -p auth.warning 'SIEM-LAB marker event'\"",
       "# from Kali: 10 failed logins against your own lab server", "$ for i in $(seq 10); do ssh -o BatchMode=yes nosuchuser@192.168.56.10 true; done 2>/dev/null",
       "# now search for both in your SIEM", "$ sudo grep -c 'nosuchuser' /var/log/auth.log", "10"],
      "Build the lab, generate both events, and find them in your SIEM within 5 minutes.", prompt=("kali@kali", ":~$"))
topic("investigate", "Investigating an alert", M5,
      "Start from the alert, pivot on its key fields (IP, user, host), and build the timeline.",
      "alert → pivot → timeline → verdict",
      [("Pivot on IP", "what else did this source do?"), ("Pivot on user", "where else did this account log in?"),
       ("Timeline", "first seen, last seen, sequence of events"), ("Verdict", "document and tune")],
      "Lecture 01 tools still matter: jq, grep, sort and uniq work on SIEM exports too.",
      ["$ sudo jq -r 'select(.rule.id==\"5712\") | .data.srcip' /var/ossec/logs/alerts/alerts.json | sort -u", "192.168.56.23",
       "$ sudo jq -r 'select(.data.srcip==\"192.168.56.23\") | .rule.description' /var/ossec/logs/alerts/alerts.json | sort | uniq -c | sort -rn",
       "     29 sshd: Attempt to login using a non-existent user", "      3 sshd: brute force trying to get access to the system. Non existent user.",
       "      1 Host Blocked by firewall-drop Active Response"],
      "Investigate the alerts from your lab test and write a case note (see the triage slide).", prompt=("analyst@wazuh", ":~$"))

# ---------- Rendering ----------
SIMS = []
def parse_examples(lines):
    ex = []
    for ln in lines:
        if ln.startswith("$ "):
            ex.append([ln[2:], []])
        elif ex:
            ex[-1][1].append(ln)
    return ex

def prompt_html(p):
    return f'<span class="pr">{e(p[0])}</span><span class="pc">{e(p[1])}</span>'

def terminal(lines, title, prompt=SH, key=None):
    SIMS.append({"cmd": key, "prompt": list(prompt), "ex": parse_examples(lines)})
    rows = []
    for ln in lines:
        if ln.startswith("$ "):
            rows.append(f'<div class="ln">{prompt_html(prompt)} <span class="cm">{e(ln[2:])}</span></div>')
        elif ln.startswith("# "):
            rows.append(f'<div class="ln co">{e(ln)}</div>')
        else:
            rows.append(f'<div class="ln">{e(ln) or "&nbsp;"}</div>')
    return (f'<div class="term" data-sim="{len(SIMS) - 1}"><div class="bar"><i></i><i></i><i></i><span>{e(title)}</span></div>'
            f'<div class="screen">{"".join(rows)}<div class="ln live">{prompt_html(prompt)} <span class="cur"></span></div></div></div>')

def foot(n, label):
    return f'<footer><span>Lecture 02 · {e(TITLE)}</span><span>{e(label)}</span><span>{n}</span></footer>'

slides = []
slides.append(lambda n: f'''<section class="slide cover" style="--c:#56d4dd">
<div class="cv-left"><p class="kicker">Lecture 02 · Security monitoring</p><h1>SIEM Tools</h1>
<p class="sub">How security teams collect logs, detect attacks and respond, with Splunk, Wazuh, Elastic, Microsoft Sentinel and IBM QRadar.</p>
<p class="meta">{len(T)} topics · 5 modules · query consoles on every slide</p></div>
{terminal(["$ cat agenda.txt", "1. What a SIEM does and why", "2. Splunk and SPL", "3. Wazuh: open-source SIEM/XDR", "4. Elastic, Sentinel, QRadar, Sigma",
           "5. Build and investigate in your own lab", "$ echo 'start monitoring'", "start monitoring"], "analyst@soc: ~")}
{foot(n, "Cover")}</section>''')

slides.append(lambda n: f'''<section class="slide">
<p class="kicker">Before we start</p><h2>How to use this lecture</h2>
<div class="two"><div><ul class="big">
<li><b>Every terminal is a simulator.</b> Click it and type the commands or queries you see. Type <code>help</code> or <code>hint</code>.</li>
<li><b>Outputs are example lab data</b> from a host-only network (192.168.56.0/24). Your results will differ.</li>
<li><b>Generate test activity only against machines you own.</b> A SIEM lab needs no outside targets.</li>
<li>Prerequisite: Lecture 01 (Linux commands). <code>grep</code>, <code>jq</code>, <code>sort</code> and <code>uniq</code> come back here.</li></ul></div>
{terminal(["$ hint", "Try typing one of these:", "  whoami", "$ whoami", "analyst"], "simulator")}</div>
{foot(n, "How to use")}</section>''')

def agenda(n):
    cards = ""
    for i, m in enumerate(MODS, 1):
        names = [t["title"] for t in T if t["mod"] == m]
        if m == M1: names.insert(1, "SIEM architecture")
        if m == M4: names.append("Comparison")
        cards += f'<div class="ag" style="--c:{COLOR[m]}"><h3>{i}. {e(m)} <small>{len(names)}</small></h3><p>{" · ".join(e(x) for x in names)}</p></div>'
    return f'<section class="slide"><p class="kicker">Agenda</p><h2>Five modules</h2><div class="agrid">{cards}</div>{foot(n, "Agenda")}</section>'
slides.append(agenda)

def arch(n):
    steps = [("Log sources", "servers · endpoints · firewall · DNS · cloud"), ("Collection", "agents · forwarders · syslog · APIs"),
             ("Parse & normalize", "fields · common schema · enrichment"), ("Store & index", "fast search · retention"),
             ("Detect & correlate", "rules · thresholds · sequences · ML"), ("Respond", "alerts · dashboards · cases · SOAR")]
    boxes = "".join(f'<li><b>{e(a)}</b><span>{e(b)}</span></li>' for a, b in steps)
    return f'''<section class="slide" style="--c:{COLOR[M1]}"><p class="kicker">{e(M1)}</p><h2>SIEM architecture</h2>
<ol class="pipe">{boxes}</ol>
<div class="archmap"><div><b>Splunk</b><span>forwarder → indexer → search head</span></div><div><b>Wazuh</b><span>agent → server → indexer → dashboard</span></div>
<div><b>Elastic</b><span>Elastic Agent → Elasticsearch → Kibana</span></div><div><b>Sentinel</b><span>connectors → Log Analytics → analytics rules</span></div></div>
{foot(n, "Architecture")}</section>'''

def compare(n):
    rows = [("Splunk", "Commercial", "SPL", "Large SOCs, flexible search, big app ecosystem"),
            ("Wazuh", "Free, open source", "Dashboard search + XML rules", "Endpoints, FIM, compliance, home labs"),
            ("Elastic Security", "Open + paid tiers", "KQL, EQL, ES|QL", "Search at scale, prebuilt detection rules"),
            ("Microsoft Sentinel", "Cloud (Azure)", "KQL (Kusto)", "Microsoft 365 and Azure environments"),
            ("IBM QRadar", "Commercial", "AQL", "Offense-based correlation, flows"),
            ("Graylog", "Open + paid tiers", "Graylog search syntax", "Log management on a budget"),
            ("Security Onion", "Free, open source", "SOC UI / hunting queries", "Network security monitoring (Suricata, Zeek)")]
    body = "".join(f"<tr><td><b>{e(a)}</b></td><td>{e(b)}</td><td><code>{e(c)}</code></td><td>{e(d)}</td></tr>" for a, b, c, d in rows)
    return f'''<section class="slide" style="--c:{COLOR[M4]}"><p class="kicker">{e(M4)}</p><h2>Choosing a SIEM</h2>
<table class="cmp"><thead><tr><th>Tool</th><th>Model</th><th>Query language</th><th>Strong at</th></tr></thead><tbody>{body}</tbody></table>
<p class="note">The concepts transfer: learn one query language well and the others take days, not months.</p>{foot(n, "Comparison")}</section>'''

num = 0
for mi, m in enumerate(MODS, 1):
    group = [t for t in T if t["mod"] == m]
    slides.append(lambda n, m=m, mi=mi, group=group: f'''<section class="slide divider" style="--c:{COLOR[m]}"><p class="kicker">Module {mi} of 5</p>
<h1>{e(m)}</h1><p class="sub">{" · ".join(e(t["title"]) for t in group)}</p>{foot(n, f"Module {mi}")}</section>''')
    for t in group:
        num += 1
        def s(n, t=t, k=num):
            pts = "".join(f"<tr><td><code>{e(a)}</code></td><td>{e(b)}</td></tr>" for a, b in t["points"])
            return f'''<section class="slide cmd topic" style="--c:{COLOR[t["mod"]]}">
<div class="left"><p class="kicker"><span class="num">{k:02d}/{len(T)}</span> {e(t["mod"])}</p>
<h2>{e(t["title"])}</h2><p class="desc">{e(t["desc"])}</p>
<p class="syn"><code>{e(t["headline"])}</code></p>
<table class="flags">{pts}</table>
<div class="use"><b>SOC tip</b><p>{e(t["tip"])}</p></div></div>
<div class="right">{terminal(t["term"], f"{t['prompt'][0]}{t['prompt'][1]}", t["prompt"], t["key"])}
<div class="task"><b>▶ Practice</b> {e(t["task"])}</div></div>
{foot(n, t["title"])}</section>'''
        slides.append(s)
        if t["key"] == "siem":
            slides.append(arch)
    if m == M4:
        slides.append(compare)

slides.append(lambda n: f'''<section class="slide" style="--c:#ff7b72">
<p class="kicker">Final lab</p><h2>Detect, respond, report</h2>
<div class="two"><div><ol class="big">
<li>Build the 3-VM lab and install Wazuh (or Splunk).</li>
<li>Enroll the web server and confirm its logs arrive.</li>
<li>Generate 10 failed SSH logins from Kali. Find rule 5710 / 5712.</li>
<li>Add custom rule 100100 and an active response with a 600 s timeout.</li>
<li>Edit a file under /etc and find the FIM alert (550).</li>
<li>Write a case note: timeline, scope, verdict, tuning.</li></ol></div>
{terminal(["$ sudo /var/ossec/bin/agent_control -l | grep Active", "   ID: 000, Name: wazuh (server), IP: 127.0.0.1, Active/Local", "   ID: 001, Name: web01, IP: any, Active",
           "$ sudo jq -r '.rule.id' /var/ossec/logs/alerts/alerts.json | sort | uniq -c | sort -rn | head -4",
           "     29 5710", "      3 5712", "      1 651", "      1 550"], "analyst@wazuh: ~", ("analyst@wazuh", ":~$"))}</div>
{foot(n, "Final lab")}</section>''')

slides.append(lambda n: f'''<section class="slide cover" style="--c:#56d4dd">
<div class="cv-left"><p class="kicker">Recap</p><h1>Logs tell the story</h1>
<p class="sub">A SIEM collects, normalizes and correlates. The tool changes, the method doesn't: good data, clear rules, careful triage and honest case notes.</p>
<p class="meta">Next: write detections with Sigma · threat hunting · SOAR automation</p></div>
{terminal(["$ man wazuh", "NAME", "       wazuh - free, open-source SIEM + XDR", "$ history | tail -1", "  42  echo 'lecture 02 complete'"], "analyst@soc: ~")}
{foot(n, "Recap")}</section>''')

body = "\n".join(f(i + 1) for i, f in enumerate(slides))

EXTRA_CSS = r"""
.topic h2 { font-family: "Noto Sans", sans-serif; font-size: 40px; letter-spacing: -.01em; line-height: 1.1; }
.topic .desc { font-size: 16.5px; }
.topic .flags td:first-child { white-space: normal; width: 34%; }
.topic .flags td { padding: 4px 8px 4px 0; font-size: 13.5px; }
.topic .use { font-size: 14px; }
.topic .screen { font-size: 12.5px; line-height: 1.5; }
.pipe { list-style: none; display: grid; grid-template-columns: repeat(6, 1fr); gap: 14px; margin-top: 18px; counter-reset: s; }
.pipe li { position: relative; background: var(--panel); border: 1px solid var(--line); border-top: 3px solid var(--c); border-radius: 10px; padding: 16px 14px; min-height: 150px; counter-increment: s; }
.pipe li::before { content: counter(s, decimal-leading-zero); display: block; color: var(--c); font: 600 13px "Fira Code", monospace; margin-bottom: 8px; }
.pipe li:not(:last-child)::after { content: "→"; position: absolute; right: -14px; top: 50%; transform: translate(50%, -50%); color: var(--c); font-size: 20px; }
.pipe b { display: block; font-size: 17px; margin-bottom: 6px; }
.pipe span { color: var(--mut); font-size: 13.5px; line-height: 1.45; }
.archmap { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-top: 34px; }
.archmap div { border: 1px dashed var(--line); border-radius: 8px; padding: 12px 14px; }
.archmap b { display: block; color: var(--c); font-size: 15px; } .archmap span { font: 12.5px "Fira Code", monospace; color: #c9d1d9; }
.cmp { width: 100%; border-collapse: collapse; font-size: 15px; margin-top: 6px; }
.cmp th { text-align: left; color: var(--c); font: 600 12px "Fira Code", monospace; text-transform: uppercase; letter-spacing: .08em; padding: 8px 10px; border-bottom: 2px solid var(--line); }
.cmp td { padding: 10px; border-bottom: 1px solid #21262d; color: #c9d1d9; vertical-align: top; }
.cmp td b { color: var(--fg); }
.note { margin-top: 18px; color: var(--mut); font-size: 15px; }
"""

SIM_DATA = {"sims": SIMS, "info": {t["key"]: {"desc": t["desc"], "syntax": t["headline"], "flags": t["points"],
            "ex": [c for c, _ in parse_examples(t["term"])]} for t in T}}
CSS = (shared / "base.css").read_text(encoding="utf-8") + EXTRA_CSS + (shared / "deck.css").read_text(encoding="utf-8")
EXTRA = ('<script type="application/json" id="sim-data">' + json.dumps(SIM_DATA).replace("</", "<\\/") + "</script>"
         + "<script>" + (shared / "deck.js").read_text(encoding="utf-8") + "</script>")
out = f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SIEM Tools Lecture</title><style>{CSS}</style></head><body>
{body}
{EXTRA}
</body></html>'''
(here / "index.html").write_text(out, encoding="utf-8")
print(f"wrote index.html with {len(slides)} slides")
