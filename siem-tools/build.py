#!/usr/bin/env python3
"""Generate Lecture 02 (SIEM tools) as index.html. Render to PDF with chromium afterwards.

Facts checked against: Wazuh v4.14.9 ruleset (0095-sshd_rules.xml, 0015-ossec_rules.xml) and docs,
sigma-cli source (convert.py), Elastic EQL syntax reference, IBM QRadar AQL reference.
"""
import html, json, pathlib

e = html.escape
here = pathlib.Path(__file__).parent
shared = here.parent / "shared"
TITLE = "SIEM Tools: Splunk, Wazuh & More"
SH = ("analyst@soc", ":~$")

# Topic: key (for `man`), title, module, desc, headline, points[(term, meaning)], tip, task.
# Either `term` (terminal lines: "$ x" typed, "# x" comment, else output) with a shell prompt,
# or `app` (a console mock-up: vendor + recorded queries with their result tables).
T = []
def topic(key, title, mod, desc, headline, points, tip, task, term=None, prompt=SH, app=None):
    T.append(dict(key=key, title=title, mod=mod, desc=desc, headline=headline, points=points, tip=tip, task=task,
                  term=term or [], prompt=prompt, app=app))

M1, M2, M3, M4, M5 = "SIEM Fundamentals", "Splunk", "Wazuh", "Elastic, Sentinel, QRadar & Sigma", "Hands-on SOC Lab"
MODS = [M1, M2, M3, M4, M5]
COLOR = {M1: "#58a6ff", M2: "#ffa657", M3: "#56d4dd", M4: "#d2a8ff", M5: "#ff7b72"}

# Shared lab story: 192.168.56.23 guesses the password of user "analyst" on web01 (29 failures, then 1 success);
# 192.168.56.41 tries root (6), 192.168.56.7 tries admin (2). 37 failed logins in total.
FAIL = "Oct 24 {t} web01 sshd[2210]: Failed password for {u} from {ip} port {p} ssh2"

# ---------- Module 1: Fundamentals ----------
topic("siem", "What is a SIEM?", M1,
      "Security Information and Event Management: one place that collects logs from everything, makes them searchable, and raises alerts when activity looks malicious.",
      "collect → normalize → correlate → alert → retain",
      [("Collect", "pull logs from servers, endpoints, network devices and cloud"), ("Normalize", "turn many formats into common field names"),
       ("Correlate", "link related events across sources and time"), ("Alert", "notify analysts when a rule matches"), ("Retain", "keep history for investigations and compliance")],
      "Without a SIEM an analyst must log into every machine one by one. With it, one query covers the whole estate.",
      "List five log sources in your own lab you would send to a SIEM, and one attack each would reveal.",
      term=["# the slow way: one server at a time",
            "$ ssh web01 \"grep -c 'Failed password' /var/log/auth.log\"", "37",
            "$ ssh db01 \"grep -c 'Failed password' /var/log/auth.log\"", "3",
            "# ...and 200 more servers. In a SIEM it is one search:",
            "$ siem-search 'event.outcome:failure' --last 24h --by host.name",
            "host.name     count", "web01            37", "vpn01            12", "db01              3",
            "# (siem-search is a teaching stand-in for any SIEM's search box)"])
topic("logsources", "Log sources", M1,
      "A SIEM is only as good as the data it receives. These sources give the most security value per byte.",
      "endpoints · identity · network · applications · cloud",
      [("Linux", "/var/log/auth.log, journald, auditd"), ("Windows", "Security log: 4624 logon, 4625 failed, 4688 process, 4720 user created"),
       ("Sysmon", "Event 1 process create, 3 network connect, 11 file create"), ("Network", "firewall, DNS, proxy, IDS (Suricata/Zeek)"),
       ("Cloud / SaaS", "AWS CloudTrail, Entra ID sign-ins, M365 audit")],
      "Start with authentication logs everywhere: most intrusions involve logging in somewhere.",
      "For each Windows event ID on this slide, write one sentence on what attacker action would create it.",
      term=["$ sudo tail -1 /var/log/auth.log", FAIL.format(t="08:51:40", u="analyst", ip="192.168.56.23", p="50466"),
            "$ tail -1 /var/log/apache2/access.log", "192.168.56.23 - - [24/Oct/2026:08:55:10 +0000] \"GET /admin HTTP/1.1\" 403 492",
            "$ jq -r '.EventID, .TargetUserName, .IpAddress' event-4625.json", "4625", "administrator", "192.168.56.23"])
topic("normalize", "Parsing & normalization", M1,
      "Every product writes logs differently. The SIEM extracts fields and maps them to a common schema so one query works across all sources.",
      "raw text → fields → common schema → enrichment",
      [("Field extraction", "regex or decoders pull out user, IP, action"), ("Schemas", "Splunk CIM, Elastic ECS, Sentinel ASIM, OCSF"),
       ("Time", "normalize timestamps to UTC or correlation breaks"), ("Enrichment", "add GeoIP, asset owner, threat-intel matches")],
      "If sources call the same thing 'src', 'SourceIP' and 'client_ip', a rule written for one silently misses the others.",
      "Take three different log lines from your lab and write the ECS field names you would map them to.",
      term=["$ head -1 raw/auth.log", FAIL.format(t="08:51:02", u="analyst", ip="192.168.56.23", p="50412"),
            "$ head -1 normalized/auth.json | jq", "{", '  "@timestamp": "2026-10-24T08:51:02Z",', '  "host.name": "web01",',
            '  "event.category": ["authentication"],', '  "event.outcome": "failure",', '  "user.name": "analyst",',
            '  "source.ip": "192.168.56.23",', '  "source.port": 50412', "}"])
topic("correlation", "Correlation rules", M1,
      "A correlation rule links several events into one meaningful alert, so analysts see incidents instead of noise.",
      "threshold · sequence · first-seen · indicator match",
      [("Threshold", "N events within T minutes (e.g. 8 failed logins in 2 min)"), ("Sequence", "A then B (many failures, then a success)"),
       ("First-seen / rarity", "new admin account, new country, new process"), ("Indicator match", "IP, domain or hash on a threat-intel list")],
      "Correlation turns thousands of raw events into the one alert worth a human's time.",
      "Write in plain English one threshold rule and one sequence rule for your lab web server.",
      term=["$ cat rules/bruteforce_then_success.yml", "name: Brute force followed by successful login", "severity: high",
            "group_by: [source.ip, user.name]", "window: 10m", "sequence:", "  - match: {event.category: authentication, event.outcome: failure}",
            "    count: '>= 10'", "  - match: {event.category: authentication, event.outcome: success}", "mitre: [T1110, T1078]",
            "# generic pseudo-rule: every SIEM writes this in its own language"])
topic("triage", "Alert triage & SOC workflow", M1,
      "Every alert follows the same path. Good notes at each step make the next analyst faster.",
      "triage → investigate → contain → close",
      [("Triage", "real or noise? how severe? which asset?"), ("Investigate", "scope it: which hosts, users, time range"),
       ("Contain", "block IP, disable account, isolate host"), ("Close", "true positive, false positive or benign; document it")],
      "A false positive is still useful: tune the rule so it doesn't fire again for the same benign reason.",
      "Write a case note like this for one alert you generate in your lab this week.",
      term=["$ cat cases/case-0142.md", "# Case 0142: SSH password guessing on web01", "Alert:    Wazuh 5763 sshd brute force (level 10)",
            "Source:   192.168.56.23 (lab attacker VM)", "Scope:    29 failures, then 1 success for user 'analyst'",
            "Action:   IP blocked (firewall-drop), 'analyst' password reset", "Verdict:  True positive (authorized lab test)",
            "Tuning:   none needed"])
topic("mitre", "MITRE ATT&CK mapping", M1,
      "ATT&CK is a public catalogue of attacker techniques. Tagging rules with technique IDs shows what you detect and where the gaps are.",
      "tactic (why) → technique (how) → your detection",
      [("T1110", "Brute Force"), ("T1078", "Valid Accounts"), ("T1059", "Command and Scripting Interpreter"),
       ("T1136", "Create Account"), ("T1053", "Scheduled Task/Job")],
      "Build an ATT&CK coverage map from your rule tags; uncovered techniques become your detection backlog.",
      "Open attack.mitre.org, pick one technique, and describe which log source would detect it.",
      term=["$ grep -H 'attack.t' rules/*.yml", "rules/ssh_bruteforce.yml:    - attack.t1110", "rules/new_local_admin.yml:   - attack.t1136",
            "rules/cron_modified.yml:     - attack.t1053", "$ grep -h 'attack.t' rules/*.yml | sort | uniq -c", "      1 - attack.t1053",
            "      1 - attack.t1110", "      1 - attack.t1136"])

# ---------- Module 2: Splunk ----------
SP_RANGE = "(10/24/26 12:00:00.000 AM to 10/24/26 9:20:00.000 AM)"
SP_FIELDS = ["SELECTED FIELDS", ("a host", "1"), ("a source", "1"), ("a sourcetype", "1"), "INTERESTING FIELDS",
             ("a src", "3"), ("a user", "3"), ("# port", "37"), ("a action", "1")]
def sp_ev(t, u, ip, p):
    return [">", f"10/24/26\n{t}.000 AM", FAIL.format(t=t, u=u, ip=ip, p=p) + "\nhost = web01   source = /var/log/auth.log   sourcetype = linux_secure"]

topic("splunk", "Splunk overview", M2,
      "A commercial data platform widely used as a SIEM. Data is indexed on arrival and searched with SPL, the Search Processing Language.",
      "forwarder → indexer → search head",
      [("Universal Forwarder", "lightweight agent that ships logs"), ("Indexer", "parses, indexes and stores events"),
       ("Search head", "web UI and search engine"), ("Ports", "8000 web · 8089 management · 9997 forwarder input (by convention)"),
       ("Enterprise Security", "premium SIEM app: correlation searches, risk-based alerting")],
      "Splunk offers a trial and a limited free license for learning; check splunk.com for current terms before building a lab.",
      "Install Splunk on a lab VM, enable receiving on 9997, and log in at http://<vm-ip>:8000.",
      term=["$ sudo /opt/splunk/bin/splunk status", "splunkd is running (PID: 1874).", "splunk helpers are running (PIDs: 1880 1902).",
            "$ sudo /opt/splunk/bin/splunk enable listen 9997", "Listening for Splunk data on TCP port 9997.",
            "$ sudo ss -tln | grep -E ':(8000|8089|9997)'", "LISTEN 0  128  0.0.0.0:8000  0.0.0.0:*", "LISTEN 0  128  0.0.0.0:8089  0.0.0.0:*",
            "LISTEN 0  128  0.0.0.0:9997  0.0.0.0:*"], prompt=("analyst@splunk01", ":~$"))
topic("forwarder", "Universal Forwarder", M2,
      "Installed on each source host, the forwarder watches files and sends new lines to the indexer.",
      "splunk add forward-server · splunk add monitor",
      [("add forward-server", "where to send data (indexer:9997)"), ("add monitor", "which file or folder to watch"),
       ("-index", "destination index (create it on the indexer first)"), ("-sourcetype", "tells Splunk how to parse it"),
       ("outputs.conf / inputs.conf", "the config files these commands write")],
      "Use a dedicated index per data type (linux, wineventlog, web) so searches and retention stay manageable.",
      "Forward /var/log/auth.log from a second VM and confirm events arrive with index=linux.",
      term=["# on web01", "$ sudo /opt/splunkforwarder/bin/splunk add forward-server 192.168.56.20:9997", "Added forwarding to: 192.168.56.20:9997.",
            "$ sudo /opt/splunkforwarder/bin/splunk add monitor /var/log/auth.log -index linux -sourcetype linux_secure",
            "Added monitor of '/var/log/auth.log'.", "$ sudo /opt/splunkforwarder/bin/splunk list forward-server", "Active forwards:",
            "\t192.168.56.20:9997", "Configured but inactive forwards:", "\tNone"], prompt=("analyst@web01", ":~$"))
topic("spl", "SPL basics in Search & Reporting", M2,
      "Choose the data first (index, sourcetype, keywords), then pipe the results through commands, like a Linux pipeline.",
      'index=… sourcetype=… "text" | command | command',
      [("index= / sourcetype=", "where to look; always set them"), ("|", "pipe results into the next command"),
       ("rex", "extract a field with a regex"), ("stats count by", "group and count"), ("sort -count", "sort descending")],
      "Same idea as Lecture 01's grep | awk | sort | uniq -c, but across every host at once.",
      "Write a search that counts failed logins per user instead of per source IP.",
      app=dict(vendor="splunk", ex=[
          dict(q='index=linux sourcetype=linux_secure "Failed password"', tab="events",
               tabs={"events": "Events (37)", "statistics": "Statistics"}, meta=f"✓ 37 events {SP_RANGE}    No Event Sampling ▾",
               res=dict(hist=[0, 0, 0, 0, 0, 0, 0, 0, 31, 6, 0, 0], fields=SP_FIELDS, cols=["i", "Time", "Event"],
                        rows=[sp_ev("8:51:40", "analyst", "192.168.56.23", "50466"), sp_ev("8:51:37", "analyst", "192.168.56.23", "50462"),
                              sp_ev("8:51:34", "analyst", "192.168.56.23", "50458")])),
          dict(q=r'index=linux sourcetype=linux_secure "Failed password" | rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)" | stats count by src_ip | sort -count',
               tab="statistics", tabs={"events": "Events (37)", "statistics": "Statistics (3)"}, meta=f"✓ 37 events {SP_RANGE}    No Event Sampling ▾",
               res=dict(cols=["src_ip ⇕", "count ⇕"], rows=[["192.168.56.23", "29"], ["192.168.56.41", "6"], ["192.168.56.7", "2"]])),
          dict(q='index=linux sourcetype=linux_secure "Failed password" | stats count by host', tab="statistics",
               tabs={"events": "Events (37)", "statistics": "Statistics (1)"}, meta=f"✓ 37 events {SP_RANGE}    No Event Sampling ▾",
               res=dict(cols=["host ⇕", "count ⇕"], rows=[["web01", "37"]])),
      ]))
topic("spl2", "SPL toolkit", M2,
      "A handful of commands cover most day-to-day hunting and reporting.",
      "timechart · table · top · where · eval · dedup",
      [("timechart", "counts over time (spot spikes)"), ("table", "choose columns to display"), ("top", "most common values"),
       ("where", "filter on calculated values"), ("eval", "create or transform fields"), ("dedup", "keep one event per value")],
      "timechart is the fastest way to see when an attack started and stopped.",
      "Build a timechart of successful logins per user over the last 7 days.",
      app=dict(vendor="splunk", ex=[
          dict(q='index=linux "Failed password" | timechart span=10m count', tab="visualization",
               tabs={"events": "Events (37)", "statistics": "Statistics (3)"}, meta=f"✓ 37 events {SP_RANGE}    No Event Sampling ▾",
               res=dict(hist=[0, 31, 6], cols=["_time ⇕", "count ⇕"],
                        rows=[["2026-10-24 08:40:00", "0"], ["2026-10-24 08:50:00", "31"], ["2026-10-24 09:00:00", "6"]])),
          dict(q=r'index=linux "Accepted password" | rex "for (?<user>\S+) from (?<src_ip>\S+)" | table _time user src_ip', tab="statistics",
               tabs={"events": "Events (2)", "statistics": "Statistics (2)"}, meta=f"✓ 2 events {SP_RANGE}    No Event Sampling ▾",
               res=dict(cols=["_time ⇕", "user ⇕", "src_ip ⇕"],
                        rows=[["2026-10-24 09:14:10", "kali", "192.168.56.1"], ["2026-10-24 08:52:03", "analyst", "192.168.56.23"]])),
          dict(q='index=linux "Failed password" | top limit=2 user', tab="statistics",
               tabs={"events": "Events (37)", "statistics": "Statistics (2)"}, meta=f"✓ 37 events {SP_RANGE}    No Event Sampling ▾",
               res=dict(cols=["user ⇕", "count ⇕", "percent ⇕"], rows=[["analyst", "29", "78.378378"], ["root", "6", "16.216216"]])),
      ]))
topic("wineventlog", "Windows events in Splunk", M2,
      "Windows Security events are the core of most enterprise detections. Know the key IDs by heart.",
      "index=wineventlog EventCode=…",
      [("4624 / 4625", "successful / failed logon"), ("4672", "special privileges assigned (admin logon)"), ("4688", "new process created"),
       ("4720", "user account created"), ("4732", "member added to a security-enabled local group")],
      "A new account (4720) quickly added to Administrators (4732) is a classic persistence pattern worth an alert.",
      "Search for 4672 events and list which accounts logged on with admin rights today.",
      app=dict(vendor="splunk", ex=[
          dict(q="index=wineventlog EventCode=4625 | stats count by Account_Name, Source_Network_Address | where count > 10", tab="statistics",
               tabs={"events": "Events (22)", "statistics": "Statistics (1)"}, meta=f"✓ 22 events {SP_RANGE}    No Event Sampling ▾",
               res=dict(cols=["Account_Name ⇕", "Source_Network_Address ⇕", "count ⇕"], rows=[["administrator", "192.168.56.23", "18"]])),
          dict(q="index=wineventlog (EventCode=4720 OR EventCode=4732) | table _time EventCode user src_user", tab="statistics",
               tabs={"events": "Events (2)", "statistics": "Statistics (2)"}, meta=f"✓ 2 events {SP_RANGE}    No Event Sampling ▾",
               res=dict(cols=["_time ⇕", "EventCode ⇕", "user ⇕", "src_user ⇕"],
                        rows=[["2026-10-24 10:02:11", "4720", "svc_backup", "labadmin"], ["2026-10-24 10:02:40", "4732", "svc_backup", "labadmin"]])),
          dict(q="index=wineventlog EventCode=4672 | stats count by Account_Name", tab="statistics",
               tabs={"events": "Events (6)", "statistics": "Statistics (2)"}, meta=f"✓ 6 events {SP_RANGE}    No Event Sampling ▾",
               res=dict(cols=["Account_Name ⇕", "count ⇕"], rows=[["labadmin", "4"], ["svc_backup", "2"]])),
      ]))
topic("splunkalerts", "Splunk alerts", M2,
      "Any search can be saved as an alert that runs on a schedule and acts when results appear. This one is Module 1's sequence rule in SPL.",
      "search → Save As › Alert → schedule → trigger → action",
      [("Schedule", "cron, e.g. */5 * * * * (every 5 minutes)"), ("Time range", "last 15 minutes, overlapping the schedule"),
       ("Trigger", "number of results > 0"), ("Actions", "add to Triggered Alerts, email, webhook"), ("Throttle", "suppress repeats per src_ip")],
      "Overlap the time range with the schedule so no event falls between two runs.",
      "Save this search as an alert in your lab and trigger it from your attacker VM.",
      app=dict(vendor="splunk", side="alert", ex=[
          dict(q=r'index=linux sourcetype=linux_secure ("Failed password" OR "Accepted password") | rex "(?<action>Failed|Accepted) password for (invalid user )?(?<user>\S+) from (?<src_ip>\S+)" | stats count(eval(action="Failed")) as failures count(eval(action="Accepted")) as successes by src_ip user | where failures>=10 AND successes>=1',
               tab="statistics", tabs={"events": "Events (39)", "statistics": "Statistics (1)"}, meta=f"✓ 39 events {SP_RANGE}    No Event Sampling ▾",
               res=dict(cols=["src_ip ⇕", "user ⇕", "failures ⇕", "successes ⇕"], rows=[["192.168.56.23", "analyst", "29", "1"]])),
      ]))

# ---------- Module 3: Wazuh ----------
WZ_COLS = ["timestamp", "agent.name", "rule.description", "rule.level", "rule.id"]
def wz(t, d, lvl, rid, agent="web01"):
    return [f"Oct 24, 2026 @ {t}.000", agent, d, str(lvl), str(rid)]

topic("wazuh", "Wazuh overview", M3,
      "A free, open-source security platform (SIEM + XDR): endpoint agents, rule-based detection, file integrity monitoring, vulnerability detection and compliance.",
      "agent → server (manager) → indexer → dashboard",
      [("Agent", "runs on endpoints, collects logs and checks"), ("Server", "decoders + rules analyse events, raise alerts"),
       ("Indexer", "stores and searches alerts (OpenSearch-based)"), ("Dashboard", "web UI on 443"),
       ("Ports", "1514 agent events · 1515 enrollment · 55000 API")],
      "The quickstart puts all components on one host: 4 vCPU / 8 GB RAM / 50 GB covers 1–25 agents (Wazuh docs).",
      "Run the all-in-one install on a lab VM and log into the dashboard.",
      term=["$ curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh", "$ sudo bash ./wazuh-install.sh -a",
            "INFO: Starting Wazuh installation assistant. Wazuh version: 4.14.x", "INFO: --- Wazuh indexer ---", "INFO: --- Wazuh server ---",
            "INFO: --- Wazuh dashboard ---", "INFO: --- Summary ---", "INFO: You can access the web interface https://<wazuh-dashboard-ip>:443",
            "    User: admin", "    Password: <generated; also in wazuh-install-files.tar>", "INFO: Installation finished.",
            "$ systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard", "active", "active", "active"],
      prompt=("analyst@wazuh", ":~$"))
topic("agents", "Deploying Wazuh agents", M3,
      "Each monitored host runs an agent that enrolls with the manager and streams events over an encrypted channel.",
      "WAZUH_MANAGER=… apt-get install wazuh-agent",
      [("WAZUH_MANAGER", "manager IP, set at install time"), ("WAZUH_AGENT_NAME", "how the host appears in the dashboard"),
       ("agent_control -l", "list agents, active or not (on the manager)"), ("ossec.conf", "agent config: /var/ossec/etc/ossec.conf")],
      "An agent showing 'Disconnected' is itself a signal: on a server it may mean someone stopped it.",
      "Enroll two agents (Linux and, if you can, Windows) and confirm both show as Active.",
      term=["# on web01 (after adding the Wazuh apt repository)", "$ sudo WAZUH_MANAGER='192.168.56.20' WAZUH_AGENT_NAME='web01' apt-get install -y wazuh-agent",
            "Setting up wazuh-agent ...", "$ sudo systemctl daemon-reload && sudo systemctl enable --now wazuh-agent", "# on the manager",
            "$ sudo /var/ossec/bin/agent_control -l", "Wazuh agent_control. List of available agents:",
            "   ID: 000, Name: wazuh (server), IP: 127.0.0.1, Active/Local", "   ID: 001, Name: web01, IP: any, Active"],
      prompt=("analyst@lab", ":~$"))
topic("logtest", "Decoders & rules", M3,
      "Decoders extract fields from a log line; rules match those fields and assign an ID and a level from 0 to 15. The deepest matching rule wins.",
      "/var/ossec/bin/wazuh-logtest",
      [("5760", "sshd: authentication failed ('Failed password', level 5)"), ("5763", "brute force: 8 × 5760 from one IP in 120 s (level 10)"),
       ("5710", "attempt to login using a non-existent user (level 5)"), ("5712", "brute force: 8 × 5710 in 120 s (level 10)"),
       ("5715", "sshd: authentication success (level 3)")],
      "Always test a new log format with wazuh-logtest before relying on it in production.",
      "Paste a successful SSH login line ('Accepted password for …') into wazuh-logtest. Which rule ID matches?",
      term=["$ sudo /var/ossec/bin/wazuh-logtest", "Type one log per line", FAIL.format(t="08:51:02", u="analyst", ip="192.168.56.23", p="50412"),
            "**Phase 2: Completed decoding.", "        name: 'sshd'", "        dstuser: 'analyst'", "        srcip: '192.168.56.23'",
            "**Phase 3: Completed filtering (rules).", "        id: '5760'", "        level: '5'", "        description: 'sshd: authentication failed.'",
            "        mitre.id: '['T1110.001', 'T1021.004']'", "**Alert to be generated."],
      prompt=("analyst@wazuh", ":~$"))
topic("localrules", "Custom rules", M3,
      "Add your own detections in local_rules.xml. They build on built-in rules and survive upgrades.",
      "/var/ossec/etc/rules/local_rules.xml",
      [("id", "use 100000–120000 for custom rules"), ("level", "0 (ignore) to 15 (critical)"), ("if_sid", "only evaluate when a parent rule fired"),
       ("frequency / timeframe", "threshold correlation"), ("mitre", "tag with an ATT&CK technique")],
      "This rule escalates a successful SSH login (5715) from outside the lab subnet to level 12.",
      "Write a rule that raises level 12 when root logs in successfully over SSH.",
      term=["$ sudo cat /var/ossec/etc/rules/local_rules.xml", '<group name="local,sshd,">', '  <rule id="100100" level="12">',
            "    <if_sid>5715</if_sid>", "    <srcip>!192.168.56.0/24</srcip>", "    <description>SSH login from outside the lab subnet</description>",
            "    <mitre><id>T1078</id></mitre>", "  </rule>", "</group>", "$ sudo systemctl restart wazuh-manager"],
      prompt=("analyst@wazuh", ":~$"))
topic("fim", "File Integrity Monitoring", M3,
      "Syscheck hashes watched files and alerts when they are added, changed or deleted. By default it scans every 12 hours (43200 s).",
      "<syscheck><directories …>",
      [("realtime", "alert immediately instead of on a schedule"), ("report_changes", "include a diff of text files"),
       ("550", "Integrity checksum changed. (level 7)"), ("553", "File deleted. (level 7)"), ("554", "File added to the system. (level 5)")],
      "Watch /etc, web roots and startup locations: attackers change them to persist.",
      "Enable realtime FIM on /var/www/html, edit index.html, and find the alert with its diff.",
      term=["$ sudo grep -A2 '<syscheck>' /var/ossec/etc/ossec.conf", "<syscheck>", "  <disabled>no</disabled>",
            '  <directories realtime="yes" report_changes="yes">/etc,/var/www/html</directories>',
            "$ echo '10.0.0.66 bank.example' | sudo tee -a /etc/hosts", "10.0.0.66 bank.example",
            "# on the manager", "$ sudo tail -1 /var/ossec/logs/alerts/alerts.json | jq -r '.rule.id, .rule.description, .syscheck.path'",
            "550", "Integrity checksum changed.", "/etc/hosts"], prompt=("analyst@web01", ":~$"))
topic("activeresponse", "Active response", M3,
      "Wazuh can run a script automatically when a rule fires, for example blocking the source IP for a few minutes.",
      "<active-response> in the manager's ossec.conf",
      [("command", "firewall-drop adds the IP to the iptables deny list"), ("location", "local (the agent that saw it), all, defined-agent"),
       ("rules_id", "which rules trigger it"), ("timeout", "seconds before the action is undone"), ("white_list", "IPs never to block (your admin IP!)")],
      "Automation cuts response time, but a bad rule can lock you out. Whitelist yourself and start with short timeouts.",
      "Enable firewall-drop for rule 5763, trigger it from your attacker VM, and watch alerts 651 (blocked) and 652 (unblocked).",
      term=["$ sudo grep -A5 '<active-response>' /var/ossec/etc/ossec.conf", "<active-response>", "  <command>firewall-drop</command>",
            "  <location>local</location>", "  <rules_id>5712,5763</rules_id>", "  <timeout>600</timeout>",
            "# on web01, after a lab brute-force test", "$ sudo iptables -L INPUT -n | grep 192.168.56.23",
            "DROP       all  --  192.168.56.23        0.0.0.0/0"], prompt=("analyst@wazuh", ":~$"))
topic("wazuhui", "Wazuh dashboard: Threat Hunting", M3,
      "The dashboard's Threat Hunting module lists every alert. Filter with DQL on alert fields such as rule.id, rule.level, rule.groups and agent.name.",
      "field:value · and / or / not · rule.level >= 10",
      [("rule.id", "exact rule, e.g. rule.id:5763"), ("rule.level", "severity 0–15; ≥ 10 is a good triage filter"),
       ("rule.groups", "categories: authentication_failed, syscheck …"), ("agent.name", "which endpoint raised it"),
       ("API :55000", "the same data for scripts and automation")],
      "Start each shift with rule.level >= 10, then pivot on the agent and source IP of anything new.",
      "In your lab dashboard, filter rule.groups:syscheck and open one alert to see its diff.",
      app=dict(vendor="wazuh", ex=[
          dict(q="rule.groups:authentication_failed and agent.name:web01", meta="37 hits",
               res=dict(hist=[0, 0, 0, 0, 31, 6, 0, 0], cols=WZ_COLS,
                        rows=[wz("09:02:14", "sshd: authentication failed.", 5, 5760), wz("08:51:40", "sshd: authentication failed.", 5, 5760),
                              wz("08:51:37", "sshd: authentication failed.", 5, 5760), wz("08:51:34", "sshd: authentication failed.", 5, 5760)])),
          dict(q="rule.level >= 10", meta="4 hits",
               res=dict(hist=[0, 0, 0, 0, 3, 1, 0, 0], cols=WZ_COLS,
                        rows=[wz("09:02:20", "sshd: brute force trying to get access to the system. Non existent user.", 10, 5712),
                              wz("08:51:30", "sshd: brute force trying to get access to the system. Authentication failed.", 10, 5763),
                              wz("08:51:00", "sshd: brute force trying to get access to the system. Authentication failed.", 10, 5763)])),
          dict(q="rule.groups:syscheck", meta="2 hits",
               res=dict(hist=[0, 0, 0, 0, 0, 0, 2, 0], cols=WZ_COLS,
                        rows=[wz("10:12:05", "Integrity checksum changed.", 7, 550), wz("10:11:48", "File added to the system.", 5, 554)])),
          dict(q="rule.id:651", meta="1 hit",
               res=dict(hist=[0, 0, 0, 0, 1, 0, 0, 0], cols=WZ_COLS,
                        rows=[wz("08:51:31", "Host Blocked by firewall-drop Active Response", 3, 651)])),
      ]))

# ---------- Module 4: other platforms ----------
KB_COLS = ["@timestamp", "source.ip", "user.name", "event.outcome", "host.name"]
def kb(t, outcome="failure", user="analyst"):
    return [f"Oct 24, 2026 @ {t}.000", "192.168.56.23", user, outcome, "web01"]

topic("elastic", "Elastic Security: Discover", M4,
      "Built on the Elastic Stack: Elasticsearch stores data, Kibana is the UI, Elastic Agent collects it, and fields follow ECS.",
      "KQL · ES|QL · EQL",
      [("KQL", "quick filters in the Discover search bar"), ("ES|QL", "piped query language for aggregation"),
       ("EQL", "event sequences (Timelines › Correlation)"), ("Elastic Agent + Fleet", "centrally managed collection"),
       ("Detection rules", "prebuilt rules mapped to ATT&CK")],
      "EQL's 'with runs' repeats a step, so '5 failures then a success by the same user' is one short query.",
      "Rewrite the Splunk brute-force search from Module 2 in ES|QL.",
      app=dict(vendor="kibana", ex=[
          dict(q="event.category:authentication and event.outcome:failure and source.ip:192.168.56.23", mode="KQL", meta="29 hits",
               res=dict(hist=[0, 0, 4, 12, 13, 0, 0, 0], cols=KB_COLS,
                        rows=[kb("08:51:40"), kb("08:51:37"), kb("08:51:34"), kb("08:51:31")])),
          dict(q='FROM logs-* | WHERE event.outcome == "failure" | STATS attempts = COUNT(*) BY source.ip | SORT attempts DESC | LIMIT 3',
               mode="ES|QL", meta="3 rows",
               res=dict(cols=["attempts", "source.ip"], rows=[["29", "192.168.56.23"], ["6", "192.168.56.41"], ["2", "192.168.56.7"]])),
          dict(q='sequence by user.name with maxspan=5m [authentication where event.outcome == "failure"] with runs=5 [authentication where event.outcome == "success"]',
               mode="EQL", meta="1 sequence · user.name: analyst",
               res=dict(cols=KB_COLS, rows=[kb("08:51:28"), kb("08:51:31"), kb("08:51:34"), kb("08:51:37"), kb("08:51:40"),
                                             kb("08:52:03", "success")])),
      ]))
topic("sentinel", "Microsoft Sentinel: Logs", M4,
      "A cloud-native SIEM on Azure. Data lands in a Log Analytics workspace and is queried with KQL (Kusto Query Language).",
      "Table | where … | summarize … by …",
      [("Data connectors", "Entra ID, M365, Defender, Syslog, CEF"), ("Analytics rules", "scheduled KQL that creates incidents"),
       ("Workbooks", "dashboards"), ("Playbooks", "Logic Apps automation (SOAR)"), ("Hunting", "saved KQL hunting queries")],
      "This KQL (Kusto) is a different language from Elastic's KQL (Kibana) despite the same acronym.",
      "Use Microsoft's free Log Analytics demo environment to run a summarize query.",
      app=dict(vendor="sentinel", ex=[
          dict(q="SecurityEvent\n| where TimeGenerated > ago(1h) and EventID == 4625\n| summarize Attempts = count() by IpAddress, TargetAccount\n| sort by Attempts desc\n| take 2",
               meta="Completed. 2 records · 00:00:00.8",
               res=dict(cols=["IpAddress", "TargetAccount", "Attempts"],
                        rows=[["192.168.56.23", "LAB\\administrator", "18"], ["192.168.56.41", "LAB\\backup", "4"]])),
          dict(q='SigninLogs\n| where ResultType != "0"\n| summarize Failures = count() by UserPrincipalName, Location\n| take 2',
               meta="Completed. 2 records · 00:00:01.1",
               res=dict(cols=["UserPrincipalName", "Location", "Failures"],
                        rows=[["student1@lab.example", "IQ", "7"], ["student2@lab.example", "DE", "3"]])),
          dict(q="SecurityEvent\n| where EventID == 4720\n| project TimeGenerated, Computer, TargetAccount, SubjectAccount",
               meta="Completed. 1 record · 00:00:00.6",
               res=dict(cols=["TimeGenerated [UTC]", "Computer", "TargetAccount", "SubjectAccount"],
                        rows=[["10/24/2026, 10:02:11.000 AM", "DC01.lab.example", "LAB\\svc_backup", "LAB\\labadmin"]])),
      ]))
topic("qradar", "IBM QRadar: Log Activity", M4,
      "A commercial SIEM that groups related events into 'offenses'. Advanced Search uses AQL, an SQL-like language with a time clause.",
      "SELECT … FROM events WHERE … LAST n HOURS",
      [("Log sources / DSMs", "parsers for each product"), ("Offenses", "correlated incidents with a magnitude score"),
       ("Flows", "network flow records alongside events"), ("AQL", "SELECT, WHERE, GROUP BY, ORDER BY + LAST"),
       ("Reference sets", "watchlists of IPs, users, hashes")],
      "If you know SQL, AQL feels familiar. Functions like QIDNAME() and LOGSOURCENAME() turn IDs into readable names.",
      "Translate the first AQL query into SPL and into Sentinel KQL.",
      app=dict(vendor="qradar", ex=[
          dict(q="SELECT sourceip, username, COUNT(*) AS attempts FROM events WHERE QIDNAME(qid) ILIKE '%failed%' GROUP BY sourceip, username ORDER BY attempts DESC LAST 1 HOURS",
               meta="Search results: 2 records", res=dict(cols=["sourceip", "username", "attempts"],
                                                          rows=[["192.168.56.23", "analyst", "29"], ["192.168.56.41", "root", "6"]])),
          dict(q="SELECT DATEFORMAT(starttime, 'HH:mm') AS t, sourceip, destinationport FROM events WHERE sourceip = '192.168.56.23' LAST 10 MINUTES",
               meta="Search results: 2 records", res=dict(cols=["t", "sourceip", "destinationport"],
                                                          rows=[["08:51", "192.168.56.23", "22"], ["08:55", "192.168.56.23", "80"]])),
          dict(q="SELECT LOGSOURCENAME(logsourceid) AS source, COUNT(*) AS events FROM events GROUP BY logsourceid ORDER BY events DESC LAST 24 HOURS",
               meta="Search results: 3 records", res=dict(cols=["source", "events"],
                                                          rows=[["Linux OS @ web01", "1284"], ["Windows Security @ DC01", "960"], ["Firewall @ fw01", "412"]])),
      ]))
topic("sigma", "Sigma: one rule, any SIEM", M4,
      "Sigma is an open, YAML-based format for detection rules. Write a rule once and convert it to SPL, KQL, ES|QL and more.",
      "sigma convert -t <backend> [-p <pipeline>] rule.yml",
      [("logsource", "what data the rule needs"), ("detection", "selections and a condition"), ("tags", "ATT&CK mapping"),
       ("sigma-cli", "pip install sigma-cli · sigma plugin install splunk"), ("--without-pipeline", "convert even when the backend expects a pipeline")],
      "Sigma keeps detections portable when your organisation changes SIEM vendor. SigmaHQ hosts thousands of community rules.",
      "Browse github.com/SigmaHQ/sigma, pick one Linux rule, and convert it for your SIEM.",
      term=["$ cat ssh_failed.yml", "title: SSH Failed Password", "status: experimental", "logsource:", "  product: linux", "  service: auth",
            "detection:", "  keywords:", "    - 'Failed password'", "  condition: keywords", "tags:", "  - attack.t1110", "level: low",
            "$ sigma convert -t splunk --without-pipeline ssh_failed.yml", "\"Failed password\""])

# ---------- Module 5: hands-on ----------
topic("lab", "Build a home SIEM lab", M5,
      "Three VMs on a host-only network are enough to practise the full detect-and-respond loop safely.",
      "SIEM VM · target VM · attacker VM",
      [("192.168.56.20", "Wazuh all-in-one (or Splunk)"), ("192.168.56.10", "web01: Ubuntu web server with agent / forwarder"),
       ("192.168.56.23", "Kali, used to generate test activity"), ("Snapshots", "take one before every experiment")],
      "Only generate test activity against machines you own. These events are harmless but real.",
      "Build the lab, generate both events, and find them in your SIEM within 5 minutes.",
      term=["# from Kali: a harmless marker event in web01's syslog", "$ ssh analyst@192.168.56.10 \"logger -p auth.warning 'SIEM-LAB marker event'\"",
            "# from Kali: 10 logins as a user that does not exist (your own server)", "$ for i in $(seq 10); do ssh -o BatchMode=yes nosuchuser@192.168.56.10 true; done 2>/dev/null",
            "# on web01: the raw evidence", "$ sudo grep -c 'Invalid user nosuchuser' /var/log/auth.log", "10",
            "# expected in Wazuh: 5710 × 10, then 5712 (brute force) once"], prompt=("analyst@lab", ":~$"))
topic("investigate", "Investigating an alert", M5,
      "Start from the alert, pivot on its key fields (IP, user, host), and build the timeline.",
      "alert → pivot → timeline → verdict",
      [("Pivot on IP", "what else did this source do?"), ("Pivot on user", "where else did this account log in?"),
       ("Timeline", "first seen, last seen, sequence of events"), ("Verdict", "document and tune")],
      "Lecture 01 tools still matter: jq, grep, sort and uniq work on SIEM exports too.",
      "Investigate the alerts from your lab test and write a case note (see the triage slide).",
      term=["$ sudo jq -r 'select(.rule.id==\"5712\") | .data.srcip' /var/ossec/logs/alerts/alerts.json | sort -u", "192.168.56.23",
            "$ sudo jq -r 'select(.data.srcip==\"192.168.56.23\") | .rule.description' /var/ossec/logs/alerts/alerts.json | sort | uniq -c | sort -rn",
            "     10 sshd: Attempt to login using a non-existent user", "      1 sshd: brute force trying to get access to the system. Non existent user.",
            "      1 Host Blocked by firewall-drop Active Response"], prompt=("analyst@wazuh", ":~$"))

# ---------- Rendering ----------
SIMS, APPS = [], []
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

def render_res(r):
    """Python twin of renderRes() in shared/deck.js."""
    h = ""
    if r.get("hist"):
        m = max(max(r["hist"]), 1)
        h += '<div class="hist">' + "".join(f'<i style="--h:{round(v / m * 100)}%"></i>' for v in r["hist"]) + "</div>"
    t = ("<table class=\"app-t\"><thead><tr>" + "".join(f"<th>{e(c)}</th>" for c in r["cols"]) + "</tr></thead><tbody>"
         + "".join("<tr>" + "".join(f"<td>{e(c)}</td>" for c in row) + "</tr>" for row in r["rows"]) + "</tbody></table>")
    if r.get("fields"):
        side = "".join(f"<h5>{e(f)}</h5>" if isinstance(f, str) else f"<div><span>{e(f[0])}</span><b>{e(f[1])}</b></div>" for f in r["fields"])
        h += f'<div class="res-split"><aside class="fields">{side}</aside>{t}</div>'
    else:
        h += t
    return h

SEARCH_SVG = '<svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true"><circle cx="10" cy="10" r="6.5" fill="none" stroke="currentColor" stroke-width="2.4"/><path d="M15 15l6 6" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"/></svg>'
EMPTY = {"splunk": "✓ 0 events    No results found.", "wazuh": "0 hits", "kibana": "0 hits", "sentinel": "Completed. No results found.",
         "qradar": "Search results: 0 records"}
MOCK = '<span class="mock">training mock-up</span>'

def app_html(t):
    a = t["app"]
    APPS.append({"vendor": a["vendor"], "empty": EMPTY[a["vendor"]], "ex": a["ex"]})
    i, x = len(APPS) - 1, a["ex"][0]
    v = a["vendor"]
    q = e(x["q"])
    inp = f'<div class="app-in" contenteditable="true" role="textbox" aria-multiline="true" spellcheck="false" aria-label="{e(t["title"])} query">{q}</div>'
    res = f'<div class="app-res">{render_res(x["res"])}</div>'
    meta = f'<div class="app-meta">{e(x["meta"])}</div>'
    if v == "splunk":
        tabs = x.get("tabs", {})
        def tab(k, label):
            on = ' class="on"' if x.get("tab") == k else ""
            return f'<span data-tab="{k}"{on}>{e(tabs.get(k, label))}</span>'
        side = ""
        if a.get("side") == "alert":
            side = ('<aside class="sp-alert"><h6>Save As Alert</h6><dl>'
                    '<dt>Title</dt><dd>SSH brute force then success</dd><dt>Alert type</dt><dd><b>Scheduled</b> · Real-time</dd>'
                    '<dt>Run on Cron Schedule</dt><dd><code>*/5 * * * *</code></dd><dt>Time Range</dt><dd>Last 15 minutes</dd>'
                    '<dt>Trigger alert when</dt><dd>Number of Results &gt; 0</dd><dt>Throttle</dt><dd>☑ suppress by src_ip for 1 hour</dd>'
                    '<dt>Trigger Actions</dt><dd>+ Add to Triggered Alerts · Send email</dd></dl><p><span>Cancel</span><b>Save</b></p></aside>')
        return f'''<div class="app app--splunk" data-app="{i}">
<div class="sp-bar"><b class="sp-logo">splunk<span>&gt;</span>enterprise</b><span>Apps ▾</span><span class="sp-r">Administrator ▾ · Messages ▾ · Settings ▾ · Activity ▾ · Help ▾ · Find</span>{MOCK}</div>
<div class="sp-nav"><span class="on">Search</span><span>Analytics</span><span>Datasets</span><span>Reports</span><span>Alerts</span><span>Dashboards</span><b>Search &amp; Reporting</b></div>
<div class="sp-main"><div class="sp-head"><h4>New Search</h4><span>Save As ▾ &nbsp; Create Table View &nbsp; Close</span></div>
<div class="sp-q">{inp}<span class="sp-time">Last 24 hours ▾</span><button type="button" class="app-go" aria-label="Run search">{SEARCH_SVG}</button></div>
<div class="sp-status">{meta}<span>Job ▾ &nbsp;❚❚ &nbsp;■ &nbsp;↗ &nbsp;⤓ &nbsp;⎙ &nbsp; Smart Mode ▾</span></div>
<div class="sp-tabs">{tab("events", "Events")}{tab("patterns", "Patterns")}{tab("statistics", "Statistics")}{tab("visualization", "Visualization")}</div>
{f'<div class="sp-split">{res}{side}</div>' if side else res}</div></div>'''
    if v == "wazuh":
        return f'''<div class="app app--wazuh" data-app="{i}">
<div class="wz-bar"><span class="wz-burger">☰</span><b class="wz-logo">wazuh<span>.</span></b><span class="wz-crumb">Threat Hunting</span>{MOCK}<span class="wz-r">⚙ &nbsp; ⓘ &nbsp; ◉ admin</span></div>
<div class="wz-tabs"><span>Dashboard</span><span class="on">Events</span><span class="wz-agent">Explore agent ▾</span></div>
<div class="wz-q"><span class="app-mode">DQL</span>{inp}<span class="wz-time">📅 Last 24 hours</span><button type="button" class="app-go">⟳ Refresh</button></div>
<div class="wz-hits">{meta}<span>wazuh-alerts-*</span></div>{res}</div>'''
    if v == "kibana":
        return f'''<div class="app app--kibana" data-app="{i}">
<div class="kb-bar"><b class="kb-logo">elastic</b><span class="kb-search">Find apps, content, and more.</span>{MOCK}<span class="kb-r">⚙ ◉</span></div>
<div class="kb-crumbs">☰ &nbsp;Discover <span>New &nbsp; Open &nbsp; Share &nbsp; Alerts &nbsp; Save</span></div>
<div class="kb-q"><span class="kb-dv">logs-* ▾</span>{inp}<span class="app-mode">{e(x.get("mode", "KQL"))}</span><span class="kb-time">📅 Last 15 minutes</span><button type="button" class="app-go">⟳ Refresh</button></div>
<div class="kb-hits">{meta}</div>{res}</div>'''
    if v == "sentinel":
        return f'''<div class="app app--sentinel" data-app="{i}">
<div class="az-bar"><b>Microsoft Azure</b><span class="az-search">Search resources, services, and docs (G+/)</span>{MOCK}<span class="az-r">⚙ ? ◉</span></div>
<div class="az-crumbs">Home &gt; Microsoft Sentinel &gt; lab-workspace</div>
<div class="az-title"><b>lab-workspace | Logs</b><span>Microsoft Sentinel</span></div>
<div class="az-tools"><button type="button" class="app-go">▶ Run</button><span>Time range : Last hour</span><span>💾 Save ▾</span><span>🔗 Share ▾</span><span>+ New alert rule ▾</span></div>
<div class="az-editor"><div class="az-gutter">1<br>2<br>3<br>4<br>5</div>{inp}</div>
<div class="az-tabs"><span class="on">Results</span><span>Chart</span>{meta}</div>{res}</div>'''
    if v == "qradar":
        return f'''<div class="app app--qradar" data-app="{i}">
<div class="qr-bar"><b>IBM QRadar</b>{MOCK}<span class="qr-r">admin ▾ &nbsp; Help ▾ &nbsp; Messages ▾</span></div>
<div class="qr-tabs"><span>Dashboard</span><span>Offenses</span><span class="on">Log Activity</span><span>Network Activity</span><span>Assets</span><span>Reports</span><span>Admin</span></div>
<div class="qr-tools"><span>Search ▾</span><span>Quick Searches ▾</span><span>Add Filter</span><span>Save Criteria</span><span>Save Results</span><span>Rules ▾</span><span>Actions ▾</span></div>
<div class="qr-q"><span class="qr-sel">Advanced Search ▾</span>{inp}<button type="button" class="app-go">Search</button></div>
<div class="qr-meta">{meta}<span>Viewing: AQL results</span></div>{res}</div>'''
    raise ValueError(v)

def foot(n, label):
    return f'<footer><span>Lecture 02 · {e(TITLE)}</span><span>{e(label)}</span><span>{n}</span></footer>'

slides = []
slides.append(lambda n: f'''<section class="slide cover" style="--c:#56d4dd">
<div class="cv-left"><p class="kicker">Lecture 02 · Security monitoring</p><h1>SIEM Tools</h1>
<p class="sub">How security teams collect logs, detect attacks and respond, with Splunk, Wazuh, Elastic, Microsoft Sentinel and IBM QRadar.</p>
<p class="meta">{len(T)} topics · 5 modules · working console mock-ups and terminals</p></div>
{terminal(["$ cat agenda.txt", "1. What a SIEM does and why", "2. Splunk and SPL", "3. Wazuh: open-source SIEM/XDR", "4. Elastic, Sentinel, QRadar, Sigma",
           "5. Build and investigate in your own lab", "$ echo 'start monitoring'", "start monitoring"], "analyst@soc: ~")}
{foot(n, "Cover")}</section>''')

slides.append(lambda n: f'''<section class="slide">
<p class="kicker">Before we start</p><h2>How to use this lecture</h2>
<div class="two"><div><ul class="big">
<li><b>Every console works.</b> Splunk, Wazuh, Kibana, Sentinel and QRadar screens are interactive mock-ups: type a query, press <b>Enter</b>. Terminals accept commands; type <code>help</code>.</li>
<li><b>Results are example lab data</b> from a host-only network (192.168.56.0/24). Your numbers will differ.</li>
<li><b>Generate test activity only against machines you own.</b> A SIEM lab needs no outside targets.</li>
<li>Prerequisite: Lecture 01 (Linux commands). <code>grep</code>, <code>jq</code>, <code>sort</code> and <code>uniq</code> come back here.</li></ul></div>
{terminal(["$ whoami", "analyst", "$ hint", "Try typing one of the commands shown on each slide."], "simulator")}</div>
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
            ("Wazuh", "Free, open source", "DQL in dashboard + XML rules", "Endpoints, FIM, compliance, home labs"),
            ("Elastic Security", "Open + paid tiers", "KQL, EQL, ES|QL", "Search at scale, prebuilt detection rules"),
            ("Microsoft Sentinel", "Cloud (Azure)", "KQL (Kusto)", "Microsoft 365 and Azure environments"),
            ("IBM QRadar", "Commercial", "AQL", "Offense-based correlation, flows"),
            ("Graylog", "Open + paid tiers", "Graylog search syntax", "Log management on a budget"),
            ("Security Onion", "Free, open source", "SOC UI / hunting queries", "Network security monitoring (Suricata, Zeek)")]
    body = "".join(f"<tr><td><b>{e(a)}</b></td><td>{e(b)}</td><td><code>{e(c)}</code></td><td>{e(d)}</td></tr>" for a, b, c, d in rows)
    return f'''<section class="slide" style="--c:{COLOR[M4]}"><p class="kicker">{e(M4)}</p><h2>Choosing a SIEM</h2>
<table class="cmp"><thead><tr><th>Tool</th><th>Model</th><th>Query language</th><th>Strong at</th></tr></thead><tbody>{body}</tbody></table>
<p class="note">The concepts transfer: learn one query language well and the others take days, not months.</p>{foot(n, "Comparison")}</section>'''

def topic_slide(t, k):
    kicker = f'<p class="kicker"><span class="num">{k:02d}/{len(T)}</span> {e(t["mod"])}</p>'
    pts = "".join(f"<tr><td><code>{e(a)}</code></td><td>{e(b)}</td></tr>" for a, b in t["points"])
    style = f'style="--c:{COLOR[t["mod"]]}"'
    if t["app"]:
        dl = "".join(f"<div><dt><code>{e(a)}</code></dt><dd>{e(b)}</dd></div>" for a, b in t["points"])
        return lambda n: f'''<section class="slide appslide" {style}>
<div class="ap-head"><div>{kicker}<h2>{e(t["title"])}</h2><p class="desc">{e(t["desc"])}</p></div><dl class="ap-pts">{dl}</dl></div>
{app_html(t)}
<div class="ap-foot"><div class="task"><b>▶ Practice</b> {e(t["task"])}</div><p class="ap-tip"><b>SOC tip</b> {e(t["tip"])}</p></div>
{foot(n, t["title"])}</section>'''
    return lambda n: f'''<section class="slide cmd topic" {style}>
<div class="left">{kicker}
<h2>{e(t["title"])}</h2><p class="desc">{e(t["desc"])}</p>
<p class="syn"><code>{e(t["headline"])}</code></p>
<table class="flags">{pts}</table>
<div class="use"><b>SOC tip</b><p>{e(t["tip"])}</p></div></div>
<div class="right">{terminal(t["term"], f"{t['prompt'][0]}{t['prompt'][1]}", t["prompt"], t["key"])}
<div class="task"><b>▶ Practice</b> {e(t["task"])}</div></div>
{foot(n, t["title"])}</section>'''

num = 0
for mi, m in enumerate(MODS, 1):
    group = [t for t in T if t["mod"] == m]
    slides.append(lambda n, m=m, mi=mi, group=group: f'''<section class="slide divider" style="--c:{COLOR[m]}"><p class="kicker">Module {mi} of 5</p>
<h1>{e(m)}</h1><p class="sub">{" · ".join(e(t["title"]) for t in group)}</p>{foot(n, f"Module {mi}")}</section>''')
    for t in group:
        num += 1
        slides.append(topic_slide(t, num))
        if t["key"] == "siem":
            slides.append(arch)
    if m == M4:
        slides.append(compare)

slides.append(lambda n: f'''<section class="slide" style="--c:#ff7b72">
<p class="kicker">Final lab</p><h2>Detect, respond, report</h2>
<div class="two"><div><ol class="big">
<li>Build the 3-VM lab and install Wazuh (or Splunk).</li>
<li>Enroll web01 and confirm its logs arrive.</li>
<li>Generate 10 logins as a non-existent user from Kali. Find rules 5710 and 5712.</li>
<li>Add custom rule 100100 and firewall-drop for 5712/5763 with a 600 s timeout.</li>
<li>Edit a file under /etc and find the FIM alert (550).</li>
<li>Write a case note: timeline, scope, verdict, tuning.</li></ol></div>
{terminal(["$ sudo /var/ossec/bin/agent_control -l | grep Active", "   ID: 000, Name: wazuh (server), IP: 127.0.0.1, Active/Local", "   ID: 001, Name: web01, IP: any, Active",
           "$ sudo jq -r '.rule.id' /var/ossec/logs/alerts/alerts.json | sort | uniq -c | sort -rn | head -4",
           "     10 5710", "      1 5712", "      1 651", "      1 550"], "analyst@wazuh: ~", ("analyst@wazuh", ":~$"))}</div>
{foot(n, "Final lab")}</section>''')

slides.append(lambda n: f'''<section class="slide cover" style="--c:#56d4dd">
<div class="cv-left"><p class="kicker">Recap</p><h1>Logs tell the story</h1>
<p class="sub">A SIEM collects, normalizes and correlates. The tool changes, the method doesn't: good data, clear rules, careful triage and honest case notes.</p>
<p class="meta">Next: write detections with Sigma · threat hunting · SOAR automation</p></div>
{terminal(["$ man wazuh", "NAME", "       wazuh - free, open-source SIEM + XDR", "$ history | tail -1", "  42  echo 'lecture 02 complete'"], "analyst@soc: ~")}
{foot(n, "Recap")}</section>''')

body = "\n".join(f(i + 1) for i, f in enumerate(slides))

SIM_DATA = {"sims": SIMS, "apps": APPS, "info": {t["key"]: {"desc": t["desc"], "syntax": t["headline"], "flags": t["points"],
            "ex": [c for c, _ in parse_examples(t["term"])] or [x["q"].replace("\n", " ") for x in (t["app"] or {}).get("ex", [])]} for t in T}}
CSS = "\n".join((p).read_text(encoding="utf-8") for p in (shared / "base.css", here / "siem.css", shared / "deck.css"))
EXTRA = ('<script type="application/json" id="sim-data">' + json.dumps(SIM_DATA).replace("</", "<\\/") + "</script>"
         + "<script>" + (shared / "deck.js").read_text(encoding="utf-8") + "</script>")
out = f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SIEM Tools Lecture</title><style>{CSS}</style></head><body>
{body}
{EXTRA}
</body></html>'''
(here / "index.html").write_text(out, encoding="utf-8")
print(f"wrote index.html with {len(slides)} slides, {len(APPS)} console mock-ups")
