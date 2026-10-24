#!/usr/bin/env python3
"""Generate the 50-commands slide deck (HTML). Render to PDF with chromium afterwards."""
import html, pathlib

# Each entry: name, category, description, syntax, flags[(flag, meaning)], security use, terminal lines, practice task.
# Terminal lines: "$ cmd" = typed command, "# text" = comment, anything else = output.
C = []
def cmd(name, cat, desc, syntax, flags, use, term, task):
    C.append(dict(name=name, cat=cat, desc=desc, syntax=syntax, flags=flags, use=use, term=term, task=task))

F, T, U, P, N, S = "Files & Navigation", "Text Processing", "Users & Permissions", "Processes & System", "Networking", "Security & Archives"

# ---------- Files & Navigation ----------
cmd("pwd", F, "Prints the full path of the directory you are currently in.", "pwd [-P]",
    [("-P", "show the physical path (resolve symlinks)"), ("-L", "show the logical path (default)")],
    "Always confirm where you are before running commands that change or delete files during an investigation.",
    ["$ pwd", "/home/kali", "$ cd /var/log && pwd", "/var/log", "$ cd /tmp/link-to-logs && pwd -P", "/var/log"],
    "Make a symlink to /etc in your home folder, cd into it, and compare pwd with pwd -P.")
cmd("ls", F, "Lists directory contents, including hidden files and permissions.", "ls [options] [path]",
    [("-l", "long format: permissions, owner, size, date"), ("-a", "include hidden (dot) files"), ("-h", "human-readable sizes"), ("-t", "sort by modification time")],
    "Hidden files and odd permissions are often the first clue when auditing a home folder or web root.",
    ["$ ls -lah ~", "drwx------ 18 kali kali 4.0K Oct 24 09:12 .", "-rw-------  1 kali kali 8.2K Oct 24 09:10 .bash_history",
     "drwx------  2 kali kali 4.0K Oct 20 14:01 .ssh", "-rw-r--r--  1 kali kali  220 Oct  1 10:00 .bashrc",
     "drwxr-xr-x  2 kali kali 4.0K Oct 23 18:44 Desktop", "$ ls -lt /var/log | head -3", "total 2140",
     "-rw-r-----  1 root adm   412K Oct 24 09:12 auth.log", "-rw-r-----  1 root adm   1.1M Oct 24 09:12 syslog"],
    "List /etc sorted by modification time. Which config file changed most recently?")
cmd("cd", F, "Changes the current working directory.", "cd [directory]",
    [("cd ~", "go to your home directory"), ("cd -", "jump back to the previous directory"), ("cd ..", "go up one level"), ("cd /", "go to the filesystem root")],
    "Moving quickly between /var/log, /etc and /tmp is the backbone of every triage session.",
    ["$ cd /etc/ssh", "$ pwd", "/etc/ssh", "$ cd -", "/home/kali", "$ cd ../..", "$ pwd", "/"],
    "From your home folder, reach /var/log/apt using one absolute and one relative path.")
cmd("cat", F, "Concatenates files and prints them to the terminal.", "cat [options] file...",
    [("-n", "number every line"), ("-A", "show hidden characters (tabs, line ends)"), ("-s", "squeeze repeated blank lines")],
    "Quickly read configs such as /etc/passwd or /etc/hosts, and reveal hidden characters with -A.",
    ["$ cat /etc/hosts", "127.0.0.1   localhost", "127.0.1.1   kali", "192.168.56.10 lab-web.local",
     "$ cat -n /etc/passwd | tail -3", "  46  kali:x:1000:1000:Kali,,,:/home/kali:/usr/bin/zsh",
     "  47  postgres:x:122:130::/var/lib/postgresql:/bin/bash", "  48  analyst:x:1001:1001::/home/analyst:/bin/bash"],
    "Use cat -n on /etc/passwd. How many accounts have a real login shell?")
cmd("cp", F, "Copies files and directories.", "cp [options] source dest",
    [("-r", "copy directories recursively"), ("-p", "preserve mode, owner and timestamps"), ("-a", "archive mode (recursive + preserve)"), ("-i", "ask before overwriting")],
    "Preserve evidence: copy logs with -a so timestamps and ownership stay intact for analysis.",
    ["$ mkdir -p ~/case01", "$ sudo cp -a /var/log/auth.log ~/case01/", "$ ls -l ~/case01",
     "-rw-r----- 1 root adm 412K Oct 24 09:12 auth.log", "# timestamp preserved from the original"],
    "Copy /etc/ssh/sshd_config with and without -p and compare the timestamps with ls -l.")
cmd("mv", F, "Moves or renames files and directories.", "mv [options] source dest",
    [("-i", "prompt before overwrite"), ("-n", "never overwrite"), ("-v", "verbose: show what was moved")],
    "Quarantine a suspicious file by moving it into an isolated folder instead of deleting it.",
    ["$ mkdir -p ~/quarantine", "$ mv -v ~/Downloads/invoice.pdf.sh ~/quarantine/", "renamed '/home/kali/Downloads/invoice.pdf.sh' -> '/home/kali/quarantine/invoice.pdf.sh'",
     "$ chmod 000 ~/quarantine/invoice.pdf.sh"],
    "Create a test file, rename it with mv -v, then move it into a new folder.")
cmd("rm", F, "Removes files or directories. There is no recycle bin.", "rm [options] file...",
    [("-i", "ask before every removal"), ("-r", "remove directories recursively"), ("-f", "force, ignore missing files"), ("-v", "verbose")],
    "Clean up lab artifacts safely. Double-check paths: rm -rf on the wrong path is unrecoverable.",
    ["$ ls ~/lab-tmp", "notes.txt  scan-old.xml  test.log", "$ rm -iv ~/lab-tmp/*.log", "rm: remove regular file 'test.log'? y",
     "removed '/home/kali/lab-tmp/test.log'"],
    "Create three files in a test folder and remove only the .log files using rm -i.")
cmd("find", F, "Searches the filesystem by name, type, size, owner, time or permission.", "find [path] [tests] [actions]",
    [("-name", "match a filename pattern"), ("-perm", "match permissions (e.g. -4000 for SUID)"), ("-mtime", "modified N days ago"), ("-user", "owned by a user")],
    "Auditors hunt for SUID binaries, world-writable files and recently changed files after an incident.",
    ["$ find / -perm -4000 -type f 2>/dev/null | head -4", "/usr/bin/passwd", "/usr/bin/sudo", "/usr/bin/mount", "/usr/bin/su",
     "$ find /etc -mtime -1 -type f 2>/dev/null", "/etc/hosts", "$ find /tmp -perm -o+w -type f", "/tmp/build.lock"],
    "Find every file in /etc modified in the last 7 days, and every SUID file on your system.")
cmd("file", F, "Identifies a file's real type by its content, not its extension.", "file [options] file...",
    [("-b", "brief: omit the filename"), ("-i", "print the MIME type"), ("-z", "look inside compressed files")],
    "Extensions lie. 'photo.jpg' might really be an ELF executable or a script; file reveals it.",
    ["$ file photo.jpg report.pdf invoice.pdf.sh", "photo.jpg:        JPEG image data, JFIF standard 1.01",
     "report.pdf:       PDF document, version 1.7", "invoice.pdf.sh:   Bourne-Again shell script, ASCII text executable",
     "$ file -i /usr/bin/ls", "/usr/bin/ls: application/x-pie-executable; charset=binary"],
    "Rename a text file to image.png, then run file on it. What does it report?")

# ---------- Text Processing ----------
cmd("grep", T, "Searches text for lines matching a pattern or regular expression.", "grep [options] pattern [file...]",
    [("-i", "case-insensitive"), ("-r", "search directories recursively"), ("-v", "invert: show non-matching lines"), ("-E", "extended regex"), ("-c", "count matches")],
    "The number one log-analysis tool: find failed logins, error codes or indicators of compromise.",
    ["$ sudo grep -c 'Failed password' /var/log/auth.log", "37",
     "$ sudo grep 'Failed password' /var/log/auth.log | tail -2",
     "Oct 24 08:51:02 kali sshd[2210]: Failed password for root from 192.168.56.23 port 50412",
     "Oct 24 08:51:05 kali sshd[2210]: Failed password for root from 192.168.56.23 port 50418",
     "$ grep -rEi 'password|secret' ~/project/config", "config/app.env:DB_PASSWORD=TODO_change_me"],
    "Search /var/log/auth.log for 'Accepted' to list successful logins on your machine.")
cmd("awk", T, "A pattern-scanning language for extracting and reshaping columns of text.", "awk 'pattern { action }' file",
    [("-F", "set the field separator"), ("$1, $NF", "first field, last field"), ("NR", "current line number")],
    "Pull specific columns out of logs, e.g. the source IP of every failed login.",
    ["$ awk -F: '$7 ~ /bash|zsh/ {print $1}' /etc/passwd", "root", "kali", "postgres", "analyst",
     "$ sudo grep 'Failed password' /var/log/auth.log | awk '{print $(NF-3)}' | head -3",
     "192.168.56.23", "192.168.56.23", "192.168.56.41"],
    "Use awk to print each user's name and home directory from /etc/passwd.")
cmd("sed", T, "A stream editor: find-and-replace and line edits on text streams.", "sed [options] 'script' file",
    [("s/a/b/g", "substitute a with b globally"), ("-n 'Np'", "print only line N"), ("-i", "edit the file in place"), ("/re/d", "delete matching lines")],
    "Redact sensitive data before sharing logs, or strip comments to see the active config.",
    ["$ sed -E 's/[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+/x.x.x.x/g' auth-sample.log | head -2",
     "Oct 24 08:51:02 sshd[2210]: Failed password for root from x.x.x.x port 50412",
     "Oct 24 08:51:05 sshd[2210]: Failed password for root from x.x.x.x port 50418",
     "$ sed -e '/^#/d' -e '/^$/d' /etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf",
     "KbdInteractiveAuthentication no", "UsePAM yes", "X11Forwarding yes"],
    "Show only the active (non-comment) lines of /etc/ssh/sshd_config.")
cmd("cut", T, "Extracts sections (fields or characters) from each line.", "cut [options] file",
    [("-d", "field delimiter"), ("-f", "field numbers to keep"), ("-c", "character positions to keep")],
    "Fast column extraction from CSVs, /etc/passwd or exported logs.",
    ["$ cut -d: -f1,6 /etc/passwd | tail -3", "kali:/home/kali", "postgres:/var/lib/postgresql", "analyst:/home/analyst",
     "$ cut -d, -f2 logins.csv | head -3", "src_ip", "192.168.56.23", "192.168.56.41"],
    "Use cut to list only the usernames from /etc/passwd.")
cmd("sort", T, "Sorts lines alphabetically, numerically or by a chosen column.", "sort [options] file",
    [("-n", "numeric sort"), ("-r", "reverse order"), ("-k", "sort by a column"), ("-u", "unique lines only"), ("-h", "human sizes (1K, 2M)")],
    "Combined with uniq, sort turns raw logs into ranked lists such as 'top attacking IPs'.",
    ["$ du -sh /var/log/* 2>/dev/null | sort -rh | head -4", "52M  /var/log/journal", "1.1M /var/log/syslog",
     "412K /var/log/auth.log", "96K  /var/log/dpkg.log"],
    "Find the five largest folders in your home directory using du and sort.")
cmd("uniq", T, "Filters or counts adjacent duplicate lines (sort first).", "uniq [options] [file]",
    [("-c", "prefix lines with their count"), ("-d", "only show duplicated lines"), ("-u", "only show unique lines")],
    "The classic 'who is hammering my SSH?' pipeline: grep, extract, sort, uniq -c, sort -rn.",
    ["$ sudo grep 'Failed password' /var/log/auth.log \\", "    | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn",
     "     29 192.168.56.23", "      6 192.168.56.41", "      2 192.168.56.7"],
    "Build the pipeline above on your own auth.log. Which source has the most failures?")
cmd("wc", T, "Counts lines, words and bytes.", "wc [options] file",
    [("-l", "count lines"), ("-w", "count words"), ("-c", "count bytes")],
    "Quantify events: how many failed logins, how many users, how many lines in a wordlist.",
    ["$ wc -l /etc/passwd", "48 /etc/passwd", "$ sudo grep -c 'Accepted' /var/log/auth.log", "5",
     "$ ls /usr/bin | wc -l", "2431"],
    "Count how many lines in /etc/group mention the 'sudo' group.")
cmd("tail", T, "Shows the end of a file and can follow it live as it grows.", "tail [options] file",
    [("-n N", "show the last N lines"), ("-f", "follow new lines in real time"), ("-F", "follow even if the file is rotated")],
    "Watch authentication or web-server logs live while you test or while an incident unfolds.",
    ["$ sudo tail -f /var/log/auth.log", "Oct 24 09:14:10 kali sshd[2391]: Accepted publickey for kali from 192.168.56.1",
     "Oct 24 09:14:10 kali sshd[2391]: pam_unix(sshd:session): session opened for user kali",
     "Oct 24 09:15:02 kali sudo:   kali : TTY=pts/1 ; COMMAND=/usr/bin/systemctl status ssh", "^C"],
    "Run tail -f on auth.log in one terminal and use sudo in another. Watch the entry appear.")
cmd("strings", T, "Prints the readable text sequences hidden inside binary files.", "strings [options] file",
    [("-n N", "minimum string length"), ("-a", "scan the whole file"), ("-e l", "16-bit little-endian (Windows) strings")],
    "First look at an unknown binary: embedded URLs, paths and messages reveal what it does.",
    ["$ strings -n 8 ./unknown-sample | grep -Ei 'http|/etc|/tmp' ", "http://update.example.com/check",
     "/etc/cron.d/", "/tmp/.cache_x", "# indicators worth noting in the report"],
    "Run strings on /usr/bin/ls and look for its usage/help text.")
cmd("xxd", T, "Creates a hex dump of a file (or reverses one).", "xxd [options] file",
    [("-l N", "only dump N bytes"), ("-s N", "start at offset N"), ("-r", "reverse a hex dump back to binary")],
    "Inspect file headers ('magic bytes') to confirm a file's true type during forensics.",
    ["$ xxd -l 16 /usr/bin/ls", "00000000: 7f45 4c46 0201 0100 0000 0000 0000 0000  .ELF............",
     "$ xxd -l 8 photo.jpg", "00000000: ffd8 ffe0 0010 4a46                      ......JF",
     "$ xxd -l 4 report.pdf", "00000000: 2550 4446                                %PDF"],
    "Dump the first 16 bytes of a PNG and an ELF file. Compare their magic bytes.")

# ---------- Users & Permissions ----------
cmd("whoami", U, "Prints the username of the current effective user.", "whoami",
    [("(none)", "no common options; same as id -un")],
    "Confirm which account you are acting as, especially after sudo or su.",
    ["$ whoami", "kali", "$ sudo whoami", "root"],
    "Run whoami, then sudo whoami, then explain why the answers differ.")
cmd("id", U, "Shows user ID, group ID and all group memberships.", "id [user]",
    [("-u", "user ID only"), ("-g", "primary group ID only"), ("-G", "all group IDs"), ("-n", "names instead of numbers")],
    "Group membership (sudo, adm, docker) decides what an account can really do; check it in every audit.",
    ["$ id", "uid=1000(kali) gid=1000(kali) groups=1000(kali),4(adm),27(sudo),100(users)",
     "$ id analyst", "uid=1001(analyst) gid=1001(analyst) groups=1001(analyst)"],
    "Check which users on your system belong to the sudo group (hint: getent group sudo).")
cmd("sudo", U, "Runs a single command with another user's (usually root's) privileges.", "sudo [options] command",
    [("-l", "list what you are allowed to run"), ("-u user", "run as a specific user"), ("-i", "start a root login shell"), ("-k", "forget cached credentials")],
    "Least privilege: use sudo per command, and review sudo -l output when auditing accounts.",
    ["$ sudo -l", "User kali may run the following commands on kali:", "    (ALL : ALL) ALL",
     "$ sudo grep -v '^#' /etc/sudoers | grep -v '^$' | tail -2", "root    ALL=(ALL:ALL) ALL", "%sudo   ALL=(ALL:ALL) ALL"],
    "Run sudo -l for your account, then read /etc/sudoers with sudo less (never edit it without visudo).")
cmd("su", U, "Switches to another user account in the current terminal.", "su [options] [user]",
    [("-", "full login environment of the target user"), ("-c cmd", "run one command as that user"), ("-s shell", "use a specific shell")],
    "Test what a low-privilege account can access by switching into it on your own lab system.",
    ["$ sudo su - analyst", "analyst@kali:~$ whoami", "analyst", "analyst@kali:~$ cat /var/log/auth.log",
     "cat: /var/log/auth.log: Permission denied", "analyst@kali:~$ exit"],
    "Create a test user (sudo adduser test1), switch to it, and see which files it cannot read.")
cmd("chmod", U, "Changes file permission bits (read, write, execute).", "chmod [options] mode file",
    [("u/g/o", "user, group, others"), ("+x / -w", "add execute, remove write"), ("600, 755", "octal modes"), ("-R", "recursive")],
    "Lock down secrets: SSH private keys must be 600, otherwise ssh refuses to use them.",
    ["$ ls -l ~/.ssh/id_ed25519", "-rw-r--r-- 1 kali kali 411 Oct 20 14:01 /home/kali/.ssh/id_ed25519",
     "$ chmod 600 ~/.ssh/id_ed25519", "$ ls -l ~/.ssh/id_ed25519", "-rw------- 1 kali kali 411 Oct 20 14:01 /home/kali/.ssh/id_ed25519",
     "# 6 = rw for owner, 0 for group, 0 for others"],
    "Create a script, make it executable with chmod +x, then convert its mode to octal.")
cmd("chown", U, "Changes the owner and group of files.", "chown [options] user[:group] file",
    [("user:group", "set both owner and group"), ("-R", "recursive"), ("--reference=f", "copy ownership from file f")],
    "Wrong ownership on web roots or service files is a common misconfiguration finding.",
    ["$ ls -l /var/www/html/index.html", "-rw-r--r-- 1 kali kali 10701 Oct 22 11:30 index.html",
     "$ sudo chown -R www-data:www-data /var/www/html", "$ ls -l /var/www/html/index.html",
     "-rw-r--r-- 1 www-data www-data 10701 Oct 22 11:30 index.html"],
    "Create a file as root with sudo touch, then give it back to your user with chown.")

# ---------- Processes & System ----------
cmd("ps", P, "Takes a snapshot of running processes.", "ps [options]",
    [("aux", "all processes, with user and CPU/RAM usage"), ("-ef", "full format listing"), ("--forest", "show parent/child tree")],
    "Spot unexpected processes, odd parents, or programs running from /tmp.",
    ["$ ps aux --sort=-%cpu | head -4", "USER   PID %CPU %MEM COMMAND", "kali  2511 12.4  3.1 /usr/bin/firefox-esr",
     "root   812  1.2  0.4 /usr/sbin/sshd -D", "kali  2390  0.6  0.2 -zsh",
     "$ ps -ef --forest | grep -A1 sshd | head -3", "root   812     1  /usr/sbin/sshd -D", "root  2391   812   \\_ sshd: kali [priv]"],
    "List all processes owned by root, then all processes running from /tmp (if any).")
cmd("top", P, "Shows a live, updating view of processes and resource usage.", "top [options]",
    [("-u user", "only one user's processes"), ("-p PID", "watch specific PIDs"), ("P / M", "sort by CPU / memory (inside top)"), ("k", "kill a process (inside top)")],
    "Sudden CPU spikes can indicate cryptominers or runaway processes; top shows them instantly.",
    ["$ top -b -n 1 | head -8", "top - 09:20:11 up 2:14,  2 users,  load average: 0.42, 0.31, 0.25",
     "Tasks: 214 total,   1 running, 213 sleeping", "%Cpu(s):  6.1 us,  1.9 sy, 91.8 id", "MiB Mem :   7951.4 total,   3120.8 free",
     "", "  PID USER   PR  NI  %CPU %MEM  COMMAND", " 2511 kali   20   0  12.4  3.1  firefox-esr"],
    "Open top, press M to sort by memory, then press q. Note the top three processes.")
cmd("kill", P, "Sends a signal to a process, usually to stop it.", "kill [-signal] PID",
    [("-15 (TERM)", "polite stop request (default)"), ("-9 (KILL)", "force stop, cannot be ignored"), ("-l", "list all signals"), ("pkill name", "kill by name")],
    "Containment: stop a malicious or runaway process after recording its details for the report.",
    ["$ sleep 600 &", "[1] 3042", "$ ps -p 3042 -o pid,user,cmd", "  PID USER  CMD", " 3042 kali  sleep 600",
     "$ kill 3042", "[1]  + terminated  sleep 600"],
    "Start sleep 600 in the background, find its PID with ps, and stop it with kill.")
cmd("lsof", P, "Lists open files: and in Linux, sockets and devices are files too.", "lsof [options]",
    [("-i", "network connections"), ("-i :PORT", "who is using a port"), ("-p PID", "files opened by a process"), ("-u user", "files opened by a user")],
    "Map a listening port back to the exact process and binary that opened it.",
    ["$ sudo lsof -i :22", "COMMAND  PID USER  FD  TYPE  NODE NAME", "sshd     812 root  3u  IPv4  TCP  *:ssh (LISTEN)",
     "sshd    2391 root  4u  IPv4  TCP  kali:ssh->192.168.56.1:51522 (ESTABLISHED)",
     "$ sudo lsof -p 812 | grep txt", "sshd 812 root txt REG 8,1 917192 /usr/sbin/sshd"],
    "Find which process is listening on each open port of your machine with lsof -i -P -n.")
cmd("uname", P, "Prints system information such as kernel version and architecture.", "uname [options]",
    [("-a", "all information"), ("-r", "kernel release"), ("-m", "machine architecture")],
    "Kernel version tells you which security patches are present when you assess a host.",
    ["$ uname -a", "Linux kali 6.11.2-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.11.2-1kali1 x86_64 GNU/Linux",
     "$ uname -r", "6.11.2-amd64", "$ cat /etc/os-release | head -2", 'PRETTY_NAME="Kali GNU/Linux Rolling"', 'NAME="Kali GNU/Linux"'],
    "Record your kernel release and compare it with the latest available version after apt update.")
cmd("systemctl", P, "Controls systemd services: start, stop, enable and inspect them.", "systemctl [command] [unit]",
    [("status", "is it running? recent logs"), ("start / stop", "run or halt now"), ("enable / disable", "start at boot or not"), ("list-units --type=service", "list services")],
    "Reduce attack surface: disable services you do not need and check for unknown ones.",
    ["$ systemctl status ssh --no-pager | head -3", "● ssh.service - OpenBSD Secure Shell server",
     "     Loaded: loaded (/usr/lib/systemd/system/ssh.service; disabled)", "     Active: active (running) since Fri 2026-10-24 07:06:12",
     "$ sudo systemctl disable --now ssh", "Removed '/etc/systemd/system/multi-user.target.wants/ssh.service'."],
    "List running services with systemctl list-units --type=service --state=running. Do you need them all?")
cmd("journalctl", P, "Queries the systemd journal (system and service logs).", "journalctl [options]",
    [("-u unit", "logs for one service"), ("-f", "follow live"), ("--since", "time filter, e.g. '1 hour ago'"), ("-p err", "only errors and worse")],
    "Central place to review service activity, failed logins and errors with precise time filters.",
    ["$ journalctl -u ssh --since '1 hour ago' --no-pager | tail -3",
     "Oct 24 08:51:05 kali sshd[2210]: Failed password for root from 192.168.56.23 port 50418",
     "Oct 24 08:51:09 kali sshd[2210]: Connection closed by 192.168.56.23 port 50418",
     "Oct 24 09:14:10 kali sshd[2391]: Accepted publickey for kali from 192.168.56.1",
     "$ journalctl -p err -b --no-pager | wc -l", "4"],
    "Show all error-level messages since the last boot with journalctl -p err -b.")
cmd("crontab", P, "Views and edits scheduled tasks (cron jobs).", "crontab [options]",
    [("-l", "list your cron jobs"), ("-e", "edit your cron jobs"), ("-u user", "act on another user (root)"), ("/etc/cron.*", "system-wide schedules")],
    "Scheduled tasks are a common persistence spot; review every user's crontab and /etc/cron.d.",
    ["$ crontab -l", "# m h dom mon dow command", "0 2 * * * /home/kali/scripts/backup.sh",
     "$ ls /etc/cron.d", "e2scrub_all  php  sysstat", "$ sudo crontab -l -u root", "no crontab for root"],
    "List your crontab and the contents of /etc/cron.d. Can you explain every entry?")

# ---------- Networking ----------
cmd("ip", N, "Shows and configures network interfaces, addresses and routes.", "ip [object] [command]",
    [("ip a", "addresses on every interface"), ("ip r", "routing table"), ("ip link", "interface state"), ("ip neigh", "ARP / neighbour table")],
    "Know your own network position first: your IP, gateway and neighbours on the segment.",
    ["$ ip -br a", "lo        UNKNOWN  127.0.0.1/8", "eth0      UP       192.168.56.101/24",
     "$ ip r", "default via 192.168.56.1 dev eth0", "192.168.56.0/24 dev eth0 proto kernel src 192.168.56.101",
     "$ ip neigh", "192.168.56.1 dev eth0 lladdr 0a:00:27:00:00:00 REACHABLE"],
    "Find your IP address, default gateway and the MAC address of the gateway.")
cmd("ss", N, "Displays sockets: listening ports and active connections (modern netstat).", "ss [options]",
    [("-t / -u", "TCP / UDP"), ("-l", "listening sockets only"), ("-n", "numeric, no name lookup"), ("-p", "show the owning process")],
    "Audit what your host exposes: every listening port should be expected and documented.",
    ["$ sudo ss -tulnp", "Netid State  Local Address:Port  Process", "tcp   LISTEN 0.0.0.0:22          users:((\"sshd\",pid=812))",
     "tcp   LISTEN 127.0.0.1:5432      users:((\"postgres\",pid=901))", "tcp   LISTEN 0.0.0.0:80          users:((\"apache2\",pid=1033))",
     "udp   UNCONN 0.0.0.0:68          users:((\"dhclient\",pid=640))"],
    "List your listening ports with ss -tulnp. Which ones are reachable from other machines (0.0.0.0)?")
cmd("ping", N, "Tests reachability and round-trip time using ICMP echo.", "ping [options] host",
    [("-c N", "send N packets then stop"), ("-i sec", "interval between packets"), ("-W sec", "timeout per reply")],
    "First connectivity check in any lab; also shows whether ICMP is filtered by a firewall.",
    ["$ ping -c 3 192.168.56.10", "64 bytes from 192.168.56.10: icmp_seq=1 ttl=64 time=0.41 ms",
     "64 bytes from 192.168.56.10: icmp_seq=2 ttl=64 time=0.38 ms", "64 bytes from 192.168.56.10: icmp_seq=3 ttl=64 time=0.44 ms",
     "--- 192.168.56.10 ping statistics ---", "3 packets transmitted, 3 received, 0% packet loss"],
    "Ping your gateway 4 times and note the average latency and the TTL value.")
cmd("traceroute", N, "Shows each router hop between you and a destination.", "traceroute [options] host",
    [("-n", "no DNS lookups (faster)"), ("-I", "use ICMP instead of UDP"), ("-T", "use TCP SYN (often passes firewalls)")],
    "Understand network paths and where traffic is filtered or slowed.",
    ["$ traceroute -n example.com", "traceroute to example.com (93.184.215.14), 30 hops max", " 1  192.168.56.1   0.52 ms",
     " 2  10.0.2.2       1.10 ms", " 3  * * *", " 4  93.184.215.14  18.33 ms"],
    "Trace the route to example.com. At which hop does your local network end?")
cmd("dig", N, "Queries DNS servers for records (A, MX, TXT, NS, ...).", "dig [@server] name [type]",
    [("+short", "answers only"), ("MX / TXT / NS", "record type"), ("-x IP", "reverse lookup"), ("@8.8.8.8", "ask a specific resolver")],
    "DNS reconnaissance of your own domains, and checking SPF/DMARC records for email security.",
    ["$ dig +short example.com A", "93.184.215.14", "$ dig +short example.com NS", "a.iana-servers.net.", "b.iana-servers.net.",
     "$ dig +short example.com TXT", "\"v=spf1 -all\""],
    "Look up the MX and TXT records of a domain you own or your school's domain.")
cmd("curl", N, "Transfers data to or from a URL; ideal for inspecting HTTP.", "curl [options] URL",
    [("-I", "fetch headers only"), ("-v", "verbose: show the whole exchange"), ("-L", "follow redirects"), ("-o file", "save to file")],
    "Check security headers (HSTS, CSP, X-Frame-Options) and server banners on your own sites.",
    ["$ curl -sI https://example.com", "HTTP/2 200", "content-type: text/html", "cache-control: max-age=3600",
     "server: ECAcc (nyd/D184)", "$ curl -sI https://example.com | grep -i strict-transport", "# (no output → HSTS header missing)"],
    "Inspect the response headers of a site you own. Which security headers are missing?")
cmd("wget", N, "Downloads files from the web, non-interactively.", "wget [options] URL",
    [("-O file", "save under a chosen name"), ("-c", "resume a partial download"), ("-q", "quiet"), ("--spider", "check the URL exists, download nothing")],
    "Fetch tools and wordlists, then verify their checksums before use.",
    ["$ wget -q https://example.com/tools/tool.tar.gz", "$ wget -q https://example.com/tools/tool.tar.gz.sha256",
     "$ sha256sum -c tool.tar.gz.sha256", "tool.tar.gz: OK"],
    "Download any file with wget, then use --spider to check a URL without downloading.")
cmd("nc", N, "Netcat: reads and writes raw TCP/UDP connections.", "nc [options] host port",
    [("-z", "scan without sending data"), ("-v", "verbose"), ("-l", "listen mode"), ("-w sec", "timeout")],
    "Quick check of whether a port is open, and simple banner checks on your own services.",
    ["$ nc -zv 192.168.56.10 22 80 443", "Connection to 192.168.56.10 22 port [tcp/ssh] succeeded!",
     "Connection to 192.168.56.10 80 port [tcp/http] succeeded!", "nc: connect to 192.168.56.10 port 443 (tcp) failed: Connection refused",
     "$ nc -v 192.168.56.10 22", "SSH-2.0-OpenSSH_9.9p1 Debian-1", "^C"],
    "On two lab VMs: start nc -l 4444 on one and connect to it from the other. Type a message.")
cmd("ssh", N, "Secure Shell: encrypted remote login and command execution.", "ssh [options] user@host",
    [("-i key", "use a specific private key"), ("-p port", "non-default port"), ("-L", "local port forward"), ("-v", "verbose debug")],
    "Secure administration. Prefer key-based login and disable password and root login on servers.",
    ["$ ssh-keygen -t ed25519 -C 'kali@lab'", "Your public key has been saved in /home/kali/.ssh/id_ed25519.pub",
     "$ ssh-copy-id analyst@192.168.56.10", "Number of key(s) added: 1", "$ ssh analyst@192.168.56.10", "analyst@lab-web:~$"],
    "Create an ed25519 key pair and log into a lab VM without a password.")
cmd("scp", N, "Copies files securely between hosts over SSH.", "scp [options] source dest",
    [("-r", "copy directories"), ("-P port", "SSH port (capital P)"), ("-i key", "identity file"), ("-p", "preserve times and modes")],
    "Move evidence or logs off a host over an encrypted channel.",
    ["$ scp -p analyst@192.168.56.10:/var/log/apache2/access.log ~/case01/", "access.log          100%  248KB  12.1MB/s   00:00",
     "$ scp -r ~/reports analyst@192.168.56.10:~/", "summary.pdf         100%   92KB   9.8MB/s   00:00"],
    "Copy a file from your Kali VM to another lab VM, then copy it back with a new name.")
cmd("nmap", N, "Network mapper: discovers hosts, open ports and service versions.", "nmap [options] target",
    [("-sn", "host discovery only (no port scan)"), ("-sV", "detect service versions"), ("-p", "choose ports (e.g. -p 1-1000)"), ("-oN file", "save output")],
    "Inventory your own network and verify firewall rules. Only scan systems you own or are authorised to test.",
    ["$ nmap -sn 192.168.56.0/24", "Nmap scan report for 192.168.56.1", "Nmap scan report for 192.168.56.10",
     "Nmap done: 256 IP addresses (2 hosts up)", "$ nmap -sV -p 22,80,443 192.168.56.10", "PORT    STATE  SERVICE VERSION",
     "22/tcp  open   ssh     OpenSSH 9.9p1 Debian", "80/tcp  open   http    Apache httpd 2.4.62", "443/tcp closed https"],
    "Scan your own lab VM or scanme.nmap.org (explicitly allowed) and compare with ss -tulnp on the target.")
cmd("tcpdump", N, "Captures and inspects network packets from the command line.", "tcpdump [options] [filter]",
    [("-i iface", "interface to capture on"), ("-n", "no name resolution"), ("-w file", "write a .pcap for Wireshark"), ("port 53", "BPF filter expression")],
    "See exactly what crosses the wire: troubleshoot, verify encryption, and record evidence.",
    ["$ sudo tcpdump -i eth0 -n -c 3 port 53", "listening on eth0, link-type EN10MB (Ethernet)",
     "09:31:02.114 IP 192.168.56.101.40122 > 192.168.56.1.53: A? example.com.",
     "09:31:02.131 IP 192.168.56.1.53 > 192.168.56.101.40122: A 93.184.215.14", "3 packets captured",
     "$ sudo tcpdump -i eth0 -w lab.pcap", "# open lab.pcap later in Wireshark"],
    "Capture 20 packets while running dig example.com, and identify the DNS query and answer.")

# ---------- Security & Archives ----------
cmd("iptables", S, "Configures the Linux kernel packet-filtering firewall.", "iptables [-t table] command [rule]",
    [("-L -n -v", "list rules with counters"), ("-A / -I", "append / insert a rule"), ("-j ACCEPT|DROP", "rule action"), ("-P", "set the chain's default policy")],
    "Host hardening: allow only the services you need and drop the rest. (nftables/ufw are modern front-ends.)",
    ["$ sudo iptables -A INPUT -i lo -j ACCEPT", "$ sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
     "$ sudo iptables -A INPUT -p tcp --dport 22 -s 192.168.56.0/24 -j ACCEPT", "$ sudo iptables -P INPUT DROP",
     "$ sudo iptables -L INPUT -n --line-numbers", "1  ACCEPT  all  --  0.0.0.0/0         0.0.0.0/0",
     "2  ACCEPT  all  --  0.0.0.0/0         0.0.0.0/0   state RELATED,ESTABLISHED", "3  ACCEPT  tcp  --  192.168.56.0/24   0.0.0.0/0   tcp dpt:22"],
    "On a lab VM, allow SSH only from your subnet, then verify with nmap from inside and outside it.")
cmd("tar", S, "Bundles files into archives and extracts them, with optional compression.", "tar [options] archive [files]",
    [("-c / -x", "create / extract"), ("-z / -J", "gzip / xz compression"), ("-v", "verbose"), ("-f file", "archive filename"), ("-t", "list contents")],
    "Package collected logs as one evidence bundle; always list (-t) an unknown archive before extracting.",
    ["$ sudo tar -czvf case01-logs.tar.gz /var/log/auth.log /var/log/syslog", "tar: Removing leading '/' from member names",
     "var/log/auth.log", "var/log/syslog", "$ tar -tzvf case01-logs.tar.gz", "-rw-r----- root/adm 421888 2026-10-24 09:12 var/log/auth.log",
     "-rw-r----- root/adm 1153024 2026-10-24 09:12 var/log/syslog"],
    "Archive a folder with tar -czf, list it with -t, and extract it into a new directory.")
cmd("base64", S, "Encodes or decodes data in Base64 text form.", "base64 [options] [file]",
    [("-d", "decode"), ("-w 0", "no line wrapping")],
    "Base64 is encoding, NOT encryption. Analysts decode it constantly when reviewing logs and scripts.",
    ["$ echo -n 'hello lab' | base64", "aGVsbG8gbGFi", "$ echo 'aGVsbG8gbGFi' | base64 -d", "hello lab",
     "# anyone can decode it: never use base64 to 'protect' a secret"],
    "Encode your name in Base64, then decode it. Why is this not a way to hide passwords?")
cmd("sha256sum", S, "Computes and verifies SHA-256 cryptographic hashes.", "sha256sum [options] file",
    [("-c file", "check hashes listed in a file"), ("--quiet", "only report failures"), ("md5sum / sha1sum", "older (weaker) siblings")],
    "Verify downloads, prove evidence integrity, and look up file hashes in threat-intel databases.",
    ["$ sha256sum case01-logs.tar.gz | tee case01.sha256", "4f2a9c...e81b  case01-logs.tar.gz",
     "$ sha256sum -c case01.sha256", "case01-logs.tar.gz: OK", "$ echo ' ' >> case01-logs.tar.gz && sha256sum -c case01.sha256",
     "case01-logs.tar.gz: FAILED", "sha256sum: WARNING: 1 computed checksum did NOT match"],
    "Hash a file, change one character in it, and hash it again. How much of the hash changes?")
cmd("openssl", S, "A toolkit for TLS, certificates, hashing and encryption.", "openssl [command] [options]",
    [("s_client -connect", "inspect a server's TLS"), ("x509 -text", "read certificate details"), ("rand -hex N", "generate random bytes"), ("enc -aes-256-cbc", "encrypt a file")],
    "Check certificate expiry and TLS configuration of your services; generate strong random secrets.",
    ["$ echo | openssl s_client -connect example.com:443 2>/dev/null | openssl x509 -noout -dates",
     "notBefore=Jan 15 00:00:00 2026 GMT", "notAfter=Jan 15 23:59:59 2027 GMT",
     "$ openssl rand -hex 16", "9b1f0c7e3a5d42e8b6c1f09a7d3e5b24"],
    "Check the certificate expiry date of a website you use daily with openssl s_client.")

assert len(C) == 50, len(C)

CATS = [F, T, U, P, N, S]
CAT_COLOR = {F: "#58a6ff", T: "#d2a8ff", U: "#ffa657", P: "#7ee787", N: "#79c0ff", S: "#ff7b72"}
e = html.escape

def term_html(lines):
    out = []
    for ln in lines:
        if ln.startswith("$ "):
            out.append(f'<div class="ln"><span class="pr">kali@kali</span><span class="pc">:~$</span> <span class="cm">{e(ln[2:])}</span></div>')
        elif ln.startswith("# "):
            out.append(f'<div class="ln co">{e(ln)}</div>')
        elif ln.startswith("    ") and out and out[-1].endswith("\\</span></div>"):
            out.append(f'<div class="ln cm">{e(ln)}</div>')
        else:
            out.append(f'<div class="ln">{e(ln) or "&nbsp;"}</div>')
    return "".join(out)

SIMS = []  # one entry per terminal; the browser simulator answers from these
def parse_examples(lines):
    ex = []
    for ln in lines:
        if ln.startswith("$ "):
            ex.append([ln[2:], []])
        elif ex and ex[-1][0].endswith("\\") and ln.startswith("    ") and not ex[-1][1]:
            ex[-1][0] = ex[-1][0][:-1].rstrip() + " " + ln.strip()
        elif ex:
            ex[-1][1].append(ln)
    return ex

def terminal(lines, title="kali@kali: ~", cmd=None):
    SIMS.append({"cmd": cmd, "ex": parse_examples(lines)})
    return f'''<div class="term" data-sim="{len(SIMS) - 1}"><div class="bar"><i></i><i></i><i></i><span>{e(title)}</span></div>
<div class="screen">{term_html(lines)}<div class="ln live"><span class="pr">kali@kali</span><span class="pc">:~$</span> <span class="cur"></span></div></div></div>'''

slides = []
TOTAL = 50 + 9  # cover, ethics, agenda, 6 section dividers... computed below for footer
def foot(n, label):
    return f'<footer><span>Top 50 Linux Commands for Cybersecurity</span><span>{e(label)}</span><span>{n}</span></footer>'

# Cover
slides.append(lambda n: f'''<section class="slide cover">
<div class="cv-left"><p class="kicker">Lecture · Linux for Cybersecurity</p>
<h1>The 50 Most-Used<br>Linux Commands</h1>
<p class="sub">for security analysts, sysadmins and blue/red-team learners — every command with a hands-on terminal practice.</p>
<p class="meta">50 commands · 6 modules · practice tasks on every slide</p></div>
{terminal(["$ whoami", "student", "$ cat goals.txt", "1. Navigate and read any Linux system", "2. Analyse logs like an investigator",
           "3. Audit users, services and ports", "4. Harden and verify a host", "$ echo 'lets begin'", "lets begin"])}
{foot(n, "Cover")}</section>''')

# Ethics / lab
slides.append(lambda n: f'''<section class="slide">
<p class="kicker">Before we start</p><h2>Your lab & the rules</h2>
<div class="two"><div><ul class="big">
<li><b>Practise on systems you own</b> — a Kali VM plus one or two target VMs on a host-only network (e.g. 192.168.56.0/24).</li>
<li><b>Scanning or testing other people's systems without written permission is illegal</b> in most countries. scanme.nmap.org is one host that explicitly allows light scanning.</li>
<li><b>Take snapshots</b> before you experiment, so you can always roll back.</li>
<li>Output in these slides is <b>example output</b> from a lab: your numbers will differ.</li></ul></div>
{terminal(["# typical lab layout", "$ ip -br a", "eth0  UP  192.168.56.101/24   # Kali", "# target VM: 192.168.56.10 (lab-web)",
           "$ ping -c 1 192.168.56.10", "64 bytes from 192.168.56.10: ttl=64 time=0.4 ms", "# ready."], "lab setup")}</div>
{foot(n, "Lab & ethics")}</section>''')

# Agenda
def agenda(n):
    rows = ""
    for c in CATS:
        names = [x["name"] for x in C if x["cat"] == c]
        rows += f'<div class="ag" style="--c:{CAT_COLOR[c]}"><h3>{e(c)} <small>{len(names)}</small></h3><p>{" · ".join(f"<code>{e(x)}</code>" for x in names)}</p></div>'
    return f'<section class="slide"><p class="kicker">Agenda</p><h2>Six modules, fifty commands</h2><div class="agrid">{rows}</div>{foot(n, "Agenda")}</section>'
slides.append(agenda)

num = 0
for mi, c in enumerate(CATS, 1):
    group = [x for x in C if x["cat"] == c]
    def divider(n, c=c, mi=mi, group=group):
        return f'''<section class="slide divider" style="--c:{CAT_COLOR[c]}"><p class="kicker">Module {mi} of 6</p>
<h1>{e(c)}</h1><p class="sub">{" ".join(f"<code>{e(x["name"])}</code>" for x in group)}</p>{foot(n, f"Module {mi}")}</section>'''
    slides.append(divider)
    for x in group:
        num += 1
        def s(n, x=x, k=num):
            flags = "".join(f"<tr><td><code>{e(f)}</code></td><td>{e(m)}</td></tr>" for f, m in x["flags"])
            return f'''<section class="slide cmd" style="--c:{CAT_COLOR[x["cat"]]}">
<div class="left"><p class="kicker"><span class="num">{k:02d}/50</span> {e(x["cat"])}</p>
<h2 class="mono">{e(x["name"])}</h2><p class="desc">{e(x["desc"])}</p>
<p class="syn"><code>{e(x["syntax"])}</code></p>
<table class="flags">{flags}</table>
<div class="use"><b>Security use</b><p>{e(x["use"])}</p></div></div>
<div class="right">{terminal(x["term"], cmd=x["name"])}
<div class="task"><b>▶ Practice</b> {e(x["task"])}</div></div>
{foot(n, x["name"])}</section>'''
        slides.append(s)

# Combined challenge + recap
slides.append(lambda n: f'''<section class="slide">
<p class="kicker">Final lab</p><h2>Put it together: a mini investigation</h2>
<div class="two"><div><ol class="big">
<li>Who has logged in, and who failed? <code>grep · awk · sort · uniq</code></li>
<li>What is listening, and which process owns it? <code>ss · lsof · ps</code></li>
<li>Anything scheduled or recently changed? <code>crontab · find</code></li>
<li>Package the evidence and prove its integrity. <code>tar · sha256sum</code></li>
<li>Harden: disable unused services, firewall the rest. <code>systemctl · iptables</code></li></ol></div>
{terminal(["$ sudo grep 'Failed password' /var/log/auth.log \\", "    | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -3",
           "     29 192.168.56.23", "$ sudo ss -tulnp | grep LISTEN | wc -l", "3", "$ find /etc -mtime -1 -type f", "/etc/hosts",
           "$ sudo tar -czf case.tgz /var/log/auth.log && sha256sum case.tgz", "4f2a9c...e81b  case.tgz"], "case01")}</div>
{foot(n, "Final lab")}</section>''')

slides.append(lambda n: f'''<section class="slide cover">
<div class="cv-left"><p class="kicker">Recap</p><h1>Keep practising</h1>
<p class="sub">Read the manual for any command with <code>man &lt;command&gt;</code> or <code>&lt;command&gt; --help</code>. Repeat each practice task until you can do it without the slide.</p>
<p class="meta">Next steps: shell scripting · log analysis with journalctl · Wireshark · hardening benchmarks (CIS)</p></div>
{terminal(["$ man grep | head -4", "GREP(1)              User Commands              GREP(1)", "", "NAME",
           "       grep - print lines that match patterns", "$ history | wc -l", "50", "$ exit"])}
{foot(n, "Recap")}</section>''')

body = "\n".join(f(i + 1) for i, f in enumerate(slides))

CSS = r"""
@page { size: 1280px 720px; margin: 0; }
:root { --bg:#0d1117; --panel:#161b22; --line:#30363d; --fg:#e6edf3; --mut:#9da7b3; --term:#0a0e14; --green:#7ee787; --blue:#58a6ff; }
* { box-sizing: border-box; margin: 0; padding: 0; }
html, body { background: #05070a; color: var(--fg); font-family: "Noto Sans", "Cantarell", sans-serif; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
code, .mono, .term { font-family: "Fira Code", "Hack", "DejaVu Sans Mono", monospace; }
.slide { width: 1280px; height: 720px; position: relative; overflow: hidden; padding: 56px 64px 70px;
  background: radial-gradient(1200px 600px at 100% 0%, color-mix(in srgb, var(--c, #58a6ff) 9%, transparent), transparent 60%), var(--bg);
  margin: 0 auto 24px; break-after: page; page-break-after: always; }
@media print { .slide { margin: 0; } body { background: var(--bg); } }
.kicker { color: var(--c, var(--blue)); font: 600 15px/1 "Fira Code", monospace; letter-spacing: .08em; text-transform: uppercase; margin-bottom: 14px; }
h1 { font-size: 58px; line-height: 1.05; letter-spacing: -.02em; }
h2 { font-size: 40px; line-height: 1.1; margin-bottom: 22px; }
.sub { color: var(--mut); font-size: 21px; line-height: 1.5; margin-top: 20px; max-width: 560px; }
.meta { margin-top: 28px; color: var(--green); font: 14px "Fira Code", monospace; }
code { background: #1f2630; padding: 1px 6px; border-radius: 4px; font-size: .9em; color: #c9d1d9; }
footer { position: absolute; left: 64px; right: 64px; bottom: 22px; display: flex; justify-content: space-between; color: #6e7781; font: 12px "Fira Code", monospace; border-top: 1px solid var(--line); padding-top: 10px; }

.cover { display: grid; grid-template-columns: 1fr 520px; gap: 48px; align-items: center; }
.cover .term { height: 420px; }
.two { display: grid; grid-template-columns: 1fr 500px; gap: 40px; align-items: start; }
.big { font-size: 18px; line-height: 1.55; padding-left: 22px; color: #c9d1d9; }
.big li { margin-bottom: 12px; } .big b { color: var(--fg); }
.agrid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 18px; }
.ag { background: var(--panel); border: 1px solid var(--line); border-top: 3px solid var(--c); border-radius: 10px; padding: 16px 18px; min-height: 230px; }
.ag h3 { font-size: 19px; margin-bottom: 10px; } .ag small { color: var(--c); font-family: "Fira Code", monospace; margin-left: 6px; }
.ag p { line-height: 2; font-size: 14px; }
.divider { display: flex; flex-direction: column; justify-content: center; }
.divider h1 { font-size: 76px; color: var(--c); }
.divider .sub { max-width: 900px; line-height: 2.1; }

.cmd { display: grid; grid-template-columns: 470px 1fr; gap: 36px; }
.cmd h2 { font-size: 54px; color: var(--c); margin-bottom: 10px; }
.num { color: var(--fg); background: color-mix(in srgb, var(--c) 22%, transparent); padding: 3px 8px; border-radius: 4px; margin-right: 8px; }
.desc { font-size: 18px; line-height: 1.45; color: #c9d1d9; margin-bottom: 14px; }
.syn code { font-size: 15px; color: var(--green); background: var(--term); border: 1px solid var(--line); padding: 6px 10px; display: inline-block; }
.flags { margin-top: 14px; border-collapse: collapse; width: 100%; font-size: 14px; }
.flags td { padding: 5px 8px 5px 0; border-bottom: 1px solid #21262d; vertical-align: top; color: #c9d1d9; }
.flags td:first-child { white-space: nowrap; width: 1%; padding-right: 14px; }
.flags code { color: var(--c); }
.use { margin-top: 16px; background: var(--panel); border-left: 3px solid var(--c); border-radius: 6px; padding: 10px 14px; font-size: 14.5px; line-height: 1.45; }
.use b { color: var(--c); font-size: 12px; text-transform: uppercase; letter-spacing: .08em; }
.use p { color: #c9d1d9; margin-top: 4px; }
.right { display: flex; flex-direction: column; gap: 14px; min-width: 0; }
.right .term { flex: 1; }
.task { background: color-mix(in srgb, var(--green) 9%, var(--panel)); border: 1px dashed color-mix(in srgb, var(--green) 50%, transparent); border-radius: 8px; padding: 12px 16px; font-size: 15px; line-height: 1.45; color: #d1d9e0; }
.task b { color: var(--green); font-family: "Fira Code", monospace; margin-right: 6px; }

.term { background: var(--term); border: 1px solid var(--line); border-radius: 10px; overflow: hidden; box-shadow: 0 18px 50px rgba(0,0,0,.45); display: flex; flex-direction: column; min-width: 0; }
.bar { background: #1c2128; height: 32px; display: flex; align-items: center; gap: 7px; padding: 0 12px; border-bottom: 1px solid var(--line); flex: none; }
.bar i { width: 12px; height: 12px; border-radius: 50%; background: #ff5f57; } .bar i:nth-child(2) { background: #febc2e; } .bar i:nth-child(3) { background: #28c840; }
.bar span { margin-left: 10px; color: var(--mut); font-size: 12.5px; }
.screen { padding: 14px 16px; font-size: 13px; line-height: 1.55; color: #b3bdc8; white-space: pre-wrap; word-break: break-all; overflow: hidden; }
.ln + .ln:has(.pr) { margin-top: 6px; }
.pr { color: #ff5c8a; font-weight: 600; } .pc { color: var(--blue); font-weight: 600; }
.cm { color: #f0f6fc; } .co { color: #6a9955; font-style: italic; }
.cur { display: inline-block; width: 8px; height: 15px; background: var(--green); vertical-align: -3px; }
"""

import json
here = pathlib.Path(__file__).parent
SIM_DATA = {"sims": SIMS, "info": {x["name"]: {"desc": x["desc"], "syntax": x["syntax"], "flags": x["flags"],
            "ex": [c for c, _ in parse_examples(x["term"])]} for x in C}}
DECK_CSS = (here / "deck.css").read_text(encoding="utf-8")
EXTRA = ('<script type="application/json" id="sim-data">' + json.dumps(SIM_DATA).replace("</", "<\\/") + '</script>'
         + '<script>' + (here / "deck.js").read_text(encoding="utf-8") + '</script>')
out = f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Top 50 Linux Commands</title><style>{CSS}{DECK_CSS}</style></head><body>
{body}
{EXTRA}
</body></html>'''
dest = pathlib.Path(__file__).with_name("index.html")
dest.write_text(out, encoding="utf-8")
print(f"wrote {dest} with {len(slides)} slides")
