# Custom Python FIM and Wazuh lab (made by ai for friend)

File integrity monitor for the month-7 lab. It hashes configured files with SHA-256, writes one JSON event per line, and leaves collection to the Wazuh agent on Kali.
## Lab network
| Segment | Network | Host | Address |
| --- | --- | --- | --- |
| LAN1 gateway | 192.168.10.0/24 | pfSense | 192.168.10.1 |
| LAN1 | 192.168.10.0/24 | Windows workstation | 192.168.10.10 |
| LAN1 | 192.168.10.0/24 | Kali Linux (FIM agent) | 192.168.10.20 |
| LAN2 gateway | 192.168.20.0/24 | pfSense | 192.168.20.1 |
| LAN2 | 192.168.20.0/24 | Wazuh manager | 192.168.20.10 |
The LAN2 firewall address is **192.168.20.1**. That interface has to sit inside `192.168.20.0/24` with the Wazuh manager. An address of `192.168.1.1` is a different subnet and cannot be the LAN2 gateway.
pfSense needs a pass rule from `192.168.10.20` to `192.168.20.10` for TCP `1514` (agent events) and TCP `1515` (agent enrollment).
```text
Windows 192.168.10.10 --+
                        +-- pfSense 192.168.10.1 / 192.168.20.1 -- Wazuh 192.168.20.10
Kali     192.168.10.20 --+          FIM JSON log --> wazuh-agent
```
## Project layout
```text
config.yaml          monitored paths, poll interval, severity, optional HTTP forward
hasher.py            SHA-256 snapshots and baseline records
logger.py            JSONL writer and optional HTTP forward
fim.py               baseline load, comparison, poll loop, watchdog wakeups
requirements.txt     pyyaml, watchdog, requests
wazuh/               agent localfile block and manager rules
watched/             safe lab directory that does not require root
```
## Run the monitor
On Kali, install the Wazuh agent separately and point it at `192.168.20.10`. Then:
```bash
cd /home/kali/custom-python-fim
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 fim.py --init-baseline
python3 fim.py
```
Reading `/etc/shadow` requires root. For a first test, point `monitor.paths` at `watched` only and run as a normal user.
The first baseline records current hashes and does not alert. Later scans emit events. `--once` runs a single comparison and exits. While the process is up, `watchdog` requests a comparison immediately after a filesystem event, and the poll interval still runs as a backstop.
Keep `monitor.log_file` and `monitor.baseline_file` outside any monitored directory. The monitor also excludes those two files itself so writing an event cannot generate another event.
### Event schema
Each line of `fim_events.log` is one JSON object:
```json
{"timestamp": "2026-11-15T14:32:01Z", "event_type": "MODIFIED", "file_path": "/etc/passwd", "sha256_before": "a1b2...", "sha256_after": "c3d4...", "hostname": "kali-vm", "severity": "CRITICAL"}
```
`event_type` is `CREATED`, `MODIFIED`, `DELETED`, or `RENAMED`. Created events leave `sha256_before` empty. Deleted events leave `sha256_after` empty. A rename stores both paths in `file_path` as `/old/path -> /new/path`. If the content also changed before the next scan, the two digests differ.
Severity comes from `config.yaml`: modifications and deletions are `CRITICAL`, creates and renames are `HIGH`.
Optional HTTP forwarding posts that same object to `siem.forward_url` when `siem.forward_enabled` is `true`. The lab path is still the local log file. Leave forwarding off unless you have a receiver.
## Wazuh agent
On Kali, edit `/var/ossec/etc/ossec.conf`. The manager address belongs in the existing client block:
```xml
<client>
  <server>
    <address>192.168.20.10</address>
    <port>1514</port>
    <protocol>tcp</protocol>
  </server>
</client>
```
Paste the localfile block from `wazuh/ossec-localfile.xml` inside the existing `<ossec_config>` element. `location` must be the absolute path of `monitor.log_file`.
```xml
<localfile>
  <log_format>json</log_format>
  <location>/home/kali/custom-python-fim/fim_events.log</location>
</localfile>
```
The agent user has to be able to read the log. If the monitor runs as root:
```bash
sudo chgrp ossec /home/kali/custom-python-fim/fim_events.log
sudo chmod 640 /home/kali/custom-python-fim/fim_events.log
sudo systemctl restart wazuh-agent
```
Confirm the agent is connected from the manager:
```bash
sudo /var/ossec/bin/agent_control -l
```
## Wazuh manager rules
Paste `wazuh/local_rules.xml` inside `<group name="local,">` in `/var/ossec/etc/rules/local_rules.xml` on the Wazuh server `192.168.20.10`. Change the rule IDs if that range is already taken. They must stay between `100000` and `120000`.
| Rule | Level | Match |
| --- | ---: | --- |
| 100210 | 3 | Any of the four FIM event types |
| 100211 | 12 | `MODIFIED` |
| 100212 | 12 | `DELETED` |
| 100213 | 10 | `RENAMED` |
| 100214 | 8 | `CREATED` |
| 100215 | 14 | Any of those events on `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/sudoers`, or `/etc/ssh/sshd_config` |
Child rules replace the parent alert. A change to `/etc/passwd` matches `100211` and then `100215`, so the visible alert is level 14. Other modifications stay at level 12.
Restart the manager and replay one log line:
```bash
sudo systemctl restart wazuh-manager
sudo /var/ossec/bin/wazuh-logtest
```
Paste a line from `fim_events.log`. Phase 3 should show rule `100211` for a normal modification, or `100215` when the path is a high-value authentication file.
## Lab check
```bash
echo "lab change $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> watched/marker.txt
tail -n 1 fim_events.log
```
Expect `CREATED` the first time the marker appears and `MODIFIED` after another write. On the manager, the same line should produce an alert under group `custom_fim`.
Protect `baseline.json`. Anyone who can rewrite it can hide a change. Keep it owned by the account that runs the monitor, and do not place it in a directory the monitor watches.
