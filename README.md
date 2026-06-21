# Wazuh SOC Detection Lab

A home Security Operations Center (SOC) lab built on virtual machines. It deploys a single-node
**Wazuh** SIEM, ingests two live log sources (Linux authentication logs and Apache web-server
logs), and uses **custom detection rules mapped to MITRE ATT&CK** to alert on attacker behavior —
each rule validated by safely simulating the attack and confirming the alert fires.

> **What this demonstrates:** the core detection-engineering loop a SOC analyst does daily —
> collect telemetry → simulate a technique → detect it → tune the rule → document it.


---

## Architecture

```
                NAT Network (internet + VM-to-VM communication)
   ┌──────────────────────────────────────────────────────────────┐
   │                                                                │
   │   ┌───────────────────────────┐                               │
   │   │  Ubuntu  (10.0.2.15)      │   WAZUH SERVER (SIEM)          │
   │   │  Wazuh manager            │   - manager + indexer +        │
   │   │  Wazuh indexer            │     dashboard (single node)    │
   │   │  Wazuh dashboard          │   - receives agent logs        │
   │   └─────────────▲─────────────┘     on ports 1514 / 1515       │
   │                 │ agent reports up                             │
   │   ┌─────────────┴─────────────┐                               │
   │   │  Kali Linux               │   MONITORED ENDPOINT           │
   │   │  Wazuh agent              │   - /var/log/auth.log (auth)   │
   │   │  rsyslog                  │   - /var/log/syslog            │
   │   │  Apache2                  │   - Apache access/error logs   │
   │   └───────────────────────────┘                               │
   └──────────────────────────────────────────────────────────────┘
```

| VM     | Role             | Components                                            |
|--------|------------------|-------------------------------------------------------|
| Ubuntu | Wazuh **server** | Wazuh manager, indexer, dashboard (all-in-one)        |
| Kali   | Endpoint + web   | Wazuh agent, rsyslog, Apache2 (auth + web log sources)|

**Hypervisor:** Oracle VirtualBox · **Networking:** NAT Network (so all VMs have internet *and*
can reach each other).

---

## Tech stack

- **Wazuh 4.14** — open-source SIEM / XDR (manager, indexer, dashboard)
- **rsyslog** — generates `/var/log/auth.log` and `/var/log/syslog` for log collection
- **Apache2** — web server providing access/error logs
- **MITRE ATT&CK** — detection-to-technique mapping
- **VirtualBox** — virtualization

---

## Custom detection rules

Custom rules live on the Wazuh server at `/var/ossec/etc/rules/local_rules.xml` and build on
Wazuh's built-in rule set. (Custom rule IDs use the `1001xx` range to avoid clashing with the
bundled sample rules at `100001`–`100002`.)

### Rule 1 — Brute-force authentication (MITRE T1110)

Fires when repeated authentication failures occur in a short window.

```xml
<group name="local,authentication,">
  <rule id="100100" level="10" frequency="4" timeframe="120">
    <if_matched_sid>5557</if_matched_sid>
    <description>Multiple failed login attempts - possible brute force (custom)</description>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>
</group>
```

### Rule 2 — Web scanning / HTTP 4xx burst (MITRE T1595)

Fires when many HTTP 4xx errors come from the same activity — the signature of a scanner probing
for hidden paths (`/admin`, `/phpmyadmin`, `/.env`, etc.).

```xml
<group name="local,web,">
  <rule id="100101" level="10" frequency="5" timeframe="120">
    <if_matched_sid>31101</if_matched_sid>
    <description>Possible web scanning - burst of HTTP 4xx errors (custom)</description>
    <mitre>
      <id>T1595</id>
    </mitre>
  </rule>
</group>
```

---

## Results — verified detections

Each custom rule was confirmed firing by simulating the matching activity and observing the alert
in the Wazuh dashboard (Threat Hunting).

| Rule ID | Detection                              | MITRE  | Log source              | How it was triggered                        | Status |
|---------|----------------------------------------|--------|-------------------------|---------------------------------------------|--------|
| 100100  | Multiple failed logins (brute force)   | T1110  | Kali `/var/log/auth.log`| Repeated failed `sudo` password attempts    | ✅ Verified |
| 100101  | Web scanning (HTTP 4xx burst)          | T1595  | Kali Apache `access.log`| `curl` against many nonexistent paths        | ✅ Verified |

**Built-in Wazuh detections also observed during testing** (showing the pipeline working
end-to-end): `5404` three failed sudo attempts, `5503` PAM login failed, `5557` password check
failed, `5902` new user added, `5903` user/group deleted, `31101` web server 4xx error,
`510` host-based anomaly (rootcheck).

**Brute-force detection — rule 100100 → MITRE T1110 (Credential Access):**

![Rule 100100 firing on repeated failed logins](screenshots/rule-100100-bruteforce.png)

**Web-scanning detection — rule 100101 → MITRE T1595 (Reconnaissance):**

![Rule 100101 firing on a burst of HTTP 4xx errors](screenshots/rule-100101-webscan.png)

---

## How to reproduce

### 1. Lab prep
- Create a **NAT Network** in VirtualBox so all VMs get internet *and* can reach each other.
- Give the Ubuntu server at least **4 GB RAM / 2 CPUs** and ~**40 GB disk**.

### 2. Install the Wazuh server (Ubuntu)
```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```
Retrieve the admin password from `wazuh-install-files.tar`, then open the dashboard at
`https://<server-ip>`.

### 3. Enroll the Kali endpoint
```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring \
  --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
sudo chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt-get update
sudo WAZUH_MANAGER="<server-ip>" apt-get install -y wazuh-agent
sudo systemctl enable --now wazuh-agent
```

### 4. Add the log sources (Kali)
```bash
# Kali uses journald by default; install rsyslog so the text logs exist
sudo apt-get install -y rsyslog apache2
sudo systemctl enable --now rsyslog apache2
```
Add these inside `<ossec_config>` in `/var/ossec/etc/ossec.conf`, then restart the agent:
```xml
<localfile><log_format>syslog</log_format><location>/var/log/auth.log</location></localfile>
<localfile><log_format>syslog</log_format><location>/var/log/syslog</location></localfile>
<localfile><log_format>apache</log_format><location>/var/log/apache2/access.log</location></localfile>
```

### 5. Add the custom rules (Ubuntu)
Add the two rules above to `/var/ossec/etc/rules/local_rules.xml`, then:
```bash
sudo systemctl restart wazuh-manager
```

### 6. Test
```bash
# brute force -> rule 100100
sudo -k; sudo ls    # enter wrong password repeatedly

# web scan -> rule 100101
for p in admin login phpmyadmin .env wp-login.php config backup .git secret api; do
  curl -s -o /dev/null http://localhost/$p; done
```
In the dashboard's **Threat Hunting** view, filter by `rule.id:100100` and `rule.id:100101`.

---

## Lessons learned / troubleshooting

Real issues hit while building this, and how they were solved — the kind of problem-solving the
job actually involves:

- **VirtualBox networking:** plain NAT isolates each VM and Host-Only has no internet. A **NAT
  Network** is required to get both internet access (for installs) and VM-to-VM traffic (for
  agents) at once.
- **Disk sizing:** the Wazuh dashboard failed to install on a full disk. Resized the VM's virtual
  disk (`growpart` + `resize2fs`) — the indexer needs room to grow.
- **Indexer won't start after reboot:** `vm.max_map_count` must be set to ≥262144 *and persisted*
  in `/etc/sysctl.conf`, or OpenSearch fails its bootstrap check on boot.
- **Failed password-tool run:** left a root-owned `/etc/wazuh-indexer/backup` directory that
  blocked the indexer from starting (`AccessDeniedException`). Removing it fixed startup.
- **Kali logging:** Kali defaults to systemd-journald with no `/var/log/auth.log`. Installing
  `rsyslog` recreates the text logs Wazuh monitors.
- **Custom rule IDs must be unique:** reusing `100001` (a bundled sample rule ID) silently
  shadowed the custom rule. Moving to the `1001xx` range fixed it.
- **Tune to the signal that actually fires:** failed `sudo` produced rule `5557` far more than
  `5503`, so the brute-force rule was re-keyed onto `5557` after reading the live alerts.

---

## Repository structure

```
wazuh-soc-lab/
├── README.md
├── rules/
│   └── local_rules.xml      # the 2 custom detection rules
└── screenshots/
    ├── dashboard.png
    ├── rule-100100-bruteforce.png
    └── rule-100101-webscan.png
```

---

## Future work (v2)

- Add a **Windows 11 endpoint** with **Sysmon** for richer telemetry.
- Three more custom rules: multiple failed Windows logons (T1110), encoded PowerShell
  (T1059.001), and a new user added to the Administrators group (T1098).
- A false-positive tuning pass and a Sigma-rule export of the detections.

---

## Author

Built as a hands-on blue-team / detection-engineering portfolio project.
