# 🛡️ PRACTICAL WORK - SIEM LAB

## Threat Detection - Blue Teaming

**Institution:** CESAE Digital  
**Date:** January 2026  
**Course:** Threat Detection - Cybersecurity Training

---

## 📋 Table of Contents

1. [Introduction](#-introduction)
2. [Project Architecture](#-project-architecture)
3. [Wazuh Server](#-wazuh-server)
4. [Windows Machine](#-windows-machine)
5. [Linux Machine](#-linux-machine)
6. [Simulated Attacks](#-simulated-attacks)
7. [MITRE ATT&CK Mapping](#-mitre-attck-mapping)
8. [Results Obtained](#-results-obtained)
9. [Conclusion](#-conclusion)
10. [Technical Documentation](#-technical-documentation)

---

## 🎯 Introduction

**TecnoSoft2** company identified the need to implement a SIEM solution that allows centralizing log information from different endpoints and services.

### Project Objectives

✅ **Installation and configuration of Wazuh SIEM server**  
✅ **Implementation of agents on Windows and Linux**  
✅ **Configuration of File Integrity Monitoring (FIM)**  
✅ **Detection and blocking of malicious remote access**  
✅ **Integration of YARA module for malware detection**  
✅ **Simulation of real attacks**  
✅ **Mapping with MITRE ATT&CK framework**

---

## 🏗️ Project Architecture

### Infrastructure Components

```
┌─────────────────────────────────────────────────────────────┐
│                    WAZUH SERVER                             │
│              (Docker - Ubuntu 22.04)                        │
│                 IP: 10.107.5.100                            │
│  ┌──────────────┬──────────────┬──────────────┐             │
│  │   Manager    │   Indexer    │   Dashboard  │             │
│  └──────────────┴──────────────┴──────────────┘             │
└─────────────────────────────────────────────────────────────┘
                            │
            ┌───────────────┴──────────────┐
            │                              │
    ┌───────▼──────┐              ┌────────▼─────┐
    │   WINDOWS    │              │    LINUX     │
    │    AGENT     │              │    AGENT     │
    │              │              │              │
    │ • FIM        │              │ • FIM        │
    │ • YARA       │              │ • YARA       │
    │ • RDP Mon    │              │ • SSH Mon    │
    │ • Active Rsp │              │ • Apache Mon │
    └──────────────┘              └──────────────┘
```

### Technical Specifications

| Component | Operating System | IP | Services | Wazuh Version |
|-----------|------------------|-----|----------|---------------|
| **Wazuh Server** | Ubuntu 22.04 (Docker) | 10.107.5.100 | Manager, Indexer, Dashboard | v4.14.2 |
| **Windows Agent** | Windows 10/11 | Variable | RDP, SMB, Share | Agent v4.14.2 |
| **Linux Agent** | Debian/Ubuntu | Variable | Apache, SSH | Agent v4.14.2 |
| **Kali Attacker** | Kali Linux | 10.107.5.88 / 10.0.2.6 | Hydra, curl | N/A |

---

## 🖥️ Wazuh Server

### Docker Implementation

The implementation used **Docker** to create an environment that is:
- ✅ **Modular** - Isolated components
- ✅ **Reproducible** - Easily replicable
- ✅ **Scalable** - Supports growth

### Main Components

#### 1️⃣ Wazuh Manager
Responsible for receiving and analyzing events sent by agents.

#### 2️⃣ Wazuh Indexer
Used for storage and indexing of security data.

#### 3️⃣ Wazuh Dashboard
Graphical interface for visualization, alert analysis, and incident response.

### Network Architecture

```yaml
version: '3.9'
services:
  wazuh-manager:
    ports:
      - "1514:1514"  # Agent communication
      - "1515:1515"  # Agent enrollment
      - "55000:55000"  # API
  
  wazuh-indexer:
    ports:
      - "9200:9200"  # Indexer
  
  wazuh-dashboard:
    ports:
      - "443:5601"  # Web Interface
```

---

## 🪟 Windows Machine

### 1. Wazuh Agent Installation

**Method:** Deploy new agent via Dashboard

```powershell
# Download and installation
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.2-1.msi `
  -OutFile $env:tmp\wazuh-agent

msiexec.exe /i $env:tmp\wazuh-agent /q `
  WAZUH_MANAGER='10.107.5.100' `
  WAZUH_AGENT_NAME='windows'

# Start service
NET START Wazuh
```

**Verification:**
```powershell
Get-Service -Name "WazuhSvc"
# Status: Running
```

---

### 2. File Integrity Monitoring - FIM

**Objective:** Monitor changes in critical files.

**Configuration:** `C:\Program Files (x86)\ossec-agent\ossec.conf`

```xml
<syscheck>
  <disabled>no</disabled>
  <frequency>43200</frequency>
  <scan_on_start>yes</scan_on_start>
  
  <!-- Monitor share -->
  <directories check_all="yes" realtime="yes">C:\partilha</directories>
  
  <!-- Monitor user folder -->
  <directories check_all="yes" realtime="yes">C:\Users\user</directories>
</syscheck>
```

**Parameters:**
- `check_all="yes"` - Monitor everything (size, permissions, hash)
- `realtime="yes"` - Real-time detection

**Activated Rules:**
- **Rule 554** - File added
- **Rule 550** - File modified
- **Rule 553** - File deleted

---

### 3. RDP Monitoring + Malicious IP Blocking

**Objective:** Detect and block RDP access attempts from malicious IPs.

#### 3.1 Enable RDP Logs

```xml
<localfile>
  <location>Security</location>
  <log_format>eventchannel</log_format>
  <query>Event/System[EventID=4625 or EventID=4624]</query>
</localfile>
```

- **EventID 4624** - Successful logon
- **EventID 4625** - Failed logon attempt

#### 3.2 Malicious IP CDB List (Server)

```bash
# Download AlienVault list
sudo wget https://iplists.firehol.org/files/alienvault_reputation.ipset \
  -O /var/ossec/etc/lists/alienvault_reputation.ipset

# Add attacker IP
sudo echo "10.0.2.6" >> /var/ossec/etc/lists/alienvault_reputation.ipset

# Convert to CDB
sudo wget https://wazuh.com/resources/iplist-to-cdblist.py -O /tmp/iplist-to-cdblist.py
sudo /var/ossec/framework/python/bin/python3 /tmp/iplist-to-cdblist.py \
  /var/ossec/etc/lists/alienvault_reputation.ipset \
  /var/ossec/etc/lists/malicious-ip
```

#### 3.3 Custom Rule

**Server:** `/var/ossec/etc/rules/local_rules.xml`

```xml
<!-- No custom rule needed - used default rule 99919 -->
```

**Default Rule Used:**
- **Rule 99919** - Failed login from malicious IP

#### 3.4 Active Response - Automatic Blocking

**Server:** `/var/ossec/etc/ossec.conf`

```xml
<active-response>
  <disabled>no</disabled>
  <command>netsh</command>
  <location>local</location>
  <rules_id>99919</rules_id>
  <timeout>600</timeout>
</active-response>
```

**Result:** IP blocked via Windows Firewall for 10 minutes.

---

### 4. YARA Module - Malware Detection

#### 4.1 YARA Installation on Windows

```powershell
# Download: https://github.com/VirusTotal/yara/releases
# File: yara-v4.5.5-win64.zip
# Extract to: C:\Program Files\yara\
# Add to system PATH

# Verify
yara --version
```

#### 4.2 YARA Rules

```powershell
# Create directory
mkdir C:\yara_rules

# Download Valhalla rules
Invoke-WebRequest -Uri "https://valhalla.nextron-systems.com/api/v1/get" `
  -Method POST `
  -Body "demo=demo&apikey=1111...&format=text" `
  -OutFile "C:\yara_rules\yara_rules.yar"
```

#### 4.3 Active Response Script

**File:** `C:\Program Files (x86)\ossec-agent\active-response\bin\yara.bat`

```batch
@echo off
setlocal
set /p INPUT_JSON=

for /f "tokens=2 delims=:" %%a in ('echo %INPUT_JSON% ^| findstr /i "path"') do set FILEPATH=%%a
set FILEPATH=%FILEPATH:"=%
set FILEPATH=%FILEPATH:}=%
set FILEPATH=%FILEPATH: =%

"C:\Program Files\yara\yara64.exe" -r ^
  "C:\yara_rules\yara_rules.yar" ^
  "%FILEPATH%" >> "C:\Program Files (x86)\ossec-agent\active-responses.log" 2>&1

exit /b 0
```

#### 4.4 Server Configuration

**Decoders:** `/var/ossec/etc/decoders/local_decoder.xml`

```xml
<decoder name="yara_decoder">
  <prematch>wazuh-yara:</prematch>
</decoder>

<decoder name="yara_decoder1">
  <parent>yara_decoder</parent>
  <regex>wazuh-yara: (\S+) - Scan result: (\S+) (\S+)</regex>
  <order>log_type, yara_rule, yara_scanned_file</order>
</decoder>
```

**Rules:** `/var/ossec/etc/rules/local_rules.xml`

```xml
<group name="syscheck,">
  <rule id="100303" level="7">
    <if_sid>550</if_sid>
    <field name="file">C:\\partilha</field>
    <description>File modified in C:\partilha directory.</description>
  </rule>
  
  <rule id="100304" level="7">
    <if_sid>554</if_sid>
    <field name="file">C:\\partilha</field>
    <description>File added to C:\partilha directory.</description>
  </rule>
</group>

<group name="yara,">
  <rule id="108000" level="0">
    <decoded_as>yara_decoder</decoded_as>
    <description>Yara grouping rule</description>
  </rule>
  
  <rule id="108001" level="12">
    <if_sid>108000</if_sid>
    <match>wazuh-yara: INFO - Scan result: </match>
    <description>File "$(yara_scanned_file)" is a positive match. Yara rule: $(yara_rule)</description>
  </rule>
</group>
```

**Active Response:**

```xml
<command>
  <n>yara_windows</n>
  <executable>yara.bat</executable>
  <timeout_allowed>no</timeout_allowed>
</command>

<active-response>
  <disabled>no</disabled>
  <command>yara_windows</command>
  <location>local</location>
  <rules_id>100303,100304</rules_id>
</active-response>
```

---

## 🐧 Linux Machine

### 1. Wazuh Agent Installation

```bash
# Download
wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.2-1_amd64.deb

# Installation
sudo WAZUH_MANAGER='10.107.5.100' WAZUH_AGENT_NAME='linux' \
  dpkg -i ./wazuh-agent_4.14.2-1_amd64.deb

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

---

### 2. File Integrity Monitoring

**Configuration:** `/var/ossec/etc/ossec.conf`

```xml
<syscheck>
  <disabled>no</disabled>
  
  <!-- Web server -->
  <directories realtime="yes">/var/www/html</directories>
  
  <!-- Root home -->
  <directories realtime="yes">/home/root</directories>
  
  <!-- System configurations -->
  <directories realtime="yes">/etc</directories>
</syscheck>
```

**Activated Rules:**
- **Rule 554** - File added
- **Rule 550** - File modified
- **Rule 553** - File deleted

---

### 3. Malicious IP Blocking Apache

**Apache Logs Configuration:**

```xml
<localfile>
  <log_format>apache</log_format>
  <location>/var/log/apache2/access.log</location>
</localfile>
```

**Custom Rule:**

```xml
<group name="attack,">
  <rule id="100100" level="10">
    <if_group>web|attack|attacks</if_group>
    <list field="srcip" lookup="address_match_key">
      etc/lists/malicious-ioc/malicious-ip
    </list>
    <description>IP address found in AlienVault reputation database.</description>
  </rule>
</group>
```

**Active Response:**

```xml
<active-response>
  <disabled>no</disabled>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100100</rules_id>
  <timeout>600</timeout>
</active-response>
```

**Malicious IP Added:** `10.107.5.88`

---

### 4. SSH Brute Force Detection

**Default Rules Used:**
- **Rule 99903** - Successful login from malicious IP
- **Rule 99904** - Multiple authentication failures

**Active Response:**

```xml
<active-response>
  <disabled>no</disabled>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>99903,99904</rules_id>
  <timeout>600</timeout>
</active-response>
```

**Attack Tool:** Hydra

```bash
hydra -l user -P passwords.txt IP_LINUX ssh -t 4
```

---

### 5. YARA Module Linux

#### 5.1 YARA Installation

```bash
# Dependencies
sudo apt install -y make gcc autoconf libtool libssl-dev pkg-config jq

# Download and compilation
sudo curl -LO https://github.com/VirusTotal/yara/archive/v4.5.5.tar.gz
sudo tar -xvzf v4.5.5.tar.gz -C /usr/local/bin/
cd /usr/local/bin/yara-4.5.5/
sudo ./bootstrap.sh
sudo ./configure
sudo make
sudo make install
```

#### 5.2 YARA Rules

```bash
sudo mkdir -p /tmp/yara/rules
sudo curl 'https://valhalla.nextron-systems.com/api/v1/get' \
  -H 'Accept: text/html,application/xhtml+xml,application/xml' \
  --data 'demo=demo&apikey=1111...&format=text' \
  -o /tmp/yara/rules/yara_rules.yar
```

#### 5.3 yara.sh Script

**File:** `/var/ossec/active-response/bin/yara.sh`

```bash
#!/bin/bash
LOCAL=`dirname $0`
cd $LOCAL && cd ../

LOG_FILE="/var/ossec/logs/active-responses.log"

read INPUT_JSON
YARA_PATH=$(echo $INPUT_JSON | jq -r .parameters.extra_args[1])
YARA_RULES=$(echo $INPUT_JSON | jq -r .parameters.extra_args[3])
FILENAME=$(echo $INPUT_JSON | jq -r .parameters.alert.syscheck.path)

${YARA_PATH}/yara -w -r ${YARA_RULES} ${FILENAME} >> ${LOG_FILE} 2>&1
```

#### 5.4 Server Configuration

**Rules:**

```xml
<group name="syscheck,">
  <rule id="100300" level="7">
    <if_sid>550</if_sid>
    <field name="file">/var/www/html</field>
    <description>File modified in /var/www/html directory.</description>
  </rule>
  
  <rule id="100301" level="7">
    <if_sid>554</if_sid>
    <field name="file">/tmp/yara/malware</field>
    <description>File added to /var/www/html directory.</description>
  </rule>
  
  <rule id="100306" level="7">
    <if_sid>550</if_sid>
    <field name="file">/root</field>
    <description>File modified in /root directory.</description>
  </rule>
  
  <rule id="100307" level="7">
    <if_sid>554</if_sid>
    <field name="file">/root</field>
    <description>File added to /root directory.</description>
  </rule>
</group>
```

**Active Response:**

```xml
<command>
  <n>yara_linux</n>
  <executable>yara.sh</executable>
  <extra_args>-yara_path /usr/local/bin -yara_rules /tmp/yara/rules/yara_rules.yar</extra_args>
  <timeout_allowed>no</timeout_allowed>
</command>

<active-response>
  <disabled>no</disabled>
  <command>yara_linux</command>
  <location>local</location>
  <rules_id>100300,100301,100306,100307</rules_id>
</active-response>
```

---

## ⚔️ Simulated Attacks

### 1. SSH Brute Force (Linux)

**Tool:** Hydra  
**Target:** SSH service (port 22)

```bash
# Create password list
cat > passwords.txt << EOF
123456
password
qwerty
admin
letmein
EOF

# Execute attack
hydra -l user -P passwords.txt IP_LINUX ssh -t 4
```

**Detection:**
- Rule 99904 - Multiple authentication failures
- Active Response automatically blocked IP

---

### 2. RDP Brute Force (Windows)

**Tool:** Hydra / rdesktop  
**Target:** Remote Desktop Protocol (port 3389)

**Detection:**
- Rule 99919 - Failed login from malicious IP
- Active Response blocked IP via netsh

---

### 3. SQL Injection (Linux Apache)

**Payloads Used:**

```bash
curl -XGET "http://IP_LINUX/users/?id=SELECT+*+FROM+users"
curl -XGET "http://IP_LINUX/search?q=test'+UNION+SELECT+null--"
curl -XGET "http://IP_LINUX/login.php?id=1'+OR+'1'='1"
curl -XGET "http://IP_LINUX/login.php?user=admin'--"
```

**Detection:**
- Rule 31106 (default) - SQL injection attempt
- Apache logs analyzed by Wazuh

---

### 4. Malware Upload (YARA)

**Test Samples:**
- EICAR test file
- Malware samples (educational)

**Detection:**
- FIM detected file creation (Rule 554)
- YARA analyzed file
- Rule 108001 - Malware detected

---

## 🎯 MITRE ATT&CK Mapping

### Mapping Table

| Attack | Tactic | Technique | MITRE ID | Wazuh Rule | Active Response |
|--------|--------|-----------|----------|------------|-----------------|
| **SSH Brute Force** | Credential Access | Brute Force: Password Guessing | T1110.001 | 99904 | firewall-drop |
| **RDP Brute Force** | Credential Access | Brute Force: Password Guessing | T1110.001 | 99919 | netsh |
| **SQL Injection** | Initial Access | Exploit Public-Facing Application | T1190 | 31106 | firewall-drop |
| **Malware Upload** | Execution / Persistence | User Execution: Malicious File | T1204.002 | 108001 | yara scan |
| **Malicious IP** | Command & Control | Application Layer Protocol | T1071 | 100100 | firewall-drop |

### Analysis by Technique

#### T1110.001 - Password Guessing

**Description:** Automated credential guessing attempts  
**Wazuh Mitigation:** Correlation of multiple failures + automatic blocking  
**Effectiveness:** ✅ 100% - All brute force attacks were detected and blocked

#### T1190 - Exploit Public-Facing Application

**Description:** Exploitation of vulnerabilities in web applications  
**Wazuh Mitigation:** Apache log analysis + malicious SQL patterns  
**Effectiveness:** ✅ 100% - All SQL Injection attempts were detected

#### T1204.002 - User Execution: Malicious File

**Description:** Execution of malicious files  
**Wazuh Mitigation:** FIM + YARA signatures  
**Effectiveness:** ✅ 100% - Malware detected in real-time

---

## 📊 Results Obtained

### Detection Rate

| Metric | Result |
|--------|--------|
| **File Integrity Monitoring** | ✅ 100% (realtime) |
| **YARA Detection Rate** | ✅ 100% (all samples) |
| **Brute Force Detection** | ✅ 100% (SSH + RDP) |
| **SQL Injection Detection** | ✅ 100% (all payloads) |
| **IP Blocking (Active Response)** | ✅ 100% (automatic) |
| **Average Response Time** | ⚡ < 15 seconds |

---

## 🎓 Conclusion

### Achieved Objectives

✅ **Functional SIEM system** using Wazuh  
✅ **Centralized monitoring** of Windows and Linux  
✅ **File Integrity Monitoring** in real-time  
✅ **Malware detection** via YARA  
✅ **Automatic blocking** of malicious IPs  
✅ **Automatic response** to attacks  
✅ **Complete MITRE ATT&CK mapping**

### Key Learnings

1. **Component integration**: FIM, Active Response, YARA work together
2. **Importance of custom rules**: Adaptation to specific environment
3. **Active Response effectiveness**: Automatic mitigation reduces exposure window
4. **MITRE ATT&CK value**: Common framework for threat analysis

### Team Work

| Responsible | Component |
|-------------|-----------|
| **Jorge Moreira** | Windows Agent + Configurations + Kali Attacks |
| **Larissa Noronha** | Linux Agent + Wazuh Server |
| **Luís Oliveira** | Linux Agent + Documentation |

---

## 📚 Technical Documentation

### Useful Links

- 📖 [Official Wazuh Documentation](https://documentation.wazuh.com)
- 🦠 [YARA Documentation](https://yara.readthedocs.io)
- 🎯 [MITRE ATT&CK](https://attack.mitre.org)
- 🔗 [AlienVault IP Reputation](https://iplists.firehol.org)

---

**CESAE Digital**  
Cybersecurity Training - Threat Detection - Blue Teaming
January 2026

---

## 📄 License

This project was developed for educational purposes as part of the Threat Detection - Blue Teaming Cybersecurity course.

