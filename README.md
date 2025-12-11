# SOC-Automation
SOC Automation with Wazuh, Shuffle SOAR & TheHive

1. Overview
This project implements a fully functional Security Operations Center (SOC) automation pipeline using:
	Wazuh (SIEM & Endpoint Security Platform)
	Sysmon (Windows Telemetry Source for Advanced Detection)
	Shuffle (Open-Source SOAR Platform)
	TheHive (Incident Response & Case Management Platform)
The objective was to simulate a real adversary technique, credential dumping using Mimikatz and detect it with Sysmon & Wazuh, automate alert enrichment in Shuffle, and generate structured cases in TheHive to support analyst investigations.

2. Architecture
Components & Roles
Component	Purpose
Windows 10 VM (Wazuh Agent)	Runs Sysmon, generates telemetry, executes Mimikatz simulation
Wazuh Manager (Ubuntu 24.04)	Receives logs, applies rules, forwards alerts to Shuffle
OpenSearch Dashboards	Visualizes Wazuh alerts and telemetry
Shuffle SOAR	Automates alert processing, extracts indicators, pushes to TheHive
TheHive (Ubuntu 24.04)	Case management for SOC analysts
Git Bash (Windows)	Used to SSH into Wazuh Manager for configuration
All servers deployed on DigitalOcean Droplets.
All public IPs have been anonymized: <WAZUH_IP>, <THEHIVE_IP>

3. Attack Simulation: Mimikatz Execution
To generate realistic adversary activity:
	Sysmon was installed and configured with detection rules for credential dumping.
	Mimikatz was executed manually via PowerShell on the Windows endpoint.
	Sysmon logged process execution events.
	Wazuh Agent forwarded the logs.
	Alerts were sent to OpenSearch, then to Shuffle via webhook.

Figure 1: Sysmon / Wazuh Detection of Mimikatz
Detection Summary:
	27 events detected within the time window.
	Confirmed Sysmon to Wazuh to OpenSearch pipeline.
	Telemetry included EventID 7 (ImageLoaded), process command lines and etc

4. Wazuh Manager Configuration
The Wazuh Manager was accessed using Git Bash on Windows via SSH:
ssh root@<WAZUH_IP>
Key configurations:
	Custom integration block added in /var/ossec/etc/ossec.conf
	Alert level threshold defined
	JSON formatting enabled
	Shuffle webhook URL inserted


Figure 2: Wazuh and Shuffle SOAR Webhook Integration
This ensures that all qualified alerts are automatically forwarded to Shuffle for automated processing.


5. SOAR Workflow: Shuffle Automation
Shuffle was used to automate:
    Receiving alerts from Wazuh
    Extracting key fields
	Pulling SHA256 hash values
	Sending data to TheHive as an alert
Workflow includes:
	Webhook trigger
	JSON parser
	Indicator extraction
	Formatting for TheHive API
Submission to TheHive


6. TheHive Case Management
TheHive was deployed on Ubuntu 24.04 with Cassandra as the backend database.
Backend validation steps included:
	Verifying Cassandra service status
	Adjusting folder permissions (chown -R thehive:thehive /opt/thp)
	Starting TheHive service

Figure 3: TheHive & Cassandra Setup
TheHive receives alerts from Shuffle and generates:
	Alerts
	Cases
	Tasks
	Observable lists
This enables structured investigations for SOC analysts.

7. Event Pipeline Summary
Here is the detection-to-response flow:
	Sysmon detects Mimikatz
	Wazuh Agent forwards logs
	Wazuh Manager parses logs, triggers custom rules
	Wazuh Integration sends alerts to Shuffle
	Shuffle Workflow enriches and forwards to TheHive
	TheHive Case is created for analyst investigation
This replicates a real SOC workflow used in enterprise environments.

8. MITRE ATT&CK Mapping
Summary: The adversary activity aligns with Credential Dumping (T1003) and Command Execution (T1059), detected through Sysmon process and image load events analyzed by Wazuh.

#9. Screenshots Summary
Figure	Description
Figure 1:	Sysmon logs in OpenSearch showing Mimikatz detection

Figure 2:	Wazuh integration with Shuffle SOAR (webhook configuration)

Figure 3;	TheHive backend (Cassandra) validation and permissions

11. Conclusion
This SOC automation project provides an end-to-end demonstration of:
	How endpoint telemetry is collected
	How security alerts are processed
	How SOAR platforms enrich and automate analysis
	How cases are built in TheHive for investigation
It strengthens practical experience across detection engineering, automation, cloud deployments, and incident response, key areas for modern SOC and security engineer roles.


10. Screenshots
    
 <img width="556" height="280" alt="image" src="https://github.com/user-attachments/assets/9f905444-46b0-4145-be70-6cb15fcec7e7" />


Figure 1: Sysmon / Wazuh Detection of Mimikatz


 <img width="597" height="317" alt="image" src="https://github.com/user-attachments/assets/d1a7663c-ef34-421d-8009-d0d4eca7a973" />


Figure 2: Wazuh and Shuffle SOAR Webhook Integration


 <img width="586" height="341" alt="image" src="https://github.com/user-attachments/assets/4e4b0577-b773-4ed8-9599-037e478dce4c" />


Figure 3: TheHive & Cassandra Setup

