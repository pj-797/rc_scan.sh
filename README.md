# rc_scan.sh
Centre for Cybersecurity Project

Mission: During attacks on the enemy's server, we waste valuable time typing wrong commands due to stress and are even exposed because the source addresses are exposed. Attacking targets behind enemy lines can become much more practical, fast, and accurate if the execution of the tasks becomes automatic.

Objective: Communicating with a remote server and executing automatic whois &amp; nmap scan anonymously.

Diagram: https://github.com/pj-797/rc_scan.sh/blob/main/rc_scan%20Process.png

Usage:

	bash rc_scan.sh
Requires:
  1) Remote Server IP Address
  2) Remote Server Login Credentials (Username, Password & Sudo Password)
  3) Remote Server - Running SSH Service

Note:
1) Results will be saved in RC_Scan folder.
2) Activity will be logged at /var/log/rc_scan.log.
