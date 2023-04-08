# rc_scan.sh
Communicating with a remote server &amp; executing automatic whois &amp; nmap scan anonymously.

Diagram: https://github.com/pj-797/rc_scan.sh/blob/main/rc_scan%20Process.png

Requires:
  1) Remote Server IP Address
  2) Remote Server Login Credentials (Username, Password & Sudo Password)
  3) Remote Server - Running SSH Service
  
Usage:

	bash rc_scan.sh
	
Note:
1) Results will be saved in RC_Scan folder.
2) Activity will be logged at /var/log/rc_scan.log.
