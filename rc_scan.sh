
#!/bin/bash
#--------------------------------------------------------------------------------
#	rc_scan.sh (For Linux)
#	Creator: Zi_WaF
#	Group: Centre for Cybersecurity (CFC311022)
#	Lecturer: J. Lim
#	whatis: rc_scan.sh	Communicating with a remote server & executing automatic whois & nmap scan anonymously
#
#	Usage: bash rc_scan.sh
#--------------------------------------------------------------------------------

function trap_all(){  	# set up for any interruptions and exit program cleanly
		cd $nipedir && sudo perl $nipe stop > /dev/null 2>&1						# revert to original IP address
		echo -e "$(date) - [INT] Script Interrupted. Reverted to original IP address." >> /var/log/rc_scan.log 2> /dev/null
		cat /tmp/rc_result.txt >> $(pwd)/RC_Scan/rc_result.txt 	2> /dev/null 		# any result will be appended to rc_result.txt
		rm -r /tmp/rc_result.txt > /dev/null 2>&1									# remove temp file
		sudo chmod 644 /var/log/rc_scan.log 2> /dev/null							# remove privilege to non sudoer
		echo -e "\n Script Interrupted. Reverted to original IP address."
		exit
}
function setup(){  		# initial setup (Remote Server info & script setup)
	#sudo timedatectl set-timezone Asia/Singapore		# set to correct timezone (optional)
	sudo echo "" && tput reset && echo -e "\n\e[1m    rc_scan.sh: Communicate & execute automatic \"whois\" & \"nmap scan\" anonymously via a Remote Server.\e[0m\n"
	echo -e "\e[1m\e[4mRemote Server Details\e[0m\e[0m"
	read -p "Remote Server IP Address: " server_ip		# set variable for login server
	read -p "Remote Server Login Username: " server_username
	server="$server_username@$server_ip"
	read -p "Remote Server Login Password: " pass				# set variable for known password for login
	read -p "Remote Server SUDO Password: " sudo_pass	# set variable for sudo password when logged in, assuming user have sudo privileges
						
	orig_ip=$(curl -s ifconfig.io)			# detect original IP address before running the script
	sudo touch /var/log/rc_scan.log			# create a log
	sudo chmod 777 /var/log/rc_scan.log		# allow permission to write
}
function bin_check(){  	# install needed applications; assuming new system
	sudo apt-get update -y #>/dev/null #&& sudo apt-get upgrade -y && sudo apt-get full-upgrade -y && sudo apt autoremove -y	# full upgrade system
	tput reset												# clean reset of terminal, instead of using clear
	#echo -e " \033[0;32m[+] Full Upgrade Complete.\033[0m"
	if [ "$(which geoiplookup)" = "/usr/bin/geoiplookup" ]	# check for geoiplookup
	then
		echo -e " \033[0;32m[+] GeoIP Detected.\033[0m"
	else
		echo -e " \033[1;31m[-] GeoIP NOT Detected.\033[0m Installing \e[1m\"Geo-IP\"\e[0m... Please wait."
		sudo DEBIAN_FRONTEND=noninteractive apt install geoip-bin -y &> /dev/null		# install geoip-bin
		echo -e " \033[0;32m[+] GeoIP Installed.\033[0m"
	fi
	if [ "$(which whois)" = "/usr/bin/whois" ]				# check for whois
	then
		echo -e " \033[0;32m[+] whois Detected.\033[0m"
	else
		echo -e " \033[1;31m[-] whois NOT Detected.\033[0m Installing \e[1m\"whois\"\e[0m... Please wait."
		sudo apt-get install -y whois &> /dev/null			# install whois
		echo -e " \033[0;32m[+] whois Installed.\033[0m"
	fi
	if [ "$(which nmap)" = "/usr/bin/nmap" ]				# check for nmap
	then
		echo -e " \033[0;32m[+] $(nmap -V | sed -n '1p' | awk '{print $1,$2,$3}' | sed 's/v/V/') Detected.\033[0m"
	else
		echo -e " \033[1;31m[-] Nmap NOT Detected.\033[0m Installing \e[1m\"Nmap\"\e[0m... Please wait."
		sudo apt-get install -y nmap &> /dev/null			# install nmap
		echo -e " \033[0;32m[+] $(nmap -V | sed -n '1p' | awk '{print $1,$2,$3}' | sed 's/v/V/') Installed.\033[0m"
	fi
	if [ "$(which ssh)" = "/usr/bin/ssh" ]					# check for openssh-client
	then
		echo -e " \033[0;32m[+] openssh-client Detected.\033[0m"
	else
		echo -e " \033[1;31m[-] openssh-client NOT Detected.\033[0m Installing \e[1m\"openssh-client\"\e[0m... Please wait."
		sudo apt-get install -y openssh-client &> /dev/null	# install openssh-client
		echo -e " \033[0;32m[+] openssh-client Installed.\033[0m"
	fi
	if [ "$(which sshpass)" = "/usr/bin/sshpass" ]			# check for sshpass
	then
		echo -e " \033[0;32m[+] $(sshpass -V | sed -n '1p' | sed 's/\s/ Version /') Detected.\033[0m"
	else
		echo -e " \033[1;31m[-] sshpass NOT Detected.\033[0m Installing \e[1m\"sshpass\"\e[0m... Please wait."
		sudo apt install -y sshpass &> /dev/null		# install sshpass
		echo -e " \033[0;32m[+] $(sshpass -V | sed -n '1p' | sed 's/\s/ Version /') Installed.\033[0m"
	fi
	if [ "$(which locate)" = "/usr/bin/locate" ]			# check for locate command
	then
		echo -e " \033[0;32m[+] plocate Detected.\033[0m"
	else
		echo -e " \033[1;31m[-] plocate NOT Detected.\033[0m Installing \e[1m\"plocate\"\e[0m... Please wait."
		sudo apt-get install -y plocate &> /dev/null		# install locate command
		sudo updatedb &> /dev/null							# update database
		echo -e " \033[0;32m[+] plocate Installed.\033[0m"
	fi
	if [ "$(which ifconfig)" = "/usr/sbin/ifconfig" ]		# check for net-tools
	then
		echo -e " \033[0;32m[+] net-tools Detected.\033[0m"
	else
		echo -e " \033[1;31m[-] net-tools NOT Detected.\033[0m Installing \e[1m\"net-tools\"\e[0m... Please wait."
		sudo apt-get install -y net-tools &> /dev/null		# install net-tools
		echo -e " \033[0;32m[+] net-tools Installed.\033[0m"
	fi
	if [ "$(which nslookup)" = "/usr/bin/nslookup" ]					# check for dnsutils
	then
		echo -e " \033[0;32m[+] dnsutils Detected.\033[0m"
	else
		echo -e " \033[1;31m[-] dnsutils NOT Detected.\033[0m Installing \e[1m\"dnsutils\"\e[0m... Please wait."
		sudo apt-get install -y dnsutils &> /dev/null		# install dnsutils
		echo -e " \033[0;32m[+] dnsutils Installed.\033[0m"
	fi
	if [ -z "$(find ~ -type f -name nipe.pl)" ]				# check for nipe
	then
		echo -e " \033[1;31m[-] Nipe NOT Detected.\033[0m Installing \e[1m\"Nipe\"\e[0m... Please wait."
		git clone --quiet https://github.com/htrgouvea/nipe && cd nipe	# https://github.com/htrgouvea/nipe
		sudo apt install cpanminus -y &>/dev/null
		export PERL_MM_USE_DEFAULT=1									# to stop the prompts when installing nipe
		sudo cpan install YAML::XS <<<yes &>/dev/null					# to stop the prompts when installing nipe for older version that don't detect a default continent
		sudo apt install libjson-perl libswitch-perl libtest-lwp-useragent-perl -y &>/dev/null	#  install the all dependencies before installing Nipe
		sudo cpan install Switch JSON LWP::UserAgent Config::Simple &>/dev/null
		sudo cpan install Try::Tiny Config::Simple JSON 1>/dev/null		
		sudo perl nipe.pl install 1>/dev/null
		echo -e " \033[0;32m[+] Nipe Installed.\033[0m ($(find ~ -type f -name nipe.pl))"
	else
		echo -e " \033[0;32m[+] Nipe Detected.\033[0m ($(find ~ -type f -name nipe.pl))"
	fi
}
function set_anon(){  	# be anonymous
	nipedir=$(find ~ -type d -name nipe)			# set location of nipe installed
	nipe=$(find ~ -type f -name nipe.pl)			# set location of nipe.pl
	cd $nipedir 									# every nipe path might be different
	sudo perl $nipe start							# start Nipe
	while true
	do
		case $(sudo perl $nipe status | grep '\S' | wc -l) in		# check of Nipe status: Nipe Error [!] status is always one line
			1) echo -e " \033[1;31m[-] You are NOT Anonymous.\033[0m Restarting \e[1m\"Nipe\"\e[0m... Please wait."; sudo perl $nipe restart;; # still not anonymous: Error, restart Nipe
			2) 	# Nipe can output an IP address but its either "Activated/Disabled"
				if [ -z "$(sudo perl $nipe status | grep disabled)" ] # activated status
				then
					if [ "$(sudo perl $nipe status | tr -d "\n\r" | awk '{print $NF}')" != "$orig_ip" ]			# compare spoof IP with original IP; RE-CONFIRMATION
					then
						echo -e " \033[0;32m[+] You are ANONYMOUS.\033[0m"										# ANONYMOUS confirmed
						echo -e "\n [+] Spoofed IP: \e[1m$(curl -s ifconfig.io) | $(curl -s ifconfig.io | xargs geoiplookup | awk '{print $5, $6, $7, $8}')\e[0m\n"
						break		
					fi
				else # disabled status
					echo -e " \033[1;31m[-] You are NOT Anonymous.\033[0m Restarting \e[1m\"Nipe\"\e[0m... Please wait." 	# still not anonymous: Disabled
					sudo perl $nipe restart		#	restart Nipe
				fi;;

		esac
	done
}
function remote_installation(){  # assuming remote server is a new system with no geoip-bin, nmap & whois, then do force installation
if [ "$(sshpass -p $pass ssh -o StrictHostKeyChecking=No -o LogLevel=QUIET -o ConnectTimeout=5 $server echo ok)" == "ok" ]
then # if remote server is connected, do installation
	echo -e "\e[1m\n\e[4mRemote Server Information\e[0m\e[0m \033[1;32m\e[1m(Connected)\e[0m\033[0m"
	sshpass -p $pass ssh -o LogLevel=QUIET -t $server "echo \"$sudo_pass\" | sudo -S apt-get install -y geoip-bin" 1>/dev/null	# force install geoip-bin
	echo -e " \033[0;32m[+] GeoIP Installed.\033[0m"

	sshpass -p $pass ssh -o LogLevel=QUIET -t $server "echo \"$sudo_pass\" | sudo -S apt-get install -y nmap" 1>/dev/null		# force install Nmap (normal capabilities)
	#sshpass -p $pass ssh -o LogLevel=QUIET -t $server "echo $sudo_pass | sudo -S apt-get install -y libcap2-bin" 1>/dev/null	# for possible -sS -O Scan (which require sudo)
	#sshpass -p $pass ssh -o LogLevel=QUIET -t $server "echo $sudo_pass | sudo -S setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)" 1>/dev/null		# for possible -sS -O Scan
	#sshpass -p $pass ssh -o LogLevel=QUIET -t $server "echo $sudo_pass | sudo -S setcap -r $(which nmap)" 1>/dev/null			# to unset or remove the capabilities of Nmap
	echo -e " \033[0;32m[+] Nmap Installed.\033[0m"

	sshpass -p $pass ssh -o LogLevel=QUIET -t $server "echo \"$sudo_pass\" | sudo -S apt-get install -y whois -q" 1>/dev/null	# force install whois
	echo -e " \033[0;32m[+] whois Installed.\033[0m"
	
	sshpass -p $pass ssh -o LogLevel=QUIET -t $server "echo \"$sudo_pass\" | sudo -S apt-get install -y curl -q" 1>/dev/null	# force install curl
	echo -e " \033[0;32m[+] curl Installed.\033[0m"
	
else # if remote server not available, inform user and exit the program cleanly
	echo -e "\e[1m\n\e[4mRemote Server Information $server\e[0m\e[0m \033[1;31m\e[1m(NOT Connected)\e[0m\033[0m"
	echo -e "$(date) - [Offline] Remote Server is offline or not accepting SSH logins." >> /var/log/rc_scan.log 2>/dev/null
	sudo chmod 644 /var/log/rc_scan.log		# exit program cleanly
	cd $nipedir && sudo perl $nipe stop > /dev/null 2>&1
	rm -r /tmp/rc_result.txt > /dev/null 2>&1
	echo "Remote Server is offline or not accepting SSH logins."
	exit
fi
}
function scanner(){ 	# scanner processes and logging
	sshpass -p $pass ssh -o LogLevel=QUIET -t $server "whois $input" >> $(pwd)/RC_Scan/whois_${input}										# whois on the input
	echo -e "\e[0m[${i}a] \e[1mwhois\e[0m scan of \"$input\"  >  saved into \e[1m$(pwd)/RC_Scan/whois_${input}\e[0m"	# inform user of whois saved data
	echo -e "$(date) - [*] whois data collected for: $input" >> /var/log/rc_scan.log									# logging of whois activity
	echo -e "\e[4m\e[1m\n$input\e[0m\e[0m" >> /tmp/rc_result.txt														# header for result; title same as input
	echo -e "$(cat $(pwd)/RC_Scan/whois_${input} | grep -i 'tech\|admin\|mail\|organisation\|registrant\|server' | grep -vi 'abuse\|notice\|solicitations\|terms\|whois' | sort -u)" >> /tmp/rc_result.txt
	echo "" >> /tmp/rc_result.txt																						# append whois output to result; only selected grep parameters
	# sshpass -p $pass ssh -o LogLevel=QUIET -t $server "nmap --privileged $input -Pn -sS -O -sV -T4" >> $(pwd)/RC_Scan/nmap_${input}  # for possible -sS -O Scan (which require sudo)
	sshpass -p $pass ssh -o LogLevel=QUIET -t $server "nmap $input -p- -Pn -sV -vv" >> $(pwd)/RC_Scan/nmap_${input}							# nmap scan on the input
	echo -e "[${i}b] \e[1mnmap\e[0m scan of \"$input\"  >  saved into \e[1m$(pwd)/RC_Scan/nmap_${input}\e[0m"			# inform user of nmap saved data
	echo -e "$(date) - [*] Nmap data collected for: $input" >> /var/log/rc_scan.log										# logging of nmap activity
	echo -e "$(cat $(pwd)/RC_Scan/nmap_${input} | grep -i 'PORT\|open\|filtered\|closed\|\|unfiltered\|service\|OS' | grep -vi 'incorrect\|starting')" >> /tmp/rc_result.txt
	echo "" >> /tmp/rc_result.txt																						# append nmap output to result; only selected grep parameters
	echo $(for i in $(seq 1 80); do printf "-"; done) >> /tmp/rc_result.txt												# separator for result
}
function quit_saved(){	# save summarized result before exiting
	cd $(find ~ -type d -name RC_Scan)
	function file_exist(){	# check if file already exist
		while true
		do
			if [ -f "$file" ]
			then
				echo -ne "File exists. Overwrite it? (yes|no): \e[1m" && read next	# check to overwrite
				echo -ne "\e[0m"
				if [ "$next" = "y" ] || [ "$next" = "yes" ] || [ "$next" = "YES" ] || [ -z "$file" ]
				then
					cat /tmp/rc_result.txt > $file
					quit
				else	# input another filename
					echo -ne "Specify a new filename: \e[1m" && read file
					echo -ne "\e[0m"
				fi
			else	# if file do not exist, create it
				cat /tmp/rc_result.txt > $file
				quit
			fi
		done
	}
	function quit(){		# clean exit
		echo -e "$(date) - [Exit] Result saved as RC_Scan/${file}." >> /var/log/rc_scan.log
		sudo chmod 644 /var/log/rc_scan.log	2>/dev/null
		rm -r /tmp/rc_result.txt 2>/dev/null
		cd $nipedir && sudo perl $nipe stop > /dev/null 2>&1
		echo -e "Result saved to \e[1m${file}\e[0m."
		exit
	}
	echo -ne "\e[0mAdd result to (\e[1mrc_result.txt\e[0m), enter \"y\", ELSE Specify a filename: \e[1m" && read file
	echo -ne "\e[0m"
	if [ "$file" = "y" ] || [ "$file" = "yes" ] || [ "$file" = "YES" ] || [ -z "$file" ]
	then
		cat /tmp/rc_result.txt >> rc_result.txt #2>/dev/null
		file="rc_result.txt"
		quit
	else
		file_exist
	fi
}
function start_scan(){ 	# begin activity
	while true	# if user did not enter any input
	do
		echo -ne "\e[0mSpecify a Domain/IP address to scan: \e[1m" && read input
		if [ -z "$input" ]
		then
			continue
		else
			break
		fi
	done
	i=1
	remote_installation	 																		# do force installation on remote server
	echo -e "Uptime: $(sshpass -p $pass ssh -o StrictHostKeyChecking=No $server "uptime")"		# check status of remote server system; time & load
	echo -e "Remote Server IP Address: $(sshpass -p $pass ssh $server "curl -s ifconfig.io")"			# display remote server IP address
	echo -e "Country: $(sshpass -p $pass ssh $server "curl -s ifconfig.io | xargs geoiplookup | cut -f 5- -d \" \"")"	# display country of remote server
	echo -e "Operating System: $(sshpass -p $pass ssh $server "uname -o")"						# display remote server OS
	echo -e "Kernel Information: $(sshpass -p $pass ssh $server "uname -sr")\n"					# display remote server Kernel Info
	
	mkdir -p $(pwd)/RC_Scan																		# create a directory for user
	scanner																						# begin first scan
	while true
	do
		echo -ne "\n\e[0mSpecify a Domain/IP address to scan (To quit, enter \"q\" | To view result, enter \"v\"): \e[1m"	# next scan | quit | view result
		read input
		lc_input=$(echo $input | tr '[:upper:]' '[:lower:]')									# set input to lower case
		case $lc_input in
		quit|q)
			quit_saved ;;
		view|v)
			cat /tmp/rc_result.txt ;;															# display the result
		*) # if user did not enter any input
			if [ -z "$lc_input" ]
			then
				continue
			else
				i=$((i+1))																		# set the number of inputs sent for scanning
				scanner
			fi ;;
		esac
	done
}
# function calls
trap "trap_all" 2
setup
bin_check
set_anon
start_scan

# To opt for OS Detection and SYN scan for Nmap, make changes below in the function: scanner,
# remove # from line 174 and add to line 175, or change line 175 to:
# sshpass -p $pass ssh -o LogLevel=QUIET -t $server "nmap --privileged $input -Pn -sS -O -sV -T4" >> $(pwd)/RC_Scan/nmap_${input}
# then, set nmap capablitites in the function: remote_installation, by removing # on line 150 & 151.
# To unset/remove nmap capabilities use line 152.
# WARNING: It will take a long time for each scan, estimated 20-30 mins per scan.

