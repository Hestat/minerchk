#!/bin/bash
# Developed by Brian Laskowski
# laskowski-tech.com

#create color vars
yell='\e[33m'
gre='\e[32m'
whi='\e[0m'

#create log dir and log vars
mkdir -p /usr/local/minerchk
logdir="/usr/local/minerchk"
log="${logdir}/miner.$(date +%y%m%d-%H%M).log"
log1="${logdir}/coinhive.$(date +%y%m%d-%H%M).log"
log2=/tmp/minerchk.report

#drop environment data into logs for easier identification
hostname > $log
echo "========================== " >> $log
hostname > $log1
echo "========================== " >> $log1
echo "Subject: [ALERT] Cryptominer report" > $log2

#start menu
while true
do
clear
	printf "%b" "\n\e[0m"
	echo " "
	echo " "
	echo "============================"
	echo "--   Miner Check beta v1.3    --"
	echo "============================"
	echo "Enter 1 to run quick miner checks on server (Active mining on server and in /tmp)"
	echo  " "
	echo "Enter 2 to run deep miner checks through site files"
	echo " "
	echo "Enter 3 to run checks for miners embeded in websites (Crypto-jacking)"
	echo  " "
	echo "Enter 4 to innoculate server (Blocks domains and IP's used to mine)"
	echo " "
	echo "Enter 5 to check version"
	echo " "
	echo "Enter 6 to report logs"
	echo " "
	echo "Enter 7 to quit"

read answer
case "$answer" in


	1) printf "%b" "$yell=== Checking for miners in /tmp ===" 
		printf "%b" "$gre"
		echo " "
		echo "Scanning ::"
	        grep -R 'stratum+tcp' /tmp 1>> $log 2> /dev/null
		grep -R 'stratum+tcp' /dev/shm 1>> $log 2> /dev/null
	        grep -R 'stratum+tcp' /tmp > proctemp 2> /dev/null
		grep -R 'stratum+tcp' /dev/shm > proctemp 2> /dev/null
		proc=$(cat proctemp | cut -d '/' -f 4 | awk '{print$1}' | head -n1 | cut -d ':' -f1) >> $log
		echo " "
		printf "%b" "$yell=== Checking for miners in running processes ==="
		echo " "
		printf "%b" "$gre"
		echo "Scanning ::"
		echo " "
		ps fauwx | grep minerd | grep -v 'grep minerd' 1>> $log 2> /dev/null
		ps faux | grep $proc 2> /dev/null | grep -v 'grep' 1>> $log 2> /dev/null
		ps fauwx | grep xmrig | grep -v 'grep xmrig' 1>> $log 2> /dev/null
		ps fauwx | grep xmr | grep -v 'grep xmr' 1>> $log 2> /dev/null
		echo " "
		printf "%b" "$yell=== Checking for common miner ports ==="
		echo " "
		printf "%b" "$gre"
		echo "Scanning ::"
		portlist=$(curl -s https://raw.githubusercontent.com/Hestat/minerchk/master/portlist.txt)
		for port in $portlist; do 
 		netstat -tpn | grep -w $port 1>> $log 2> /dev/null;
		done
		rm -f proctemp
		printf "%b" "$yell"
		echo "=== Current Scan Results logged in the following file ==="
		printf "%b" "$gre"
		echo $log
		printf "%b" "$yell"
		echo "=== Hits in the Scan ==="
		printf "%b" "$gre"
		cat $log;;

	2)
		printf "%b" "$yell=== Checking for miners in site files  ===" 
		printf "%b" "$gre"
		echo " "
		# Adapted from Mark Cunningham module
		# Scan of Sites for on server miners in site files
		# Define the scan function
		sitescan(){

 		 # Use the positional parameter to define directory location, and build list
  		dirlist=$(find $1 -maxdepth 0 -type d -print)

  		# Loop through list of directories
  		for account in $dirlist; do
    		echo "Scanning :: $account"

		 grep -wiR 'stratum+tcp' $account 1>> $log 2>/dev/null
		 egrep -wir 'xmrig' $account 1>>$log 2>/dev/null;

  		done; echo
 		 }
	 		 


		# Check for common control panels / configurations
		if [[ -x $(which whmapi1) ]] 2> /dev/null ; then #cPanel
  		printf "%b" "cPanel detected\n"
  		sitescan "/home*/*/public_html/"

		elif [[ -x $(which plesk) ]] 2> /dev/null; then #Plesk
  		printf "%b" "Plesk detected\n"
  		sitescan "/var/www/vhosts/*/httpdocs/"

		else #Core-Managed
  		printf "%b"  "Unknown control panel, assuming Apache and Nginx defaults\n"
  		sitescan "/var/www/html/" 2> /dev/null
		sitescan "/usr/share/nginx/" 2> /dev/null
		fi
		printf "%b" "$yell"
		echo "=== Current Scan Results logged in the following file ==="
		printf "%b" "$gre"
		echo $log
		printf "%b" "$yell"
		echo "=== Hits in the Scan ==="
		printf "%b" "$gre"
		cat $log;;

	3) printf "%b" "$yell=== Checking for Crypto-jacking injections ===\n"
		echo "This make take some time if you have many sites."
		echo " "
		touch $log1
		printf "%b" "$gre"
		#coinhive module
		# Author: Mark David Scott Cunningham                      | M  | D  | S  | C  |
		#                                                          +----+----+----+----+
		# Created: 2017-12-24
		# Updated: 2017-12-24
		#
		# Purpose: To scan for files injected with coinhive content and coinhive .js files
		#          Based on work by Brian Laskowski, intended to assist Brian.
		coin=$(curl -s https://raw.githubusercontent.com/Hestat/minerchk/master/coinhive.txt)
		# Define the scan function
		coinhivescan(){

 		 # Use the positional parameter to define directory location, and build list
  		dirlist=$(find $1 -maxdepth 0 -type d -print)

  		# Loop through list of directories
  		for account in $dirlist; do
    		echo "Scanning :: $account"

    		find $account -type f -name '*.php' -print0 | xargs -0 egrep -Hw "$coin" 1>> $log1 2>/dev/null;

    		# Search for any actual .js files
    		find $account -name coinhive.min.js 1>> $log1 2> /dev/null

		grep -wiR 'miner.start' $account 1>> $log1 2> /dev/null

  		done; echo
 		 }
	 		 


		# Check for common control panels / configurations
		if [[ -x $(which whmapi1) ]] 2> /dev/null; then #cPanel
  		printf "%b" "cPanel detected\n"
  		coinhivescan "/home*/*/public_html/"

		elif [[ -x $(which plesk) ]] 2> /dev/null; then #Plesk
  		printf "%b" "Plesk detected\n"
  		coinhivescan "/var/www/vhosts/*/httpdocs/"

		else #Core-Managed
  		printf "%b"  "Unknown control panel, assuming Apache and Nginx defaults\n"
  		coinhivescan "/var/www/html/" 2> /dev/null
		coinhivescan "/usr/share/nginx/" 2> /dev/null
		fi
                printf "%b" "$yell"
                echo "=== Current Scan Results logged in the following file ==="
                printf "%b" "$gre"
                echo $log1
                printf "%b" "$yell"
                echo "=== Hits in the Scan ==="
                printf "%b" "$gre"
                cat $log1;;

	4) 	if [[ -x $(which csf) ]] 2> /dev/null; then #CSF	
			printf "%b" "$gre" "Config Server Firewall Detected\n"
			echo " " >> /etc/csf/csf.blocklists
			echo "#Minerchk" >> /etc/csf/csf.blocklists
			echo "#list to block known Monero miner pools" >> /etc/csf/csf.blocklists
			echo "Minerchk|86400|0|https://raw.githubusercontent.com/Hestat/minerchk/master/ip-only.txt" >> /etc/csf/csf.blocklists
			service csf restart
			service lfd restart

		else #Not CSF
			printf "%b" "$yell === Mining domains will be added to hosts file to prevent DNS lookup ===\n"
			hostlist=$(curl https://raw.githubusercontent.com/Hestat/minerchk/master/hostslist.txt)		
			printf "%b" "$gre"
			for domain in $hostlist; do
 			echo "Blocking $domain in /etc/hosts.."
 			echo "127.0.0.1 $domain" >> /etc/hosts
		done
	fi;;

	5) 	echo " "
		printf "%b" "$yell"
		echo " Local Version "
		version=$(which minerchk)
		if [[ -x $(which minerchk) ]] 2> /dev/null; then #installed
			cat $version | grep "Miner Check" | grep -v 'grep "Miner Check"' | awk '{print$6}'
			echo " "
			printf "%b" "$gre"
			echo " Current Version "
			curl -s https://raw.githubusercontent.com/Hestat/minerchk/master/minerchk.sh | grep "Miner Check" | grep -v 'grep "Miner Check"'| awk '{print$6}'
		else #not installed
			printf "%b" "$yell"
			echo " Not Installed "
			echo " "
			printf "%b" "$gre"
			echo " Current Version "
			curl -s https://raw.githubusercontent.com/Hestat/minerchk/master/minerchk.sh | grep "Miner Check" | grep -v 'grep "Miner Check"'| awk '{print$6}'
	fi;;
	
	6) 	printf "%b" "$yell"
		echo "=== Sending Log Data ==="
		cat $log >> $log2
		echo "========================== " >> $log2
		cat $log1 >> $log2
		cat $log2 | sendmail miner@laskowski-tech.com
		echo "Reports sents, have any other information you would like to report? Send to miner@laskowski-tech.com";;


	7) 	rm /tmp/minerchk.report
		exit ;;

esac
echo " "
echo " "
printf "%b" "$whi Enter to return to the menu \c"
	read input

done

