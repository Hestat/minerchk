#!/bin/bash
# Developed by Brian Laskowski
# laskowski-tech.com

yell='\e[33m'
gre='\e[32m'
whi='\e[0m'

while true
do
clear
	printf "%b" "\n\e[0m"
	echo " "
	echo " "
	echo "============================"
	echo "--   Miner Check beta v1.1    --"
	echo "============================"
	echo "Enter 1 to run miner checks on server."
	echo  " "
	echo "Enter 2 to run miner checks embeded in Website"
	echo  " "
	echo "Enter 3 to innoculate server"
	echo " "
	echo "Enter 4 to check version"
	echo " "
	echo "Enter 5 to quit"

read answer
case "$answer" in


	1) printf "%b" "$yell=== Checking for miners in /tmp ===" 
		printf "%b" "$gre"
		echo " "
		ls /tmp | grep 'php*.c' 2> /dev/null
	        grep -R 'stratum+tcp' /tmp  2> /dev/null
		grep -R 'stratum+tcp' /dev/shm 2> /dev/null
	        grep -R 'stratum+tcp' /tmp > proctemp 2> /dev/null
		grep -R 'stratum+tcp' /dev/shm > proctemp 2> /dev/null
		proc=$(cat proctemp | cut -d '/' -f 4 | awk '{print$1}' | head -n1 | cut -d ':' -f1)
		echo " "
		printf "%b" "$yell=== Checking for miners in running processes ==="
		echo " "
		printf "%b" "$gre"
		echo " "
		ps fauwx | grep minerd | grep -v 'grep minerd'
		ps faux | grep $proc 2> /dev/null | grep -v 'grep' 2> /dev/null
		ps fauwx | grep xmrig | grep -v 'grep xmrig'
		ps fauwx | grep xmr | grep -v 'grep xmr'
		echo " "
		printf "%b" "$yell=== Checking for common miner ports ==="
		echo " "
		printf "%b" "$gre"
		portlist=$(curl -s https://raw.githubusercontent.com/Hestat/minerchk/master/portlist.txt)
		for port in $portlist; do 
 		netstat -tpn | grep -w $port;
		done
		rm -f proctemp
		echo " "
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

		 grep -wiR 'stratum+tcp' $account  2>/dev/null;

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
  		sitescan "/var/www/html/"
		sitescan "/usr/share/nginx/"
		fi;;

	2) printf "%b" "$yell=== Checking for Coinhive injections ===\n"
		echo "This make take some time if you have many sites."
		echo " "
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

    		find $account -type f -name '*.php' -print0 | xargs -0 egrep -Hw "$coin"  2>/dev/null;

    		# Search for any actual .js files
    		find $account -name coinhive.min.js 2> /dev/null

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
  		coinhivescan "/var/www/html/"
		coinhivescan "/usr/share/nginx/"
		fi;;

	3) printf "%b" "$yell === Mining domains will be added to hosts file to prevent DNS lookup ===\n"
		printf "%b" "$gre"
		hostlist=$(curl https://raw.githubusercontent.com/Hestat/minerchk/master/hostslist.txt)		
		for domain in $hostlist; do
 		echo "Blocking $domain in /etc/hosts.."
 		echo "127.0.0.1 $domain" >> /etc/hosts
		done;;

	4) 	echo " "
		printf "%b" "$yell"
		echo " Local Version "
		grep "Miner Check" ./minerchk.sh | grep -v 'grep "Miner Check"' | awk '{print$6}'
		echo " "
		printf "%b" "$gre"
		echo " Current Version "
		curl -s https://raw.githubusercontent.com/Hestat/minerchk/master/minerchk.sh | grep "Miner Check" ./minerchk.sh | grep -v 'grep "Miner Check"'| awk '{print$6}';;

	5) exit ;;

esac
echo " "
echo " "
printf "%b" "$whi Enter to return to the menu \c"
	read input

done
