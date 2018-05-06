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

#remote logging via sendmail
if [[ ! -f /usr/local/minerchk/remotelog ]]; then
	wget -O /usr/local/minerchk/remotelog https://raw.githubusercontent.com/Hestat/minerchk/master/remotelog
fi
remotelog=$(cat /usr/local/minerchk/remotelog)


#create formatting
div(){
  for ((i=0;i<$1;i++)); do printf '='; done;
}

header(){
	echo -e "\n$(div 40)\n"
}

header2=$(echo -e "$(div 3)")

scanhead=$(echo -e "\n$gre Scanning ::\n")

#check yara signatures
remotesig1=$(curl -sS https://raw.githubusercontent.com/Hestat/minerchk/master/miners.yar | md5sum | awk '{print $1}')
localsig1=$(md5sum /usr/local/minerchk/miners.yar | awk '{print $1}')
if [[ "$remotesig1" =  "$localsig1" ]]; then
	echo -e "$gre Local Yara Signatures up to date $whi"
else echo -e "$gre Updating signatures $whi"
	wget -O /usr/local/minerchk/miners.yar https://raw.githubusercontent.com/Hestat/minerchk/master/miners.yar
	sleep 1
fi

#check IP signatures
remotesig2=$(curl -sS https://raw.githubusercontent.com/Hestat/minerchk/master/ip-only.txt | md5sum | awk '{print $1}')
localsig2=$( md5sum /usr/local/minerchk/ip-only.txt | awk '{print $1}')
if [[ "$remotesig2" = "$localsig2" ]]; then
	echo -e "$gre Local IP list up to date $whi"
	sleep 1
else echo -e "$gre Updating IP list $whi"
	wget -O /usr/local/minerchk/ip-only.txt https://raw.githubusercontent.com/Hestat/minerchk/master/ip-only.txt
	sleep 1
fi

#check if minerchk is up to date
remoteprogsig=$(curl -sS https://raw.githubusercontent.com/Hestat/minerchk/master/minerchk.sh | md5sum | awk '{print$1}')
localprogsig=$(md5sum /usr/local/minerchk/minerchk | awk '{print$1}')
if [[ "$remoteprogsig" = "$localprogsig" ]]; then
	echo -e "$gre Minerchk is up to date $whi"
	sleep 1
else echo -e "$yell Newer version of Minerchk available, please use option 5 to update"
	sleep 10
fi

#drop environment data into logs for easier identification
header > $log
hostname >> $log
header  >> $log
header > $log1
hostname >> $log1
header  >> $log1
echo "Subject: [ALERT] Cryptominer report" > $log2

#start menu
while true
do
clear
	printf "%b" "\n\e[0m"
	echo
	echo
	header
	echo "  --   Miner Check beta v1.40    --"
	header
	echo "Enter 1 to run quick miner checks on server (Active mining on server and in /tmp)"
	echo 
	echo "Enter 2 to run deep miner checks through site files"
	echo
	echo "Enter 3 to run checks for miners embeded in websites (Crypto-jacking)"
	echo
	echo "Enter 4 to innoculate server (Blocks domains and IP's used to mine)"
	echo
	echo "Enter 5 to run updates"
	echo
	echo "Enter 6 to report logs"
	echo
	echo "Enter 7 to quit"

read answer
case "$answer" in


	1) echo -e "$yell $header2 Checking for miners in /tmp $header2" 
		echo $scanhead
		if [[ -x $(which clamscan) ]] ; then #use clamav and yara
			echo -e "$gre ClamAV installed using clamscan for scanning \n"
			clamscan -ir --no-summary -l $log -d /usr/local/minerchk/miners.yar /tmp
			clamscan -ir --no-summary -l $log -d /usr/local/minerchk/miners.yar /dev/shm
			clamscan -ir --no-summary -l $log -d /usr/local/minerchk/miners.yar /var/tmp
		else
	        	grep -R 'stratum+tcp' /tmp 1>> $log 2> /dev/null
			grep -R 'stratum+tcp' /dev/shm 1>> $log 2> /dev/null
			grep -R 'stratum+tcp' /var/tmp 1>> $log 2> /dev/null
		fi
		echo -e "$yell $header2 Checking for miners in running processes $header2"
		echo
		echo $scanhead
		echo
		for line in $(cat /usr/local/minerchk/ip-only.txt); do lsof -nP | grep $line; done
		ps fauwx | grep minerd | grep -v 'grep minerd' 1>> $log 2> /dev/null
		ps fauwx | grep xmrig | grep -v 'grep xmrig' 1>> $log 2> /dev/null
		ps fauwx | grep xmr | grep -v 'grep xmr' 1>> $log 2> /dev/null
		echo
		echo -e "$yell $header2  Checking for common miner ports $header2"
		echo
		echo $scanhead
		portlist=$(curl -s https://raw.githubusercontent.com/Hestat/minerchk/master/portlist.txt)
		for port in $portlist; do 
 		netstat -tpn | grep -w $port 1>> $log 2> /dev/null;
		done
		grep 'crypto_miner_config_file' $log | cut -d : -f1 | xargs cat >> $log
		echo -e "$yell $header2 Current Scan Results logged in the following file $header2 $gre"
		echo $log
		echo -e "$yell $header2 Hits in the Scan $header2 $gre"
		cat $log;;

	2)
		printf "%b" "$yell=== Checking for miners in site files  ===" 
		printf "%b" "$gre"
		echo
		find /home/*  -maxdepth 1 -type f | xargs grep 'stratum+tcp' >> $log 2>/dev/null
		# Adapted from Mark Cunningham module
		# Scan of Sites for on server miners in site files
		# Define the scan function
		sitescan(){

 		 # Use the positional parameter to define directory location, and build list
  		dirlist=$(find $1 -maxdepth 0 -type d -print)

  		# Loop through list of directories
  		for account in $dirlist; do
    		echo $scanhead

		if [[ -x $(which clamscan) ]] ; then #use clamav and yara
			echo -e "$gre ClamAV installed using clamscan for scanning \n"
			clamscan -ir --no-summary -l $log -d /usr/local/minerchk/miners.yar $account
			else
			grep -wiR 'stratum+tcp' $account 1>> $log 2>/dev/null
		fi

  		done; echo
 		 }
	 		 


		# Check for common control panels / configurations
		if [[ -x $(which whmapi1) ]] ; then #cPanel
  		printf "%b" "cPanel detected\n"
  		sitescan "/home*/*/public_html/"

		elif [[ -x $(which plesk) ]] ; then #Plesk
  		printf "%b" "Plesk detected\n"
  		sitescan "/var/www/vhosts/*/httpdocs/"

		else #Core-Managed
  		printf "%b"  "Unknown control panel, assuming Apache and Nginx defaults\n"
  		sitescan "/var/www/html/" 2> /dev/null
		sitescan "/usr/share/nginx/" 2> /dev/null
		fi
		echo -e "$yell $header2 Current Scan Results logged in the following file $header2 $gre"
		echo $log
		echo -e "$yell $header2 Hits in the Scan $header2 $gre"
		cat $log;;

	3) echo -e "$yell $header2 Checking for Crypto-jacking injections $header2 $gre\n"
		echo "This make take some time if you have many sites."
		echo
		touch $log1
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
		if [[ -x $(which whmapi1) ]] ; then #cPanel
  		printf "%b" "cPanel detected\n"
  		coinhivescan "/home*/*/public_html/"

		elif [[ -x $(which plesk) ]] ; then #Plesk
  		printf "%b" "Plesk detected\n"
  		coinhivescan "/var/www/vhosts/*/httpdocs/"

		else #Core-Managed
  		printf "%b"  "Unknown control panel, assuming Apache and Nginx defaults\n"
  		coinhivescan "/var/www/html/" 2> /dev/null
		coinhivescan "/usr/share/nginx/" 2> /dev/null
		fi
                echo -e "$yell $header2 Current Scan Results logged in the following file $header2 $gre"
                echo $log1
                echo -e "$yell $header2 Hits in the Scan $header2 $gre"
                cat $log1;;

	4) 	if [[ -x $(which csf) ]] ; then #CSF	
			echo -e "$gre" "Config Server Firewall Detected\n"
			echo " " >> /etc/csf/csf.blocklists
			echo "#Minerchk" >> /etc/csf/csf.blocklists
			echo "#list to block known Monero miner pools" >> /etc/csf/csf.blocklists
			echo "Minerchk|86400|0|https://raw.githubusercontent.com/Hestat/minerchk/master/ip-only.txt" >> /etc/csf/csf.blocklists
			service csf restart
			service lfd restart

		else #Not CSF
			echo -e "$yell $header2 Mining domains will be added to hosts file to prevent DNS lookup $header2 $gre\n"
			hostlist=$(curl https://raw.githubusercontent.com/Hestat/minerchk/master/hostslist.txt)		
			for domain in $hostlist; do
 			echo "Blocking $domain in /etc/hosts.."
 			echo "127.0.0.1 $domain" >> /etc/hosts
		done
	fi;;

	5) 	echo
	        echo -e "$yell $header2 Updating Minerchk $header2 $gre"
       		wget -O /usr/local/minerchk/minerchk https://raw.githubusercontent.com/Hestat/minerchk/master/minerchk.sh
 		newlocalprogsig=$(md5sum /usr/local/minerchk/minerchk | awk '{print$1}')
		if [[ "$newlocalprogsig" = "$remoteprogsig" ]]; then
		chmod +x /usr/local/minerchk/minerchk 2> /dev/null
		ln -s /usr/local/minerchk/minerchk /usr/local/bin/minerchk 2> /dev/null
		echo
		echo -e "$header2 Update Successful! $header2"
		echo -e " Please restart Minerchk now $whi"
	else echo
		echo -e "$yell $header2 Something went wrong, try a manual reinstall $header2 $whi"	
	fi;;
	
	6) 	echo -e "$yell $header2 Sending Log Data $header2"
		cat $log >> $log2
		header >> $log2
		cat $log1 >> $log2
		cat $log2 | sendmail $remotelog
		echo "Reports sents, have any other information you would like to report? Send to $remotelog";;


	7) 	rm /tmp/minerchk.report
		exit ;;

esac
echo
echo
printf "%b" "$whi Enter to return to the menu \c"
	read input

done

