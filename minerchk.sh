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
	echo "--   Miner Check alpha    --"
	echo "============================"
	echo "Enter 1 to run miner checks on server."
	echo  " "
	echo "Enter 2 to run miner checks embeded in Website"
	echo  " "
	echo "Enter 3 to innoculate server"
	echo " "
	echo "Enter 4 to quit"

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
		ps faux | grep $proc | grep -v 'grep'
		ps fauwx | grep xmrig | grep -v 'grep xmrig'
		echo " "
		printf "%b" "$yell=== Checking for common miner ports ==="
		echo " "
		printf "%b" "$gre"
		netstat -tpn | grep -w 3333
		netstat -tpn | grep -w 4444
		netstat -tpn | grep -w 5555
		netstat -tpn | grep -w 6666
		netstat -tpn | grep -w 7777
		netstat -tpn | grep -w 8888
		netstat -tpn | grep -w 9999
		netstat -tpn | grep 14444
		netstat -tpn | grep 14433 
		rm -f proctemp;;

	2) printf "%b" "$yell=== Checking for Coinhive injections ===\n"
		echo "This make take some time if you have many sites."
		echo " "
		printf "%b" "$gre"
		for x in $(find /home/*/public_html/ -type f -name '*.php'); do egrep -Hw 'coinhive.min.js|wpupdates.github.io/ping|cryptonight.asm.js|coin-hive.com' $x; 
		done 2> /dev/null
		for x in $(find /var/www/html -type f -name '*.php'); do egrep -Hw 'coinhive.min.js|wpupdates.github.io/ping|cryptonight.asm.js|coin-hive.com' $x; 
		done 2> /dev/null
		for x in $(find /var/www/vhosts/*/httpdocs -type f -name '*.php'); do egrep -Hw 'coinhive.min.js|wpupdates.github.io/ping|cryptonight.asm.js|coin-hive.com' $x;
		done 2> /dev/null
		find /home/*/public_html -name coinhive.min.js 2> /dev/null
		find /var/www/html -name coinhive.min.js 2> /dev/null
		find /var/www/vhosts/*/httpdocs -name coinhive.min.js 2> /dev/null;;
	3) printf "%b" "$yell === Mining domains will be added to hosts file to prevent DNS lookup ===\n"
		printf "%b" "$gre"
		echo "blocking cryptoescrow.eu cryptonotepool.org fcn-mro.pool.minergate.com kippo.eu mine.moneropool.com monero.crypto-pool.fr monero.farm monerohash.com monerominers.net mro.extremeool.org mro.poolto.be pool.minexmr.com webcoin.me xdn.miner.center xmr.crypto-pool.fr xmr-eu.nanopool.org xmr.hashinvest.ws xmr.prohash.net yescrypt.mine.zpool.ca"
		echo "127.0.0.1 xmr.crypto-pool.fr" >> /etc/hosts
		echo "127.0.0.1 xmr-eu1.nanopool.org" >> /etc/hosts
		echo "127.0.0.1 yescrypt.mine.zpool.ca" >> /etc/hosts
		echo "127.0.0.1 pool.minexmr.com" >> /etc/hosts
		echo "127.0.0.1 monerohash.com" >> /etc/hosts 
		echo "127.0.0.1 mine.moneropool.com" >> /etc/hosts 
		echo "127.0.0.1 xdn.miner.center" >> /etc/hosts 
		echo "127.0.0.1 xmr.prohash.net" >> /etc/hosts 
		echo "127.0.0.1 mro.poolto.be" >> /etc/hosts 
		echo "127.0.0.1 monero.crypto-pool.fr" >> /etc/hosts 
		echo "127.0.0.1 cryptoescrow.eu" >> /etc/hosts 
		echo "127.0.0.1 monerominers.net" >> /etc/hosts 
		echo "127.0.0.1 fcn-mro.pool.minergate.com" >> /etc/hosts 
		echo "127.0.0.1 cryptonotepool.org" >> /etc/hosts 
		echo "127.0.0.1 mro.extremeool.org" >> /etc/hosts 
		echo "127.0.0.1 mro.poolto.be" >> /etc/hosts 
		echo "127.0.0.1 webcoin.me" >> /etc/hosts 
		echo "127.0.0.1 monerominers.net" >> /etc/hosts 
		echo "127.0.0.1 kippo.eu" >> /etc/hosts 
		echo "127.0.0.1 cryptoescrow.eu" >> /etc/hosts 
		echo "127.0.0.1 xmr.hashinvest.ws" >> /etc/hosts 
		echo "127.0.0.1 monero.farm" >> /etc/hosts 
		echo "127.0.0.1 pool.supportxmr.com" >> /etc/hosts ;;
	4) exit ;;

esac
echo " "
echo " "
printf "%b" "$whi Enter to return to the menu \c"
	read input

done
