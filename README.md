# minerchk
Bash script to Check for malicious Cryptomining

See the script in action here: https://laskowski-tech.com/2018/01/08/minerchk-beta-announcement/

Download and set up for the root user:

 `mkdir /usr/local/minerchk`

 `wget -O /usr/local/minerchk/minerchk https://raw.githubusercontent.com/Hestat/minerchk/master/minerchk.sh`

 `chmod +x /usr/local/minerchk/minerchk`
 
  `ln -s /usr/local/minerchk/minerchk /usr/local/bin/minerchk`


Run once without installing script

`exec 3<&1 && bash <&3 <(curl -sq https://raw.githubusercontent.com/Hestat/minerchk/master/minerchk.sh)`
