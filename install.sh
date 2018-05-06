PWD=$(pwd)

if [[ -x $(which minerchk) ]]; then #Minerchk already installed
	echo -e "Minerchk is already installed, if you want to update use option 5 in the script"
else echo -e "Installing minerchk"
	mkdir -p /usr/local/minerchk/
	cp -av $PWD/minerchk.sh /usr/local/minerchk/minerchk
	cp -av $PWD/ip-only.txt /usr/local/minerchk/
	cp -av $PWD/miners.yar /usr/local/minerchk/
	cp -ac $PWD/remotelog /usr/local/minerchk/
	chmod -x /usr/local/minerchk/minerchk
	echo -e "Install Complete"
fi

