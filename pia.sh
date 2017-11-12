#!/bin/bash

## pia Copyright (C) 2017 d4rkcat (thed4rkcat@yandex.com)
#
## This program is free software: you can redistribute it and/or modify
## it under the terms of the GNU General Public License Version 2 as published by
## the Free Software Foundation.
#
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License at (http://www.gnu.org/licenses/) for
## more details.

fupdate()						# Update the PIA openvpn files.
{
	CONFIGDEFAULT="https://www.privateinternetaccess.com/openvpn/openvpn.zip"
	CONFIGSTRONG="https://www.privateinternetaccess.com/openvpn/openvpn-strong.zip"
	CONFIGIP="https://www.privateinternetaccess.com/openvpn/openvpn-ip.zip"
	CONFIGTCP="https://www.privateinternetaccess.com/openvpn/openvpn-tcp.zip"
	CONFIGTCPSTRONG="https://www.privateinternetaccess.com/openvpn/openvpn-strong-tcp.zip"

	echo -e " [$BOLD$BLUE"'>'"$RESET] Please choose configuration:"
	echo " $BOLD$RED[$RESET""1""$BOLD$RED]$RESET Default UDP (aes-128-cbc sha1 rsa-2048)"
	echo " $BOLD$RED[$RESET""2""$BOLD$RED]$RESET Strong UDP (aes-256-cbc sha256 rsa-4096)"
	echo " $BOLD$RED[$RESET""3""$BOLD$RED]$RESET Direct IP (aes-128-cbc sha1 rsa-2048)"
	echo " $BOLD$RED[$RESET""4""$BOLD$RED]$RESET Default TCP (aes-128-cbc sha1 rsa-2048)"
	echo " $BOLD$RED[$RESET""5""$BOLD$RED]$RESET Strong TCP (aes-256-cbc sha256 rsa-4096)"
	read -p " ["$BOLD$BLUE">"$RESET"] " CONFIGNUM

	if [[ $CONFIGNUM =~ ^[0-9]+$ && $CONFIGNUM -lt 6 && $CONFIGNUM -gt 0 ]];then
		case $CONFIGNUM in
			1) DOWNURL=$CONFIGDEFAULT;echo -e " [$BOLD$GREEN"'*'"$RESET] Selected Default UDP configuration.";;
			2) DOWNURL=$CONFIGSTRONG;echo -e " [$BOLD$GREEN"'*'"$RESET] Selected Strong UDP configuration.";;
			3) DOWNURL=$CONFIGIP;echo -e " [$BOLD$GREEN"'*'"$RESET] Selected Direct IP configuration.";;
			4) DOWNURL=$CONFIGTCP;echo -e " [$BOLD$GREEN"'*'"$RESET] Selected Default TCP configuration.";;
			5) DOWNURL=$CONFIGTCPSTRONG;echo -e " [$BOLD$GREEN"'*'"$RESET] Selected Strong TCP configuration.";;
		esac
	else
		echo " [$BOLD$RED"'X'"$RESET] $CONFIGNUM is not a valid option! 1-5 only."
		exit
	fi
	
	echo -e " [$BOLD$BLUE"'>'"$RESET] Updating PIA openvpn files."
	rm -rf $VPNPATH/*.ovpn $VPNPATH/servers $VPNPATH/*.crt $VPNPATH/*.pem
	wget -q $DOWNURL -O $VPNPATH/pia.zip
	cd $VPNPATH && unzip -q pia.zip && rm $VPNPATH/pia.zip
	cd $VPNPATH && for file in *.ovpn;do mv "$file" `echo $file | tr ' ' '_'` &>/dev/null;done
	for file in $VPNPATH/*.ovpn;do sed -i 's/auth-user-pass/auth-user-pass pass.txt/' $file;done
	for file in $VPNPATH/*.ovpn;do echo -e "auth-nocache\nlog /var/log/pia.log" >> $file;done
	for file in $VPNPATH/*.ovpn;do echo $(basename $file) >> $VPNPATH/servers;done
	echo -e " [$BOLD$GREEN"'*'"$RESET] Files Updated."
}

fforward()						# Forward a port.
{
	sleep 1
	if [ ! -f $VPNPATH/client_id ];then head -n 100 /dev/urandom | sha256sum | tr -d " -" > $VPNPATH/client_id;fi
	while [ $(echo $FORWARDEDPORT | wc -c) -lt 3 ] 2>/dev/null;do
		FORWARDEDPORT=$(curl -s -m 4 "http://209.222.18.222:2000/?client_id=$(cat $VPNPATH/client_id)" | cut -d ':' -f 2 | cut -d '}' -f 1)
		sleep 0.2
	done
}

fnewport()						# Change port forwarded.
{
	NEWPORT=1
	PORTFORWARD=1
	mv $VPNPATH/client_id $VPNPATH/client_id.bak
	head -n 100 /dev/urandom | sha256sum | tr -d " -" > $VPNPATH/client_id
}

ffirewall()						# Set up ufw firewall rules to only allow traffic on tun0.
{
	ufw default deny outgoing &>/dev/null
	ufw default deny incoming &>/dev/null
	ufw allow out on tun0 &>/dev/null
	ufw allow in on tun0 &>/dev/null
	echo -e " [$BOLD$GREEN"'*'"$RESET] $(ufw enable 2>/dev/null)"
}

fhelp()						# Help function.
{
	echo """Usage: ./pia.sh [Options]

	-s	- Server number to connect to
	-l	- List available servers.
	-u	- Update PIA openvpn files before connecting.
	-p	- Forward a port.
	-n	- Change to another random port.
	-d	- Change DNS servers to PIA.
	-f	- Enable firewall to block all traffic apart from tun0
	-v	- Display verbose information.
	-h	- Display this help.

Examples: 
	pia -dps 24 	- Change DNS, forward a port and connect to Switzerland
	pia -nfv	- Forward a new port, run firewall and be verbose"""
	exit
}

fvpnreset()						# Restore all settings and exit openvpn gracefully.
{
	if [ $DNS -gt 0 ];then
		fdnsrestore
	fi
	kill -s SIGINT "$(ps aux | grep openvpn | grep root | grep -v grep | awk '{print $2}')" &>/dev/null
	if [ $FIREWALL -gt 0 ];then
		echo -e " [$BOLD$GREEN"'*'"$RESET] $(ufw disable 2>/dev/null)"
	fi
	echo " [$BOLD$GREEN"'*'"$RESET] VPN Disconnected."
	exit 0
}

fdnschange()						# Change DNS servers to PIA.
{
	echo -e " [$BOLD$GREEN"'*'"$RESET] Changed DNS to PIA servers."
	cp /etc/resolv.conf /etc/resolv.conf.bak
	echo '''#PIA DNS Servers
nameserver 209.222.18.222
nameserver 209.222.18.218
''' > /etc/resolv.conf.pia
	cp /etc/resolv.conf.pia /etc/resolv.conf
}

fdnsrestore()						# Revert to original DNS servers.
{
	echo -e " [$BOLD$GREEN"'*'"$RESET] Restored DNS servers."
	cp /etc/resolv.conf.bak /etc/resolv.conf
}

flist()						# List available servers
{
	if [ ! -f $VPNPATH/servers ];then
		fupdate
	fi
	
	echo " [$BOLD$GREEN"'*'"$RESET] $BOLD$GREEN""green$RESET servers allow port forwarding"
	for i in $(seq $(cat $VPNPATH/servers | wc -l));do
		echo -n " $BOLD$RED[$RESET$i$BOLD$RED]$RESET "
		SERVERNAME=$(cat $VPNPATH/servers | head -n $i | tail -n 1 | cut -d '.' -f 1)
		case $SERVERNAME in
			"Netherlands") echo $BOLD$GREEN$SERVERNAME$RESET;;
			"Switzerland") echo $BOLD$GREEN$SERVERNAME$RESET;;
			"CA_Toronto") echo $BOLD$GREEN$SERVERNAME$RESET;;
			"CA_Montreal") echo $BOLD$GREEN$SERVERNAME$RESET;;
			"Romania") echo $BOLD$GREEN$SERVERNAME$RESET;;
			"Israel") echo $BOLD$GREEN$SERVERNAME$RESET;;
			"Sweden") echo $BOLD$GREEN$SERVERNAME$RESET;;
			"France") echo $BOLD$GREEN$SERVERNAME$RESET;;
			"Germany") echo $BOLD$GREEN$SERVERNAME$RESET;;
			*) echo $SERVERNAME;;
		esac
	done
}

fchecklog()						# Check openvpn logs to get connection state
{
	LOGRETURN=0
	while [ $LOGRETURN -eq 0 ]; do
		VCONNECT=$(cat /var/log/pia.log)
		if [ $(echo "$VCONNECT" | grep 'Initialization Sequence Completed' | wc -c) -gt 1	];then
			LOGRETURN=1
		fi
		if [ $(echo "$VCONNECT" | grep 'auth-failure' | wc -c) -gt 1	];then
			LOGRETURN=2
		fi
		sleep 0.2
	done
}

fgetint()						# Check if user supplied server number is valid
{
	if [[ $SERVERNUM =~ ^[0-9]+$ ]];then
		MAXSERVERS=$(cat $VPNPATH/servers | wc -l)
		if [ $SERVERNUM -gt $MAXSERVERS ];then
			flist
			echo " [$BOLD$RED"'X'"$RESET] $SERVERNUM is too high! Maximum $MAXSERVERS servers to choose from."
			exit
		fi
	else
		flist
		echo " [$BOLD$RED"'X'"$RESET] $SERVERNUM is not an integer!"
		exit
	fi
}

						# Colour codes for terminal
BOLD=$(tput bold)
BLUE=$(tput setf 1)
GREEN=$(tput setf 2)
CYAN=$(tput setf 3)
RED=$(tput setf 4)
RESET=$(tput sgr0)

						# This is where we will store PIA openVPN files and user config
VPNPATH='/etc/openvpn/pia'

						# Initialize switches
PORTFORWARD=0
NEWPORT=0
NOPORT=0
DNS=0
FORWARDEDPORT=0
VERBOSE=0
FIREWALL=0
SERVERNUM=0

						# Check if user is root
if [ $(id -u) != 0 ];then echo -e " [$BOLD$RED"'X'"$RESET] Script must be run as root." && fhelp;fi

						# Check for missing dependencies and install
if [ $(uname -r | grep ARCH | wc -c) -gt 1 ];then
	command -v openvpn >/dev/null 2>&1 || { echo >&2 " [$BOLD$GREEN"'*'"$RESET] openvpn required, installing..";pacman -S openvpn; }
	command -v ufw >/dev/null 2>&1 || { echo >&2 " [$BOLD$GREEN"'*'"$RESET] ufw required, installing..";pacman -S ufw; }
else
	command -v apt-get >/dev/null 2>&1 || { echo >&2 " [$BOLD$RED"'X'"$RESET] OS not detected as Arch or Debian, Please install openvpn and ufw packages and retry.";exit; }
	command -v openvpn >/dev/null 2>&1 || { echo >&2 " [$BOLD$GREEN"'*'"$RESET] openvpn required, installing..";apt-get install openvpn; }
	command -v ufw >/dev/null 2>&1 || { echo >&2 " [$BOLD$GREEN"'*'"$RESET] ufw required, installing..";apt-get install ufw; }
fi

if [ ! -d $VPNPATH ];then mkdir -p $VPNPATH;fi

						# Check for existence of credentials file
if [ ! -f $VPNPATH/pass.txt ];then
	fupdate
	read -p " [$BOLD$BLUE"'>'"$RESET] Please enter your username: " USERNAME
	read -s -p " [$BOLD$BLUE"'>'"$RESET] Please enter your password: " PASSWORD
	echo -e "$USERNAME\n$PASSWORD" > $VPNPATH/pass.txt
	echo
	chmod 400 $VPNPATH/pass.txt
	unset USERNAME PASSWORD
fi

while getopts "lhupndfvs:" opt
do
 	case $opt in
 		l) flist;exit;;
		h) fhelp;;
		u) fupdate;;
		p) PORTFORWARD=1;;
		n) fnewport;;
		d) DNS=1;;
		f) FIREWALL=1;;
		v) VERBOSE=1;curl -s icanhazip.com > /tmp/ip.txt&;;
		s) SERVERNUM=$OPTARG;fgetint;;
		*) fhelp;;
	esac
done

trap fvpnreset INT

if [ $SERVERNUM -lt 1 ];then
	echo -e " [$BOLD$BLUE"'>'"$RESET] Please choose a server: "
	flist
	read -p " ["$BOLD$BLUE">"$RESET"]" SERVERNUM
fi

SERVER=$(cat $VPNPATH/servers | head -n $SERVERNUM | tail -n 1)
SERVERNAME=$(echo $SERVER | cut -d '.' -f 1)
clear
echo -e " [$BOLD$BLUE"'>'"$RESET] Connecting to $SERVERNAME, Please wait..."


cd $VPNPATH && openvpn --config $SERVER --daemon

fchecklog
if [ $LOGRETURN -eq 2 ];then
	echo -e " [$BOLD$RED"'X'"$RESET] Authorization Failed. Please check login details."
	rm -rf $VPNPATH/pass.txt
	fvpnreset
fi

if [ $VERBOSE -gt 0 ];then
	echo -e " [$BOLD$GREEN"'*'"$RESET] OpenVPN Logs:\n"
	echo -n $CYAN
	cat /var/log/pia.log
	echo $RESET
fi

echo -e " [$BOLD$GREEN"'*'"$RESET] Connected, OpenVPN is running daemonized on PID $BOLD$CYAN""$(ps aux | grep openvpn | grep root | grep -v grep | awk '{print $2}')$RESET"

if [ $DNS -gt 0 ];then
	fdnschange
fi

if [ $FIREWALL -gt 0 ];then
	ffirewall
fi

if [ $VERBOSE -gt 0 ];then
	NEWIP=''
	CURRIP=$(cat /tmp/ip.txt)
	rm /tmp/ip.txt
	echo -e " [$BOLD$GREEN"'*'"$RESET] Checking new IP.."
	sleep 1
	while [ $(echo $NEWIP | wc -c) -lt 2 ];do
		NEWIP=$(curl -s -m 2 icanhazip.com)
	done

	WHOISOLD="$(whois $CURRIP)"
	WHOISNEW="$(whois $NEWIP)"
	COUNTRYOLD=$(echo "$WHOISOLD" | grep country | head -n 1)
	COUNTRYNEW=$(echo "$WHOISNEW" | grep country | head -n 1)
	DESCROLD="$(echo "$WHOISOLD" | grep descr)"
	DESCRNEW="$(echo "$WHOISNEW" | grep descr)"
	
	echo -e " [$BOLD$BLUE"'>'"$RESET] Old IP:\n$RED$CURRIP\n$COUNTRYOLD\n$DESCROLD$RESET"
	echo -e " [$BOLD$BLUE"'>'"$RESET] Current IP:\n$GREEN$BOLD$NEWIP\n$COUNTRYNEW\n$DESCRNEW$RESET\n"

fi

case $SERVERNAME in
	"Netherlands") fforward;;
	"Switzerland") fforward;;
	"CA_Toronto") fforward;;
	"CA_Montreal") fforward;;
	"Romania") fforward;;
	"Israel") fforward;;
	"Sweden") fforward;;
	"France") fforward;;
	"Germany") fforward;;
	*) NOPORT=1;;
esac

if [ $NOPORT -eq 0 ];then
	if [ $PORTFORWARD -gt 0 ];then
		if [ $NEWPORT -gt 0 ]; then
			echo -e " [$BOLD$BLUE"'>'"$RESET] Changing identity.."
			echo -e " [$BOLD$GREEN"'*'"$RESET] Identity changed to $BOLD$GREEN$(cat $VPNPATH/client_id)$RESET"
		else
			if [ $VERBOSE -gt 0 ];then
				echo -e " [$BOLD$BLUE"'>'"$RESET] Using identity $BOLD$GREEN$(cat $VPNPATH/client_id)$RESET"
			fi
		fi

		if [ $FORWARDEDPORT -gt 0 ] &>/dev/null;then
			echo -e " [$BOLD$GREEN"'*'"$RESET] Port $GREEN$BOLD$FORWARDEDPORT$RESET has been forwarded to you."
		else
			echo -e " [$BOLD$RED"'X'"$RESET] Port forwarding failed."
		fi
	fi
else
	echo -e " [$BOLD$RED"'X'"$RESET] Port forwarding is only available at: Netherlands, Switzerland, CA_Toronto, CA_Montreal, Romania, Israel, Sweden, France and Germany."
fi

echo -n -e " [$BOLD$GREEN"'*'"$RESET] VPN setup complete, press $RED""ENTER$RESET or $RED""Ctrl+C$RESET to shut down."
read -p "" WAITVAR
fvpnreset
