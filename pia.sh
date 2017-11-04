#!/bin/bash

## pia Copyright 2017, d4rkcat (thed4rkcat@yandex.com)
#
## This program is free software: you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation, either version 3 of the License, or
## (at your option) any later version.
#
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License at (http://www.gnu.org/licenses/) for
## more details.

fupdate()						# Update the PIA openvpn files.
{
	echo -e " ["$BOLD$BLUE">"$RESET"]"" Updating PIA openvpn files."
	rm -rf $VPNPATH/*.ovpn
	rm -rf $VPNPATH/*.crt
	rm -rf $VPNPATH/*.pem
	rm -rf $VPNPATH/servers
	wget -q https://www.privateinternetaccess.com/openvpn/openvpn-strong.zip -O $VPNPATH/pia.zip
	(cd $VPNPATH && unzip -q pia.zip)
	rm $VPNPATH/pia.zip
	(cd $VPNPATH && for file in *.ovpn;do mv "$file" `echo $file | tr ' ' '_'` &>/dev/null;done)
	for file in $VPNPATH/*.ovpn;do sed -i 's/auth-user-pass/auth-user-pass pass.txt/' $file;done
	for file in $VPNPATH/*.ovpn;do echo 'auth-nocache' >> $file;done
	for file in $VPNPATH/*.ovpn;do echo $file | cut -d '/' -f 4 | cut -d '.' -f 1 >> $VPNPATH/servers;done
	echo -e " ["$BOLD$GREEN"*"$RESET"]"" Files Updated."
}

fforward()						# Forward a port.
{
	if [ ! -f $VPNPATH/client_id ];then head -n 100 /dev/urandom | sha256sum | tr -d " -" > $VPNPATH/client_id;fi
	CLIENTID=$(cat $VPNPATH/client_id)
	FORWARDEDPORT=$(curl -s -m 3 "http://209.222.18.222:2000/?client_id=$CLIENTID" | cut -d ':' -f 2 | cut -d '}' -f 1)
	unset CLIENTID
}

fnewport()						# Change port forwarded.
{
	NEWPORT=1
	PORTFORWARD=1
	rm -rf $VPNPATH/client_id
}

ffirewall()						# Set up ufw firewall rules to only allow traffic on tun0.
{
	ufw allow out on tun0 &>/dev/null
	ufw allow in on tun0 &>/dev/null
	ufw default deny outgoing &>/dev/null
	ufw default deny incoming &>/dev/null
	echo -e " ["$BOLD$GREEN"*"$RESET"]"" $(ufw enable 2>/dev/null)"
}

fhelp()						# Help function.
{
	echo """Usage: ./pia.sh [Options]
	-u	- Update PIA openvpn files before connecting.
	-p	- Forward a port.
	-n	- Change to another random port.
	-d	- Change DNS servers to PIA.
	-f	- Enable firewall to block all traffic apart from tun0
	-l	- List available servers.
	-v	- Display verbose information.
	-h	- Display this help."""
	exit
}

fvpnreset()						# Restore all settings and exit openvpn gracefully.
{
	if [ $DNS -gt 0 ];then
		fdnsrestore
	fi
	kill -s SIGINT "$(ps aux | grep openvpn | grep root | awk '{print $2}' | head -n 1)" &>/dev/null
	if [ $FIREWALL -gt 0 ];then
		echo -e " ["$BOLD$GREEN"*"$RESET"]"" $(ufw disable 2>/dev/null)"
	fi
	echo " ["$BOLD$GREEN"*"$RESET"]"" VPN Disconnected."
	exit 0
}

fdnschange()						# Change DNS servers to PIA.
{
	echo -e " ["$BOLD$GREEN"*"$RESET"]"" Changed DNS to PIA servers."
	cp /etc/resolv.conf /etc/resolv.conf.bak
	echo '''#PIA DNS Servers
nameserver 209.222.18.222
nameserver 209.222.18.218
''' > /etc/resolv.conf.pia
	cp /etc/resolv.conf.pia /etc/resolv.conf
}

fdnsrestore()						# Revert to original DNS servers.
{
	echo -e " ["$BOLD$GREEN"*"$RESET"]"" Restored DNS servers."
	cp /etc/resolv.conf.bak /etc/resolv.conf
}

flist()						# List available servers
{
	if [ ! -f $VPNPATH/servers ];then
		fupdate
	fi
	for i in $(seq $(cat $VPNPATH/servers | wc -l));do echo -n " $BOLD$RED[$RESET$i$BOLD$RED]$RESET " && cat $VPNPATH/servers | head -n $i | tail -n 1 | cut -d '.' -f 1;done
}

fchecklog()						# Check openvpn logs to get connection state
{
	LOGRETURN=0
	VCONNECT=''
	while [ $LOGRETURN -eq 0 ]; do
		if [ $ARCH -gt 0 ];then
			VCONNECT=$(journalctl /usr/bin/openvpn | tail -n 1)
		else
			VCONNECT=$(cat /var/log/pia.log)
		fi
		if [ $(echo $VCONNECT | grep 'Initialization Sequence Completed' | wc -c) -gt 1	];then
			LOGRETURN=1
		fi
		if [ $(echo $VCONNECT | grep 'auth-failure' | wc -c) -gt 1	];then
			LOGRETURN=2
		fi
		sleep 0.2
	done
}

						# Colour codes for terminal
BOLD=$(tput bold)
BLUE=$(tput setf 1)
GREEN=$(tput setf 2)
CYAN=$(tput setf 3)
RED=$(tput setf 4)
RESET=$(tput sgr0)

						# This is where we will store PIA openVPN files and user config
VPNPATH='/etc/openvpn'
PORTFORWARD=0
NEWPORT=0
DNS=0
FORWARDEDPORT=0
VERBOSE=0
ARCH=0
FIREWALL=0

						# Check if user is root and OS is Arch
if [ $(id -u) != 0 ];then echo -e " ["$BOLD$RED"X"$RESET"]"" Script must be run as root." && exit;fi
if [ $(uname -r | grep ARCH | wc -c) -gt 1 ];then ARCH=1;fi

						# Check for missing dependencies and install
if [ $ARCH -gt 0 ];then
	command -v openvpn >/dev/null 2>&1 || { echo >&2 " ["$BOLD$GREEN"*"$RESET"]"" openvpn required, installing..";pacman -S openvpn; }
	command -v ufw >/dev/null 2>&1 || { echo >&2 " ["$BOLD$GREEN"*"$RESET"]"" ufw required, installing..";pacman -S ufw; }
else
	command -v apt-get >/dev/null 2>&1 || { echo >&2 " ["$BOLD$RED"X"$RESET"]"" OS not detected as Arch or Debian, script will not work for you.";exit; }
	command -v openvpn >/dev/null 2>&1 || { echo >&2 " ["$BOLD$GREEN"*"$RESET"]"" openvpn required, installing..";apt-get install openvpn; }
	command -v ufw >/dev/null 2>&1 || { echo >&2 " ["$BOLD$GREEN"*"$RESET"]"" ufw required, installing..";apt-get install ufw; }
fi

if [ ! -d $VPNPATH ];then mkdir $VPNPATH;fi

						# Check for existence of credentials file
if [ ! -f $VPNPATH/pass.txt ];then
	fupdate
	read -p " ["$BOLD$BLUE">"$RESET"]"" Please enter your username: " USERNAME
	read -s -p " ["$BOLD$BLUE">"$RESET"]"" Please enter your password: " PASSWORD
	echo -e "$USERNAME\n$PASSWORD" > $VPNPATH/pass.txt
	chmod 400 $VPNPATH/pass.txt
	unset USERNAME PASSWORD
fi

while getopts "uphndlfv" opt
do
 	case $opt in
		u) fupdate;;
		p) PORTFORWARD=1;;
		h) fhelp;;
		n) fnewport;;
		d) DNS=1;;
		l) flist;exit;;
		f) FIREWALL=1;;
		v) VERBOSE=1;CURRIP=$(curl -s icanhazip.com);;
		*) fhelp;;
	esac
done

trap fvpnreset INT
echo -e " ["$BOLD$BLUE">"$RESET"]"" Please choose a server: "
flist
read -p " ["$BOLD$BLUE">"$RESET"]" SERVERNUM

SERVER=$(cat $VPNPATH/servers | head -n $SERVERNUM | tail -n 1)
clear
echo -e " ["$BOLD$BLUE">"$RESET"]"" Connecting to $SERVER""..."
OVPNFILE=$SERVER".ovpn"

if [ $ARCH -gt 0 ];then
	cd $VPNPATH && openvpn --config $OVPNFILE --daemon
else
	cd $VPNPATH && openvpn --config $OVPNFILE --daemon --log /var/log/pia.log
fi

fchecklog
if [ $LOGRETURN -eq 2 ];then
	echo -e " ["$BOLD$RED"X"$RESET"]"" Authorization Failed. Please check login details."
	rm -rf $VPNPATH/pass.txt
	fvpnreset
fi

if [ $VERBOSE -gt 0 ];then
	echo -e " ["$BOLD$GREEN"*"$RESET"]"" OpenVPN Logs:\n"
	echo -n $CYAN
	if [ $ARCH -gt 0 ];then
		journalctl /usr/bin/openvpn | tail -n 13 | cut -d ' ' -f 6- | grep -v WARN
	else
		cat /var/log/pia.log
	fi
	echo -n $RESET
fi

echo -e " ["$BOLD$GREEN"*"$RESET"]"" Connected, OpenVPN is running daemonized on PID ""$(ps aux | grep openvpn | grep root | awk '{print $2}' | head -n 1)"

if [ $DNS -gt 0 ];then
	fdnschange
fi

if [ $FIREWALL -gt 0 ];then
	ffirewall
fi

if [ $VERBOSE -gt 0 ];then
	sleep 1
	NEWIP=$(curl -s -m 2 icanhazip.com)
	echo -e " ["$BOLD$BLUE">"$RESET"]"" Old IP:\t\t$CURRIP"
	if [ $(echo $NEWIP | wc -c) -lt 6 ];then
		echo -e " ["$BOLD$RED"X"$RESET"]"" Failed to get new IP!"
	else
		echo -e " ["$BOLD$BLUE">"$RESET"]"" Current IP:\t$NEWIP"
	fi
fi

if [ $PORTFORWARD -gt 0 ];then
	if [ $NEWPORT -gt 0 ]; then
		echo -e " ["$BOLD$BLUE">"$RESET"]"" Changing identity.."
	fi
	echo -e " ["$BOLD$BLUE">"$RESET"]"" Attempting to forward a port.."
	fforward
	if [ $(echo $FORWARDEDPORT | wc -c) -gt 3 ] &>/dev/null;then
		echo -e " ["$BOLD$GREEN"*"$RESET"]"" Port $FORWARDEDPORT has been forwarded to you."
	else
		echo -e " ["$BOLD$RED"X"$RESET"]"" Port forwarding failed."
		echo -e " ["$BOLD$RED"X"$RESET"]"" Port forwarding is only available at: Netherlands, Switzerland, CA_Toronto, CA_Montreal, Romania, Israel, Sweden, France and Germany."
	fi
fi

echo -n -e " ["$BOLD$GREEN"*"$RESET"]"" VPN setup complete, press ENTER to shut down."
read -p "" WAITVAR
fvpnreset
