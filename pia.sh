#!/bin/bash

## pia v0.3 Copyright (C) 2017 d4rkcat (thed4rkcat@yandex.com)
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

_SAVE_ARGS=("$@")
_DEPENDENCIES=(openvpn ufw curl unzip)

								# Re-run as root as needed.
fcheckroot()
{
	if [ $(id -u) != 0 ]; then
		echo "$INFO Re-running script as root..."
		FULLSCRIPTPATH=$(readlink -f "${BASH_SOURCE[0]}")
		exec sudo "$FULLSCRIPTPATH" "${_SAVE_ARGS[@]}"
	fi
}

fcheckdependencies()
{
	local missing=()
	for dep in "${_DEPENDENCIES[@]}"; do
		command -v $dep > /dev/null 2>&1 || missing+=($dep)
	done
	if [ ${#missing[@]} -gt 0 ]; then
		if [ -n "$INSTALLCMD" ];then
			fcheckroot
			for dep in "${missing[@]}"; do
				echo >&2 "$INFO $dep required, installing..."; $INSTALLCMD $dep
			done
		else
			echo "$ERROR OS not identified as arch or debian based, please install the following and run this script again."
			echo "$ERROR    Missing components: ${missing[@]}"
			exit 1
		fi
	fi
}

fupdate()						# Update the PIA openvpn files.
{
	fcheckroot

	CONFIGDEFAULT="https://www.privateinternetaccess.com/openvpn/openvpn.zip"
	CONFIGSTRONG="https://www.privateinternetaccess.com/openvpn/openvpn-strong.zip"
	CONFIGIP="https://www.privateinternetaccess.com/openvpn/openvpn-ip.zip"
	CONFIGTCP="https://www.privateinternetaccess.com/openvpn/openvpn-tcp.zip"
	CONFIGTCPSTRONG="https://www.privateinternetaccess.com/openvpn/openvpn-strong-tcp.zip"

	if [ $CONFIGNUM -eq 0 ];then
		echo "$PROMPT Please choose configuration:"
		echo " $BOLD$RED[$RESET""1""$BOLD$RED]$RESET Default UDP (aes-128-cbc sha1 rsa-2048)"
		echo " $BOLD$RED[$RESET""2""$BOLD$RED]$RESET Strong UDP (aes-256-cbc sha256 rsa-4096)"
		echo " $BOLD$RED[$RESET""3""$BOLD$RED]$RESET Direct IP (aes-128-cbc sha1 rsa-2048)"
		echo " $BOLD$RED[$RESET""4""$BOLD$RED]$RESET Default TCP (aes-128-cbc sha1 rsa-2048)"
		echo " $BOLD$RED[$RESET""5""$BOLD$RED]$RESET Strong TCP (aes-256-cbc sha256 rsa-4096)"
		read -p "$PROMPT " CONFIGNUM
	fi

	if [[ $CONFIGNUM =~ ^[0-9]+$ && $CONFIGNUM -lt 6 && $CONFIGNUM -gt 0 ]];then
		case $CONFIGNUM in
			1) DOWNURL=$CONFIGDEFAULT;echo "$INFO Selected Default UDP configuration.";;
			2) DOWNURL=$CONFIGSTRONG;echo "$INFO Selected Strong UDP configuration.";;
			3) DOWNURL=$CONFIGIP;echo "$INFO Selected Direct IP configuration.";;
			4) DOWNURL=$CONFIGTCP;echo "$INFO Selected Default TCP configuration.";;
			5) DOWNURL=$CONFIGTCPSTRONG;echo "$INFO Selected Strong TCP configuration.";;
		esac
	else
		echo "$ERROR $CONFIGNUM is not a valid option! 1-5 only."
		exit 1
	fi

	echo -n "$PROMPT Updating PIA openvpn files..."
	rm -rf $VPNPATH/*.ovpn $VPNPATH/servers.txt $VPNPATH/*.crt $VPNPATH/*.pem
	curl -so $VPNPATH/pia.zip $DOWNURL
	echo "$CONFIGNUM $DOWNURL $(curl -sI $DOWNURL | grep Last-Modified | cut -d ' ' -f 2-)" > $VPNPATH/configversion.txt
	cd $VPNPATH && unzip -q pia.zip && rm pia.zip
	cd $VPNPATH && for CONFIGFILE in *.ovpn;do mv "$CONFIGFILE" $(echo $CONFIGFILE | tr ' ' '_') &>/dev/null;done
	for CONFIGFILE in $VPNPATH/*.ovpn;do
		OLD="auth-user-pass"
		NEW="auth-user-pass $VPNPATH/pass.txt"
		sed -i "s%$OLD%$NEW%g" $CONFIGFILE
		OLD="crl-verify crl.rsa.2048.pem"
		NEW="crl-verify $VPNPATH/crl.rsa.2048.pem"
		sed -i "s%$OLD%$NEW%g" $CONFIGFILE
		OLD="crl-verify crl.rsa.4096.pem"
		NEW="crl-verify $VPNPATH/crl.rsa.4096.pem"
		sed -i "s%$OLD%$NEW%g" $CONFIGFILE
		OLD="ca ca.rsa.2048.crt"
		NEW="ca $VPNPATH/ca.rsa.2048.crt"
		sed -i "s%$OLD%$NEW%g" $CONFIGFILE
		OLD="ca ca.rsa.4096.crt"
		NEW="ca $VPNPATH/ca.rsa.4096.crt"
		sed -i "s%$OLD%$NEW%g" $CONFIGFILE
		echo -e "auth-nocache\nlog /var/log/pia.log" >> $CONFIGFILE
		echo -n $(basename $CONFIGFILE | cut -d '.' -f 1)" " >> $VPNPATH/servers.txt
		cat $CONFIGFILE | grep .com | awk '{print $2}' >> $VPNPATH/servers.txt
	done
	echo -e "\r$INFO Files Updated.                     "
}

fforward()						# Forward a port.
{
	echo -n "$PROMPT Forwarding a port..."
	sleep 1.5
	if [ ! -f $VPNPATH/client_id ];then head -n 100 /dev/urandom | sha256sum | tr -d " -" > $VPNPATH/client_id;fi
	CNT=0
	while [[ $(echo $FORWARDEDPORT | wc -c) -lt 3 && $CNT -lt 2 ]];do
		FORWARDEDPORT=$(curl -s -m 4 "http://209.222.18.222:2000/?client_id=$(cat $VPNPATH/client_id)" | cut -d ':' -f 2 | cut -d '}' -f 1)
		((++CNT))
	done
}

fnewport()						# Change port forwarded.
{
	fcheckroot
	NEWPORT=1
	PORTFORWARD=1
	mv $VPNPATH/client_id $VPNPATH/client_id.bak
	head -n 100 /dev/urandom | sha256sum | tr -d " -" > $VPNPATH/client_id
}

ffirewall()						# Set up ufw firewall rules to only allow traffic on tunneled interface and within LAN.
{
	DEVICE=$(echo "$PLOG" | grep 'TUN/TAP device' | awk '{print $8}')
	ufw default deny outgoing &>/dev/null
	ufw default deny incoming &>/dev/null
	ufw allow in on $DEVICE from 0.0.0.0/0 &>/dev/null
	ufw allow out on $DEVICE to 0.0.0.0/0 &>/dev/null
	if [ $FLAN -eq 1 ];then
		ufw allow in from $LAN &>/dev/null
		ufw allow out to $LAN &>/dev/null
	fi
	echo "$INFO $(ufw enable 2>/dev/null)."
}

fhelp()						# Help function.
{
	echo """Usage: $(basename $0 .sh) [options]

	-s	- Server number to connect to.
	-l	- List available servers.
	-r	- Reset and terminate current VPN connection.
	-u	- Update PIA openvpn files before connecting.
	-p	- Forward a port.
	-n	- Change to another random port.
	-d	- Change DNS servers to PIA.
	-f	- Enable firewall to block all non-tunnel traffic.
	-e	- Allow LAN through firewall.
	-m	- Enable PIA MACE ad blocking.
	-k	- Enable internet killswitch.
	-g	- Display GeoIP data.
	-v	- Display verbose information.
	-j	- Write JSON VPN data to $DEFAULTJSONOUTPUTPATH.
	-b	- Exit with VPN running in the background.
	-h	- Display this help.

Examples:
	pia -dps 24 	- Change DNS, forward a port and connect to Sweden.
	pia -nfv	- Forward a new port, run firewall and be verbose.
"""
}

fvpnreset()						# Restore all settings and exit openvpn gracefully.
{
	fcheckroot

	if [ $DNS -gt 0 ];then
		fdnsrestore
	fi
	if [ $(command -v lsof) ];then
		for PID in $(lsof -i | grep openvpn | awk '{ print $2 }'); do
			kill -s SIGINT $PID &>/dev/null
		done
	else
		test -n "$VPNPID" || fopenvpnruncheck
		if [ -n "$VPNPID" ]; then
			kill -s SIGINT $VPNPID &>/dev/null
		fi
	fi
	if [[ $FIREWALL -gt 0 && $KILLS -eq 0 ]];then
		echo "$INFO $(ufw disable 2>/dev/null)"
	elif [ $KILLS -gt 0 ];then
		CNT=0
		while [ $CNT -lt 5 ];do
			echo y | ufw delete 1&>/dev/null
			((++CNT))
		done
		echo -e "\r $BOLD$RED[$BOLD$GREEN*$BOLD$RED] WARNING:$RESET Killswitch engaged, no internet will be available until you run this script again."
	fi
	if [ $RESTARTVPN -eq 1 ];then
		echo "$PROMPT Restarting VPN..."
		RESTARTVPN=0
		fconnect
	else
		echo "$INFO VPN Disconnected."
		exit 0
	fi
}

fdnschange()						# Change DNS servers to PIA.
{
	echo "$INFO Changed DNS to PIA servers."
	cp /etc/resolv.conf /etc/resolv.conf.bak
	echo '''#PIA DNS Servers
nameserver 209.222.18.222
nameserver 209.222.18.218
''' > /etc/resolv.conf.pia
	cp /etc/resolv.conf.pia /etc/resolv.conf
}

fmace()						# Enable PIA MACE DNS based ad blocking.
{
	curl -s "http://209.222.18.222:1111/"
	echo "$INFO PIA MACE enabled."
}

fdnsrestore()						# Revert to original DNS servers.
{
	echo "$INFO Restored DNS servers."
	cp /etc/resolv.conf.bak /etc/resolv.conf
}

flist()						# List available servers.
{
	if [ ! -f $VPNPATH/servers.txt ];then
		fupdate
	fi

	echo "$INFO$BOLD$GREEN Green$RESET servers allow port forwarding."
	for i in $(seq $(cat $VPNPATH/servers.txt | wc -l));do
		echo -n " $BOLD$RED[$RESET$i$BOLD$RED]$RESET "
		SERVERNAME=$(cat $VPNPATH/servers.txt | head -n $i | tail -n 1 | awk '{print $1}')
		case $SERVERNAME in
			"Netherlands") echo $BOLD$GREEN$SERVERNAME$RESET;;
			"Switzerland") echo $BOLD$GREEN$SERVERNAME$RESET;;
			"CA_Toronto") echo $BOLD$GREEN$SERVERNAME$RESET;;
			"CA_Montreal") echo $BOLD$GREEN$SERVERNAME$RESET;;
			"CA_Vancouver") echo $BOLD$GREEN$SERVERNAME$RESET;;
			"Romania") echo $BOLD$GREEN$SERVERNAME$RESET;;
			"Israel") echo $BOLD$GREEN$SERVERNAME$RESET;;
			"Sweden") echo $BOLD$GREEN$SERVERNAME$RESET;;
			"France") echo $BOLD$GREEN$SERVERNAME$RESET;;
			"Germany") echo $BOLD$GREEN$SERVERNAME$RESET;;
			*) echo $SERVERNAME;;
		esac
	done
}

fchecklog()						# Check openvpn logs to get connection state.
{
	LOGRETURN=0
	while [ $LOGRETURN -eq 0 ]; do
		VCONNECT=$(cat /var/log/pia.log)
		if [ $(echo "$VCONNECT" | grep 'Initialization Sequence Completed' | wc -c) -gt 1 ];then
			LOGRETURN=1
		elif [ $(echo "$VCONNECT" | grep 'auth-failure' | wc -c) -gt 1 ];then
			LOGRETURN=2
		elif [ $(echo "$VCONNECT" | grep 'RESOLVE: Cannot resolve host address' | wc -c) -gt 1 ];then
			LOGRETURN=3
		elif [ $(echo "$VCONNECT" | grep 'process exiting' | wc -c) -gt 1 ];then
			LOGRETURN=4
		elif [ $(echo "$VCONNECT" | grep 'Exiting due to fatal error' | wc -c) -gt 1 ];then
			LOGRETURN=5
		fi
		sleep 0.2
	done
}

fping()						# Get latency to VPN server.
{
	PING=$(ping -c 3 $1 | grep rtt | cut -d '/' -f 4 | awk '{print $3}')
	PINGINT=$(echo $PING | cut -d '.' -f 1)
	SPEEDCOLOR=$BOLD$GREEN
	SPEEDNAME="fast"
	if [ $PINGINT -gt 40 ];then
		SPEEDCOLOR=$BOLD$CYAN
		SPEEDNAME="medium"
	fi
	if [ $PINGINT -gt 80 ];then
		SPEEDCOLOR=$BOLD$BLUE
		SPEEDNAME="slow"
	fi
	if [ $PINGINT -gt 160 ];then
		SPEEDCOLOR=$BOLD$RED
		SPEEDNAME="very slow"
	fi
}

fcheckupdate()						# Check if a new config zip is available and download.
{
	CONFIGNUM=$(cat $VPNPATH/configversion.txt | cut -d ' ' -f 1)
	CONFIGURL=$(cat $VPNPATH/configversion.txt | cut -d ' ' -f 2)
	CONFIGVERSION=$(cat $VPNPATH/configversion.txt | cut -d ' ' -f 3-)
	CONFIGMODIFIED=''
	CNT=0
	while [[ $(echo $CONFIGMODIFIED | wc -c) -lt 6 && $CNT -lt 3 ]];do
		CONFIGMODIFIED=$(curl -sI $CONFIGURL | grep Last-Modified | cut -d ' ' -f 2-)
		((++CNT))
	done
	if [ $(echo $CONFIGMODIFIED | wc -c) -gt 6 ];then
		if [ "$CONFIGVERSION" != "$CONFIGMODIFIED" ];then
			RESTARTVPN=1
			echo "$ERROR WARNING: OpenVPN configuration is out of date!"
			echo "$PROMPT New PIA OpenVPN config file available! Updating..."
			fupdate
			fvpnreset
		else
			if [ $VERBOSE -eq 1 ];then
				echo "$INFO OpenVPN configuration up to date: $CONFIGMODIFIED"
			fi
		fi
	else
		echo "$ERROR Failed to check OpenVPN config Last-Modified date!"
	fi
}

fdisplaygeoip()
{
	python - <<EOF
import json
import urllib2
my_ip = urllib2.urlopen('http://icanhazip.com').read().strip()
geoip_data = json.load(urllib2.urlopen('http://freegeoip.net/json/%s' % my_ip))
print('$INFO GeoIP Data for WAN IP address $BOLD$GREEN{}$RESET'.format(my_ip))
two_column_format = '%%-%ds  $BOLD$GREEN%%s$RESET' % max(len(k) for k in geoip_data)
for key in sorted(geoip_data.keys()):
	print two_column_format % (key, geoip_data[key])
EOF
}

fopenvpnruncheck()
{
	VPNPID=$(ps aux | grep openvpn | grep root | grep -v grep | awk '{print $2}')
}

fconnect()
{
	if [ $VERBOSE -gt 0 ];then
		echo -n "$PROMPT Testing latency to $DOMAIN..."
		fping $DOMAIN
		echo -e "\r$INFO $SERVERNAME latency: $SPEEDCOLOR$PING ms ($SPEEDNAME)$RESET                       "
	fi

	echo -n "$PROMPT Connecting to $BOLD$GREEN$SERVERNAME$RESET, Please wait..."
	cd $VPNPATH && openvpn --config $CONFIG --daemon
	fopenvpnruncheck

	fchecklog

	case $LOGRETURN in
		1) echo -e "\r$INFO$BOLD$GREEN Connected$RESET, OpenVPN is running daemonized on PID $BOLD$CYAN$VPNPID$RESET                    ";;
		2) echo -e "\r$ERROR Authorization Failed. Please rerun script to enter correct login details.                    ";rm $VPNPATH/pass.txt;exit 1;;
		3) echo -e "\r$ERROR OpenVPN failed to resolve $DOMAIN.                    ";kill -s SIGINT $VPNPID&>/dev/null;exit 1;;
		4) echo -e "\r$ERROR OpenVPN exited unexpectedly. Please review log:                    ";cat /var/log/pia.log;exit 1;;
		5) echo -e "\r$ERROR OpenVPN suffered a fatal error. Please review log:                    ";cat /var/log/pia.log;exit 1;;
	esac

	fcheckupdate

	PLOG=$(cat /var/log/pia.log)
	if [ $VERBOSE -gt 0 ];then
		echo "$INFO OpenVPN Logs:"
		echo -n $CYAN
		while IFS= read -r LNE ; do echo "     $LNE" | awk '{$1=$2=$3=$4=$5=""; print $0}';done <<< "$PLOG"
		echo "$RESET$PROMPT OpenVPN Settings:"
		SETTINGS=$(cat $VPNPATH/$CONFIG)
		if [ $(echo "$SETTINGS" | grep 'proto udp' | wc -c) -gt 3 ];then
			echo "$INFO$BOLD$GREEN UDP$RESET Protocol."
		fi
		if [ $(echo "$SETTINGS" | grep 'proto tcp' | wc -c) -gt 3 ];then
			echo "$INFO$BOLD$CYAN TCP$RESET Protocol."
		fi
		if [ $(echo "$SETTINGS" | grep 'ca.rsa.2048.crt' | wc -c) -gt 3 ];then
			echo "$INFO$BOLD$CYAN 2048 Bit RSA$RESET Certificate."
		fi
		if [ $(echo "$SETTINGS" | grep 'ca.rsa.4096.crt' | wc -c) -gt 3 ];then
			echo "$INFO$BOLD$GREEN 4096 Bit RSA$RESET Certificate."
		fi
		if [ $(echo "$SETTINGS" | grep 'cipher aes-128-cbc' | wc -c) -gt 3 ];then
			echo "$INFO$BOLD$CYAN 128 Bit AES-CBC$RESET Cipher."
		fi
		if [ $(echo "$SETTINGS" | grep 'cipher aes-256-cbc' | wc -c) -gt 3 ];then
			echo "$INFO$BOLD$GREEN 256 Bit AES-CBC$RESET Cipher."
		fi
		if [ $(echo "$SETTINGS" | grep 'auth sha1' | wc -c) -gt 3 ];then
			echo "$INFO$BOLD$CYAN SHA1$RESET Authentication."
		fi
		if [ $(echo "$SETTINGS" | grep 'auth sha256' | wc -c) -gt 3 ];then
			echo "$INFO$BOLD$GREEN SHA256$RESET Authentication."
		fi

		NEWIP=''
		CURRIP=$(cat /tmp/ip.txt)
		rm /tmp/ip.txt
		echo  -n "$PROMPT Fetching IP..."
		sleep 1.5
		CNT=0
		while [[ $(echo $NEWIP | wc -c) -lt 2 && $CNT -lt 2 ]];do
			NEWIP=$(curl -s -m 4 icanhazip.com)
			((++CNT))
		done

		if [ $(echo $NEWIP | wc -c) -gt 2 ];then
			WHOISOLD="$(whois $CURRIP)"
			WHOISNEW="$(whois $NEWIP)"
			COUNTRYOLD=$(echo "$WHOISOLD" | grep country | head -n 1)
			COUNTRYNEW=$(echo "$WHOISNEW" | grep country | head -n 1)
			DESCROLD="$(echo "$WHOISOLD" | grep descr)"$RESET
			DESCRNEW="$(echo "$WHOISNEW" | grep descr)"$RESET

			echo -e "\r$PROMPT Old IP:$RED$BOLD $CURRIP"
			if [ $(echo $COUNTRYOLD | wc -c) -gt 8 ];then
				while IFS= read -r LNE ; do echo "     $LNE";done <<< "$COUNTRYOLD"
			fi
			if [ $(echo $DESCROLD | wc -c) -gt 8 ];then
				while IFS= read -r LNE ; do echo "     $LNE";done <<< "$DESCROLD"
			fi
			echo "$PROMPT Current IP:$GREEN$BOLD $NEWIP"
			if [ $(echo $COUNTRYNEW | wc -c) -gt 8 ];then
				while IFS= read -r LNE ; do echo "     $LNE";done <<< "$COUNTRYNEW"
			fi
			if [ $(echo $DESCRNEW | wc -c) -gt 8 ];then
				while IFS= read -r LNE ; do echo "     $LNE";done <<< "$DESCRNEW"
			fi
		else
			echo -e "\r$ERROR Failed to fetch new IP.                   "
		fi
	fi

	if [ $DNS -gt 0 ];then
		fdnschange
	fi

	if [ $MACE -gt 0 ];then
		fmace
	fi

	if [ $FIREWALL -gt 0 ];then
		ffirewall
	fi

	if [[ $KILLS -gt 0 && $VERBOSE -gt 0 ]];then
		echo "$PROMPT Killswitch activated."
	fi

	if [ $PORTFORWARD -gt 0 ];then
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
			"CA_Vancouver") fforward;;
			*) NOPORT=1;;
		esac
		if [ $NOPORT -eq 0 ];then
			if [ $NEWPORT -gt 0 ]; then
				echo -e "\r$INFO Identity changed to $BOLD$GREEN$(cat $VPNPATH/client_id)$RESET"
			else
				if [ $VERBOSE -gt 0 ];then
					echo -e "\r$PROMPT Using port forwarding identity $BOLD$CYAN$(cat $VPNPATH/client_id)$RESET"
				fi
			fi

			if [ $FORWARDEDPORT -gt 0 ] &>/dev/null;then
				echo -e "\r$INFO Port $GREEN$BOLD$FORWARDEDPORT$RESET has been forwarded to you.                    "
			else
				echo -e "\r$ERROR $SERVERNAME failed to forward us a port!                   "
			fi
		else
			echo "$ERROR Port forwarding is only available at: Netherlands, Switzerland, CA_Toronto, CA_Montreal, CA_Vancouver, Romania, Israel, Sweden, France and Germany."
		fi
	fi

	fwritejsonoutput

	if [ $BACKGROUNDVPN -ne 1 ];then
		echo -n "$INFO VPN setup complete, press$BOLD$RED ENTER$RESET or$BOLD$RED Ctrl+C$RESET to shut down."
		read -p "" WAITVAR
		fvpnreset
	fi
}

fwritejsonoutput()
{
	test -n "$JSONOUTPUTPATH" || return
	# Write simple JSON file with basic data as strings.
	test -f "$JSONOUTPUTPATH" && rm -f "$JSONOUTPUTPATH"
	for envname in	CONFIG DOMAIN FORWARDEDPORT SERVERNAME VPNPATH VPNPID; do
		if [ -e "$JSONOUTPUTPATH" ]; then
			echo "," >> "$JSONOUTPUTPATH"
		else
			echo "{" > "$JSONOUTPUTPATH"
		fi
		varname=$(echo $envname | tr "A-Z" "a-z")
		local varvalue=$(eval echo "\$$envname")
		printf '"%s": "%s"' "$varname" "$varvalue" >> "$JSONOUTPUTPATH"
	done
	echo "" >> "$JSONOUTPUTPATH"
	echo "}" >> "$JSONOUTPUTPATH"
	# Add IP and GeoIP data to the JSON file, convert numbers, and reformat the file.
	python - <<EOF
import sys
import json
import urllib2
with open('$JSONOUTPUTPATH') as handle:
	data = json.load(handle)
for name in data:
	try:
		data[name] = int(data[name])
	except ValueError:
		try:
			data[name] = float(data[name])
		except ValueError:
			pass
data['wan_ip'] = urllib2.urlopen('http://icanhazip.com').read().strip()
data['geo_ip'] = json.load(urllib2.urlopen('http://freegeoip.net/json/%s' % data['wan_ip']))
with open('$JSONOUTPUTPATH', 'w') as handle:
	json.dump(data, handle, sort_keys=True, indent=4)
EOF
	test -n "$SUDO_USER" && chown $SUDO_USER "$JSONOUTPUTPATH"
	echo "$INFO Saved JSON output to $JSONOUTPUTPATH."
}

						# Colour codes for terminal.
BOLD=$(tput bold)
BLUE=$(tput setf 1 || tput setaf 4)
GREEN=$(tput setf 2 || tput setaf 2)
CYAN=$(tput setf 3 || tput setaf 6)
RED=$(tput setf 4 || tput setaf 1)
RESET=$(tput sgr0)

INFO=" [$BOLD$GREEN*$RESET]"
ERROR=" [$BOLD$RED"'X'"$RESET]"
PROMPT=" [$BOLD$BLUE>$RESET]"

						# This is where we will store PIA openVPN files and user config.
VPNPATH='/etc/openvpn/pia'

						# Initialize switches.
PORTFORWARD=0
NEWPORT=0
NOPORT=0
MACE=0
KILLS=0
DNS=0
FORWARDEDPORT=0
VERBOSE=0
FIREWALL=0
SERVERNUM=0
FLAN=0
INSTALLCMD=
MISSINGDEP=0
CONFIGNUM=0
RESTARTVPN=0
BACKGROUNDVPN=0

						# Receives a path when a JSON output file is desired.
JSONOUTPUTPATH=
DEFAULTJSONOUTPUTPATH=/tmp/pia.json

if [ $(command -v pacman) ];then
	INSTALLCMD="pacman --noconfirm -S"
elif [ $(command -v apt-get) ];then
	INSTALLCMD="apt-get install -y"
elif [ $(command -v yum) ];then
	INSTALLCMD="yum install -y"
fi

while getopts "lhgrupnmkdfvjes:b" opt
do
	case $opt in
		l) flist;exit 0;;
		h) fhelp;exit 0;;
		g) fdisplaygeoip;exit 0;;
		r) fvpnreset;exit 0;;
		u) fupdate;;
		p) PORTFORWARD=1;;
		n) fnewport;;
		m) MACE=1;DNS=1;;
		k) KILLS=1;FIREWALL=1;;
		d) DNS=1;;
		f) FIREWALL=1;;
		e) FLAN=1;FIREWALL=1;;
		v) VERBOSE=1;curl -s icanhazip.com > /tmp/ip.txt&;;
		j) JSONOUTPUTPATH="$DEFAULTJSONOUTPUTPATH";;
		s) SERVERNUM=$OPTARG;;
		b) BACKGROUNDVPN=1;;
		*) echo "$ERROR Error: Unrecognized arguments.";fhelp;exit 1;;
	esac
done

						# Assume we need to be root from here on.
fcheckroot

						# Check for missing dependencies and install.
fcheckdependencies

if [ ! -d $VPNPATH ];then mkdir -p $VPNPATH;fi

						# Check for existence of credentials file.
if [ ! -f $VPNPATH/pass.txt ];then
	read -p "$PROMPT Please enter your username: " USERNAME
	read -sp "$PROMPT Please enter your password: " PASSWORD
	echo -e "$USERNAME\n$PASSWORD" > $VPNPATH/pass.txt
	echo
	chmod 400 $VPNPATH/pass.txt
	unset USERNAME PASSWORD
fi

LAN=$(ip route show | grep -i 'default via'| awk '{print $3 }' | cut -d '.' -f 1-3)".0/24"
ufw disable&>/dev/null

if [ ! -f $VPNPATH/servers.txt ];then fupdate;fi

if [ $SERVERNUM -lt 1 ];then
	echo "$PROMPT Please choose a server: "
	flist
	read -p "$PROMPT " SERVERNUM
	clear
fi

if [ $BACKGROUNDVPN -ne 1 ]; then
	trap fvpnreset INT
fi

MAXSERVERS=$(cat $VPNPATH/servers.txt | wc -l)
if [[ $SERVERNUM =~ ^[0-9]+$ && $SERVERNUM -gt 0 && $SERVERNUM -le $MAXSERVERS ]];then
	:
else
	flist
	echo "$ERROR $SERVERNUM is not valid! 1-$MAXSERVERS only."
	exit 1
fi

SERVERNAME=$(cat $VPNPATH/servers.txt | head -n $SERVERNUM | tail -n 1 | awk '{print $1}')
DOMAIN=$(cat $VPNPATH/servers.txt | head -n $SERVERNUM | tail -n 1 | awk '{print $2}')
CONFIG=$SERVERNAME.ovpn

fconnect

# vim: noet:ts=4:sts=4:sw=4
