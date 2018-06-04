#!/bin/bash

## pia v0.5 Copyright (C) 2017 d4rkcat (thed4rkcat@yandex.com)
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
	OLDS=("auth-user-pass" "crl-verify crl.rsa.2048.pem" "crl-verify crl.rsa.4096.pem" "ca ca.rsa.2048.crt" "ca ca.rsa.4096.crt" "verb 1")
	NEWS=("auth-user-pass $VPNPATH/pass.txt" "crl-verify $VPNPATH/crl.rsa.2048.pem" "crl-verify $VPNPATH/crl.rsa.4096.pem" "ca $VPNPATH/ca.rsa.2048.crt" "ca $VPNPATH/ca.rsa.4096.crt" "verb 2")
	for CONFIGFILE in $VPNPATH/*.ovpn;do
		CNT=0
		for OLD in "${OLDS[@]}";do 
			sed -i "s%$OLD%${NEWS[$CNT]}%g" $CONFIGFILE
			((++CNT))
		done
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
	while [ $(echo $FORWARDEDPORT | wc -c) -lt 3 ];do
		FORWARDEDPORT=$(curl -s -m 4 "http://209.222.18.222:2000/?client_id=$(cat $VPNPATH/client_id)" | cut -d ':' -f 2 | cut -d '}' -f 1)
	done
}

fnewport()						# Change port forwarded.
{
	NEWPORT=1
	PORTFORWARD=1
	mv $VPNPATH/client_id $VPNPATH/client_id.bak
	head -n 100 /dev/urandom | sha256sum | tr -d " -" > $VPNPATH/client_id
}

ffirewall()						# Set up iptables firewall rules to only allow traffic on tunneled interface and (optionally) within LAN.
{
	fresetfirewall
	LAN=$(ip route show | grep default | awk '{print $3 }' | cut -d '.' -f 1-3)".0/24"
	DEFAULTDEVICE=$(ip route show | grep default | awk '{print $5}')
	VPNDEVICE=$(echo "$PLOG" | grep 'TUN/TAP device' | awk '{print $8}')
	VPNPORT=$(cat $VPNPATH/$CONFIG | grep 'remote ' | awk '{print $3}')
	PROTO=$(cat $VPNPATH/$CONFIG | grep proto | awk '{print $2}')

	iptables -P OUTPUT DROP																# default policy for outgoing packets
	iptables -P INPUT DROP																# default policy for incoming packets
	iptables -P FORWARD DROP															# default policy for forwarded packets

	# allowed outputs
	iptables -A OUTPUT -o lo -j ACCEPT													# enable localhost out
	iptables -A OUTPUT -o $VPNDEVICE -j ACCEPT											# enable outgoing connections on tunnel
	if [[ "$PROTO" == "udp" ]];then
		iptables -A OUTPUT -o $DEFAULTDEVICE -p udp --dport $VPNPORT -j ACCEPT			# enable port for communicating with PIA on default device
	else
		iptables -A OUTPUT -o $DEFAULTDEVICE -p tcp --dport $VPNPORT -j ACCEPT
	fi

	# allowed inputs
	iptables -A INPUT -i lo -j ACCEPT													# enable localhost in
	iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT					# enable requested packets on tunnel

	if [ $PORTFORWARD -eq 1 ];then
		iptables -A INPUT -i $VPNDEVICE -p tcp --dport $FORWARDEDPORT -j ACCEPT			# enable port forwarding
		iptables -A INPUT -i $VPNDEVICE -p udp --dport $FORWARDEDPORT -j ACCEPT
	fi

	if [ $FLAN -eq 1 ];then
		iptables -A OUTPUT -o $DEFAULTDEVICE -d $LAN -j ACCEPT							# enable incoming and outgoing connections within LAN (potentially dangerous!)
		iptables -A INPUT -i $DEFAULTDEVICE -s $LAN -j ACCEPT
	fi
	echo "$INFO Firewall enabled."
}

fresetfirewall()
{
	iptables --policy INPUT ACCEPT
	iptables --policy OUTPUT ACCEPT
	iptables --policy FORWARD ACCEPT
	iptables -Z
	iptables -F
	iptables -X
}

flockdown()
{
	fresetfirewall
	iptables -P OUTPUT DROP
	iptables -P INPUT DROP
	iptables -P FORWARD DROP
}

fhelp()						# Help function.
{
	echo """Usage: $(basename $0) [options]

	-s	- Server number to connect to.
	-l	- List available servers.
	-u	- Update PIA openvpn files before connecting.
	-p	- Forward a port.
	-n	- Change to another random port.
	-d	- Change DNS servers to PIA.
	-f	- Enable firewall to block all non tunnel traffic.
	-e	- Allow LAN through firewall.
	-m	- Enable PIA MACE ad blocking.
	-k	- Enable internet killswitch.
	-x	- Encrypt the credetials file.
	-v	- Display verbose information.
	-h	- Display this help.

	Examples: 
	pia -dps 6  	- Change DNS, forward a port and connect to CA_Montreal.
	pia -nfv	- Forward a new port, run firewall and be verbose.
"""
}

fvpnreset()						# Restore all settings and exit openvpn gracefully.
{
	echo
	if [ $DNS -eq 1 ];then
		fdnsrestore
	fi

	kill -s SIGINT $VPNPID &>/dev/null

	if [ $RESTARTVPN -eq 0 ];then
		if [[ $FIREWALL -eq 1 && $KILLS -eq 0 ]];then
			fresetfirewall
			echo "$INFO Firewall disabled."
		elif [[ $KILLS -eq 1 && $RESTARTVPN -lt 1 ]];then
			echo -e "\r $BOLD$RED[$BOLD$GREEN*$BOLD$RED] WARNING:$RESET Killswitch engaged, no internet will be available until you run this script again."
			flockdown
			echo > $VPNPATH/.killswitch
		fi

		echo "$INFO VPN Disconnected."
		exit 0
	else
		RESTARTVPN=0
		echo "$PROMPT Restarting VPN..."
	fi
}

fdnschange()						# Change DNS servers to PIA.
{
	cp /etc/resolv.conf /etc/resolv.conf.bak
	echo '''#PIA DNS Servers
nameserver 209.222.18.222
nameserver 209.222.18.218
''' > /etc/resolv.conf.pia
	cp /etc/resolv.conf.pia /etc/resolv.conf
	echo "$INFO Changed DNS to PIA servers."
}

fmace()						# Enable PIA MACE DNS based ad blocking.
{
	curl -s "http://209.222.18.222:1111/"
	echo "$INFO PIA MACE enabled."
}

fdnsrestore()						# Revert to original DNS servers.
{
	cp /etc/resolv.conf.bak /etc/resolv.conf
	echo "$INFO Restored DNS servers."
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
			"Czech_Republic") echo $BOLD$GREEN$SERVERNAME$RESET;;
			"Spain") echo $BOLD$GREEN$SERVERNAME$RESET;;
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
	while [ $LOGRETURN -eq 0 ];do
		VCONNECT=$(cat /var/log/pia.log)
		if [ $(echo "$VCONNECT" | grep 'auth-failure' | wc -c) -gt 1 ];then
			LOGRETURN=2
		elif [ $(echo "$VCONNECT" | grep 'RESOLVE: Cannot resolve host address' | wc -c) -gt 1 ];then
			LOGRETURN=3
		elif [ $(echo "$VCONNECT" | grep 'process exiting' | wc -c) -gt 1 ];then
			LOGRETURN=4
		elif [ $(echo "$VCONNECT" | grep 'Exiting due to fatal error' | wc -c) -gt 1 ];then
			LOGRETURN=5
		elif [ $(echo "$VCONNECT" | grep 'ERROR: Linux route add command failed:' | wc -c) -gt 1 ];then
			LOGRETURN=6
		elif [ $(echo "$VCONNECT" | grep 'Initialization Sequence Completed' | wc -c) -gt 1 ];then
			LOGRETURN=1
		fi
		sleep 0.2
	done
}

fping()						# Get latency to VPN server.
{
	PINGINT=0
	while [ $PINGINT -lt 1 ];do
		PING=$(ping -c 3 $1 | grep rtt | cut -d '/' -f 4 | awk '{print $3}')
		PINGINT=$(echo $PING | cut -d '.' -f 1)
	done
	
	SPEEDCOLOR=$BOLD$GREEN
	SPEEDNAME="fast"
	if [ $PINGINT -gt 39 ];then
		SPEEDCOLOR=$BOLD$CYAN
		SPEEDNAME="medium"
	fi
	if [ $PINGINT -gt 79 ];then
		SPEEDCOLOR=$BOLD$BLUE
		SPEEDNAME="slow"
	fi
	if [ $PINGINT -gt 159 ];then
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
	while [ $(echo $CONFIGMODIFIED | wc -c) -lt 6 ];do
		CONFIGMODIFIED=$(curl -sI $CONFIGURL | grep Last-Modified | cut -d ' ' -f 2-)
	done
	if [ $(echo $CONFIGMODIFIED | wc -c) -gt 6 ];then
		if [ "$CONFIGVERSION" != "$CONFIGMODIFIED" ];then
			RESTARTVPN=1
			echo "$ERROR WARNING: OpenVPN configuration is out of date!"
			echo "$PROMPT New PIA OpenVPN config file available! Updating..."
		else
			if [[ $VERBOSE -eq 1 && UPDATEOUTPUT -eq 1 ]];then
				echo "$INFO OpenVPN configuration up to date: $CONFIGMODIFIED"
			fi
		fi
	else
		if [ $UPDATEOUTPUT -eq 1 ];then
			echo "$ERROR Failed to check OpenVPN config Last-Modified date!"
		fi
	fi
	UPDATEOUTPUT=0
}

fconnect()						# Main function
{
	if [ $UNLOCK -eq 1 ];then
		fresetfirewall
		UNLOCK=0
	fi

	if [ $VERBOSE -eq 1 ];then
		echo -n "$PROMPT Testing latency to $DOMAIN..."
		fping $DOMAIN
		echo -e "\r$INFO $SERVERNAME latency: $SPEEDCOLOR$PING ms ($SPEEDNAME)$RESET                       "
	fi

	if [[ -f $VPNPATH/pass.enc && $(echo $CREDS | wc -c) -lt 3 ]];then
		fdecryptcreds
	fi

	if [ $(echo $CREDS | wc -c) -gt 3 ];then
		echo "$CREDS" > $VPNPATH/pass.txt
	fi

	echo -n "$PROMPT Connecting to $BOLD$GREEN$SERVERNAME$RESET, Please wait..."
	cd $VPNPATH && openvpn --config $CONFIG --daemon
	VPNPID=$(ps aux | grep openvpn | grep root | grep -v grep | awk '{print $2}')

	fchecklog

	case $LOGRETURN in
		1) echo -e "\r$INFO$BOLD$GREEN Connected$RESET, OpenVPN is running daemonized on PID $BOLD$CYAN$VPNPID$RESET                    ";;
		2) echo -e "\r$ERROR Authorization Failed. Please rerun script to enter correct login details.                    ";rm $VPNPATH/pass.txt;kill -s SIGINT $VPNPID&>/dev/null;exit 1;;
		3) echo -e "\r$ERROR OpenVPN failed to resolve $DOMAIN.                    ";kill -s SIGINT $VPNPID&>/dev/null;exit 1;;
		4) echo -e "\r$ERROR OpenVPN exited unexpectedly. Please review log:                    ";cat /var/log/pia.log;kill -s SIGINT $VPNPID&>/dev/null;exit 1;;
		5) echo -e "\r$ERROR OpenVPN suffered a fatal error. Please review log:                    ";cat /var/log/pia.log;kill -s SIGINT $VPNPID&>/dev/null;exit 1;;
		6) echo -e "\r$ERROR OpenVPN failed to add routes. Please review log:                    ";cat /var/log/pia.log;kill -s SIGINT $VPNPID&>/dev/null;exit 1;;
	esac

	if [ $ENCRYPT -eq 1 ];then
		CREDS="$(cat $VPNPATH/pass.txt 2>/dev/null)"
		fencryptcreds
	fi

	UPDATEOUTPUT=1
	fcheckupdate
	if [ $RESTARTVPN -eq 1 ];then
		fupdate
		fvpnreset
		return 0
	fi

	PLOG=$(cat /var/log/pia.log)

	if [ $VERBOSE -eq 1 ];then
		echo "$INFO OpenVPN Logs:"
		echo -n $CYAN
		while IFS= read -r LNE ;do echo "     $LNE" | awk '{$1=$2=$3=$4=$5=""; print $0}';done <<< "$PLOG"
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

		echo  -n "$PROMPT Fetching IP..."
		while [ $(echo $NEWIP | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | wc -c) -lt 3 ];do
			NEWIP=$(curl -s -m 4 icanhazip.com)
		done

		while [ $(echo $MYIP | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | wc -c) -lt 3 ];do
			MYIP=$(cat /tmp/ip.txt)
			sleep 0.3
		done
		
		if [ $(echo $NEWIP | wc -c) -gt 2 ];then
			WHOISOLD="$(whois $MYIP)"
			WHOISNEW="$(whois $NEWIP)"
			COUNTRYOLD=$(echo "$WHOISOLD" | grep country | head -n 1)
			COUNTRYNEW=$(echo "$WHOISNEW" | grep country | head -n 1)
			DESCROLD="$(echo "$WHOISOLD" | grep descr)"$RESET
			DESCRNEW="$(echo "$WHOISNEW" | grep descr)"$RESET
			
			echo -e "\r$PROMPT Old IP:$RED$BOLD $MYIP"
			if [ $(echo $COUNTRYOLD | wc -c) -gt 8 ];then
				while IFS= read -r LNE ;do echo "     $LNE";done <<< "$COUNTRYOLD"
			fi
			if [ $(echo $DESCROLD | wc -c) -gt 8 ];then
				while IFS= read -r LNE ;do echo "     $LNE";done <<< "$DESCROLD"
			fi
			echo "$PROMPT Current IP:$GREEN$BOLD $NEWIP"
			if [ $(echo $COUNTRYNEW | wc -c) -gt 8 ];then
				while IFS= read -r LNE ;do echo "     $LNE";done <<< "$COUNTRYNEW"
			fi
			if [ $(echo $DESCRNEW | wc -c) -gt 8 ];then
				while IFS= read -r LNE ;do echo "     $LNE";done <<< "$DESCRNEW"
			fi
		else
			echo -e "\r$ERROR Failed to fetch new IP.                   "
		fi
	fi

	if [ $PORTFORWARD -eq 1 ];then
		if [ $NEWPORT -eq 1 ]; then
			echo -e "\r$INFO Identity changed to $BOLD$GREEN$(cat $VPNPATH/client_id)$RESET"
		else
			if [ $VERBOSE -eq 1 ];then
				echo -e "\r$PROMPT Using port forwarding identity $BOLD$CYAN$(cat $VPNPATH/client_id)$RESET"
			fi
		fi
		case $SERVERNAME in
			"Czech_Republic") fforward;;
			"Spain") fforward;;
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
			if [ $FORWARDEDPORT -gt 0 ] &>/dev/null;then
				echo -e "\r$INFO Port $GREEN$BOLD$FORWARDEDPORT$RESET has been forwarded to you.                    "
			else
				echo -e "\r$ERROR $SERVERNAME failed to forward us a port!                   "
			fi
		else
			echo "$ERROR Port forwarding is only available at: Spain, Czech_Republic, Switzerland, CA_Toronto, CA_Montreal, CA_Vancouver, Romania, Israel, Sweden, France and Germany."
		fi
	fi

	if [ $DNS -eq 1 ];then
		fdnschange
	fi

	if [ $MACE -eq 1 ];then
		fmace
	fi

	if [ $FIREWALL -eq 1 ];then
		ffirewall
	fi
	if [[ $KILLS -eq 1 && $VERBOSE -eq 1 ]];then
		echo "$PROMPT Killswitch activated."
	fi


	echo -n "$INFO VPN setup complete, press$BOLD$RED Ctrl+C$RESET to shut down."
	flogwatcher
	if [ $RESTARTVPN -eq 0 ];then
		echo -e "\r$ERROR$RED$BOLD WARNING:$RESET New OpenVPN log entries detected:                         "
		NEWLOGS=$(cat /var/log/pia.log | tail -n +$(($LOGLENGTH + 1)) | sed '/^$/d')
		while IFS= read -r LNE ;do echo "$BOLD$RED     $LNE$RESET";done <<< "$NEWLOGS"
		RESTARTVPN=1
		if [ $FIREWALL -eq 1 ];then
			flockdown
			UNLOCK=1
		fi
	else
		fupdate
	fi	
	fvpnreset
}

flogwatcher()						# Check the log for new entries
{
	LOGLENGTH=$(cat /var/log/pia.log | wc -l)
	LOGALERT=$LOGLENGTH
	while [ $LOGALERT -eq $LOGLENGTH ];do
		sleep 20
		LOGALERT=$(cat /var/log/pia.log | wc -l)
		fcheckupdate
		if [ $RESTARTVPN -eq 1 ];then
			return 0
		fi
	done
	
}

fgetip()						# Get external IP
{
	while [ $(echo $MYIP | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | wc -c) -lt 3 ];do
		MYIP=$(curl -m 5 -s icanhazip.com)
	done
	echo $MYIP > /tmp/ip.txt
}

fdecryptcreds()
{
	if [ $(cat $VPNPATH/pass.txt 2>/dev/null | wc -c) -lt 6 ];then	
		if [ $(cat $VPNPATH/pass.enc | wc -c) -gt 3 ];then
			echo "$PROMPT Decrypting creds.."
			cat $VPNPATH/pass.enc | openssl base64 -d | openssl enc -d -aes-256-cbc > $VPNPATH/pass.txt
			chmod 400 $VPNPATH/pass.txt && CREDS="$(cat $VPNPATH/pass.txt 2>/dev/null)" 
			if [ $ENCRYPT -eq 0 ];then
				rm $VPNPATH/pass.enc
			fi
		else
			rm $VPNPATH/pass.enc
		fi
	fi
}

fencryptcreds()
{
	echo "$INFO Encypting creds.."
	cat $VPNPATH/pass.txt 2>/dev/null | openssl enc -e -aes-256-cbc -a > $VPNPATH/pass.enc && rm $VPNPATH/pass.txt && chmod 400 $VPNPATH/pass.enc
}


						# Colour codes for terminal.
BOLD=$(tput bold)
BLUE=$(tput setf 1)
GREEN=$(tput setf 2)
CYAN=$(tput setf 3)
RED=$(tput setf 4)
RESET=$(tput sgr0)

INFO=" [$BOLD$GREEN*$RESET]"
ERROR=" [$BOLD$RED"'X'"$RESET]"
PROMPT=" [$BOLD$BLUE>$RESET]"

						# This is where we will store PIA openVPN files and user config.
VPNPATH='/etc/openvpn/pia'

						# Initialize switches.
PORTFORWARD=0
NEWPORT=0
NEWIP=0
NOPORT=0
MACE=0
KILLS=0
DNS=0
FORWARDEDPORT=0
VERBOSE=0
FIREWALL=0
SERVERNUM=0
FLAN=0
UNKNOWNOS=0
MISSINGDEP=0
CONFIGNUM=0
RESTARTVPN=0
UNLOCK=0
UPDATEOUTPUT=0
ENCRYPT=0
CREDS=0

						# Check if user is root.
if [ $(id -u) != 0 ];then echo "$ERROR Script must be run as root." && exit 1;fi

						# Check for missing dependencies and install.
if [ $(command -v pacman) ];then
	INSTALLCMD="pacman --noconfirm -S"
elif [ $(command -v apt-get) ];then
	INSTALLCMD="apt-get install -y"
elif [ $(command -v yum) ];then
	INSTALLCMD="yum install -y"
else
	UNKNOWNOS=1
fi

if [ $UNKNOWNOS -eq 1 ];then
	command -v openvpn >/dev/null 2>&1 || MISSINGDEP=1
	command -v openssl >/dev/null 2>&1 || MISSINGDEP=1
	command -v iptables >/dev/null 2>&1 || MISSINGDEP=1
	command -v curl >/dev/null 2>&1 || MISSINGDEP=1
	command -v unzip >/dev/null 2>&1 || MISSINGDEP=1
	if [ $MISSINGDEP -eq 1 ];then
		echo "$ERROR OS not identified as arch or debian based, please install openvpn, openssl, iptables, curl and unzip and run script again."
		exit 1
	fi
else
	command -v openvpn >/dev/null 2>&1 || { echo >&2 "$INFO openvpn required, installing...";$INSTALLCMD openvpn; }
	command -v openssl >/dev/null 2>&1 || { echo >&2 "$INFO openssl required, installing...";$INSTALLCMD openssl; }
	command -v iptables >/dev/null 2>&1 || { echo >&2 "$INFO iptables required, installing...";$INSTALLCMD iptables; }
	command -v curl >/dev/null 2>&1 || { echo >&2 "$INFO curl required, installing...";$INSTALLCMD curl; }
	command -v unzip >/dev/null 2>&1 || { echo >&2 "$INFO unzip required, installing...";$INSTALLCMD unzip; }
fi


if [ ! -d $VPNPATH ];then mkdir -p $VPNPATH;fi

						# Check for existence of credentials file.
if [[ ! -f $VPNPATH/pass.txt && ! -f $VPNPATH/pass.enc ]];then
	read -p "$PROMPT Please enter your username: " USERNAME
	read -sp "$PROMPT Please enter your password: " PASSWORD
	echo -e "$USERNAME\n$PASSWORD" > $VPNPATH/pass.txt
	echo
	chmod 400 $VPNPATH/pass.txt
	unset USERNAME PASSWORD
fi

while getopts "lhupnmkdfvxes:" opt
do
	case $opt in
		l) flist;exit 0;;
		h) fhelp;exit 0;;
		u) fupdate;;
		p) PORTFORWARD=1;;
		n) fnewport;;
		m) MACE=1;DNS=1;;
		k) KILLS=1;FIREWALL=1;;
		d) DNS=1;;
		f) FIREWALL=1;;
		e) FLAN=1;FIREWALL=1;;
		v) VERBOSE=1;fgetip&;;
		x) ENCRYPT=1;;
		s) SERVERNUM=$OPTARG;;
		*) echo "$ERROR Error: Unrecognized arguments.";fhelp;exit 1;;
	esac
done

if [ ! -f $VPNPATH/servers.txt ];then fupdate;fi
MAXSERVERS=$(cat $VPNPATH/servers.txt | wc -l)

if [ $SERVERNUM -lt 1 ];then
	echo "$PROMPT Please choose a server: "
	flist
	read -p "$PROMPT " SERVERNUM
	clear
fi

trap fvpnreset INT

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

if [ -f $VPNPATH/.killswitch ];then
	UNLOCK=1
	rm -rf $VPNPATH/.killswitch
fi

while [ true ];do
	fconnect
done
