pia v0.5 Features:
==========
- Update openvpn configuration files using any of the 5 available configuration zips.
- Auto-update whenever PIA releases new configuration zips.
- Auto reconnect on dropped connections.
- Instant connections with secure permissions of VPN password.
- Optionally AES encrypt creds with openssl and a password.
- Forward ports and change port fowarding identity.
- Change DNS to PIA secure leak-proof DNS servers.
- Enable firewall to block all non-tunnel traffic.
- Enable PIA MACE DNS based ad blocking.
- Enable internet killswitch.
- Detailed verbose output.
- Designed for debian and arch based linux but should work on any linux.

This client has all of the functionality of the official one and works on any linux with bash, openvpn and iptables installed.  


It also has the added advantage of using the versions of OpenVPN and OpenSSL installed on your system, which will always be more secure than the old fork of old versions of this software that the official PIA app uses as long as you regulary update.  


pia can be run interactivley or with switches. It will only ask you to supply your credentials once and then after that it connects without asking.  


The credentials file is permissions protected by 'chmod 400', which means only the root user can view the file. You can also optionally AES encrypt the creds file on disk with a password using the the -x arg.  


The ovpn files are editited and 'auth-nocache' option is added, which means openvpn will not store your creds in memory.  


Dependencies:
==========
- bash
- iptables
- openvpn
- openssl
- curl
- unzip
- whois
- git

Installation:
==========
Clone the repository to a suitable place:  
`cd ~/scripts && git clone https://github.com/d4rkcat/pia`

Then to install the script:  
`cd ~/scripts/pia && sudo make install`

pia will now be installed and can be run from any directory with:  
`sudo pia [options]`

You can update to the latest version easily with:  
`cd ~/scripts/pia && git pull && sudo make install`

Usage:
==========
	Usage: pia [options]

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
