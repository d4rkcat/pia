pia v0.2 Features:
==========
- Update openvpn configuration files using any of the 5 available configuration zips.
- Instant connections with secure storage of VPN password.
- Forward ports and change port fowarding identity.
- Change DNS to PIA secure leak-proof DNS servers.
- Enable firewall to block all non-tunnel traffic.
- Enable PIA MACE DNS based ad blocking.
- Enable internet killswitch.
- Detailed vebose output.
- Designed for debian and arch based linux but should work on any linux.

This client has all of the functionality of the official one and works on any linux with bash, openvpn and ufw installed.  


pia can be run interactivley or with switches. It will only ask you to supply your credentials once and then after that it connects without asking.  


The credentials file is protected by 'chmod 400', which means only the root user can view the file. If you have a malicious root user on your box it's game over anyway.  


The ovpn files are editited and 'auth-nocache' option is added, which means openvpn will not store your creds in memory.  


Dependencies:
==========
- bash
- openvpn
- ufw
- curl
- unzip

Installation:
==========
Run 'sudo make install' in the pia directory.
pia will now be installed and can be run with 'sudo pia'.

Usage
==========
	Usage: pia [Options]

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
	-v	- Display verbose information.
	-h	- Display this help.

	Examples: 
	pia -dps 24 	- Change DNS, forward a port and connect to Switzerland.
	pia -nfv	- Forward a new port, run firewall and be verbose.
