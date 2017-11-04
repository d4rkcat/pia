pia
==========
- Only designed for Arch and Debian (only tested in Arch)
- Update openvpn configuration files using maximum security configuration.
- Forward ports.
- Change DNS to PIA secure DNS servers.
- Use firewall to block all non-tunnel traffic

Installation:
==========

Run 'sudo make install' in the pia directory.
pia will now be installed and can be run with 'pia'.
	
Usage
==========
	Usage: ./pia.sh [Options]
		-u	- Update PIA openvpn files before connecting.
		-p	- Forward a port.
		-n	- Change to another random port.
		-d	- Change DNS servers to PIA.
		-f	- Enable firewall to block all traffic apart from tun0
		-l	- List available servers.
		-v	- Display verbose information.
		-h	- Display this help.

		Examples: 
			 pia -dpu	- Update openvpn files, forward a port and change DNS servers to PIA
			 pia -nfv	- Forward a new port, run firewall and be verbose.
