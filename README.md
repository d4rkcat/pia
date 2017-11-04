pia
==========
- Only designed for Arch linux (Antergos)
- Update openvpn configuration files using maximum security configuration.
- Forward ports.
- Change DNS to PIA secure DNS servers.

Installation:
==========

Run 'sudo make install' in the pia directory.
pia will now be installed and can be run with 'pia'.
	
Usage
==========
	Usage: ./pia [Options]
	-u	- Update PIA openvpn files before connecting.
	-p	- Forward a port.
	-n 	- Change to another random port.
	-d	- Change DNS servers to PIA.
	-l	- List available servers.
	-v  - Display verbose information.

		Examples: 
			 pia -dpu	- Update openvpn files, forward a port and change DNS servers to PIA