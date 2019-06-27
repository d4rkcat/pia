BIN=/usr/local/bin
ETC=/etc/openvpn/pia

install:
	install -m 755 pia.sh ${BIN}/pia

uninstall:
	rm -f ${BIN}/pia

purge: uninstall
	rm -fr ${ETC}
