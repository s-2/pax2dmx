pax2dmx is a highly experimental "paxcounter" style sniffer for 802.11 Probe Request packets to control DMX stage lights based on the current wifi activity (i.e. phones nearby).

Requirements:

	opkg install libftdi1 python3 python3-pip scapy

	pip install pydmx PyDMX-Drivers-FTDI

For OpenWrt, PyDMX-Drivers-FTDI needs to be patched to use `usleep` instead of `nanosleep` (seem to be issues with musl).
