#!/usr/bin/env Python
#-*-utf8-*-

from scapy.all import * 
import argparse

parse = argparse.ArgumentParser()
parse.add_argument('-r', '--rango', help='Rango de direcciones a escanear')
parse = parse.parse_args()

def ip_scan(ip):
	range_ip = ARP(pdst=ip)
	broadcast = Ether(dst='ff:ff:ff:ff:ff:ff')
	final_packet = broadcast/range_ip
	res = srp(final_packet, timeout=2, verbose=False)[0]
	for n in res:
                print("[+] HOST: {}       MAC: {}".format(n[1].psrc, n[1].hwsrc))

def main():
	if parse.rango:
		ip_scan(parse.rango)
	else:
		print("Se es necesario un rango de IPs a escanear.")

if __name__ == "__main__":
	main()
