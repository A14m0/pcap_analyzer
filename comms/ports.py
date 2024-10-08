"""Holds port-related requests"""

from scapy.all import *
import statistics
import re

def init_mod(cmd_list):
    cmd_list["port_get_avg_ephemeral"] = (port_get_avg_ephemeral, "Returns the median ephemeral port of the target IP. Takes a list of IP addresses")

def port_get_avg_ephemeral(cmd, packets, args):
    pattern = r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$"
    args = [v for v in args if re.match(pattern, v)]

    if len(args) == 0:
        print("No IPs provided.")
        return 

    print(f"[PORT] Processing {len(args)} IP addresses")
    ret = {}
    for ip in args:
        ctr = 0
        pctr = 0

        ephemeral_ports = []

        for packet in packets:
            pctr += 1
            try:
                if packet[scapy.layers.inet.IP].src == ip:
                    if packet.haslayer(TCP):
                        ephemeral_ports.append(packet[TCP].sport)
                    elif packet.haslayer(UDP):
                        ephemeral_ports.append(packet[UDP].sport)

            except Exception as e:
                print(e)
                ctr += 1

        print(f"[PORT] Total errors encountered: {ctr}/{pctr} packets")

        print(f"[PORT] Calculating median port for {ip}...")
        med = statistics.median(ephemeral_ports)
        print(f"\tMedian: {med}")
        ret[ip] = med
    return ret
