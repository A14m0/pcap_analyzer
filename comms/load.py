"""Provides data loading functions"""


from scapy.all import *


def init_mod(cmd_list):
    cmd_list["load"] = (load_dat, "Loads a PCAP file for analysis. Takes a single path as an argument")

def load_dat(cmd, packets, args):
    target_path = args[0]
    print(f"[LOAD] Trying to load file {target_path}...")
    try:
        ret = []
        cap = rdpcap(target_path)
        for packet in cap:
            ret.append(packet)
        print(f'[LOAD] Processed {len(ret)} packets')
        cmd.PACKETS = ret
    except Exception as e:
        print(f"[LOAD] Failed to load PCAP: {e}")
