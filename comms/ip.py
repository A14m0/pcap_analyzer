"""Holds IP-related commands"""


from scapy.all import *
from ipaddress import ip_address


def init_mod(cmd_list):
    cmd_list["ip_all_internal"] = (ip_all_internal, "Prints all internal IP addresses seen in the data")
    cmd_list["ip_all_external"] = (ip_all_external, "Prints all external IP addresses seen in the data")


def ip_all_internal(cmd, packets, args):
    ret = []
    for p in packets:
        try:
            ip_layer = p[IP]
            src = ip_address(ip_layer.src)
            dst = ip_address(ip_layer.dst)

            if src.is_private and ip_layer.src not in ret:
                ret.append(ip_layer.src)
            if dst.is_private and ip_layer.dst not in dst:
                ret.append(ip_layer.dst)

        except:
            pass
    print(f"[IP] Found {len(ret)} unique internal addresses")
    for ip in ret:
        print(f"\t{ip}")

    return ret


def ip_all_external(cmd, packets, args):
    ret = []
    for p in packets:
        try:
            ip_layer = p[IP]
            src = ip_address(ip_layer.src)
            dst = ip_address(ip_layer.dst)

            if not src.is_private and ip_layer.src not in ret:
                ret.append(ip_layer.src)
            if not dst.is_private and ip_layer.dst not in dst:
                ret.append(ip_layer.dst)

        except:
            pass
    print(f"[IP] Found {len(ret)} unique external addresses")
    for ip in ret:
        print(f"\t{ip}")

    return ret