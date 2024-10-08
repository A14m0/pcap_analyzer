"""Holds DNS-related requests"""

from scapy.all import *
import ssl
import OpenSSL


def init_mod(cmd_list):
    cmd_list["dns_get_all_sites"] = (dns_get_all_sites, "Prints a list of sites that were requested, providing an IP-to-DNS lookup table")
    cmd_list["dns_get_ip_searched_domains"] = (dns_get_ip_searched_domains, "Prints a list of sites that were requested by a target IP. Takes an optional list of IP addresses to look up, otherwise prints everything.")
    cmd_list["dns_get_domain_to_ip"] = (dns_get_domain_to_ip, "Tries to look up a domain in the lookup database. Takes an optional list of domains to look up, otherwise prints everything.")
    cmd_list["dns_lookup_ip"] = (dns_lookup_ip, "Tries to look up an IP's domain name. Takes a list of IPs to look up.")
    cmd_list["dns_lookup_ip_ssl"] = (dns_lookup_ip_ssl, "Tries to look up an IP's domain name using the IP's SSL certificate hosted over port 443. Takes a list of IPs to look up.")


def dns_get_all_sites(cmd, packets, args):
    ret = []
    for p in packets:
        if p.haslayer(DNS):
            ret.append(p)
    
    print(f"[DNS] Found {len(ret)} DNS requests in data")

    ip_searched_domains = {}
    domain_to_ip = {}
    # process all DNS querries and build our tables
    for p in ret:
        if p[DNS].qr == 0:
            try:
                if p[IP].src not in ip_searched_domains:
                    ip_searched_domains[p[IP].src] = []
                ip_searched_domains[p[IP].src].append(p[DNS].qd.qname.decode())
            except Exception as e:
                #print(f"failed: {e}, {p.fields}")
                pass
        else:
            try:
                answer = p[DNS].an
                rdat = answer.rdata
                if type(rdat) == bytes:
                    rdat = rdat.decode()
                domain_to_ip[answer.rrname.decode()] = rdat
            except Exception as e:
                pass

    # print out some stuff
    for ip in ip_searched_domains:
        print(f"{ip}:")
        for v in ip_searched_domains[ip]:
            try:
                print(f"\t{v} -> {domain_to_ip[v]}")
            except KeyError:
                print(f"\t{v} (no answer)")

    # save the lookups to the command object
    cmd.store["ip_searched_domains"] = ip_searched_domains
    cmd.store["domain_to_ip"] = domain_to_ip

def dns_get_ip_searched_domains(cmd, packets, args):
    if "ip_searched_domains" not in cmd.store:
        print(f"[DNS] The IP searched domains value has not been set. Run `dns_get_all_sites` to populate this!")
        return
    if "domain_to_ip" not in cmd.store:
        print(f"[DNS] The IP searched domain value is set, but the DNS lookup is not set. This should not happen, but try running `dns_get_all_sites` to remedy this...")
        return
    
    ip_searched_domains = cmd.store["ip_searched_domains"]
    domain_to_ip = cmd.store["domain_to_ip"]

    print_all = True if len(args)==0 else False

    # see if there's any IPs that are not stored in the lookup
    for ip in args:
        if ip not in ip_searched_domains:
            print(f"IP {ip} is not in this packet capture! Did you load the correct one?")

    for ip in ip_searched_domains:
        if ip in args or print_all:
            print(f"IP: {ip}")
            for v in ip_searched_domains[ip]:
                try:
                    print(f"\t{v} -> {domain_to_ip[v]}")
                except KeyError:
                    print(f"\t{v} (no answer)")

    return ip_searched_domains

def dns_get_domain_to_ip(cmd, packets, args):
    if "domain_to_ip" not in cmd.store:
        print(f"[DNS] The DNS lookup is not set. Run `dns_get_all_sites` to remedy this!")
        return
    
    domain_to_ip = cmd.store["domain_to_ip"]

    print_all = True if len(args)==0 else False

    ret = {}
    for domain, ip in domain_to_ip.items():
        if domain in args or print_all:
            print(f"{domain} -> {ip}")
            ret[domain] = ip

    return ret


def dns_lookup_ip(cmd, packets, args):
    if "domain_to_ip" not in cmd.store:
        print(f"[DNS] The DNS lookup is not set. Run `dns_get_all_sites` to remedy this!")
        return
    
    domain_to_ip = cmd.store["domain_to_ip"]
    ip_to_domain = {v: k for k, v in domain_to_ip.items()}

    ret = {}

    for ip in args:
        if ip in ip_to_domain:
            print(f"\t{ip} -> {ip_to_domain[ip]}")
            ret[ip] = ip_to_domain[ip]

    return ret
    
def dns_lookup_ip_ssl(cmd, packets, args):
    ret = {}
    for ip in args:
        try:

            # "magic" :D
            cert = ssl.get_server_certificate((ip, 443), timeout=5)
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        
            print(f"[DNS] {ip} -> {x509.get_subject().CN}")
            ret[ip] = x509.get_subject().CN


        except Exception as e:
            #print(f"IP {ip} encountered an error while processing: {e}")
            print(f"[DNS] {ip} has no SSL cert to compare against")
            ret[ip] = ""

    return ret