"""Provides a help command"""


from scapy.all import *
import statistics


def init_mod(cmd_list):
    cmd_list["help"] = (run_help, "Prints a list of help options")

def run_help(cmd, packets, args):
    print("\tHELP MENU")
    print("-"*40)
    for c, v in cmd.commands.items():
        print(f"{c} :\t {v[1]}")