from scapy.all import *
from importlib import reload

from prompt_toolkit import prompt
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.styles import Style
from prompt_toolkit import PromptSession
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory

from comms import dns
from comms import help
from comms import ip
from comms import load
from comms import ports
from comms import save

#PCAP_PATH="/home/morpheus/nfs/Data/Pcaps/BrokenBGJobTest_Pixel.pcapng"
#TARGET_IP = "192.168.137.8"


class Command:

    def __init__(self):
        self.PACKETS = []
        self.commands = {}
        self.store = {}

        # add a reload command
        self.commands["reload"] = (reload_mods, "Reloads all currently loaded modules")

        self.completer= WordCompleter([])

        # make sure we reload everything once at the beginning
        self.call_comm(["reload"])

    def call_comm(self, command):
        if command[0] not in self.commands:
            print(f"Unknown command '{command[0]}'. Use 'help' to view available commands")
            return
        
        return self.commands[command[0]][0](self, self.PACKETS, command[1:])


def reload_mods(cmd, packets, args):
    mods = [
        dns,
        help,
        ports,
        load,
        save,
        ip
    ]

    for m in mods:
        reload(m)
        m.init_mod(cmd.commands)

    c = [v for v in cmd.commands.keys()]
    c.append("exit")
    cmd.completer = WordCompleter(c)

    print(f"[RELOAD] Reloaded {len(mods)} modules")


PCAP_PATH="/home/morpheus/nfs/Data/Pcaps/BrokenBGJobTest_Samsung.pcapng"
TARGET_IP = "192.168.137.109"

if __name__ == "__main__":
    cmd = Command()
    print(f"Loaded {len(cmd.commands)} commands")

    colors = Style.from_dict({
        # User input (default text).
        '':          '#ff0066',

        # Prompt.
        'prompt': '#884444'
    })


    session = PromptSession()


    user_comm = ""
    while True:

        message = [
            ('class:prompt', ' > ')
        ]

        try:
            user_comm = session.prompt(message, style=colors, completer=cmd.completer, auto_suggest=AutoSuggestFromHistory()).split(" ")
        except KeyboardInterrupt:
            continue

        if user_comm[0] == "exit":
            print("Exiting...")
            exit(0)

        try:
            cmd.call_comm(user_comm)
        except Exception as e:
            print(f"Failed to run command: {e}")
        



#print(f"Found {ctr} packets")
