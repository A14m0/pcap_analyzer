"""Holds save-related commands"""


def init_mod(cmd_list):
    cmd_list["save_text"] = (save_text, "Saves the output of a command to a text file. Takes a file path, followed by the target command and its required arguments. Requires that the command provided returns a data structure, otherwise nothing will be saved.")

def save_text(cmd, packets, args):
    path = args[0]
    ret = cmd.call_comm(args[1:])
    if ret == None:
        print("Command did not return any data, nothing will be saved!")
    else:
        print(f"[SAVE] Saving data to {path}...")
        with open(path, "w") as f:
            f.write(str(ret))
        print("[SAVE] Complete!")