#!/usr/bin/env python3
"""
RTOoOS Emulator for Defcon Quals 2019

This is an example using uDdbg embedded in "normal" unicorn code.

To run, download the crux challenge binary here:
https://github.com/o-o-overflow/dc2019q-rtooos/raw/master/crux/crux_7377a1f43e35924971ef1b172c080e03131bed56
"""
from __future__ import print_function
import subprocess
import sys
from unicorn import *
from unicorn.x86_const import *
import capstone

# Make sure you have installed uddbg first.
from udbg import UnicornDbg

__author__ = "domenukk"

# code to be emulated
try:
    with open("./crux_7377a1f43e35924971ef1b172c080e03131bed56", "rb") as bf:
        GUEST_BINARY = bf.read()
except:
    print("Please drop a valid RTOoOS binary in this folder:")
    print("wget https://github.com/o-o-overflow/dc2019q-rtooos/raw/master/crux/crux_7377a1f43e35924971ef1b172c080e03131bed56")
    exit(1)

# Not used for now.
TXT_POS = 0x0
TXT_SIZE = 8 * 1024 * 1024

HEAP_POS = TXT_SIZE + 0x4096
HEAP_SIZE = TXT_SIZE

STACK_POS = 16 *  HEAP_POS + 0x4096

HEAP_MIN = 0x1000
HEAP_MAX = 0x3650

COMPLETE_SIZE = 16 * 1024 * 1024

#ENTRY = TXT_POS + 0x13f0
ENTRY = TXT_POS # TXT_POS + 0x13f0

def read_str(uc: Uc, pos: int) -> str:
    ret = ""
    char = chr(uc.mem_read(pos, 1)[0])
    while char != '\0':
        ret += char
        pos += 1
        char = chr(uc.mem_read(pos, 1)[0])
    return ret


# callback for OUT instruction
def hook_out(uc: Uc, port, size, value, user_data):
    try: 
        eip = uc.reg_read(UC_X86_REG_EIP)
        hyp_num = uc.reg_read(UC_X86_REG_EDI)
        hypercall = chr(hyp_num)
        #print("Got Hypercall {}".format(hypercall))

        if hypercall == "a":
            # putc
            sys.stdout.write(chr(uc.reg_read(UC_X86_REG_RAX) & 0xFF))
            sys.stdout.flush()

        elif hypercall == "b":
            # WE DONT KNOW
            print("You triggered this Hypercall... We don't know what it does! No go do this on the real binary.")

        elif hypercall == "c":
            # read
                # read
            input = sys.stdin.buffer.readline()
            input += b"\0"

            uc.mem_write(uc.reg_read(UC_X86_REG_RAX), input)
            uc.reg_write(UC_X86_REG_RAX, len(input) - 1) # 0 bytes?

        elif hypercall == "d":
            # puts
            output = read_str(uc, uc.reg_read(UC_X86_REG_RAX))
            print(output)

        elif hypercall == "e":
            # ls
            print("Calling ls.")
            ls_out = subprocess.check_output(["ls"])
            print(ls_out.decode("utf-8"))

        elif hypercall == "f":
            # cat
            filename = read_str(uc, uc.reg_read(UC_X86_REG_RAX))
            print("Calling cat on File {}".format(filename))
            cat_out = subprocess.check_output(["cat", filename])
            print(cat_out.decode("utf-8"))

        else: 
            print("Unknown Hypercall!")

    except KeyboardInterrupt as ex:
        print("\n\nEmulator says baiii <3")
        uc.emu_stop()


def init_emu() -> Uc:
    # Initialize emulator in X86-64bit mode
    mu = Uc(UC_ARCH_X86, UC_MODE_64)

    mu.mem_map(0, 16 * 1024 * 1024)

    # write machine code to be emulated to memory
    mu.mem_write(TXT_POS, GUEST_BINARY)

    mu.reg_write(UC_X86_REG_RSP, 0xFFF000)

    mu.mem_write(0xFFFF00, b"./crux")
    mu.mem_write(0xFFF000, b"\xFF\xFF\x00")

    # initialize machine registers
    mu.hook_add(UC_HOOK_INSN, hook_out, None, 1, 0, UC_X86_INS_OUT)
    return mu

def run_nodebug():
    mu = init_emu()
    # emulate code in infinite time & unlimited instructions
    mu.emu_start(ENTRY, TXT_POS + len(GUEST_BINARY))

def run_debug():
    """
    This starts uDdbg.
    """
    udbg = UnicornDbg()
    udbg.initialize(emu_instance=init_emu(),  # We pass in our own unicorn instance with hooks.
        entry_point=ENTRY,  # Execution will start here
        exit_point=TXT_POS + len(GUEST_BINARY),  # we never reach this (endless loop)
        hide_binary_loader=True,  # Our users never want to load other things.
        mappings=[("main", 0x0, COMPLETE_SIZE)]  # We tell the debugger about the mappings we have.
    )

    # udbg.add_module(Heapdump(udbg)) # << We can add specific modules here.

    # Kick off emulation.
    udbg.start()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "run":
        run_nodebug()
    else:
        # uDdbg it.
        # Example usage:
        # ./rtooos_emulator.py
        # b 0x74
        # c
        run_debug()  