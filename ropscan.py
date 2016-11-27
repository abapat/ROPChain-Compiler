import os, sys
import collections
import pprint
from capstone import *
from capstone.x86 import *

MAX_GADGET_LEN = 4

def printHelp():
    print("Usage: ropscan [binary]")

def printGadgets(gadgets):
    for g in gadgets:
        if g:
            print("0x%x:\t%s\t%s [%d]" % (g.address, g.mnemonic, g.op_str, g.id))
    print("\n\n")

def scan(roplen, data, offset):
    gadgets = collections.deque([None]*roplen, roplen)

    md = Cs(CS_ARCH_X86, CS_MODE_32) #TODO detect architecture automatically?
    md.detail = True
    for i in md.disasm(data, offset):
        gadgets.append(i)
        if i.id == X86_INS_RET:
            printGadgets(gadgets)
            gadgets = collections.deque([None]*roplen, roplen) #reset

def main():
    if len(sys.argv) < 2:
        print("Not enough arguments")
        printHelp()
        return 1

    with open(sys.argv[1], "rb") as f:
        data = f.read()

    for offset in range(0, len(data)): #disassemble at every offset
        print("**Offset %d**\n" % offset)
        scan(MAX_GADGET_LEN, data, offset)

    return 0

if __name__ == '__main__':
    sys.exit(main())
