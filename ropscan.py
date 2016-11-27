import os, sys
import collections
import pprint
from capstone import *
from capstone.x86 import *

MAX_GADGET_LEN = 4
GADGET_GROUPS = [X86_GRP_CALL, X86_GRP_RET, X86_GRP_INT]

def printHelp():
    print("Usage: ropscan [binary]")

def printGadgets(gadgets):
    for g in gadgets:
        if g:
            print("0x%x:\t%s\t%s [%d]" % (g.address, g.mnemonic, g.op_str, g.id))
    print("\n")

def getGroup(i):
    if i.groups:
        for group in i.groups:
            if group in GADGET_GROUPS:
                return group
    return None

def scan(roplen, data):
    gadgets = collections.deque([None]*roplen, roplen)
    d = dict()
    for t in GADGET_GROUPS:
        d[t] = list()

    md = Cs(CS_ARCH_X86, CS_MODE_32) #TODO detect architecture automatically?
    md.detail = True

    for offset in range(0, len(data)): #disassemble at every offset
        #print("[*] Offset %d\n" % offset)

        for i in md.disasm(data, offset):
            gadgets.append(i)
            group = getGroup(i)
            #print("0x%x:\t%s\t%s [%d]" % (i.address, i.mnemonic, i.op_str, i.id))
            if group:
                printGadgets(gadgets)
                d[group].append(list(gadgets))
                gadgets = collections.deque([None]*roplen, roplen) #reset
            else:
                if i.id == X86_INS_RET:
                    print("Ret instruction found: %s" + str(i))

    return d

def main():
    if len(sys.argv) < 2:
        print("Not enough arguments")
        printHelp()
        return 1

    with open(sys.argv[1], "rb") as f:
        data = f.read()

    gadgets = scan(MAX_GADGET_LEN, data)

    return 0

if __name__ == '__main__':
    sys.exit(main())
