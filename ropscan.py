import os, sys
import collections
import pprint
from capstone import *
from capstone.x86 import *

MAX_GADGET_LEN = 4
GADGET_GROUPS = [X86_GRP_RET, X86_GRP_INT]
MAX_GADGETS = 5000

def printHelp():
    print("Usage: ropscan [binary]")

def printGadgets(gadgets):
    for g in gadgets:
        if g:
            print("0x%x:\t%s\t%s [%d]" % (g.address, g.mnemonic, g.op_str, g.id))
    print("\n")

def serializeInstructions(gadget):
    seq = list()
    for i in gadget:
        if i: #skip None
            tup = (i.id, i.op_str)
            seq.append(tup)

    h = hash(tuple(seq))
    #print("seq: %s, hash: %d" % (str(tuple(seq)), h))
    return h

def getGroup(i):
    if i.groups:
        for group in i.groups:
            if group in GADGET_GROUPS:
                return group
    return None

def scan(roplen, data):
    count = 0
    gadget = collections.deque([None]*roplen, roplen)
    d = dict()
    for t in GADGET_GROUPS:
        d[t] = (set(), list())

    md = Cs(CS_ARCH_X86, CS_MODE_32) #TODO detect architecture automatically?
    md.detail = True

    for offset in range(0, 5): #disassemble at every offset?
        #print("[*] Offset %d\n" % offset)
        instructions = md.disasm(data, offset)
        for i in instructions:
            gadget.append(i)
            group = getGroup(i)
            seq = serializeInstructions(list(gadget))
            print("0x%x:\t%s\t%s [%d]" % (i.address, i.mnemonic, i.op_str, i.id))
            if group and seq not in d[group][0]:
                #printGadgets(gadgets)
                #print("Adding seq")
                d[group][0].add(seq)
                d[group][1].append(list(gadget))
                gadget = collections.deque([None]*roplen, roplen) #reset
                count += 1
                if count > MAX_GADGETS:
                    return d

    return d

def main():
    if len(sys.argv) < 2:
        print("Not enough arguments")
        printHelp()
        return 1

    with open(sys.argv[1], "rb") as f:
        data = f.read()

    gadgets = scan(MAX_GADGET_LEN, data)

    with open("gadgets.txt", "w") as f:
        for group, tup in gadgets.iteritems():
            gadgetList = tup[1]
            if len(gadgetList) <= 0:
                continue
            f.write("---------------------------------------------------------------------------\n")
            for g in gadgetList:
                baseAddr = None
                s = ""
                for i in g:
                    if i:
                        if not baseAddr:
                            baseAddr = i.address
                        s += " %s %s ;" % (i.mnemonic, i.op_str)
                        #s = "0x%x:\t%s\t%s\n" % (i.address, i.mnemonic, i.op_str)

                f.write("0x%x:" % baseAddr)
                f.write(s)
                f.write("\n")
            f.write("----------------------------------------------------------------------------\n")

    return 0

if __name__ == '__main__':
    sys.exit(main())
