import os, sys
import collections
import pprint
import re
import platform
from capstone import *
from capstone.x86 import *

MAX_GADGET_LEN = 8
MAX_GADGETS = 10000
MAX_INSTRUCTION_LEN = 11 #32 bytes
GADGET_TYPES = [X86_INS_RET, X86_INS_CALL]
BINARY_RET = "0xc3"

FILTER_INSTR = ["enter", "leave", ".byte"]
#we need gadgets to set these regs, and one to call syscall
REQUIRED_GADGETS = ["rax", "rdi", "rsi", "rdx"]

class GadgetList:
    def __init__(self, logfile):
        self.set = set()
        self.gadgets = dict()
        self.size = 0
        self.out = logfile
        self.useful_gadgets = dict()
        for t in GADGET_TYPES:
            self.gadgets[t] = list()

        for g in REQUIRED_GADGETS:
            self.useful_gadgets[g] = list()
        self.useful_gadgets["syscall"] = list()

    def serializeInstructions(self, gadget):
        seq = list()
        for i in gadget:
            if i: #skip None
                tup = (i.id, i.op_str)
                seq.append(tup)

        h = hash(tuple(seq))
        return h

    def addGadget(self, gadget, gadgetID):
        if self.size > MAX_GADGETS:
            print("[*] Exiting early- MAX_GADGETS found")
            sys.exit(1)

        seq = self.serializeInstructions(gadget)
        if seq not in self.set and gadgetID in GADGET_TYPES:
            while None in gadget: #remove Nones
                gadget.remove(None)

            self.logGadget(gadget)
            self.gadgets[gadgetID].append(gadget)
            self.set.add(seq)
            self.size += 1

            self.checkGadget(gadget);
            return True

        return False

    def checkGadget(self, gadget):
        for ind in range(0, len(gadget)):
            i = gadget[ind]
            g = list(gadget)[ind:] #only need part of this gadget
            seq = self.serializeInstructions(g)
            if seq in self.set:
                continue
            info = self.getGadgetInfo(g)
            if i.mnemonic == "pop" and i.op_str.lower() in REQUIRED_GADGETS:
                self.useful_gadgets[i.op_str.lower()].append(g)
                self.set.add(seq)
                print("[*] Found Gadget %s" % info)

            if i.mnemonic == "syscall" and ind+2 == len(gadget): #try to find just syscall ; ret
                self.useful_gadgets["syscall"].append(g)
                self.set.add(seq)
                print("[*] Found Gadget %s" % info)
                return
            #TODO add support for mov gadgets

    def logGadget(self, gadget):
        s = self.getGadgetInfo(gadget)
        if not s:
            return

        self.out.write(s)
        self.out.write("\n")

    def getGadgetInfo(self, gadget):
        baseAddr = None
        s = ""
        for i in gadget:
            if not baseAddr:
                baseAddr = i.address
            s += " %s %s ;" % (i.mnemonic, i.op_str)

        if not baseAddr:
            return None

        addr = "0x%x:" % baseAddr
        return addr + s

def printHelp():
    print("Usage: ropscan [binary]")

def instructionScan(roplen, data, instruction): #"0xc3"
    hex_data =  " ".join(hex(ord(n)) for n in data)
    #inds = [m.start() for m in re.finditer("0xc3", hex_data)]

    inds = []
    arr = hex_data.split(" ")
    for i in range(0, len(arr)):
        if arr[i] == instruction:
            inds.append(i)

    blob = MAX_INSTRUCTION_LEN * MAX_GADGET_LEN
    offsets = []
    for i in inds:
        offsets.append(i - blob)

    print("%d ret instructions found" % len(inds))
    '''
    prev = offsets[0]
    if prev < 0:
        prev = 0

    for i in range(0, len(inds)):
        if offsets[i] > 0:
            print("scan on data[%d:%d] (%d bytes)" % (prev, inds[i], len(data[prev:inds[i]+1])))
            #linearScan(roplen, data[prev:inds[i]+1]) #TODO wrong addresses b/c offsets are wrong...
            prev = offsets[i]
    '''

def linearScan(roplen, data):
    global gadgetList
    count = 0
    gadget = collections.deque([None]*roplen, roplen)
    arch = None
    if platform.architecture()[0] == "32bit":
        arch = CS_MODE_32
    elif platform.architecture()[0] == "64bit":
        arch = CS_MODE_64
    else:
        print("Cannot find platform architecture")
        sys.exit(1)

    md = Cs(CS_ARCH_X86, arch)
    md.skipdata = True
    #md.detail = True
    #start = int(0x340)

    addr = set()
    for offset in range(0,8): #instructions eventually converge
        print("Scan %d" % offset)
        instructions = md.disasm(data, offset)
        for i in instructions:
            if i.mnemonic in FILTER_INSTR or "j" in i.mnemonic: #filter jumps
                gadget = collections.deque([None]*roplen, roplen) #reset
                continue
            '''
            if i.mnemonic == "int" and i.op_str == "0x80" and i.address not in addr:
                print("\t[*] Found int 0x80: 0x%x" % i.address)
                addr.add(i.address)
            if (i.mnemonic == "sysenter" or i.mnemonic == "syscall") and i.address not in addr:
                print("\t[*] Found %s: 0x%x" % (i.mnemonic, i.address))
                addr.add(i.address)
            '''
            gadget.append(i)
            #print("0x%x:\t%s\t%s [%d]" % (i.address, i.mnemonic, i.op_str, i.id))
            if i.id in GADGET_TYPES:
                #print("\t[*] Found %s" % getGadgetInfo(gadget))
                if "0x" not in i.op_str and "[" not in i.op_str: #dont want call to have certain args
                    gadgetList.addGadget(gadget,i.id)
                gadget = collections.deque([None]*roplen, roplen) #reset

def main():
    global gadgetList

    if len(sys.argv) < 2:
        print("Not enough arguments")
        printHelp()
        return 1

    logfile = open("gadgets.txt", "w")
    gadgetList = GadgetList(logfile)

    with open(sys.argv[1], "rb") as f:
        data = f.read()

    instructionScan(MAX_GADGETS, data, BINARY_RET)
    linearScan(MAX_GADGET_LEN, data)

    gadgetList.out.close()

    print("Found %d Unique Gadgets" % gadgetList.size)
    return 0

if __name__ == '__main__':
    sys.exit(main())
