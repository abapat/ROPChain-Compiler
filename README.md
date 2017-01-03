# ROP Chain Compiler

The ROP Chain Compiler is a simple script to analyze a binary for
certain gadgets and chain them together to give execute permissions to
second stage shellcode. It will return a raw payload consisting of
memory addresses of the scanned binary followed by shellcode to open up
a command shell. This payload is introduced to vulnerable programs to
trigger a buffer overflow and redirect control flow to the gadget chain.
A proof of concept example is also included in this repo.

# Compiling and Running

Currently, the ROP Chain Compiler only supports scanning for 64-bit binaries.

## Prerequites
    - Capstone Disassembly Framework
      (http://www.capstone-engine.org/download.html)

## Running

To run the ROP Chain Compiler, simply run:
ropscan.py \[binary\] \[binary base address\] \[shellcode address\]

To compile the vulnerable binary, a makefile is also included (run make)

It is left to the user to find the base address the binary will be loaded
in and which address the shellcode will be in. To find the base address
of the binary (assuming ASLR is off), readelf and ldd are useful linux
commands to analyze a binary and its loaded libraries (libc will contain
many useful gadgets!). Another way is to run the binary with gdb and
check /proc/\<pid\>/mappings for the exact location a library is loaded.
To find the address the shellcode is loaded requires knowledge of where
the buffer overflow occurs, which can be found with gdb.

Alternatively, the GadgetScanner class can be used when importing the
ropscan script, like in payloadtester.py. The payloadtester.py script is
a hacky, proof of concept that will figure out the base address and run
the binary with the payload returned from the scanner.

If an appropriate ROP chain could not be found, a log file "gadgets.txt"
will contain any "useful" gadgets found during the scans.

## Demo

To test the functionality of the scanner, a binary with a buffer
overflow vulnerability is included. The buffer overflow occurs on
read(), so null bytes (from addresses) are acceptable in the payload. The
vulnerable binary will read the file "in.txt", so our payload will be
placed here. There will be 24 bytes of junk/padding, which will
overwrite everything up to the return address. Then, the payload of the
scanner will be added (to redirect execution to the gadgets), and
finally the NOP sled (~20 bytes) and shellcode, as shown in the main
method in ropscan.py. When the binary is run with this input, the ROP
chain will call mprotect to give execute privileges on the stack
(bypassing Data Execution Prevention, DEP) and return to the shellcode,
opening up a bash shell.

The script was tested on 64-bit Ubuntu 16.04

# "Compiling" the ROP Chain

To compile a ROP Chain that calls mprotect() syscall, certain registers
(rax, rdi, rsi, rdx) will need to be set. The scanner follows a
simplistic approach by searching for "pop ; ret" instructions to set the
registers properly. It will also search for "syscall ; ret" gadget to
invoke the interupt handler and call the syscall.

Other types of instructions to craft the ROP payload such as xor, add, mov,
and call may be included in a later update. For libc, there were enough
"pop ; ret" gadgets to be scanned to create the chain.

## Scanning for Gadgets

To find the right gadgets quickly and efficiently, the binary is
searched for all "ret" instructions (0xc3). For each instruction found,
we try dissassembling "backwards": start scanning the section of the
binary ending in a ret instruction at different offsets. In this way,
each scan may yield a different gadget, as x86 has a variable length
instruction set. After each scan, we check if we have enough "useful"
gadgets to set our registers and return out if the chain can be
compiled.

When scanning for gadgets, certain instructions are filtered out that
might complicate the ROP chain by affecting the stack: enter, leave,
push, .byte, and any branch instructions. .byte is a special instruction
set by capstone if the dissasembly lead to an invalid instruction. We
also filter "[]" to avoid any complications with dereferencing
registers. In this way, the ROP chain is simpler and guaranteed to set
the registers it needs properly. A "useful" gadget is one that is able
to set a register and passes the filter.

## Putting the ROP chain together

Once all gadgets have been found, an appropriate ROP chain will need to
be assembled. First, simple gadgets of length 2 (pop ; ret) are used at
the end of the chain, as they do not trash any other registers. For the
other instructions, it checks if any important registers are clobbered
between the pop and ret calls, and if not, they are added in the
beginning of the chain. Finally, the "syscall ; ret" gadget and address
of the shellcoded is added at the end of the chain. If all is well, the
ROP chain will contain the addresses of the gadgets which will call
mprotect(). If the chain could not be crafted, a log file "gadgets.txt"
will contain any useful gadgets found, for manual inspection.

