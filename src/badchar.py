# -*- coding: utf-8 -*-
"""
Created on Sat Sep 17 22:57:08 2011

@author: luki
"""

import immlib

def main(args):
    
    imm         = immlib.Debugger()
    
    bad_char_found   = False

    # Erstes argument ist die Startadresse der Suche
    address     = int(args[0],16)
    
    # Zu prüfender Shell-Code
    shellcode           = "\xcc\xcc\xcc\xcc"
    shellcode_length    = len(shellcode)
    
    debug_shellcode     = imm.readMemory(address, shellcode_length)
    debug_shellcode     = debug_shellcode.encode("HEX")
    
    imm.log("Address: 0x%08x" % address)
    imm.log("Shellcode Length: %d" % shellcode_length)    
    
    imm.log("Attack Shellcode: %s"    % shellcode[:512])
    imm.log("In Memory Shellcode: %s" % debug_shellcode[:512])
  
    # Byte-für-Byte vergleich der beiden shellcodes
    count = 0
    while count < shellcode_length: #count <= shellcode_length:
        if debug_shellcode[count] == shellcode[count]:
            imm.log("Bad Char Detected at offset %d" % count)
            bad_char_found = True
            break
        
        count += 1
    
    if bad_char_found:
        imm.log("[*****] ")
        imm.log("Bad character found: %s" % debug_shellcode[count])
        imm.log("Bad character original: %s" % shellcode[count])
        imm.log("[*****] ")
    
    return "[*] !badchar finished, check Log window."
    