# -*- coding: utf-8 -*-
"""
Created on Sat Sep 17 22:57:08 2011

@author: luki
"""

import immlib

def main(args):
    
    imm         = immlib.Debugger()
    search_code = " ".join(args)
    
    search_bytes    = imm.assemble(search_code)
    search_results  = imm.search(search_bytes)
    
    for hit in search_results:
        
        # Speicherseite des Treffers ermitteln und
        # sicherstellen, dass sie ausführbar ist
        code_page       = imm.getMemoryPageByAddress(hit)
        access          = code_page.getAccess(human=True)
        
        if "execute" in access.lower():
            imm.log("[*] Found: %s (0x%08x)" % (search_code, hit), 
                    address = hit)
    return "[*] Finished searchig for the instructions, check the Log window."
    