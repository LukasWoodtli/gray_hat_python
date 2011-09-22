# -*- coding: utf-8 -*-
"""
Created on Mon Sep 19 21:58:30 2011

@author: luki
"""

import immlib
import immutils

# Diese Funktion sucht nach dem richtigen Basisblock,
# der die richtige ret-Instruktion enthält. Sie wird
# genutzt, um den richtigen Hook-Punkt für RtlAllocateHeap
# zu finden.
def getRet(imm, allocaddr, max_opcodes = 300):
    addr = allocaddr
    for a in range(0, max_opcodes):
        op = imm.disasmForward( addr )

        if op.isRet():
            if op.getImmConst() == 0xC:
                op = imm.disasmBackward( addr, 3)                   
                return op.getAddress()
        addr = op.getAddress()
    
    return 0x0
    
# Ein einfacher Wrapper, der die Hook-Ergebnisse auf 
# nette Art ausgibt. Er vergleicht einfach die 
# Hook-Addresse mit den gespeicherten Addressen für
# RtlAllocateHeap und RtlFreeHeap
def showresult(imm, a, rtlallocate, extra = ""):
    if a[0] == rtlallocate:
        imm.log("RtlAllocateHeap(0x%08x, 0x%08x, 0x%08x) <- 0x%08x %s" %
        (a[1][0], a[1][1], a[1][2], a[1][3], extra), address = a[1][3])
        
        return "done"
    
    else:
        imm.log("RtlFreeHeap(0x%08x, 0x%08x, 0x%08x)" % 
        a[1][0], a[1][1], a[1][2])
        

def main(args):

    imm          = immlib.Debugger()
    Name         = "hippie"

    fast = imm.getKnowledge( Name )
    if fast:
        # Wir haben bereits Hooks fesetzt, d.h., wir
        # wollen nun die Ergebnisse ausgeben.
        hook_list = fast.getAllLog()
        
        rtallocate, rtlfree = imm.getKnowledge("FuncNames")
        for a in hook_list:
            ret = showresult( imm, a, rtlallocate )
        
        return "Logged: %d hook hits. Results output to log window." % len(hook_list)
        
    # Wir halten den Debugger an bevor wir herumspielen
    imm.pause()
    rtlfree     = imm.getAddress("ntdll.RtlFreeHeap")
    rtlallocate = imm.getAddress("ntdll.RtlAllocateHeap")

    module = imm.getModule("ntdll.dll")
    if not module.isAnalysed():
        imm.analyseCode( module.getCodebase() )
     
    # Wir suchen den richtigen Exit-Punkt der Funktion
    rtlallocate = getRet( imm, rtlallocate, 1000 )
    imm.log("RtlAllocateHeap hook: 0x%08x" % rtlallocate)
   
    # Die Hook-Punkte speichern
    imm.addKnowledge("FuncNames",  ( rtlallocate, rtlfree ) )
    
    # Nun beginnen wir damit, den Hook aufzubauen
    fast = immlib.STDCALLFastLogHook( imm )
    
    # Wir fangen RtlAllocateHeap am Ende der Funktion ab
    imm.log("Logging on Alloc 0x%08x" % rtlallocate)
    fast.logFunction( rtlallocate )
    fast.logBaseDisplacement( "EBP",    8)
    fast.logBaseDisplacement( "EBP",  0xC)
    fast.logBaseDisplacement( "EBP", 0x10)
    fast.logRegister( "EAX" )      
    
    # Wir fangen RtlFreeHeap zu Beginn der Funktion ab
    imm.log("Logging on RtlFreeHeap 0x%08x" % rtlfree)
    fast.logFunction( rtlfree, 3 )
    
    # Den Hook setzen
    fast.Hook()
    
    # Das Hook-Objekt speichern, damit wir die Ergebnisse später
    # abrufen können
    imm.addKnowledge(Name, fast, force_add = 1)
    
    return "Hooks set, press F9 to continue the process."