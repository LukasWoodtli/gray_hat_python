'''
Created on 15.09.2011

@author: luki
'''
from pydbg import *
from pydbg.defines import *

import threading
import time
import sys

class snapshotter(object):
  
  def __init__(self,exe_path):
    
    self.exe_path   = exe_path
    self.pid        = None
    self.dbg        = None
    self.running    = True
    
    # Debugger-Threadd starten und warten,bis die PID des
    # Zielprozesses gesetzt wurde
    pydbg_thread = threading.Thread(target=self.start_debugger)
    pydbg_thread.setDaemon(0)
    pydbg_thread.start()
    
    while self.pid == None:
      time.sleep(1)
      
    # Wir besitzen nun eine PID und der Zielprocess l�uft.
    # Wir starten einen zweiten Thread, der den Schnappschuss vornimmt.
    monitor_thread = threading.Thread(target=self.monitor_debugger)
    monitor_thread.setDaemon(0)
    monitor_thread.start()
    
  
  def monitor_debugger(self):
    
    while self.running == True:
      
      input = raw_input("Enter: 'snap', 'restore' or 'quit'")
      input = input.lower().strip()
      
      if input == "quit":
        print "[*] Exiting the snapshotter."
        self.running = False
        self.dbg.terminate_process()
        
      elif input == 'snap':
        print "[*] Suspending all threads."
        self.dbg.suspend_all_threads()
    
        print "[*] Obtaining snapshot."
        self.dbg.process_snapshot()
    
        print "[*] Resuming operation."
        self.dbg.resume_all_threads()
        
      elif input == "restore":
        print "[*] Suspending all threads."
        self.dbg.suspend_all_threads()
    
        print "[*] Restoring snapshot."
        self.dbg.process_restore()
    
        print "[*] Resuming operation."
        self.dbg.resume_all_threads()
        
  
  def start_debugger(self):
    self.dbg = pydbg()
    pid = self.dbg.load(self.exe_path)
    self.pid = self.dbg.pid
    
    self.dbg.run()
    
exe_path = "C:\\Windows\\System32\\calc.exe"
snapshotter(exe_path)
  