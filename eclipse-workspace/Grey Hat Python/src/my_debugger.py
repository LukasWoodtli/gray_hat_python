'''
Created on 13.07.2011

@author: luki
'''

from ctypes import *
from my_debugger_defines import *

kernel32 = windll.kernel32

class debugger():
    def __init__(self):
        self.h_process          = None
        self.pid                = None
        self.debugger_active    = False
        self.h_thread           = None
        self.context         =     None
        
    
    def load(self, path_to_exe):
        #...
        creation_flags = DEBUG_PROCESS
        
        startupinfo = STARTUPINFO()
        process_information = PROCESS_INFORMATION()
        
        startupinfo.dwFlags     = 0x1
        startupinfo.wShowWindow = 0x0
        
        startupinfo.cb = sizeof(startupinfo)
        
        if kernel32.CreateProcessA(path_to_exe,
                                   None,
                                   None,
                                   None,
                                   None,
                                   creation_flags,
                                   None,
                                   None,
                                   byref(startupinfo),
                                   byref(process_information)):
            
            print "[*] We have successfully launched the process!"
            print "[*] PID: %d" % process_information.dwProcessId
            
            # Handle vom erzeugten prozess
            self.pid = process_information.dwProcessId
            self.h_process = self.open_process(self,process_information.dwProcessId)
            self.debugger_active = True

        else:
            print "[*] Error: 0x%08x." % kernel32.getLastError()
            
        
    def open_process(self, pid):
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        return h_process
    
    def attach(self, pid):
        self.h_process = self.open_process(pid)
        
        if kernel32.DebugActiveProcess(pid):
            self.debugger_active    = True
            self.pid                = int(pid)
                       
        else:
            print "[*] Unable to attach to the process."
            
    def run(self):
        while self.debugger_active == True:
            self.get_debug_event()
            
    def get_debug_event(self):
        debug_event         = DEBUG_EVENT()
        continue_status     = DBG_CONTINUE
        
        if kernel32.WaitForDebugEvent(byref(debug_event), 100):
            #dummy
            # raw_input("Press a key to continue...")
            # self.debugger_active    = False
            
            kernel32.ContinueDebugEvent( \
                         debug_event.dwProcessId, \
                         debug_event.dwThreadId, \
                         continue_status)

    def detach(self):
        if kernel32.DebugActiveProcessStop(self.pid):
            print "[*] Finished debugging. Exiting..."
            return True
        
        else:
            print "There was an error."
            return False
        
    def open_thread(self, thread_id):
        h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, None, thread_id)
        
        if h_thread is not None:
            return h_thread
        
        else:
            print "[*] Could not obtain a valid thread handle."
            return False
        
    def enumerate_threads(self):
        thread_entry = THREADENTRY32()
        thread_list = []
        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, self.pid)
        
        if snapshot is not None:
            # muss Groesse der Struktur enthalten
            thread_entry.dwSize = sizeof(thread_entry)
            
            success = kernel32.Thread32First(snapshot, byref(thread_entry))
            
            while success:
                if thread_entry.th32OwnerProcessID == self.pid:
                    thread_list.append(thread_entry.th32ThreadID)
                success = kernel32.Thread32Next(snapshot, byref(thread_entry))
                    
            kernel32.CloseHandle()
            return thread_list
        
        else:
            return False
        
    def get_thread_context(self, thread_id=None, h_thread=None):
        
        context = CONTEXT()
        context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS
        
        if h_thread is None:
            self.h_thread = self.open_thread(thread_id)
        
        if kernel32.GetThreadContext(h_thread, byref(context)):
            kernel32.CloseHandle(h_thread)
            return context
        else:
            return False
        
            
        