'''
Created on 13.07.2011

@author: luki
'''

from ctypes import *
from my_debugger_defines import *

kernel32 = windll.kernel32

class debugger():
    def __init__(self):
        self.h_process              = None
        self.pid                    = None
        self.debugger_active        = False
        self.h_thread               = None
        self.context                = None
        self.exception              = None
        self.exception_address      = None
        self.breakpoints            = {}
        self.first_breakpoint       = True
        self.hardware_breakpoints   = {}
        self.guarded_pages          = []
        self.memory_breakpoints     = {}
        # Hier bestimmen und speichern wir die
        # Standardseitengroesse des Systems
        system_info = SYSTEM_INFO()
        kernel32.GetSystemInfo(byref(system_info))
        self.page_size = system_info.dwPageSize 
    
    def load(self, path_to_exe):
        
        # dwCreation flag determines how to create the process
        # set creation_flags = CREATE_NEW_CONSOLE if you want
        # to see the calculator GUI
        creation_flags = DEBUG_PROCESS
        
        # instantiate the structs
        startupinfo = STARTUPINFO()
        process_information = PROCESS_INFORMATION()
        
        # The following two options allow the started process
        # to be shown as a separate window. This also illustrates
        # how different settings in the STARTUPINFO struct can affect
        # the debuggee.
        startupinfo.dwFlags     = 0x1
        startupinfo.wShowWindow = 0x0
        
        # We then initialize the cb variable in the STARTUPINFO struct
        # which is just the size of the struct itself
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
        
        # We attempt to attach to the process
        # if this fails we exit the call
        if kernel32.DebugActiveProcess(pid):
            self.debugger_active    = True
            self.pid                = int(pid)
                       
        else:
            print "[*] Unable to attach to the process."
            
    def run(self):
        
        # Now we have to poll the debuggee for 
        # debugging events           
        while self.debugger_active == True:
            self.get_debug_event()
            
    def get_debug_event(self):
                       
        debug_event         = DEBUG_EVENT()
        continue_status     = DBG_CONTINUE
        
        if kernel32.WaitForDebugEvent(byref(debug_event),100):
            # grab various information with regards to the current exception.
            self.h_thread          = self.open_thread(debug_event.dwThreadId)
            self.context           = self.get_thread_context(h_thread=self.h_thread)
            self.debug_event       = debug_event
            
            print "Event code: %d Thread ID: %d" % (debug_event.dwDebugEventCode, debug_event.dwThreadId)
            
            if debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
                self.exception = debug_event.u.Exception.ExceptionRecord.ExceptionCode
                self.exception_address = debug_event.u.Exception.ExceptionRecord.ExceptionAddress
                
                # call the internal handler for the exception event that just occured.
                if self.exception == EXCEPTION_ACCESS_VIOLATION:
                    print "Access Violation Detected."
                elif self.exception == EXCEPTION_BREAKPOINT:
                    continue_status = self.exception_handler_breakpoint()
                    
                elif self.exception == EXCEPTION_GUARD_PAGE:
                    print "Guard Page Access Detected."
                    
                elif self.exception == EXCEPTION_SINGLE_STEP:
                    self.exception_handler_single_step()
                    
            kernel32.ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, continue_status)

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
                    
            # No need to explain this call, it closes handles
            # so that we don't leak them.
            kernel32.CloseHandle(snapshot)
            return thread_list
        
        else:
            return False
        
    def get_thread_context(self, thread_id=None, h_thread=None):
        
        context = CONTEXT()
        context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS
        
        # Obtain a handle to the thread
        if h_thread is None:
            self.h_thread = self.open_thread(thread_id)
        
        if kernel32.GetThreadContext(self.h_thread, byref(context)):
            kernel32.CloseHandle(h_thread)
            return context
        else:
            return False
        
    def read_process_memory(self,address,length):
        
        data         = ""
        read_buf     = create_string_buffer(length)
        count        = c_ulong(0)
        
        
        kernel32.ReadProcessMemory(self.h_process, address, read_buf, 5, byref(count))
        data    = read_buf.raw
        
        return data
    
    
    def write_process_memory(self,address,data):
        
        count  = c_ulong(0)
        length = len(data)
        
        c_data = c_char_p(data[count.value:])

        if not kernel32.WriteProcessMemory(self.h_process, address, c_data, length, byref(count)):
            return False
        else:
            return True
    
    def bp_set(self,address):
        print "[*] Setting breakpoint at: 0x%08x" % address
        if not self.breakpoints.has_key(address):

            # store the original byte
            old_protect = c_ulong(0)
            kernel32.VirtualProtectEx(self.h_process, address, 1, PAGE_EXECUTE_READWRITE, byref(old_protect))
            
            original_byte = self.read_process_memory(address, 1)
            if original_byte != False:
                
                # write the INT3 opcode
                if self.write_process_memory(address, "\xCC"):
                    
                    # register the breakpoint in our internal list
                    self.breakpoints[address] = (original_byte)
                    return True
            else:
                return False

    def exception_handler_breakpoint(self):
        print "[*] Exception address: 0x%08x" % self.exception_address
        # check if the breakpoint is one that we set
        if not self.breakpoints.has_key(self.exception_address):
        
                # if it is the first Windows driven breakpoint
                # then let's just continue on
                if self.first_breakpoint == True:
                   self.first_breakpoint = False
                   print "[*] Hit the first breakpoint."
                   return DBG_CONTINUE
        
        else:
            print "[*] Hit user defined breakpoint."
            # this is where we handle the breakpoints we set 
            # first put the original byte back
            self.write_process_memory(self.exception_address, self.breakpoints[self.exception_address])

            # obtain a fresh context record, reset EIP back to the 
            # original byte and then set the thread's context record
            # with the new EIP value
            self.context = self.get_thread_context(h_thread=self.h_thread)
            self.context.Eip -= 1
   
            kernel32.SetThreadContext(self.h_thread,byref(self.context))

            continue_status = DBG_CONTINUE


        return continue_status

    def func_resolve(self,dll,function):
        
        handle  = kernel32.GetModuleHandleA(dll)
        address = kernel32.GetProcAddress(handle, function)
        
        kernel32.CloseHandle(handle)

        return address
        
        
        
    def bp_set_hw(self, address, length, condition):
        
        # Auf gueltige Laenfge pruefen
        if length not in (1, 2, 4):
            return False
        else:
            length -= 1
            
        # Auf gueltige Bedingung pruefen
        if condition not in (HW_ACCESS, HW_EXECUTE, HW_WRITE):
            return False
        
        # Freien Platz bestimmen
        if not self.hardware_breakpoints.has_key(0):
            available = 0
        elif not self.hardware_breakpoints.has_key(1):
            available = 1
        elif not self.hardware_breakpoints.has_key(2):
            available = 2
        elif not self.hardware_breakpoints.has_key(3):
            available = 3
        else:
            return False
        
        # Wir setzten die Debug-Register in jedem Thread
        for thread_id in self.enumerate_threads():
            context = self.get_thread_context(thread_id=thread_id)
            
            if not context:
                return False
            
            # Wir aktivieren das entsprechende Bit im DR7-Register,
            # um den Breakpoint zu setzen.
            context.Dr7 |= 1 << (available * 2)
  
            # Adresse des Breakpoints im gefundenen freien Registr speichern
            if available == 0:
                context.Dr0 = address
            elif available == 1:
                context.Dr1 = address
            elif available == 2:
                context.Dr2 = address
            elif available == 3:
                context.Dr3= address    
            
            # Breakpunkt Bedingung setzen
            context.Dr7 |= condition << ((available * 4) + 16)
            
            # Laenge setzen
            context.Dr7 |= length << ((available * 4) + 18)
            
            # Threadcontext mit aktiviertem Breakpoint setzen
            h_thread = self.open_thread(thread_id)
            kernel32.SetThreadContext(h_thread, byref(context))
            
        # Internes Hardware-Breakpoint-Array am verwendeten Index setzen
        self.hardware_breakpoints[available] = (address, length, condition)
            
        return True 
            
            
    def exception_handler_single_step(self):
        print "[*] Exception address: 0x%08x" % self.exception_address
        # Comment from PyDbg:
        # determine if this single step event occured in reaction to a hardware breakpoint and grab the hit breakpoint.
        # according to the Intel docs, we should be able to check for the BS flag in Dr6. but it appears that windows
        # isn't properly propogating that flag down to us.
        if self.context.Dr6 & 0x1 and self.hardware_breakpoints.has_key(0):
            slot = 0
        elif self.context.Dr6 & 0x2 and self.hardware_breakpoints.has_key(1):
            slot = 0
        elif self.context.Dr6 & 0x4 and self.hardware_breakpoints.has_key(2):
            slot = 0
        elif self.context.Dr6 & 0x8 and self.hardware_breakpoints.has_key(3):
            slot = 0
        else:
            # Dies war kein durch einen HW-Breakpoint generierter INT1
            continue_status = DBG_EXCEPTION_NOT_HANDLED
        
        # Nun entfernen wir den Breakpoint aus der Liste
        if self.bp_del_hw(slot):
            continue_status = DBG_CONTINUE
            
        print "[*] Hardware Breakpoint entfernt"
        return continue_status
    
    def bp_del_hw(self, slot):
        # Breakpoint fuer alle aktiven Threads deaktivieren
        for thread_id in self.enumerate_threads():
            context = self.get_thread_context(thread_id=thread_id)
            
            # Zum entfernen des Breakpoints die Flags zuruecksetzen
            context.Dr7 &= ~(1 << (slot * 2))
            
            # Adresse mit Nullen fuellen
            if slot == 0:
                context.Dr0 = 0x00000000
            elif slot == 1:
                context.Dr1 = 0x00000000
            elif slot == 2:
                context.Dr2 = 0x00000000
            elif slot == 3:
                context.Dr3 = 0x00000000
                
            # Bedingngsflag entfernen
            context.Dr7 &= ~(3 << ((slot * 4) + 16))
            
            # Laengenflag entfernen
            context.Dr7 &= ~(3 << ((slot * 4) + 18))
            
            # Threadcontext mit entferntem Breakpoint zuruecksetzen
            h_thread = self.open_thread(thread_id)
            kernel32.SetThreadContext(h_thread,byref(context))
            
        # Breakpoint aus der internen Liste entfernen
        del self.hardware_breakpoints[slot]
        
        return True
            
        
    def bp_set_mem(self, address, size):
        
        mbi = MEMORY_BASIC_INFORMATION()
        
        # Liefert unser VirtualQueryEx()-Aufruf keine vollstaendige
        # MEMORY_BASIC_INFORMATION, dann geben wir False zurueck
        if kernel32.VirtualQueryEx(self.h_process, address, byref(mbi), sizeof(mbi)) < sizeof(mbi):
            return False
        
        current_page = mbi.BaseAddress
        
        # Wir setzten die Rechte bei allen Seiten, die vin unserem
        # Speicher-Breakpoint betroffen sind.
        while current_page <= address + size:
            
            # Seite in die Liste einfuegen. Damit unterscheiden wir die durch
            # uns gesetzten Guard-Pages von denen, die durch das Betriebssystem 
            # oder vom Prozess selbst gesetzt wurden.
            self.guarded_pages.append(current_page)
            
            old_protection = c_ulong(0)
            if not kernel32.VirtualProtectEx(self.h_process, current_page, size,
                                             mbi.Protect | PAGE_GUARD,
                                             byref(old_protection)):
                return False
            
            # Bereich um die Groesse der Standardspeicherseite erhoehen
            current_page += self.page_size
        
        # Speicher Breakpoint in unsere globale Liste eintragen
        self.memory_breakpoints[address] = (address, size, mbi)
        
        return True
    
        
        