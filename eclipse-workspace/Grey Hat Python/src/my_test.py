'''
Created on 16.07.2011

@author: luki
'''
import my_debugger

debugger = my_debugger.debugger()

#debugger.load("C:\\WINDOWS\\system32\\calc.exe")

pid = raw_input("Enter the PID of the process to attach to: ")

debugger.attach(int(pid))

list = debugger.enumerate_threads()

for thread in list:
    thread_context = debugger.get_thread_context(thread)

#...
    print "[**] EIP: 0x%08x" % thread_context.Eip
    




#debugger.run()

debugger.detach()

