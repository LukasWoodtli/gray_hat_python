'''
Created on 16.07.2011

@author: luki
'''
import my_debugger

debugger = my_debugger.debugger()

#debugger.load("C:\\WINDOWS\\system32\\calc.exe")

pid = raw_input("Enter the PID of the process to attach to: ")

debugger.attach(int(pid))

debugger.run()


# list = debugger.enumerate_threads()

# for thread in list:
    # thread_context = debugger.get_thread_context(thread)

# #...
    # print "[*] Dumping registers for thread ID 0x%08x" % thread
    # print "[**] EIP: 0x%08x" % thread_context.Eip
    # print "[**] ESP: 0x%08x" % thread_context.Esp
    # print "[**] EBP: 0x%08x" % thread_context.Ebp
    # print "[**] EAX: 0x%08x" % thread_context.Eax
    # print "[**] EBX: 0x%08x" % thread_context.Ebx
    # print "[**] ECX: 0x%08x" % thread_context.Ecx
    # print "[**] EDX: 0x%08x" % thread_context.Edx
    # print "[*] End Dump."
    
debugger.detach()






