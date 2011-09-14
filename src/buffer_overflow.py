'''
Created on 14.09.2011

@author: luki
'''

from ctypes import *

msvcrt = cdll.msvcrt

# Debugger Zeit zum Ankoppeln geben und dann eine Taste drücken
raw_input("Once the debugger is attached, press any key.")

# Den 5-Byte-Zielpuffer erzeugen
buffer = c_char_p("AAAAA")

# Der Überlaufstring
overflow = "A" * 100

# Überlauf ausführen
msvcrt.strcpy(buffer, overflow)
