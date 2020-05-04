# coding: utf-8
#run as: ipython -i solve.py
#assuming venv python3, pip install angr ubuntu 18.04 system
import angr, claripy

#functions hooked as SimProcedures
from angr.procedures.libc.scanf import scanf
from angr.procedures.libc.printf import printf
from angr.procedures.libc.exit import exit 
from angr.procedures.libc.malloc import malloc

#addresses in solution:
#--------------------------------------------------#
#address we want to enter to, skipping all annoying go setup
main_addr = 0x0049d7d0

#goal_addr, hopefully we can reach the win function and have a correct solution
win_addr = 0x49d730

#skip some go  functions/addresses:
#rutime.morestack = 0x00459ca0
skipping  = [0x00459ca0]

#--------------------------------------------------#

#setup angr project
#the binary is a 64-bit golang binary, and not terribly obfuscated, and statically linked
#if the binary fails the original code is here, and can be compiled with the makefile
#assuming the system has a go compiler:
# https://github.com/b01lers/b01lers-ctf-2020/blob/master/rev/100_chugga_chugga/chugga.go
p = angr.Project('./chugga', main_opts={'entry_point': main_addr})

#--------------------------------------------------#
#sim procedure to skip over avoiding functions
class skip(angr.SimProcedure):
    def run(self):
        return

for x in skipping:
    p.hook(x, skip())

#mallocing stuff
#runtime.newobject = 0x0040bc60
#runtime.convt = 0x004092e0
mallocd = (0x0040bc60, 0x004092e0)

for m in mallocd:
    p.hook(m, malloc())
	

# simProcedures to simulate I/O
#runtime.println = 0x00491920 => printf  (no new lines, but meh)
#runtime.Fscan = 0x00497d50 => scanf
#runtime.panicIndex  = 0x045c4f0 => exit, may need to do errors
#main.win = win_addr => PRINT WIN, we did it
p.hook(0x00491920,printf())
p.hook(0x00497d50,scanf())
p.hook(0x045c4f0,exit())
#--------------------------------------------------#

#input length: 
in_len = 23

#looking at the code/binary, we can tell the input string is expected to fill 22 bytes,
# thus the 8 byte symbolic size. Hopefully we can find the constraints the binary
# expects during symbolic execution
flag_chars = [claripy.BVS('flag_%d' % i, 8) for i in range(in_len)]
flag = claripy.Concat(*flag_chars + [claripy.BVV(b'\n')]) #adding newline to secure ending


# enable unicorn engine for fast efficient solving
# running with LAZY_SOLVES option
st = p.factory.entry_state(
        add_options=angr.options.unicorn,
        stdin=flag
)

#avoid needless golang calls
st.options.add(angr.options.CALLLESS)

#constrain to non-newline bytes
#constrain to ascii-only characters (as a guess)
for k in flag_chars:
    st.solver.add(k != 10)
    st.solver.add(k < 0x7f)
    st.solver.add(0x20 < k)

#add some more costraints
st.solver.add(flag_chars[0] == ord('p'))
st.solver.add(flag_chars[1] == ord('c'))
st.solver.add(flag_chars[2] == ord('t'))
st.solver.add(flag_chars[3] == ord('f'))
st.solver.add(flag_chars[9] == ord('c'))
st.solver.add(flag_chars[16] == ord('n'))
st.solver.add(flag_chars[21] == ord('z'))
st.solver.add(flag_chars[22] == ord('}'))

# Construct a SimulationManager to perform symbolic execution.
# Step until there is nothing left to be stepped.
sm = p.factory.simulation_manager(st)

# goal address, hopefully it can reach the win_addr
goal_addr = win_addr
#sm.explore(find=goal_addr)
