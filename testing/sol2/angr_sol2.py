#!/usr/bin/env python
# coding: utf-8
import angr
import claripy
import time
import logging

#enable/disable logging
logging.getLogger('angr.manager').setLevel(logging.DEBUG)



#solve chugga challenge
def main():
    #setup angr project
    #the binary is a 64-bit golang binary, and not terribly obfuscated, and statically linked
    #if the binary fails the original code is here, and can be compiled with the makefile
    #assuming the system has a go compiler: 
    # https://github.com/b01lers/b01lers-ctf-2020/blob/master/rev/100_chugga_chugga/chugga.go
    p = angr.Project('./engine')

    #looking at the code/binary, we can tell the input string is expected to fill 22 bytes,
    # thus the 8 byte symbolic size. Hopefully we can find the constraints the binary 
    # expects during symbolic execution
    flag_chars = [claripy.BVS('flag_%d' % i, 8) for i in range(75)]
    flag = claripy.Concat([claripy.BVV(b'\n')] + *flag_chars + [claripy.BVV(b'\n')])

    # enable unicorn engine for fast efficient solving 
    # running with LAZY_SOLVES option
    st = p.factory.entry_state(
            add_options=angr.options.unicorn,
            stdin=flag
    )

    #constrain to non-newline bytes
    #constrain to ascii-only characters (as a guess)
    for k in flag_chars:
        st.solver.add(k != 10)
        st.solver.add(k < 0x7f)
        st.solver.add(0x20 < k)


    # Construct a SimulationManager to perform symbolic execution.
    # Step until there is nothing left to be stepped.
    sm = p.factory.simulation_manager(st)

    #we need to define our address we want to reach, so angr can finish faster
    #via: objdump -d ./chugga | grep -i win
    #win_addr = 0x49d730

    #explore looking for any input which reaches the win function
    sm.run()

    # investigate states for valid addresses

    #for any state reaching the win function return the input
    #it should be our flag
    return final

def test():
    assert main() == b'flag{dr4g0n_or_p4tric1an_it5_LLVM}'

if __name__ == "__main__":
    before = time.time()
    print(main())
    after = time.time()
    print("Time elapsed: {}".format(after - before))
