#!/usr/bin/python3
# -----------------------------------------------------------------------------
# Mnemonics.py
# Dictionnaries of x86 opcodes and their corresponding mnemonics. Will be used
# in other modules.
# Author: Eval (@cyberjucou)
# -----------------------------------------------------------------------------

OPCODES = {
    0x89: 'MOV r/m32,r32',    # Move r16(or 32) to r/m16(or 32).
    0x8B: 'MOV r32,r/m32',    # Move r/m16 to r16.
    0xB8: 'MOV r32,imm32',    # Move imm16(or 32) to r16(or 32).
    0xC7: 'MOV r/m32,imm32',  # Move imm16(or 32) to r/m16(or 32).
    0x58: 'POP r32',          # Pop top of stack into r32; incr SP.
    0x59: 'POP r32',
    0x5A: 'POP r32',
    0x5B: 'POP r32',
    0x5C: 'POP r32',
    0x5D: 'POP r32',
    0x5E: 'POP r32',
    0x5F: 'POP r32',
    0xC3: 'RET',
}
