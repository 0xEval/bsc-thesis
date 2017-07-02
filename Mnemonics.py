#!/usr/bin/python3
# -----------------------------------------------------------------------------
# Mnemonics.py
# Dictionnaries of x86 opcodes and their corresponding mnemonics. Will be used
# in other modules.
# Author: Eval
# GitHub: https://github.com/jcouvy
# -----------------------------------------------------------------------------

OPCODES = {
    0x89: 'MOV r/m32,r32',    # Memory WRITE (or register move) w/ 32bits regs
    0xC7: 'MOV r/m32,imm32',  # Memory WRITE from an imm value
    0xC705: 'MOV r/m32,imm32',  # mov dword ptr ds:0x(...), imm32
    0xB8: 'MOV r/m32,imm32',  # mov eax, 0x(...)
    0xBB: 'MOV r/m32,imm32',  # mov ebx, 0x(...)
    0xB9: 'MOV r/m32,imm32',  # mov ecx, 0x(...)
    0xBA: 'MOV r/m32,imm32',  # mov edx, 0x(...)

    0x8B: 'MOV r32,r/m32',    # Memory READ w/ 32bits registers.
    0xA1: 'MOV r32,imm32',    # mov eax, ds:0x0
    0x8B1D: 'MOV r32,imm32',  # mov ebx, ds:0x0
    0x8B0D: 'MOV r32,imm32',  # mov ecx, ds:0x0
    0x8B15: 'MOV r32,imm32',  # mov edx, ds:0x0

    0xA3: 'MOV imm32,r32',    # mov ds:0x0, eax

    0x58: 'POP r32',          # Pop top of stack into r32; incr SP.
    0x59: 'POP r32',
    0x5A: 'POP r32',
    0x5B: 'POP r32',
    0x5C: 'POP r32',
    0x5D: 'POP r32',
    0x5E: 'POP r32',
    0x5F: 'POP r32',
    0xC9: 'LEAVE',
    0xE8: 'CALL',
    0xC3: 'RET',
}
