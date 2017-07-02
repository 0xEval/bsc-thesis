#!/usr/bin/python3
# -----------------------------------------------------------------------------
# Structures.py
# Custom data structures for gadgets and instructions.
# Author: Eval
# GitHub: https://github.com/jcouvy
# -----------------------------------------------------------------------------


class Gadget:
    """
    A gadget is represented by the address of its first gadget and a list of
    instructions (custom object).
    """
    def __init__(self, address, instructions):
        self.address = address
        self.instructions = instructions

    def __str__(self):
        string = "Gadget <%s>:" % hex(self.address)
        offset = len(string)
        # string += "%s\n" % ("-"*len(string))
        i = 0
        for insn in self.instructions:
            i += 1
            string += "\tg%s: %s\n" % (i, insn.simple_print())
            string += " "*offset
        return string


class Instruction:
    """
    An instruction is represented by multiples parameters

    Label (string): raw instruction.
    Addr (string): address of the instruction.
    Mnemonic (string): short string representing an instruction format.
    Dst, src (string): destination and source registers.
    Dst_offset, src_offset (string): memory offset.

    Note that the last four parameters are initialized at None, this helps
    simplifying printing when the information is absent (ex: ret instruction).
    """
    def __init__(self, label, addr, mnemonic,
                 dst=None, src=None, dst_off=None, src_off=None):
        self.label = label
        self.addr = addr
        self.mnemonic = mnemonic
        self.dst = dst
        self.dst_offset = dst_off
        self.src = src
        self.src_offset = src_off

    def __str__(self):
        # Can be reworked with **kwargs later ?
        string = "Instruction found at <%s>\n" % hex(self.addr)
        string += "-"*len(string)+"\n"
        string += "Mnemonic: %s\n" % self.mnemonic
        string += "   Label: %s\n" % self.label
        if self.dst is not None:
            string += "    Dest: %s\n" % self.dst
        if self.dst_offset is not None:
            string += "\twith offset: %s\n" % self.dst_offset
        if self.src is not None:
            string += "     Src: %s\n" % self.src
        if self.src_offset is not None:
            string += "\twith offset: %s\n" % self.src_offset
        return string

    def simple_print(self):
        return self.label
