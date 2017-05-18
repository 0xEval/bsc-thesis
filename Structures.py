#!/usr/bin/python3
# -----------------------------------------------------------------------------
# Structures.py
# Custom data structures for gadgets and instructions.
# Author: Eval (@cyberjucou)
# -----------------------------------------------------------------------------


class Gadget:
    """
    A gadget is represented by the address of its first gadget and a list of
    instructions.
    """
    def __init__(self, address, instructions):
        self.address = address
        self.instructions = instructions

    def __str__(self):
        string = "Gadget <%s>\n" % self.address
        string += "-"*len(string)+"\n"
        i = 0
        for instr in self.instructions:
            i += 1
            string += "g%s: %s\n" % (i, instr)
        return string

    @property
    def instructions(self):
        return self.__instructions

    @instructions.setter
    def instructions(self, instructions):
        self.__instructions = instructions


class Instruction:
    def __init__(self, addr, mnemonic, dst, src, dst_off=None, src_off=None):
        self.addr = addr
        self.mnemonic = mnemonic
        self.dst = dst
        self.dst_offset = dst_off
        self.src = src
        self.src_offset = src_off

    def __str__(self):
        string = "Instruction found at <%s>\n" % hex(self.addr)
        string += "-"*len(string)+"\n"
        string += "Mnemonic: %s\n" % self.mnemonic
        string += "    Dest: %s\n" % self.dst
        if self.dst_offset is not None:
            string += "\twith offset: %s\n" % self.dst_offset
        string += "     Src: %s\n" % self.src
        if self.src_offset is not None:
            string += "\twith offset: %s\n" % self.src_offset
        return string

    @property
    def src(self):
        return self.__src

    @property
    def dst(self):
        return self.__dst
