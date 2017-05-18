#!/usr/bin/python3
# -----------------------------------------------------------------------------
# Extractor.py
# Search for all ROP gadgets in a given binary using Ropper.
# The gadgets can be searched according to a label or an opcode.
#
# Author: Eval (@cyberjucou)
# -----------------------------------------------------------------------------

import argparse
import re
from ropper import RopperService
from Structures import Instruction, Gadget
from Mnemonics import OPCODES


class Extractor:
    def __init__(self, options, target):
        self.rs = RopperService(options)
        self.rs.addFile(target)
        self.rs.loadGadgetsFor(name=target)
        self.target = target

    def search_gadgets(self, label):
        """
        Using Ropper's engine, the function searches for all gadgets matching
        a given label.

        Args:
            label: Search pattern to be used by Ropper. A '?' character will be
            interpreted as any character, the '%' is any string.
            (example: 'mov e??, [e??]')

        Returns:
            List of Gadget objects matching the gadgets found in the binary.
        """
        def find_mnemonic(insn):
            """ Returns a String of the mnemonic version of a given opcode """
            opcode = self.rs.asm(insn)
            opcode = re.findall('.{1,2}', opcode)
            opcode = int(opcode[0], 16)
            for i in OPCODES:
                if i == opcode:
                    return OPCODES[i]
            return 'not supported'

        gadget_list = []
        for file, gadget in self.rs.search(search=label, name=self.target):
            addr_str = str(gadget).partition(':')[0]
            insn_str = str(gadget).partition(':')[2].strip(' ').split('; ')
            insn_list = []
            for i in insn_str:
                address = int(addr_str, 16)
                regs = re.findall(r'e[a-z][a-z]', i)
                mnemonic = find_mnemonic(i)
                if len(regs) == 2:
                    insn = Instruction(i, address, mnemonic,
                                       regs[0], regs[1])
                elif len(regs) == 1:
                    insn = Instruction(i, address, mnemonic,
                                       regs[0])
                else:
                    insn = Instruction(i, address, mnemonic)
                insn_list.append(insn)
            gadget_list.append(Gadget(address, insn_list))
        return gadget_list


def print_gadgets(gtype, glist):
    """
    Pretty print each gadget found in a given list.

    Args:
        gtype: Short string indicating the instruction type. \
        (example: load, store...)
        glist: List of instructions.
    """
    print("Searching for type: "+gtype)
    print("Found %i gadgets:\n" % len(glist))
    for g in glist:
        print("%s" % g)


def test_class():
    """ Test-run function for debugging """
    print_gadgets("load", extract.search_gadgets('mov [e??], e??'))
    print_gadgets("store", extract.search_gadgets('mov e??, [e??]'))
    print_gadgets("pop", extract.search_gadgets('pop ???; ret;'))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='')
    parser.add_argument("target", help="path to target binary")
    args = parser.parse_args()
    target = args.target

    options = {
        'color': False,
        'all': False,
        'inst_count': 3,
        'type': 'rop',
        'detailed': False,
    }

    extract = Extractor(options, target)
    test_class()
