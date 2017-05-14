#!/usr/bin/python3
# -----------------------------------------------------------------------------
# Extractor.py
# Search for all ROP gadgets in a given binary using Ropper.
# The gadgets can be searched according to a label or an opcode.
#
# Author: Eval (@cyberjucou)
# -----------------------------------------------------------------------------

import argparse
from ropper import RopperService


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
        gadget_list = []
        for file, gadget in self.rs.search(search=label, name=self.target):
            address = str(gadget).partition(':')[0]
            instr = str(gadget).partition(':')[2].strip(' ').split('; ')
            gadget_list.append(Gadget(address, instr))
        return gadget_list

#     def opcode_search(self, opcode):
#         gadgets_dict = self.rs.searchOpcode(opcode=opcode)
#         print("Opcode: "+opcode)
#         print("Disassembled: \n\t%s" %
#               (self.rs.disasm(opcode, arch='x86').strip('\n')))
#         if not gadgets_dict:
#             print("No gadgets found")
#         else:
#             for file, gadgets in gadgets_dict.items():
#                 for g in gadgets:
#                     print(g)

#     def ppr_search(self):
#         pprs = self.rs.searchPopPopRet(name=self.target)
#         ppr_gadgets = {}
#         for file, ppr in pprs.items():
#             for p in ppr:
#                 address = str(p).partition(':')[0]
#                 instr = str(p).partition(':')[2].strip(' ')
#                 if instr not in ppr_gadgets:
#                     ppr_gadgets[instr] = address


class Gadget:
    """
    A gadget is represented by the address of its first gadget and a list of
    instructions.
    """
    def __init__(self, address, instructions):
        self.address = address
        self.instructions = instructions

    def __str__(self):
        string = "Gadget <"+self.address+">\n"
        string += "-"*len(string)+"\n"
        i = 0
        for instr in self.instructions:
            i += 1
            string += "g"+str(i)+": "+instr+"\n"
        return string

    @property
    def instructions(self):
        return self.__instructions

    @instructions.setter
    def instructions(self, instructions):
        self.__instructions = instructions


def print_gadgets(gtype, glist):
    """
    Pretty print each gadget found in a given list.

    Args:
        gtype: Short string indicating the instruction type. \
        (example: load, store...)
        glist: List of instructions.
    """
    print("*" * 40)
    print("Searching for type: "+gtype)
    print("Found %i gadgets:\n" % len(glist))
    for g in glist:
        print("%s" % g)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='')
    parser.add_argument("target", help="path to target binary")
    parser.add_argument("-c", "--color", help="print a colored output WARNING:\
                    will break the dictionnaries", action='store_true')
    args = parser.parse_args()
    target = args.target
    color = args.color

    extract = Extractor(target)
#    rs = RopperService(options)
#    rs.addFile(args.target)
#    rs.loadGadgetsFor(name=target)

    mov_rm_gadgets = extract.search_gadgets('mov [e??], e??', target)
    print_gadgets("load", mov_rm_gadgets)
    mov_mr_gadgets = extract.search_gadgets('mov e??, [e??]', target)
    print_gadgets("store", mov_mr_gadgets)

    print_gadgets("pop", extract.search_gadgets('pop ???; ret;', target))
    # for g in mov_mr_gadgets:
    #     for i in g.instructions:
    #         print(Extractor.rs.asm(i))

    # print("*" * 80)
    # pprint.pprint(mov_rm_gadgets)
    # pprint.pprint(mov_mr_gadgets)
    # print("*" * 80)
    # opcodes = "55 89e5 83ec10 c745fc01000000 c745f802000000 \
    # 8b55fc 8b45f8 01d0 c9 c3".split()
    # for op in opcodes:
    #     opcode_search(op)
