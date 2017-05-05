#!/usr/bin/python3

import argparse
import pprint
from ropper import RopperService


def search_gadgets(label, target):
    gadgets_dict = {}
    for file, gadget in rs.search(search=label, name=target):
        print(gadget)
        address = str(gadget).partition(':')[0]
        instr = str(gadget).partition(':')[2].strip(' ')
        if instr not in gadgets_dict:
            gadgets_dict[instr] = address
    return gadgets_dict


parser = argparse.ArgumentParser(description='')
parser.add_argument("target", help="path to target binary")
parser.add_argument("-c", "--color", help="print a colored output WARNING: \
                    will break the dictionnaries", action='store_true')
args = parser.parse_args()
target = args.target
color = args.color

options = {
    'color': color,
    'badbytes': 00,
    'all': False,
    'inst_count': 3,
    'type': 'rop',
    'detailed': False,
}

rs = RopperService(options)
rs.addFile(args.target)
rs.loadGadgetsFor(name=target)

ppr_gadgets = {}  # Available POP; POP; RET gadgets
mov_mr_gadgets = {}  # Available MOV Reg; Mem gadgets
mov_rm_gadgets = {}  # Available MOV Mem; Reg gadgets
mov_rr_gadgets = {}  # Available MOV Reg; Reg gadgets

print ("+==================+")
print ("|  POP; POP; RET;  |")
print ("+==================+")
pprs = rs.searchPopPopRet(name=target)
for file, ppr in pprs.items():
    for p in ppr:
        print (p)
        address = str(p).partition(':')[0]
        instr = str(p).partition(':')[2].strip(' ')
        if instr not in ppr_gadgets:
            ppr_gadgets[instr] = address

print ("\nUnique PPR gadgets:")
pprint.pprint(ppr_gadgets)

print ("+==================+")
print ("| MOV <REG>, <REG> |")
print ("+==================+")
mov_rr_gadgets = search_gadgets('mov e??, e??', target)
pprint.pprint(mov_rr_gadgets)

print ("+==================+")
print ("| MOV <REG>, <MEM> |")
print ("+==================+")
mov_rm_gadgets = search_gadgets('mov [e??], e??', target)
pprint.pprint(mov_rm_gadgets)

print ("+==================+")
print ("| MOV <MEM>, <REG> |")
print ("+==================+")
mov_mr_gadgets = search_gadgets('mov e??, [e??]', target)
pprint.pprint(mov_mr_gadgets)
