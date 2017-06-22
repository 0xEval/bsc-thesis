#!/usr/bin/python3
# -----------------------------------------------------------------------------
# Matcher.py
# Using Extractor and Disasm, the module searches for read, write, and register
# move gadgets in a given binary.
#
# Author: Eval (@cyberjucou)
# -----------------------------------------------------------------------------


import Extractor
import Disasm
import argparse

from termcolor import colored
from capstone import CS_ARCH_X86, CS_MODE_32
from Structures import Instruction


options = {
    'color': False,
    'all': False,
    'inst_count': 6,
    'type': 'rop',
    'detailed': False,
}


def search_pop_gadgets(extractor):
    """ Using the Extractor module, returns a list of pop gadgets """
    glist = extractor.search_gadgets('pop ???; ret;')
    return glist


def search_push_gadgets(extractor):
    """ Using the Extractor module, returns a list of push gadgets """
    glist = extractor.search_gadgets('push e??; pop % ret;')
    return glist


def search_payload_insn(disassembler):
    """ Using the Disasm module, returns a list of mov gadgets"""
    insn = disassembler.extract_insn()
    return insn


def is_controllable(target_reg, controlled_regs):
    """
    Check if register is controlled (ie: a pop reg; ret; gadget exists)

    Args:
            reg: String representing the register.
            controlled_regs: List of Gadget objects

    Returns:
            True if the register is found, False otherwise
    """
    for reg in controlled_regs:
        if target_reg == reg:
            return True
    return False


def check_memread_rules(g):
    if g.instructions[0].src == 'esp':
        print(colored('✘ read from ESP', 'red'))
        return False
    if g.instructions[len(g.instructions) - 1].label != 'ret;':
        print(colored('✘ ret to address', 'red'))
        return False
    for i in g.instructions[1:]:
        if i.mnemonic == 'CALL':
            print(colored('✘ call instruction', 'red'))
            return False
        if i.dst == g.instructions[0].dst:
            print(colored('✘ conflicting instructions', 'red'))
            return False
        if i.dst == 'esp':
            print(colored('✘ write on ESP', 'red'))
            return False
    print(colored('✓ potential gadget', 'green'))
    return True


def check_memwrite_rules(g):
    if g.instructions[0].src == 'esp' or g.instructions[0].dst == 'esp':
        print(colored('✘ read from ESP', 'red'))
        return False
    if g.instructions[len(g.instructions) - 1].label != 'ret;':
        print(colored('✘ ret to address', 'red'))
        return False
    for i in g.instructions[1:]:
        if i.mnemonic == 'CALL':
            print(colored('✘ call instruction', 'red'))
            return False
        if i.mnemonic == 'MOV r/m32,r32' and i.dst == g.instructions[0].dst:
            print(colored('✘ conflicting instructions', 'red'))
            return False
        if i.dst == 'esp':
            print(colored('✘ write on ESP', 'red'))
            return False
    print(colored('✓ potential gadget', 'green'))
    return True


def check_gadget_validity(g, controlled_regs):
    """
    Checks a set of rules on a given gadget, returns True if all are passed
    False otherwise.
    """
    # if not is_controllable(g.instructions[0].dst, controlled_regs) or\
    #    not is_controllable(g.instructions[0].src, controlled_regs):
    #     return False
    if g.instructions[0].src == 'esp' or\
       g.instructions[0].dst == 'esp' or\
       g.instructions[len(g.instructions)-1].label != 'ret;':
        return False
    for i in g.instructions[1:]:
        if i.mnemonic == 'CALL' or\
           i.mnemonic == 'MOV r/m32,r32' and i.dst == g.instructions[0].dst or\
           i.dst == 'esp':
            return False
    return True


def _print_rule_validation(glist):
    """ Prints the rule check detail for every gadget in a list """
    for g in glist:
        check_memwrite_rules(g)
        print(g)


def find_matching_format(insn, ex, pop_gadgets_list, verbose=False):
    glist = []
    matching_glist = []

    if insn.mnemonic == 'MOV r/m32,imm32':
        glist = ex.search_gadgets('mov [e??], e??')
        glist = sorted(glist, key=lambda gadget: len(gadget.instructions))
        for g in glist:
            if not is_controllable(insn.dst, pop_gadgets_list):
                print(colored('✘ register(s) not controlled', 'red'))
            if check_memwrite_rules(g):
                matching_glist.append(g)
            print(g)

    if insn.mnemonic == 'MOV r/m32,r32':
        # need to differentiate between reg to mem and reg to reg
        if insn.label.find('ptr') != -1:
            glist = ex.search_gadgets('mov [e??], e??')
        else:
            glist = ex.search_gadgets('mov e??, e??')

        glist = sorted(glist, key=lambda gadget: len(gadget.instructions))
        for g in glist:
            if not is_controllable(insn.src, pop_gadgets_list) or \
                    not is_controllable(insn.dst, pop_gadgets_list):
                print(colored('✘ register(s) not controlled', 'red'))
            if check_memwrite_rules(g):
                matching_glist.append(g)
            print(g)

    if insn.mnemonic == 'MOV r32,r/m32':
        glist = ex.search_gadgets('mov e??, [e??]')
        glist = sorted(glist, key=lambda gadget: len(gadget.instructions))
        for g in glist:
            if not is_controllable(insn.src, pop_gadgets_list) or \
                    not is_controllable(insn.dst, pop_gadgets_list):
                print(colored('✘ register(s) not controlled', 'red'))
            if check_memread_rules(g):
                matching_glist.append(g)
            print(g)

    return matching_glist


def is_reg_movable(src, dst, mov_gadget_dict, payload_insn):
    print("-> Trying to move %s to %s" % (src, dst))
    # Direct move
    for g in mov_gadget_dict['register_move']:
        if g.instructions[0].src == src and g.instructions[0].dst == dst:
            print("-> Register Move: %s to %s" % (src, dst))
            print(g)
            if not search_regmov_conflict(payload_insn, g):
                return True

    # Chained move
    index = 0
    movchain = []
    for g in mov_gadget_dict['register_move']:
        if g.instructions[0].src == src:
            if not search_regmov_conflict(payload_insn, g):
                movchain.append(src)
                while movchain.count(src) < 2:
                    for tmp in mov_gadget_dict['register_move']:
                        if tmp.instructions[0].src == movchain[index]:
                            if not search_regmov_conflict(payload_insn, tmp):
                                movchain.append(tmp.instructions[0].dst)
                                index += 1
    for m in movchain:
        print(m)

    return False


def is_movable(src, dst, payload_insn, regmove_glist, move_mapping,
               visited=[]):

    print(visited)

    for reg in move_mapping[src]['direct']:
        if reg == dst:
            for g in regmove_glist:
                if g.instructions[0].src == src and\
                        g.instructions[0].dst == reg:
                    print("Move %s to %s" % (src, reg))
                    print(g)
                    return True

    for reg in move_mapping[src]['direct']:
        if reg not in visited:
            visited.append(reg)
            print("Move %s to %s" % (src, reg))
            for gadget in regmove_glist:
                if gadget.instructions[0].src == src and\
                        gadget.instructions[0].dst == reg:
                    if not search_regmov_conflict(payload_insn, gadget):
                        return is_movable(reg, dst, payload_insn,
                                          regmove_glist, move_mapping, visited)

    return False


def search_regmov_conflict(payload_insn, target_gadget):
    unavailable_regs = [payload_insn.src, payload_insn.dst]

    if target_gadget.instructions[0].src == payload_insn.dst:
        unavailable_regs.append(target_gadget.instructions[0].dst)
        unavailable_regs.remove(payload_insn.dst)

    for i in target_gadget.instructions[1:]:
        if i.dst in unavailable_regs:
            print("Conflicting instructions during mov sequence")
            print("Conflict on: " + i.dst)
            print(colored(target_gadget, 'red'))
            return True

    print("No conflict:")
    print(target_gadget)
    return False


def find_chain(payload_insn, mov_gadget_dict, move_mapping):
    # Case 1
    for g in mov_gadget_dict['memory_write']:
        if g.instructions[0].dst == payload_insn.dst and \
                g.instructions[0].src == payload_insn.src:
            print("Case 1: same src same dst")
            print(g)
            print(colored("✓ Chain found", 'green'))
            return
    # Case 2
    for g in mov_gadget_dict['memory_write']:
        if g.instructions[0].dst == payload_insn.dst and \
                g.instructions[0].src != payload_insn.src:
            print("Case 2: same dst, diff src")
            print("Target gadget:")
            print(g)
            if is_movable(payload_insn.src,
                          g.instructions[0].src,
                          payload_insn,
                          mov_gadget_dict['register_move'],
                          move_mapping,
                          visited=[]):
                print(colored("✓ Chain found", 'green'))
                return
    # Case 3
    for g in mov_gadget_dict['memory_write']:
        if g.instructions[0].dst != payload_insn.dst and \
                g.instructions[0].src == payload_insn.src:
            print("Case 3: diff dst, same src")
            print("Target gadget:")
            print(g)
            if is_movable(payload_insn.dst,
                          g.instructions[0].dst,
                          payload_insn,
                          mov_gadget_dict['register_move'],
                          move_mapping,
                          visited=[]):
                print(colored("✓ Chain found", 'green'))
                return

    print("%s\n" % colored("✘ Chain not found", 'red'))
    return


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='')
    parser.add_argument("target", help="path to target binary")
    parser.add_argument("object", help="path to payload object file")
    parser.add_argument("-D", "--DEBUG", action="store_true",
                        help="enable detailed output")

    args = parser.parse_args()
    target = args.target
    obj = args.object

    objdump = Disasm.dump_object(obj)
    opcode = Disasm.extract_opcode(objdump)

    X86_CODE32 = bytes.fromhex(opcode)
    all_tests = (
        (CS_ARCH_X86, CS_MODE_32, X86_CODE32, "X86 32 (Intel syntax)", 0),
    )

    ex = Extractor.Extractor(options, target)
    dis = Disasm.Disasm(all_tests)

    pop_gadgets = search_pop_gadgets(ex)
    push_gadgets = search_push_gadgets(ex)
    payload_insns = search_payload_insn(dis)

    print("Dumping target payload <%s>:" % obj)
    print("-" * 80)
    print(objdump)

    print("Pop gadgets:")
    print("-" * 80)
    for g in pop_gadgets:
        print(g)

    gadgets_lists = {
        'memory_write': sorted(ex.search_gadgets('mov [e??], e??;'),
                               key=lambda gadget: len(gadget.instructions)),
        'memory_read': sorted(ex.search_gadgets('mov e??, [e??]'),
                              key=lambda gadget: len(gadget.instructions)),
        'register_move': sorted(ex.search_gadgets('mov e??, e??'),
                                key=lambda gadget: len(gadget.instructions)),
    }

    # Print the rulecheck details on each gadget
    if args.DEBUG:
        for gtype, glist in gadgets_lists.items():
            print("DEBUG: " + gtype)
            print("-" * 80)
            _print_rule_validation(glist)

    reglist = ['eax', 'ebx', 'ecx', 'edx', 'ebp', 'esp', 'edi', 'esi']
    controlled_regs = []

    for reg in pop_gadgets:
        if reg not in controlled_regs:
            controlled_regs.append(reg.instructions[0].dst)

    missing_regs = list(set(reglist) - set(controlled_regs))

    for gtype in gadgets_lists.keys():
        gadgets_lists[gtype] = [
            g for g in gadgets_lists[gtype]
            if check_gadget_validity(g, controlled_regs)
        ]

    # Test cases with manual instructions:
    # Case 1: Direct write (same dst)
    test_insn1 = Instruction('mov dword ptr [edi], eax', 0x12345678,
                             'mov r/m32, r32', 'edi', 'eax')
    # Case 2 (same dst, different src):
    # 1-Chained write (same dst)
    test_insn2 = Instruction('mov dword ptr [ebx], ecx', 0x12345678,
                             'mov r/m32, r32', 'ebx', 'ecx')
    # N-Chained write (same dst)
    test_insn3 = Instruction('mov dword ptr [edi], ecx', 0x12345678,
                             'mov r/m32, r32', 'edi', 'ecx')
    # Case 3 (different dst, same src):
    test_insn4 = Instruction('mov dword ptr [esi], eax', 0x12345678,
                             'mov r/m32, r32', 'esi', 'eax')

    print("Register move gadgets: ")
    print("-" * 80)
    for g in gadgets_lists['register_move']:
        print(g)

    print("Memory read gadgets: ")
    print("-" * 80)
    for g in gadgets_lists['memory_read']:
        print(g)

    print("Memory write gadgets: ")
    print("-" * 80)
    for g in gadgets_lists['memory_write']:
        print(g)

    print("Controlled registers: \n\t%s" %
          colored(' '.join(str(cr) for cr in controlled_regs), 'green'))
    if missing_regs:
        print("Missing: \n\t%s" %
              colored(' '.join(str(mr) for mr in missing_regs), 'red'))

    # Each register is associated with 3 lists mapping the possible
    # Register to register move:
    # - direct: list for direct moves (ex: mov eax, ebx)
    # - chained: list with chained moves 1...n
    #   (ex: mov ecx, eax is not available directly, instead we have a chain:
    #       mov edx, eax --> mov ecx, edx).

    move_mapping = {}
    for reg in reglist:
        move_mapping[reg] = {'direct': [], 'chained': [], 'missing': []}

    print("Possible reg mov:")
    print("\tsrc: dst (green = direct mov, blue = chained)")
    for reg in move_mapping.keys():
        # Find the direct mov possibilites in the Reg-to-Reg gadget list.
        for g in gadgets_lists['register_move']:
            src = g.instructions[0].src
            dst = g.instructions[0].dst
            if src == reg and dst not in move_mapping[reg]["direct"]:
                move_mapping[reg]["direct"].append(dst)

        # Find the possible chains within the direct mov list (length 2).
        for g in gadgets_lists['register_move']:
            src = g.instructions[0].src
            dst = g.instructions[0].dst
            for m in move_mapping[reg]["direct"]:
                if src == m and \
                   dst not in move_mapping[reg]["direct"] and \
                   dst not in move_mapping[reg]["chained"]:
                    move_mapping[reg]["chained"].append(dst)

        # Find the possible chains within the 2-chain mov list (length 3+).
        for g in gadgets_lists['register_move']:
            src = g.instructions[0].src
            dst = g.instructions[0].dst
            for m in move_mapping[reg]["chained"]:
                if src == m and \
                  dst not in move_mapping[reg]["direct"] and \
                  dst not in move_mapping[reg]["chained"]:
                    move_mapping[reg]["chained"].append(dst)

        # Appends the missing destinations to the missing list.
        for k in move_mapping.keys():
            if k not in move_mapping[reg]["direct"] and \
               k not in move_mapping[reg]["chained"]:
                move_mapping[reg]["missing"].append(k)

        if move_mapping[reg]["direct"]:
            print("\t%s: %s %s %s" % (
                reg,
                colored(' '.join(
                    str(m) for m in move_mapping[reg]["direct"]), 'green'),
                colored(' '.join(
                    str(m) for m in move_mapping[reg]["chained"]), 'cyan'),
                colored(' '.join(
                    str(m) for m in move_mapping[reg]["missing"]), 'red'),
            ))

    print("-" * 40)
    print("TEST INSN: %s" % test_insn1.label)
    print("-" * 40)
    find_chain(test_insn1, gadgets_lists, move_mapping)
    print("-" * 40)
    print("TEST INSN: %s" % test_insn2.label)
    print("-" * 40)
    find_chain(test_insn2, gadgets_lists, move_mapping)
    print("-" * 40)
    print("TEST INSN: %s" % test_insn3.label)
    print("-" * 40)
    find_chain(test_insn3, gadgets_lists, move_mapping)
    print("-" * 40)
    print("TEST INSN: %s" % test_insn4.label)
    print("-" * 40)
    find_chain(test_insn4, gadgets_lists, move_mapping)

    print("Possible memory write: ")
    for reg in move_mapping.keys():
        del move_mapping[reg]["direct"][:]
        del move_mapping[reg]["missing"][:]

        for g in gadgets_lists['memory_write']:
            dst = g.instructions[0].dst
            src = g.instructions[0].src
            if src == reg and dst not in move_mapping[reg]["direct"]:
                move_mapping[reg]["direct"].append(dst)

        # Appends the missing destinations to the missing list.
        for k in move_mapping.keys():
            if k not in move_mapping[reg]["direct"]:
                move_mapping[reg]["missing"].append(k)

        if move_mapping[reg]["direct"]:
            print("\t%s: %s %s" % (
                reg,
                colored(' '.join(
                    str(m) for m in move_mapping[reg]["direct"]), 'green'),
                colored(' '.join(
                    str(m) for m in move_mapping[reg]["missing"]), 'red'),
            ))

    print("Possible memory read: ")
    for reg in move_mapping.keys():
        del move_mapping[reg]["direct"][:]
        del move_mapping[reg]["missing"][:]

        for g in gadgets_lists['memory_read']:
            dst = g.instructions[0].dst
            src = g.instructions[0].src
            if src == reg and dst not in move_mapping[reg]["direct"]:
                move_mapping[reg]["direct"].append(dst)

        # Appends the missing destinations to the missing list.
        for k in move_mapping.keys():
            if k not in move_mapping[reg]["direct"]:
                move_mapping[reg]["missing"].append(k)

        if move_mapping[reg]["direct"]:
            print("\t%s: %s %s" % (
                reg,
                colored(' '.join(
                    str(m) for m in move_mapping[reg]["direct"]), 'green'),
                colored(' '.join(
                    str(m) for m in move_mapping[reg]["missing"]), 'red'),
            ))
