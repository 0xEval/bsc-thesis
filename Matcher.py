#!/usr/bin/python3
# -----------------------------------------------------------------------------
# Matcher.py
# Using Extractor and Disasm, the module searches for read, write, and register
# move gadgets in a given binary. The gadgets are filtered with a ruleset and
# then chained to match with a each instruction contained in the exploit we
# want to translate.
#
# Author: Eval
# GitHub: https://github.com/jcouvy
# -----------------------------------------------------------------------------

import Extractor
import Disasm
import argparse

from termcolor import colored
from capstone import CS_ARCH_X86, CS_MODE_32
from Structures import Instruction
from Mnemonics import OPCODES

options = {
    'color': False,
    'all': False,
    'inst_count': 6,
    'type': 'rop',
    'detailed': False,
}

DEBUG = False


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


def is_reg_controllable(target_reg, controlled_regs):
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


def is_reg_movable(src, dst, mov_gadget_dict, payload_insn):
    """
    Checks if a src register can be moved to a target register with no side
    effects.
    """
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


def is_supported(payload_insn):
    """ Check if a given payload instruction is supported """
    if payload_insn.mnemonic in OPCODES.values():
        return True
    print(colored("Not supported", "red"))
    return False


def check_gadget_validity(g, controlled_regs):
    """
    Checks a set of rules on a given gadget, returns True if all are passed
    False otherwise.
    """
    gadget_src = g.instructions[0].src
    gadget_dst = g.instructions[0].dst
    if gadget_src == 'esp' or\
            gadget_dst == 'esp' or\
            g.instructions[len(g.instructions)-1].label != 'ret;':
        return False
    for i in g.instructions[1:]:
        if i.mnemonic == 'CALL' or\
                i.mnemonic == 'LEAVE' or\
                i.mnemonic == 'MOV r/m32,r32' and i.dst == gadget_dst or\
                i.dst == 'esp':
            return False
    return True


def search_regmov_conflict(payload_insn, target_gadget):
    """
    Search for a conflicting register move between a given instruction and a
    target gadget.

    Args:
        payload_insn: payload instruction used to check for possible conflicts

        target_gadget: potential Gadget found in the binary

    Returns:
        True if a conflict has been found, False otherwise.
    """
    if payload_insn.label.find('ptr') == -1:
        unavailable_regs = []
    else:
        unavailable_regs = [payload_insn.src, payload_insn.dst]

    if target_gadget.instructions[0].src == payload_insn.dst:
        unavailable_regs.append(target_gadget.instructions[0].dst)
        if payload_insn.dst in unavailable_regs:
            unavailable_regs.remove(payload_insn.dst)

    for i in target_gadget.instructions[1:]:
        if i.dst in unavailable_regs:
            print("Conflicting instructions during mov sequence")
            print(colored("Conflict on: " + i.dst, 'red'))
            print(target_gadget)
            return True

    return False


def map_possible_movements(move_type, gagdgets_lists):
    """
     Each register is associated with 3 lists mapping the possible
     Register to register move:
     - direct: list for direct moves (ex: mov eax, ebx)
     - chained: list with chained moves 1...n
       (ex: mov ecx, eax is not available directly, instead we have a chain:
           mov edx, eax --> mov ecx, edx).
    """
    move_mapping = {}
    for reg in reglist:
        move_mapping[reg] = {'direct': [], 'chained': [], 'missing': []}

    if move_type == 'register_move':
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
    else:
        for reg in move_mapping.keys():
            for g in gadgets_lists[move_type]:
                dst = g.instructions[0].dst
                src = g.instructions[0].src
                if src == reg and dst not in move_mapping[reg]["direct"]:
                    move_mapping[reg]["direct"].append(dst)

            # Appends the missing destinations to the missing list.
            for k in move_mapping.keys():
                if k not in move_mapping[reg]["direct"]:
                    move_mapping[reg]["missing"].append(k)

    return move_mapping


def is_movable(src, dst, payload_insn, regmove_glist, move_mapping,
               gadget_chain, visited=[]):
    """
    Checks if a non conflicting (ie: w/o side effects) register move chain can
    be found to transfer a given src register to a target one. If so, the
    corresponding gadget(s) is(are) added to the gadget chain in parameters.

    Args:
        src: String representing the source register

        dst: String representing the target register

        payload_insn: target payload Instruction

        regmove_glist: List of register move gadgets

        move_mapping: Dict containing Lists of register movements in the
        current context (direct, chained or missing)

    Returns:
        True if a move chain is found, False otherwise
    """
    if src not in ['eax', 'ebx', 'ecx', 'edx', 'ebp', 'esp', 'edi', 'esi']:
        debug("Constant")
        for pg in pop_gadgets:
            debug(pg)
            if pg.instructions[0].dst == dst:
                gadget_chain.append(pg)
                return True
        return False

    if dst not in ['eax', 'ebx', 'ecx', 'edx', 'ebp', 'esp', 'edi', 'esi']:
        debug("Constant")
        for pg in pop_gadgets:
            debug(pg)
            if pg.instructions[0].dst == src:
                gadget_chain.append(pg)
                return True
        return False

    debug("Visited regs: %s" % colored(' '.join(str(r) for r in visited),
                                       'cyan'))

    for reg in move_mapping[src]['direct']:
        if reg == dst and reg != src:
            for g in regmove_glist:
                if g.instructions[0].src == src and\
                        g.instructions[0].dst == reg:
                    debug("Move %s to %s" % (src, reg))
                    debug(g)
                    if not search_regmov_conflict(payload_insn, g):
                        gadget_chain.append(g)
                        return True

    for reg in move_mapping[src]['direct']:
        if reg not in visited and reg != src:
            visited.append(reg)
            debug("Move %s to %s" % (src, reg))
            for g in regmove_glist:
                if g.instructions[0].src == src and\
                        g.instructions[0].dst == reg:
                    if not search_regmov_conflict(payload_insn, g):
                        debug(g)
                        gadget_chain.append(g)
                        return is_movable(reg, dst, payload_insn,
                                          regmove_glist, move_mapping,
                                          gadget_chain, visited)
    return False


def solve_chain(chain_type, payload_insn, mov_gadget_dict, move_mapping):
    """
    Tries to find a side-effect free gadget chain that matches a given payload
    instruction.

    Args:
        chain_type: String representing the type of chain searched
            (register_move, memory_read, memory_write)

        payload_insn: target payload Instruction

        mov_gadget_dict: Dict containing Lists of all gadgets found for each
            each type of mov instructions.

        move_mapping: Dict containing Lists of register movements in the
            current context (direct, chained or missing)

    Returns:
        List of gadgets consituting the chain, None if none is found.
    """

    gadget_chain = []

    if payload_insn.label.find('ptr') == -1:
        debug("Case 0: register move")
        if is_movable(payload_insn.src, payload_insn.dst, payload_insn,
                      mov_gadget_dict['register_move'], move_mapping,
                      gadget_chain,
                      visited=[]):
            debug(colored("✓ Chain found", 'green'))
            return gadget_chain
    else:
        # Case 1
        for g in mov_gadget_dict[chain_type]:
            if g.instructions[0].dst == payload_insn.dst and \
                    g.instructions[0].src == payload_insn.src:
                gadget_chain.append(g)
                debug("Case 1: same src same dst")
                debug(g)
                debug(colored("✓ Chain found", 'green'))
                return gadget_chain
        # Case 2
        for g in mov_gadget_dict[chain_type]:
            if g.instructions[0].dst == payload_insn.dst and \
                    g.instructions[0].src != payload_insn.src:
                debug("Case 2: same dst, diff src")
                debug("Target gadget:")
                debug(g)
                debug("Objective: mov %s to %s" % (payload_insn.src,
                                                   g.instructions[0].src))
                if is_movable(payload_insn.src, g.instructions[0].src,
                              payload_insn,
                              mov_gadget_dict['register_move'],
                              move_mapping,
                              gadget_chain,
                              visited=[]):
                    gadget_chain.append(g)
                    debug(colored("✓ Chain found", 'green'))
                    return gadget_chain
        # Case 3
        for g in mov_gadget_dict[chain_type]:
            if g.instructions[0].dst != payload_insn.dst and \
                    g.instructions[0].src == payload_insn.src:
                debug("Case 3: diff dst, same src")
                debug("Target gadget:")
                debug(g)
                debug("Objective: mov %s to %s" % (payload_insn.dst,
                                                   g.instructions[0].dst))
                if is_movable(payload_insn.dst, g.instructions[0].dst,
                              payload_insn,
                              mov_gadget_dict['register_move'],
                              move_mapping,
                              gadget_chain,
                              visited=[]):
                    gadget_chain.append(g)
                    debug(colored("✓ Chain found", 'green'))
                    return gadget_chain
        # Case 4
        for g in mov_gadget_dict[chain_type]:
            if g.instructions[0].dst != payload_insn.dst and \
                    g.instructions[0].src != payload_insn.src:
                debug("Case 4: diff dst, diff src")
                debug("Target gadget:")
                debug(g)
                debug("Objective 1: mov %s to %s" % (payload_insn.dst,
                                                     g.instructions[0].dst))
                if is_movable(payload_insn.dst, g.instructions[0].dst,
                              payload_insn,
                              mov_gadget_dict['register_move'],
                              move_mapping,
                              gadget_chain,
                              visited=[]):
                    debug("Objective 2: mov %s to %s" % (payload_insn.src,
                                                         g.instructions[0].src))
                    if is_movable(payload_insn.src, g.instructions[0].src,
                                  payload_insn,
                                  mov_gadget_dict['register_move'],
                                  move_mapping,
                                  gadget_chain,
                                  visited=[]):
                        gadget_chain.append(g)
                        debug(colored("✓ Chain found", 'green'))
                        return gadget_chain
    return


def find_chain(payload_insn, mov_gadget_dict, move_mapping):
    """
    Search in a dictionnary of MOV gadgets for a gadget (or gadget chain) that
    matches a given payload instruction.

    Args:
        payload_insn: String representing the payload instruction.

        mov_gadget_dict: Dict containing lists of diff mov gadgets available.

        move_mapping: Dict representing the possible movements.

    Returns:
        An ordered list of gadgets constituting the chain.
    """
    gadget_chain = []

    if payload_insn.mnemonic in ['MOV r/m32,r32', 'MOV r/m32,imm32']:
        gadget_chain = solve_chain('memory_write', payload_insn,
                                   mov_gadget_dict, move_mapping)

    if payload_insn.mnemonic in ['MOV r32,r/m32', 'MOV r32,imm32']:
        gadget_chain = solve_chain('memory_read', payload_insn,
                                   mov_gadget_dict, move_mapping)

    if not gadget_chain:
        debug("%s\n" % colored("✘ Chain not found", 'red'))

    return gadget_chain


def print_rule_validation(glist):
    """ Prints the rule check detail for every gadget in a list """
    def _check_ruleset(g):
        if g.instructions[0].src == 'esp' or g.instructions[0].dst == 'esp':
            print(colored('✘ forbidden access to/from ESP', 'red'))
            return False
        if g.instructions[len(g.instructions) - 1].label != 'ret;':
            print(colored('✘ ret to address', 'red'))
            return False
        for i in g.instructions[1:]:
            if i.mnemonic == 'LEAVE':
                print(colored('✘ leave instruction', 'red'))
                return False
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

    for g in glist:
        _check_ruleset(g)
        print(g)


def print_chain(gadget_chain):
    """ Prints all the gadgets from a given chain """
    for g in gadget_chain:
        print(g)


def print_stack(gadget_chain, payload_insn):
    """ Prepare and prints a visualization of the stack holding the payload"""
    CELL_WIDTH = 58
    ADDRESS_LENGTH = 10

    def _stack_cell(size, value, desc):
        """ Prints a stack cell with a given value and description """
        print("|" + " "*size + "<"+str(value)+">" + " "*(size-1) + "| " +
              colored(desc, 'yellow'))

    def _stack_separator(size=CELL_WIDTH):
        """ Prints a separator between two stack cells """
        print("+" + "="*int(size/2) + "+")

    def _address_filling(value):
        """ Reformat a given string to a 8 char long hexadecimal string """
        if len(value) != ADDRESS_LENGTH:
            return value[:2] + "0"*(ADDRESS_LENGTH-len(value)) + value[2:]
        return value

    def _prepare_stack(g):
        """ Inserts a placeholder value to be popped by subsequent gadgets """
        label = colored("value to be popped", "cyan")
        value = None
        if payload_insn.mnemonic == 'MOV r/m32,r32':
            value = _address_filling(payload_insn.dst)
        elif payload_insn.mnemonic in ['MOV r/m32,imm32', 'MOV r32,imm32',
                                       'MOV r32,r/m32']:
            value = _address_filling(payload_insn.src)
        if g.instructions[0].mnemonic == 'POP r32':
            _stack_cell(len(str(g.address)), value, label)
            _stack_separator()
        for insn in g.instructions[1:]:
            if insn.mnemonic == 'POP r32':
                _stack_cell(len(str(g.address)), "0x42424242", label)
                _stack_separator()

    print(" "*13 + "STACK")
    _stack_separator()
    for index, g in enumerate(gadget_chain, start=1):
        label = "address of G"+str(index)
        value = _address_filling(hex(g.address))
        _stack_cell(len(str(g.address)), value, label)
        _stack_separator()
        _prepare_stack(g)


def print_statistics(total, supported, assumed):
    """ Prints approximative stats of the program's results """
    print("Total instructions: {}".format(colored(total, 'yellow')))
    print("Supported: {} [{}%] "
          "- All assumptions".format(colored(supported, 'green'),
                                     int((supported/total)*100)))
    print("Supported: {} [{}%] "
          "- No offsets".format(colored(abs(supported-assumed), 'green'),
                                int((abs(supported-assumed)/total)*100)))
    print("Not supported: {} [{}%]".format(colored(total-supported, 'red'),
                                           int(((total-supported)/total)*100)))


def debug(msg):
    if DEBUG:
        print(str(msg))


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

    if args.DEBUG:
        DEBUG = True

    gadgets_lists = {
        'memory_write': sorted(ex.search_gadgets('mov [e??], e??;'),
                               key=lambda gadget: len(gadget.instructions)),
        'memory_read': sorted(ex.search_gadgets('mov e??, [e??]'),
                              key=lambda gadget: len(gadget.instructions)),
        'register_move': sorted(ex.search_gadgets('mov e??, e??'),
                                key=lambda gadget: len(gadget.instructions)),
    }

    # Test cases with manual instructions used to find gadget chains
    debug_instructions = [
        Instruction('mov ecx, ebp', 0x12345678, 'MOV r/m32,r32',
                    'ecx', 'ebp'),
        Instruction('mov eap, ecx', 0x12345678, 'MOV r/m32,r32',
                    'eax', 'ecx'),
        Instruction('mov dword ptr [edi], eax', 0x12345678, 'MOV r/m32,r32',
                    'edi', 'eax'),
        Instruction('mov dword ptr [ebx], ecx', 0x12345678, 'MOV r/m32,r32',
                    'ebx', 'ecx'),
        Instruction('mov dword ptr [edi], ecx', 0x12345678, 'MOV r/m32,r32',
                    'edi', 'ecx'),
        Instruction('mov dword ptr eax, [edx]', 0x12345678, 'MOV r32,r/m32',
                    'eax', 'edx'),
        Instruction('mov dword ptr ebx, [ecx]', 0x12345678, 'MOV r32,r/m32',
                    'ebx', 'ecx'),
        Instruction('mov dword ptr [eax], 0x1', 0x12345678, 'MOV r/m32,imm32',
                    'eax', '0x1'),
        Instruction('mov dword ptr [eax], ds:0x0', 0x12345678, 'MOV r/m32,imm32',
                    'eax', '0x0'),
        Instruction('mov eax, 0x8000000', 0x12345678, 'MOV r/m32,imm32',
                    'eax', '0x8000000'),
    ]

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

    print("Dumping target payload <%s>:" % obj)
    print("-" * 80)
    print(objdump)

    print("Pop gadgets:")
    print("-" * 80)
    for g in pop_gadgets:
        print(g)

    if DEBUG:
        for gtype, glist in gadgets_lists.items():
            print("DEBUG: " + gtype)
            print("-" * 80)
            print_rule_validation(glist)

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

    regmove_map = map_possible_movements('register_move', gadgets_lists)
    memwrite_map = map_possible_movements('memory_write', gadgets_lists)
    memread_map = map_possible_movements('memory_read', gadgets_lists)

    print("Possible reg mov:")
    print("\tsrc: dst (green = direct mov, blue = chained)")
    for reg in regmove_map.keys():
        if regmove_map[reg]["direct"]:
            print("\t%s: %s %s %s" % (
                reg,
                colored(' '.join(
                    str(m) for m in regmove_map[reg]["direct"]), 'green'),
                colored(' '.join(
                    str(m) for m in regmove_map[reg]["chained"]), 'cyan'),
                colored(' '.join(
                    str(m) for m in regmove_map[reg]["missing"]), 'red'),
            ))

    print("Possible memory write: ")
    for reg in memwrite_map.keys():
        if memwrite_map[reg]["direct"]:
            print("\t%s: %s %s" % (
                reg,
                colored(' '.join(
                    str(m) for m in memwrite_map[reg]["direct"]), 'green'),
                colored(' '.join(
                    str(m) for m in memwrite_map[reg]["missing"]), 'red'),
            ))

    print("Possible memory read: ")
    for reg in memread_map.keys():
        if memread_map[reg]["direct"]:
            print("\t%s: %s %s" % (
                reg,
                colored(' '.join(
                    str(m) for m in memread_map[reg]["direct"]), 'green'),
                colored(' '.join(
                    str(m) for m in memread_map[reg]["missing"]), 'red'),
            ))
    print()

    # Search a gadget chain for each test instruction in our list
    supported_insns = 0
    assumed_insns = 0
    for insn in payload_insns:
        print("-"*80)
        print()
        print(colored("Target: "+insn.label, "yellow"))
        if is_supported(insn):
            if insn.src_offset or insn.dst_offset:
                assumed_insns += 1
            gchain = find_chain(insn, gadgets_lists, regmove_map)
            debug(insn.src)
            debug(insn.dst)
            debug(insn.mnemonic)
            if gchain:
                supported_insns += 1
                print_chain(gchain)
                print_stack(gchain, insn)
            else:
                print(colored("No chain found", "red"))
            print()
    print_statistics(len(payload_insns), supported_insns, assumed_insns)

    if DEBUG:
        for insn in debug_instructions:
            print("-"*80)
            print()
            gchain = find_chain(insn, gadgets_lists, regmove_map)
            print(colored("Target: "+insn.label, "yellow"))
            print(insn.src)
            print(insn.dst)
            debug(insn.mnemonic)
            if gchain:
                print_chain(gchain)
                print_stack(gchain, insn)
            else:
                print(colored("No chain found", "red"))
