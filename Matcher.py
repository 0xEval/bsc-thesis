import Extractor
import Disasm
import argparse
from termcolor import colored
from capstone import CS_ARCH_X86, CS_MODE_32


options = {
    'color': False,
    'all': False,
    'inst_count': 6,
    'type': 'rop',
    'detailed': False,
}


def search_pop_gadgets(extractor, verbose=False):
    regs = extractor.search_gadgets('pop ???; ret;')
    if verbose:
        print("Found %s controllable registers:" % len(regs))
        for g in regs:
            print(g)
    return regs


def search_push_gadgets(extractor, verbose=False):
    glist = extractor.search_gadgets('push e??; pop % ret;')
    return glist


def search_payload_insn(disassembler, verbose=False):
    insn = disassembler.extract_insn()
    if verbose:
        for i in insn:
            print(i)
    return insn


def is_controllable(reg, glist):
    for g in glist:
        if g.instructions[0].dst == reg:
            return True
    return False


def print_available_dest(glist):
    pairs = []
    for g in glist:
        dest = g.instructions[0].dst
        src = g.instructions[0].src
        if not (src, dest) in pairs:
            pairs.append((src, dest))
    # pairs = sorted(pairs)
    for p in pairs:
        print("\t%s \t-> \t%s" % (p[0], p[1]))


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


def find_matching_format(insn, ex, pop_gadgets_list, verbose=False):
    glist = []
    matching_glist = []
    # pop_gadgets_list = search_pop_gadgets(ex)
    # push_gadgets_list = search_push_gadgets(ex)

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


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='')
    parser.add_argument("target", help="path to target binary")
    parser.add_argument("object", help="path to payload object file")
    parser.add_argument("-v", "--verbose", action="store_true",
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

    pop_gadgets = search_pop_gadgets(ex, args.verbose)
    push_gadgets = search_push_gadgets(ex, args.verbose)
    payload_insns = search_payload_insn(dis, args.verbose)
    payload_matching_gadgets = []

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

    gadgets_lists['register_move'] = [
        g for g in gadgets_lists['register_move'] if check_memwrite_rules(g)
    ]
    gadgets_lists['memory_write'] = [
        g for g in gadgets_lists['memory_write'] if check_memwrite_rules(g)
    ]
    gadgets_lists['memory_read'] = [
        g for g in gadgets_lists['memory_read'] if check_memread_rules(g)
    ]

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
    # for gadget in gadgets_lists['memory_write']:
    #     if not check_memwrite_rules(gadget):
    #         gadgets_lists['memory_write'].remove(gadget)

    # for gadget in gadgets_lists['memory_read']:
    #     if check_memread_rules(gadget) is False:
    #         gadgets_lists['memory_read'].remove(gadget)
    #     # print(gadget)

    # print()

    # for i in payload_insns:
    #     print("Payload instruction: %s // mnemonic: [%s]" % (
    #         i.label, i.mnemonic))
    #     print("=" * 80)
    #     glist = find_matching_format(i, ex, pop_gadgets, args.verbose)
    #     payload_matching_gadgets.append(glist)

    # # Prints all available gadgets (after rule-checking)
    # for insn, glist in zip(payload_insns, payload_matching_gadgets):
    #     print("Payload instruction: %s // mnemonic: [%s]" % (
    #         insn.label, insn.mnemonic))
    #     print("=" * 80)
    #     for gadget in glist:
    #         print(gadget)

    # register_move_glist = []
    # for glist in payload_matching_gadgets:
    #     for g in glist:
    #         if g.instructions[0].mnemonic == 'MOV r/m32,r32' and \
    #            g.instructions[0].label.find('ptr') != -1:
    #             register_move_glist = glist

    reglist = ['eax', 'ebx', 'ecx', 'edx', 'ebp', 'esp', 'edi', 'esi']
    controlled_regs = []

    for reg in pop_gadgets:
        if reg not in controlled_regs:
            controlled_regs.append(reg.instructions[0].dst)

    missing_regs = list(set(reglist) - set(controlled_regs))

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
    move_mapping = {
        'eax': {'direct': [], 'chained': [], 'missing': []},
        'ebx': {'direct': [], 'chained': [], 'missing': []},
        'ecx': {'direct': [], 'chained': [], 'missing': []},
        'edx': {'direct': [], 'chained': [], 'missing': []},
        'ebp': {'direct': [], 'chained': [], 'missing': []},
        'esp': {'direct': [], 'chained': [], 'missing': []},
        'edi': {'direct': [], 'chained': [], 'missing': []},
        'esi': {'direct': [], 'chained': [], 'missing': []},
    }

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
