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
    parser.add_argument("-q", "--quality", type=int,
                        help="maximum number of instructions in a gadget")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="enable detailed output")
    args = parser.parse_args()
    target = args.target
    obj = args.object

    if args.quality:
        options['inst_count'] = args.quality

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

    print("+" + "=" * 78 + "+")
    print("Dumping target payload <%s>:\n" % obj)
    print(objdump)
    print("+" + "=" * 78 + "+")

    print("Pop gadgets:\n")
    for g in pop_gadgets:
        print(g)
    print("Push gadgets:\n")
    for g in push_gadgets:
        print(g)

    for i in payload_insns:
        print("Payload instruction: %s // mnemonic: [%s]"
              % (i.label, i.mnemonic))
        print("=" * 80)
        glist = find_matching_format(i, ex, pop_gadgets, args.verbose)
        payload_matching_gadgets.append(glist)

    for insn, glist in zip(payload_insns, payload_matching_gadgets):
        print("Payload instruction: %s // mnemonic: [%s]"
              % (insn.label, insn.mnemonic))
        print("=" * 80)
        for gadget in glist:
            print(gadget)

    register_move_glist = find_matching_format(
        payload_insns[0], ex, pop_gadgets, args.verbose)

    memory_write_glist = find_matching_format(
        payload_insns[1], ex, pop_gadgets, args.verbose)

    # memory_read_glist = find_matching_format(
    #     payload_insns[4], ex, pop_gadgets, args.verbose)
    reglist = ['eax', 'ebx', 'ecx', 'edx', 'ebp', 'esp', 'edi', 'esi']
    controlled_regs = []
    for reg in pop_gadgets:
        if reg not in controlled_regs:
            controlled_regs.append(reg.instructions[0].dst)
    print("Controlled registers: \n\t%s" %
          colored(' '.join(str(cr) for cr in controlled_regs), 'green'))
    missing_regs = list(set(reglist) - set(controlled_regs))
    if missing_regs:
        print("Missing: \n\t%s" %
              colored(' '.join(str(mr) for mr in missing_regs), 'red'))

    print("Possible reg mov: (green = direct mov, blue = chained)")
    for reg in reglist:
        possible_movs = []
        combo_movs = []
        for g in register_move_glist:
            if g.instructions[0].src == reg and \
               g.instructions[0].dst not in possible_movs:
                possible_movs.append(g.instructions[0].dst)

        for g in register_move_glist:
            for m in possible_movs:
                if g.instructions[0].src == m and \
                   g.instructions[0].dst not in combo_movs and \
                   g.instructions[0].dst not in possible_movs:
                    combo_movs.append(g.instructions[0].dst)
            # for m in combo_movs:
            #     if g.instructions[0].src == m and \
            #        g.instructions[0].dst not in combo_movs and \
            #        g.instructions[0].dst not in possible_movs:
            #         combo_movs.append(g.instructions[0].dst)

        missing_regs = list(set(reglist) - set(possible_movs))
        missing_regs = list(set(missing_regs) - set(combo_movs))
        if possible_movs:
            print("\t%s: %s %s %s" % (
                reg,
                colored(' '.join(str(pm) for pm in possible_movs), 'green'),
                colored(' '.join(str(cm) for cm in combo_movs), 'cyan'),
                colored(' '.join(str(mr) for mr in missing_regs), 'red')
            ))

    # print_available_dest(register_move_glist)
    # print("Dest registers for MEM_WRITE: ")
    # print_available_dest(memory_write_glist)
    # print("Dest registers for MEM_READ: ")
    # print_available_dest(memory_read_glist)
