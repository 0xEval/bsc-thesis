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


def check_matching_rules(g):
    if g.instructions[0].src == 'esp':
        print(colored('✘ read from ESP', 'red'))
        return
    for i in g.instructions[1:]:
        if i.mnemonic == 'CALL':
            print(colored('✘ call instruction', 'red'))
            return
        if i.dst == g.instructions[0].dst:
            print(colored('✘ conflicting instructions', 'red'))
            return
        if i.dst == 'esp':
            print(colored('✘ write on ESP', 'red'))
            return
    
    print(colored('✓ potential gadget', 'green'))
    

def find_matching_format(insn, ex, verbose=False):
    glist = []
    pop_gadgets_list = search_pop_gadgets(ex)
    push_gadgets_list = search_push_gadgets(ex)

    if insn.mnemonic == 'MOV r/m32,r32' or insn.mnemonic == 'MOV r/m32,imm32':
        # need to differentiate between reg to mem and reg to reg
        if insn.label.find('ptr') != -1:
            glist = ex.search_gadgets('mov [e??], e??')
        else:
            glist = ex.search_gadgets('mov e??, e??')
        
        glist = sorted(glist, key=lambda gadget:len(gadget.instructions))
        for g in glist:
            print(g)

    if insn.mnemonic == 'MOV r32,r/m32':
        glist = ex.search_gadgets('mov e??, [e??]')
        glist = sorted(glist, key=lambda gadget:len(gadget.instructions))
        for g in glist:
            if not is_controllable(insn.src, pop_gadgets_list) or \
                    not is_controllable(insn.dst, pop_gadgets_list):
                print(colored('✘ register(s) not controlled', 'red'))
            
            check_matching_rules(g)
            print(g)

    return glist


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
        find_matching_format(i, ex, args.verbose)
