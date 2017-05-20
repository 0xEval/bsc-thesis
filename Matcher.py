import Extractor
import Disasm
import argparse
import pprint
from capstone import CS_ARCH_X86, CS_MODE_32
from Extractor import print_gadgets

ROPPER_REGEX = {
    'MOV r/m32,r32': 'mov e??, e??',    # Move r16(or 32) to r/m16(or 32).
    'MOV r32,r/m32': 'mov e??, [???]',    # Move r/m16 to r16.
}

options = {
    'color': False,
    'all': False,
    'inst_count': 3,
    'type': 'rop',
    'detailed': False,
}


def search_controllable_regs(extractor, verbose=False):
    regs = extractor.search_gadgets('pop ???; ret;')
    if verbose:
        print("Found %s controllable registers:" % len(regs))
        for g in regs:
            print(g)
    return regs


def search_payload_insn(disassembler, verbose=False):
    insn = disassembler.extract_insn()
    if verbose:
        for i in insn:
            print(i)
    return insn


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

    bin_regs = search_controllable_regs(ex, args.verbose)
    payload_insns = search_payload_insn(dis, args.verbose)

    print("+" + "=" * 78 + "+")
    print("Dumping target payload <%s>:\n" % obj)
    print(objdump)
    print("+" + "=" * 78 + "+")

    for reg in bin_regs:
        print(reg)

    for i in payload_insns:
        glist = []
        print("Payload instruction: %s // mnemonic: [%s]"
              % (i.label, i.mnemonic))
        print("=" * 80)
        if i.mnemonic == 'MOV r32,r/m32':
            glist = ex.search_gadgets('mov e??, [e??]')
        elif i.mnemonic == 'MOV r/m32,r32':
            glist = ex.search_gadgets('mov [e??], e??')
            glist += ex.search_gadgets('mov e??, e??')
        elif i.mnemonic == 'MOV r/m32,imm32':
            tmp = ex.search_gadgets('mov [e??], %')
            for i in tmp:
                print(i)
        for g in glist:
            print(g)
