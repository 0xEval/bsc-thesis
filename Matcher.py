import Extractor
import Disasm
import argparse

options = {
    'color': False,
    'all': False,
    'inst_count': 3,
    'type': 'rop',
    'detailed': False,
}


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

    ex = Extractor.Extractor(options, target)
    pop_gadgets = ex.search_gadgets('pop ???; ret;')
    load_gadgets = ex.search_gadgets('mov e??, [e??]')
    store_gadgets = ex.search_gadgets('mov [e??], e??')

    if args.verbose:
        print("*" * 40)
        print("Dumping: " + obj + "\n%s" % objdump)
        print("\nOpcode: %s" % opcode)
        Extractor.print_gadgets('pop', pop_gadgets)
        Extractor.print_gadgets('load', load_gadgets)
        Extractor.print_gadgets('store', store_gadgets)
