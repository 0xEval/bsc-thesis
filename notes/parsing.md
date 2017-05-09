# Main goal

We want to build a tool able to parse two input files:

  + A binary targetting X86 32bits architecture. The tool will extract all the available gadgets within the program's space using `Ropper`.
  + The dump of an object file compiled in X86 32bits containing the exploit that needs to be translated

Once parsed, we need to find a way to examine if the instructions found in the object file can be mapped with available gadgets. If so, a return-oriented payload needs to be generated (the format still needs to be determined: python string, asm, opcodes chain?)

# Parsing

To simplify the parsing job we will write a `Python` script using `Capstone` a disassembly framework (used by `Ropper`).
Ropper outputs gadget details in NASM syntax (Intel assembly), we can dump the exploit object file with `objdump` using the `-M intel` flag to obtain NASM syntax.

At first, I tried to implement a naïve Python Lexer for NASM assembly using regular expressions. However, `Capstone` provides pre-built functions able to parse much more precisely the contents of a line. This will prove especially useful when trying to deal instructions accessing memory with offsets.


# References

![Capstone Engine](http://www.capstone-engine.org/)
