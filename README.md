# JavaByteCodeGenerator
This program takes class files from the NIST Juliet SARD testsuite and compiles them into bytecode in the output file 'ByteCode.txt'

Then, for the purposes of feeding our software vulnerability analysis neural network, we create a dictionary of the Java list of
instructions i.e mnemonics and corresponding opcodes.

With this dictionary, we match each line in the ByteCode.txt file to our mnemonic keys. If there's a mnemonic word match,
the mnemonic's key's value (which is the opcode) is added to the file 'Opcode.txt' which will eventually have all the opcodes
used within 'ByteCode.txt'.
