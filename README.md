# JavaByteCodeGenerator for NIST Juliet SARD testsuite

This program takes class files from the NIST Juliet SARD testsuite and compiles them into bytecode per class files. 

We then iterate through each class file and extract good methods and put these in a new byte code file for a particular CWE. 
We do the same for bad methods by iterating through each class file and putting these in a new byte code file for a particular CWE.
In the end, we have a collection of clean bytecode files per CWE per flaww type and vulnerable bytecode files per CWE per flaw type. 
These are stored in the 'Dataset/Clean' and 'Dataset/Vuln' folders respectively.

Then, for the purposes of feeding our software vulnerability analysis neural network, we create a dictionary of the Java list of
instructions i.e mnemonics and corresponding opcodes(in binary vector form).

With this dictionary, we match each line in the clean bytecode text files to our mnemonic keys. If there's a mnemonic word match,
the mnemonic's key's value (which is the opcode) is added to a clean opcode file per bytecode file. 
Same is done for each of the vulnerable bytecode text files.
These will be stored in the 'Opcodes/Clean_Opcodes' and 'Opcodes/Vuln_Opcodes' folders respectively.

We then read each of these opcode files and create a list that holds opcodes for each line from each opcode file. 
A line represents a method/collection of methods e.g if there are three good methods in that one line for a particular CWE flaw type. 
We then append this list to a 'clean' and 'vuln' list that will now be a list of opcode lists:
    clean = [[opcodes_for_line_1_clean_file_1], [opcodes_for_line_2_clean_file_1]]
    vuln = [[opcodes_for_line_1_vuln_file_1], [opcodes_for_line_1_vuln_file_1]]

We append labels 1 or 0 to each list within depending on whether it is clean or vulnerable:
    final_clean_list = [[[opcodes_for_line_1_clean_file_1], 1], [[opcodes_for_line_2_clean_file_1], 1]...]
    final_vuln_list = [[[opcodes_for_line_1_vuln_file_1], 0], [[opcodes_for_line_1_vuln_file_1], 0]...]

The neural network is then fed and trained on the clean and vuln samples. 
