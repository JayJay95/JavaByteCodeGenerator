from pandas import *
import xlrd
import re

bytecode_dir = 'D:/After4thYear/MSc Applied Cyber Security/Research Project/tests/JavaByteCodeGenerator/ByteCode.txt'
opcode_file = 'D:/After4thYear/MSc Applied Cyber Security/Research Project/tests/JavaByteCodeGenerator/Opcode.txt'

def create_dictionary():
    d = {}
    wb = xlrd.open_workbook('D:/After4thYear/MSc Applied Cyber Security/Research Project/tests/JavaByteCodeGenerator/Java_Bytecode_Instructions.xlsx')
    sh = wb.sheet_by_index(0) 
    for i in range(206):
        cell_value_class = str(sh.cell(i,1).value).strip('.0') # values - opcodes
        cell_value_id = sh.cell(i,0).value # keys - mnemonics
        d[cell_value_id] = cell_value_class
    return d

instruction_dict = create_dictionary()
mnemonics = instruction_dict.keys() 
write_opcode_file = open(opcode_file, "w")
read_bytecode_file = open(bytecode_dir, "r")
for line in read_bytecode_file:
    for mnemonic in mnemonics:
          if re.search(r'\b' + mnemonic + r'\b', line):  # match exact mnemonics
            write_opcode_file.write(instruction_dict.get(mnemonic, "none") + "\n")
write_opcode_file.close()
read_bytecode_file.close()