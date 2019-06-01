from pandas import *
import xlrd
import re
import os

clean_folder = 'D:/After4thYear/MSc Applied Cyber Security/Research Project/tests/JavaByteCodeGenerator/Dataset/Clean'
vuln_folder = 'D:/After4thYear/MSc Applied Cyber Security/Research Project/tests/JavaByteCodeGenerator/Dataset/Vuln'
clean_opcode_folder = 'D:/After4thYear/MSc Applied Cyber Security/Research Project/tests/JavaByteCodeGenerator/Opcodes/Clean_Opcodes'
vuln_opcode_folder = 'D:/After4thYear/MSc Applied Cyber Security/Research Project/tests/JavaByteCodeGenerator/Opcodes/Vuln_Opcodes'

def create_dictionary():
    d = {}
    wb = xlrd.open_workbook('D:/After4thYear/MSc Applied Cyber Security/Research Project/tests/JavaByteCodeGenerator/Java_Bytecode_Instructions.xlsx')
    sh = wb.sheet_by_index(0) 
    for i in range(206):
        cell_value_class = str(sh.cell(i,1).value).replace(" ", "") # values - opcodes in binary (binary vectors)
        cell_value_id = sh.cell(i,0).value # keys - mnemonics
        d[cell_value_id] = cell_value_class
    return d

def find_files( files, dirs=[], extensions=[]): # recursively find files in directories
    new_dirs = []
    for d in dirs:
        try:
            new_dirs += [ os.path.join(d, f) for f in os.listdir(d)] # check in all directories 
        except OSError:
            if os.path.splitext(d)[1] in extensions:
                files.append(d)

    if new_dirs:
        find_files(files, new_dirs, extensions)
    else:
        return

def create_clean_opcode_files():
  clean_files = []
  find_files(clean_files, dirs=[clean_folder], extensions=['.txt'] ) # find all clean bytecode files in the directory 
  for file_pathname in clean_files:
    (dirname, filename) = os.path.split(file_pathname) # split full pathname into directory name and filename(has .class)
    (shortname, extension) = os.path.splitext(filename)
    read_bytecode_file = open(file_pathname, "r")
    write_opcode_file = open(opcode_file, "w")
    for line in read_bytecode_file:
      for mnemonic in mnemonics:
        if re.search(r'\b' + mnemonic + r'\b', line):  # match exact mnemonics
            opcode_file = clean_opcode_folder + '/' + shortname + extension
            write_opcode_file.write(instruction_dict.get(mnemonic, "none") + "\n")
    write_opcode_file.close()
  read_bytecode_file.close()  

def create_vuln_opcode_files():
  vuln_files = []
  find_files(vuln_files, dirs=[vuln_folder], extensions=['.txt'] ) # find all clean bytecode files in the directory 
  for file_pathname in vuln_files:
    (dirname, filename) = os.path.split(file_pathname) # split full pathname into directory name and filename(has .class)
    (shortname, extension) = os.path.splitext(filename)
    read_bytecode_file = open(file_pathname, "r")
    write_opcode_file = open(opcode_file, "w")
    for line in read_bytecode_file:
      for mnemonic in mnemonics:
        if re.search(r'\b' + mnemonic + r'\b', line):  # match exact mnemonics
            opcode_file = vuln_opcode_folder + '/' + shortname + extension
            write_opcode_file.write(instruction_dict.get(mnemonic, "none") + "\n")
    write_opcode_file.close()
  read_bytecode_file.close()

instruction_dict = create_dictionary()
mnemonics = instruction_dict.keys()

create_clean_opcode_files()     
create_vuln_opcode_files()

# Old Code
# instruction_dict = create_dictionary()
# mnemonics = instruction_dict.keys() 
# write_opcode_file = open(opcode_file, "w")
# read_bytecode_file = open(bytecode_dir, "r")
# for line in read_bytecode_file:
#     for mnemonic in mnemonics:
#           if re.search(r'\b' + mnemonic + r'\b', line):  # match exact mnemonics
#             write_opcode_file.write(instruction_dict.get(mnemonic, "none") + "\n")
# write_opcode_file.close()
# read_bytecode_file.close()