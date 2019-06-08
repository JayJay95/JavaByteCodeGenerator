from pandas import *
import xlrd
import re
import os
import pdb

clean_folder = 'D:/After4thYear/MSc Applied Cyber Security/Research Project/tests/JavaByteCodeGenerator/Dataset/Clean'
vuln_folder = 'D:/After4thYear/MSc Applied Cyber Security/Research Project/tests/JavaByteCodeGenerator/Dataset/Vuln'
clean_opcode_folder = 'D:/After4thYear/MSc Applied Cyber Security/Research Project/tests/JavaByteCodeGenerator/Opcodes/Clean_Opcodes'
vuln_opcode_folder = 'D:/After4thYear/MSc Applied Cyber Security/Research Project/tests/JavaByteCodeGenerator/Opcodes/Vuln_Opcodes'

def create_dictionary():
    d = {}
    wb = xlrd.open_workbook('D:/After4thYear/MSc Applied Cyber Security/Research Project/tests/JavaByteCodeGenerator/Java_Bytecode_Instructions.xlsx')
    sh = wb.sheet_by_index(0) 
    for i in range(205):
        cell_value_class = str(sh.cell(i,1).value).strip('.0') # values - opcodes in hex (binary vectors)
        cell_value_id = sh.cell(i,0).value # keys - mnemonics
        if cell_value_class == '0':
          cell_value_class = '00'
        elif cell_value_class == '1':
          cell_value_class = '01'
        elif cell_value_class == '2':
          cell_value_class = '02'
        elif cell_value_class == '3':
          cell_value_class = '03'
        elif cell_value_class == '4':
          cell_value_class = '04'  
        elif cell_value_class == '5':
          cell_value_class = '05'
        elif cell_value_class == '6':
          cell_value_class = '06'
        elif cell_value_class == '7':
          cell_value_class = '07'
        elif cell_value_class == '8':
          cell_value_class = '08'
        elif cell_value_class == '9':
          cell_value_class = '09'
        elif cell_value_class == 'a':
          cell_value_class = '0a'
        elif cell_value_class == 'b':
          cell_value_class = '0b'
        elif cell_value_class == 'c':
          cell_value_class = '0c'
        elif cell_value_class == 'd':
          cell_value_class = '0d'
        elif cell_value_class == 'e':
          cell_value_class = '0e'  
        elif cell_value_class == 'f':
          cell_value_class = '0f'
        
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
    opcode_file = clean_opcode_folder + '/' + shortname + extension
    read_bytecode_file = open(file_pathname, "r")
    write_opcode_file = open(opcode_file, "w")
    for line in read_bytecode_file:
      for mnemonic in mnemonics:
        if re.search(r'\b' + mnemonic + r'\b', line):  # match exact mnemonics     
          write_opcode_file.write(instruction_dict.get(mnemonic, "none") + "\n")
    write_opcode_file.close()
  read_bytecode_file.close()
    

def create_vuln_opcode_files():
  vuln_files = []
  find_files(vuln_files, dirs=[vuln_folder], extensions=['.txt'] ) # find all clean bytecode files in the directory 
  for file_pathname in vuln_files:
    (dirname, filename) = os.path.split(file_pathname) # split full pathname into directory name and filename(has .class)
    (shortname, extension) = os.path.splitext(filename)
    opcode_file = vuln_opcode_folder + '/' + shortname + extension
    read_bytecode_file = open(file_pathname, "r")
    write_opcode_file = open(opcode_file, "w")
    for line in read_bytecode_file:
      for mnemonic in mnemonics:
        if re.search(r'\b' + mnemonic + r'\b', line):  # match exact mnemonics            
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