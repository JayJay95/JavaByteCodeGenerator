from subprocess import call
import os
import fnmatch 
import pdb
import re

directory = 'D:/After4thYear/MSc Applied Cyber Security/Research Project/tests/Juliet_Test_Suite_v1.3_for_Java/Java/src/testcases/'     # Directory
clean_folder = 'D:/After4thYear/MSc Applied Cyber Security/Research Project/tests/JavaByteCodeGenerator/Dataset/Clean'
vuln_folder = 'D:/After4thYear/MSc Applied Cyber Security/Research Project/tests/JavaByteCodeGenerator/Dataset/Vuln'
full_class_bytecode_folder = 'D:/After4thYear/MSc Applied Cyber Security/Research Project/tests/JavaByteCodeGenerator/Full_Class_ByteCode'

good_string = '_good1'
bad_string = '_bad'
ignored_folders = {"testcasesupport"}

def find_files( files, dirs=[], extensions=[]): # recursively find files in directories
    new_dirs = []
    for d in dirs:
        try:
            new_dirs += [ os.path.join(d, f) for f in os.listdir(d) if f not in ignored_folders] # check in all directories except testcasesupport 
        except OSError:
            if os.path.splitext(d)[1] in extensions:
                files.append(d)

    if new_dirs:
        find_files(files, new_dirs, extensions)
    else:
        return

files = []
find_files(files, dirs=[directory], extensions=['.class']) # find all class files in the directory 
for file_pathname in files: 
   (dirname, filename) = os.path.split(file_pathname) # split full pathname into directory name and filename(has .class)
   (shortname, extension) = os.path.splitext(filename) # split filename into shortname and extension .class
   full_class_bytecode_file = full_class_bytecode_folder + '/' + shortname + '.txt'
   if fnmatch.fnmatch(file_pathname, "*"+good_string+"*"): # good class_based flaw test cases       
       with open(full_class_bytecode_file, "w") as fa:
        call(["javap", "-c", file_pathname], stdout= fa, universal_newlines=True) # convert all good class-based flaw class files to bytecode
       fa.close()
       clean_filename = clean_folder + '/' + shortname + '_clean' + '.txt'
       with open(clean_filename, "w") as fb: # write bytecode to CWE_clean_txt file 
           call(["javap", "-c", file_pathname], stdout= fb, universal_newlines=True) # convert all good class-based flaw class files to bytecode
       fb.close()
   elif fnmatch.fnmatch(file_pathname, "*"+bad_string+"*"): # bad class_based flaw test cases
       with open(full_class_bytecode_file, "w") as fc:
        call(["javap", "-c", file_pathname], stdout= fc, universal_newlines=True) # convert all bad class-based flaw class files to bytecode
       fc.close()
       vuln_filename = vuln_folder + '/' + shortname + '_vuln' + '.txt'
       with open(vuln_filename, "w") as fd: # write bytecode to CWE_vuln_txt file 
           call(["javap", "-c", file_pathname], stdout= fd, universal_newlines=True) # convert all bad class-based flaw class files to bytecode
       fd.close()
   else:
       with open(full_class_bytecode_file, "w") as fe:
        call(["javap", "-c", file_pathname], stdout= fe, universal_newlines=True) # convert all other good/bad non-class based flaw class files to bytecode files individually
       fe.close()
       file = open(full_class_bytecode_file, "r")
       file_to_string = file.read()
       
       if re.search(r'((public|private)(.*)(\bgood\b)(.*)(\n*)(.+\n)+(return)*?$)', file_to_string, re.MULTILINE):
           result_good = re.search(r'((public|private)(.*)(\bgood\b)(.*)(\n*)(.+\n)+(return)*?$)', file_to_string, re.MULTILINE)       
           good_methods_by_class_file = clean_folder + '/' + shortname + '_clean' + '.txt'
           with open(good_methods_by_class_file, "a") as f1:
               f1.write(result_good.group())
               f1.close()
               
       if re.search(r'((public|private)(.*)(\bbad\b)(.*)(\n*)(.+\n)+(return)*?$)', file_to_string, re.MULTILINE):
           result_bad = re.search(r'((public|private)(.*)(\bbad\b)(.*)(\n*)(.+\n)+(return)*?$)', file_to_string, re.MULTILINE)      
           bad_methods_by_class_file =  vuln_folder + '/' + shortname + '_vuln' + '.txt'
           with open(bad_methods_by_class_file, "a") as f2:
               f2.write(result_bad.group())
               f2.close()

       if re.search(r'((public|private)(.*)(\bgood(\d+|G2B\d*)\b)(.*)(\n*)(.+\n)+(return)*?$)', file_to_string, re.MULTILINE):  
           result_secondary_good_G2B = re.search(r'((public|private)(.*)(\bgood(\d+|G2B\d*)\b)(.*)(\n*)(.+\n)+(return)*?$)', file_to_string, re.MULTILINE)      
           with open(good_methods_by_class_file, "a") as f3:
               f3.write(result_secondary_good_G2B.group())
               f3.close()

       if re.search(r'((public|private)(.*)(\bgood(\d+|B2G\d*)\b)(.*)(\n*)(.+\n)+(return)*?$)', file_to_string, re.MULTILINE):
           result_secondary_good_B2G = re.search(r'((public|private)(.*)(\bgood(\d+|B2G\d*)\b)(.*)(\n*)(.+\n)+(return)*?$)', file_to_string, re.MULTILINE)      
           with open(good_methods_by_class_file, "a") as f4:
               f4.write(result_secondary_good_B2G.group())
               f4.close()

       if re.search(r'((public|private)(.*)(\bhelperBad\b)(.*)(\n*)(.+\n)+(return)*?$)', file_to_string, re.MULTILINE): 
           result_helper_bad = re.search(r'((public|private)(.*)(\bhelperBad\b)(.*)(\n*)(.+\n)+(return)*?$)', file_to_string, re.MULTILINE)      
           with open(bad_methods_by_class_file, "a") as f5:
               f5.write(result_helper_bad.group())
               f5.close()

       if re.search(r'((public|private)(.*)(\bhelperGood(G2B)?\d*\b)(.*)(\n*)(.+\n)+(return)*?$)', file_to_string, re.MULTILINE):
           result_helper_good_G2B = re.search(r'((public|private)(.*)(\bhelperGood(G2B)?\d*\b)(.*)(\n*)(.+\n)+(return)*?$)', file_to_string, re.MULTILINE)       
           with open(good_methods_by_class_file, "a") as f6:
               f6.write(result_helper_good_G2B.group())
               f6.close()

       if re.search(r'((public|private)(.*)(\bhelperGood(B2G)?\d*\b)(.*)(\n*)(.+\n)+(return)*?$)', file_to_string, re.MULTILINE):
           result_helper_good_B2G = re.search(r'((public|private)(.*)(\bhelperGood(B2G)?\d*\b)(.*)(\n*)(.+\n)+(return)*?$)', file_to_string, re.MULTILINE)       
           with open(good_methods_by_class_file, "a") as f7:
               f7.write(result_helper_good_B2G.group())
               f7.close()

       if re.search(r'((public|private)(.*)(\bbadSource\b)(.*)(\n*)(.+\n)+(return)*?$)', file_to_string, re.MULTILINE):
           result_bad_source = re.search(r'((public|private)(.*)(\bbadSource\b)(.*)(\n*)(.+\n)+(return)*?$)', file_to_string, re.MULTILINE)      
           with open(bad_methods_by_class_file, "a") as f8:
               f8.write(result_bad_source.group())
               f8.close()

       if re.search(r'((public|private)(.*)(\bbadSink\b)(.*)(\n*)(.+\n)+(return)*?$)', file_to_string, re.MULTILINE):
           result_bad_sink = re.search(r'((public|private)(.*)(\bbadSink\b)(.*)(\n*)(.+\n)+(return)*?$)', file_to_string, re.MULTILINE)      
           with open(bad_methods_by_class_file, "a") as f9:
               f9.write(result_bad_sink.group())
               f9.close()
     
       if re.search(r'((public|private)(.*)(\bgood(G2B\d*)?Source\b)(.*)(\n*)(.+\n)+(return)*?$)', file_to_string, re.MULTILINE):
           result_good_source_G2B = re.search(r'((public|private)(.*)(\bgood(G2B\d*)?Source\b)(.*)(\n*)(.+\n)+(return)*?$)', file_to_string, re.MULTILINE)       
           with open(good_methods_by_class_file, "a") as f10:
               f10.write(result_good_source_G2B.group())
               f10.close()

       if re.search(r'((public|private)(.*)(\bgood(B2G\d*)?Source\b)(.*)(\n*)(.+\n)+(return)*?$)', file_to_string, re.MULTILINE):
           result_good_source_B2G = re.search(r'((public|private)(.*)(\bgood(B2G\d*)?Source\b)(.*)(\n*)(.+\n)+(return)*?$)', file_to_string, re.MULTILINE)       
           with open(good_methods_by_class_file, "a") as f11:
               f11.write(result_good_source_B2G.group())
               f11.close()

       if re.search(r'((public|private)(.*)(\bgood(G2B\d*)?Sink\b)(.*)(\n*)(.+\n)+(return)*?$)', file_to_string, re.MULTILINE):
          result_good_sink_G2B = re.search(r'((public|private)(.*)(\bgood(G2B\d*)?Sink\b)(.*)(\n*)(.+\n)+(return)*?$)', file_to_string, re.MULTILINE)       
          with open(good_methods_by_class_file, "a") as f12:
              f12.write(result_good_sink_G2B.group())
              f12.close()
    
       if re.search(r'((public|private)(.*)(\bgood(B2G\d*)?Sink\b)(.*)(\n*)(.+\n)+(return)*?$)', file_to_string, re.MULTILINE):
           result_good_sink_B2G = re.search(r'((public|private)(.*)(\bgood(B2G\d*)?Sink\b)(.*)(\n*)(.+\n)+(return)*?$)', file_to_string, re.MULTILINE)       
           with open(good_methods_by_class_file, "a") as f13:
               f13.write(result_good_sink_B2G.group())
               f13.close()

       file.close()



# Old Code
# from subprocess import call
# import os

# directory = 'D:/After4thYear/MSc Applied Cyber Security/Research Project/tests/Juliet_Test_Suite_v1.3_for_Java/Java/src/testcases/'     # Directory
# output_dir = 'D:/After4thYear/MSc Applied Cyber Security/Research Project/tests/JavaByteCodeGenerator/Bytecode.txt'    # the txt or other file

# my_output = open(output_dir, 'w')     # creates file if it does not exist & empties it if it does

# def find_files( files, dirs=[], extensions=[]): # recursively find files in directories
#     new_dirs = []
#     for d in dirs:
#         try:
#             new_dirs += [ os.path.join(d, f) for f in os.listdir(d) ]
#         except OSError:
#             if os.path.splitext(d)[1] in extensions:
#                 files.append(d)

#     if new_dirs:
#         find_files(files, new_dirs, extensions)
#     else:
#         return

# files = []
# find_files( files, dirs=[directory], extensions=['.class'] ) # find all class files in the directory 
# for file in files:
#     call(["javap", "-c", file], stdout=my_output, universal_newlines=True) # convert class files to bytecode
        
# my_output.close()
# print ('Done :)')