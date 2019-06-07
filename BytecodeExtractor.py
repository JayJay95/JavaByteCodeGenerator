from subprocess import call
import os
import fnmatch 
import pdb
import re

directory = 'D:/After4thYear/MSc Applied Cyber Security/Research Project/tests/Juliet_Test_Suite_v1.3_for_Java/Java/src/testcases/'     # Directory
clean_folder = 'D:/After4thYear/MSc Applied Cyber Security/Research Project/tests/JavaByteCodeGenerator/Dataset/Clean'
vuln_folder = 'D:/After4thYear/MSc Applied Cyber Security/Research Project/tests/JavaByteCodeGenerator/Dataset/Vuln'
full_class_bytecode_folder = 'D:/After4thYear/MSc Applied Cyber Security/Research Project/tests/JavaByteCodeGenerator/Full_Class_ByteCode'

good_string1 = '_good1'
good_string2 = '_good2'
good_string3 = '_good3'
good_G2B_string = 'goodG2B'
good_B2G_string = 'goodB2G'
bad_string = '_bad'
base_string = '_base'
dollar_string = '$'
main_string = 'Main'
servlet_main_string = 'ServletMain'
clone_string = '_clone_01a'
helper_string = '_Helper'
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


def match_methods():
    files = []
    find_files(files, dirs=[directory], extensions=['.class']) # find all class files in the directory 
    for file_pathname in files: 
        (dirname, filename) = os.path.split(file_pathname) # split full pathname into directory name and filename(has .class)
        (shortname, extension) = os.path.splitext(filename) # split filename into shortname and extension .class
        full_class_bytecode_file = full_class_bytecode_folder + '/' + shortname + '.txt'
        if fnmatch.fnmatch(file_pathname, "*"+good_string1+"*") or fnmatch.fnmatch(file_pathname, "*"+good_string2+"*") or fnmatch.fnmatch(file_pathname, "*"+good_string3+"*"): # good class_based flaw test cases       
            with open(full_class_bytecode_file, "w") as fa:
                call(["javap", "-c", "-private", file_pathname], stdout= fa, universal_newlines=True) # convert all good class-based flaw class files to bytecode
            fa.close()
            clean_filename = clean_folder + '/' + shortname + '_clean' + '.txt'
            with open(clean_filename, "w") as fb: # write bytecode to CWE_clean_txt file 
                call(["javap", "-c", "-private", file_pathname], stdout= fb, universal_newlines=True) # convert all good class-based flaw class files to bytecode
            fb.close()
        elif fnmatch.fnmatch(file_pathname, "*"+bad_string+"*"): # bad class_based flaw test cases
            with open(full_class_bytecode_file, "w") as fc:
                call(["javap", "-c", "-private", file_pathname], stdout= fc, universal_newlines=True) # convert all bad class-based flaw class files to bytecode
            fc.close()
            vuln_filename = vuln_folder + '/' + shortname + '_vuln' + '.txt'
            with open(vuln_filename, "w") as fd: # write bytecode to CWE_vuln_txt file 
                call(["javap", "-c", "-private", file_pathname], stdout= fd, universal_newlines=True) # convert all bad class-based flaw class files to bytecode
            fd.close()
        elif fnmatch.fnmatch(file_pathname, "*"+good_G2B_string+"*"): # goodG2B servlet class_based flaw test cases       
            with open(full_class_bytecode_file, "w") as fe:
                call(["javap", "-c", "-private", file_pathname], stdout= fe, universal_newlines=True) # convert all good class-based flaw class files to bytecode
            fe.close()
            clean_filename = clean_folder + '/' + shortname + '_clean' + '.txt'
            with open(clean_filename, "w") as ff: # write bytecode to CWE_clean_txt file 
                call(["javap", "-c", "-private", file_pathname], stdout= ff, universal_newlines=True) # convert all good class-based flaw class files to bytecode
            ff.close()
        elif fnmatch.fnmatch(file_pathname, "*"+good_B2G_string+"*"): # goodG2B servlet class_based flaw test cases       
            with open(full_class_bytecode_file, "w") as fg:
                call(["javap", "-c", "-private", file_pathname], stdout= fg, universal_newlines=True) # convert all good class-based flaw class files to bytecode
            fg.close()
            clean_filename = clean_folder + '/' + shortname + '_clean' + '.txt'
            with open(clean_filename, "w") as fh: # write bytecode to CWE_clean_txt file 
                call(["javap", "-c", "-private", file_pathname], stdout= fh, universal_newlines=True) # convert all good class-based flaw class files to bytecode
            fh.close()
        else:
            if fnmatch.fnmatch(full_class_bytecode_file, "*"+base_string+"*") or fnmatch.fnmatch(full_class_bytecode_file, "*"+dollar_string+"*") or fnmatch.fnmatch(full_class_bytecode_file, "*"+main_string+"*") or fnmatch.fnmatch(full_class_bytecode_file, "*"+servlet_main_string+"*") or fnmatch.fnmatch(full_class_bytecode_file, "*"+clone_string+"*") or fnmatch.fnmatch(full_class_bytecode_file, "*"+helper_string+"*"):
                pass
            else:
                with open(full_class_bytecode_file, "w") as fi:
                    call(["javap", "-c", "-private", file_pathname], stdout= fi, universal_newlines=True) # convert all other good/bad non-class based flaw class files to bytecode files individually
                fi.close()
                file = open(full_class_bytecode_file, "r")
                file_to_string = file.read()
                
                good_methods_by_class_file = clean_folder + '/' + shortname + '_clean' + '.txt'
                bad_methods_by_class_file =  vuln_folder + '/' + shortname + '_vuln' + '.txt'
                
                # Finding good primary methods, secondary good methods - good1, goodG2B, goodB2G
                if re.search(r'((public|private)(.*)(\bgood(\d*|G2B\d*|B2G\d*)\b)(\n*)[\s\S]+?(return)$)', file_to_string, re.MULTILINE):
                    result_good = re.finditer(r'((public|private)(.*)(\bgood(\d*|G2B\d*|B2G\d*)\b)(\n*)[\s\S]+?(return)$)', file_to_string, re.MULTILINE)           
                    with open(good_methods_by_class_file, "a") as f1:
                        for good_method in result_good:                 
                            f1.write(good_method.group() + '\n')

                # find bad primary methods      
                if re.search(r'((public|private)(.*)(\bbad\b)(\n*)[\s\S]+?(return)$)', file_to_string, re.MULTILINE):
                    result_bad = re.search(r'((public|private)(.*)(\bbad\b)(\n*)[\s\S]+?(return)$)', file_to_string, re.MULTILINE)
                    with open(bad_methods_by_class_file, "a") as f2:
                        f2.write(result_bad.group() + '\n')

                # find helperBad methods
                if re.search(r'((public|private)(.*)(\bhelperBad\b)(\n*)[\s\S]+?(return)$)', file_to_string, re.MULTILINE): 
                    result_helper_bad = re.search(r'((public|private)(.*)(\bhelperBad\b)(\n*)[\s\S]+?(return)$)', file_to_string, re.MULTILINE)      
                    with open(bad_methods_by_class_file, "a") as f3:
                        f3.write(result_helper_bad.group() + '\n')
                
                # find helperGood, helperGood1, helperGoodG2B, helperGoodB2G, helperGoodG2B1, helperGoodB2G1
                if re.search(r'((public|private)(.*)(\bhelperGood(G2B|B2G)?\d*\b)(\n*)[\s\S]+?(return)$)', file_to_string, re.MULTILINE):
                    result_helper_good = re.finditer(r'((public|private)(.*)(\bhelperGood(G2B)?\d*\b)(\n*)[\s\S]+?(return)$)', file_to_string, re.MULTILINE)       
                    with open(good_methods_by_class_file, "a") as f4:
                        for helper_good_method in result_helper_good:
                            f4.write(helper_good_method.group() + '\n')
               
                # find badSource, badSink
                if re.search(r'((public|private)(.*)(\bbadSource|badSink\b)(\n*)[\s\S]+?(return)$)', file_to_string, re.MULTILINE):
                    result_bad_source_sink = re.finditer(r'((public|private)(.*)(\bbadSource|badSink\b)(\n*)[\s\S]+?(return)$)', file_to_string, re.MULTILINE)      
                    with open(bad_methods_by_class_file, "a") as f5:
                        for bad_source_sink_method in result_bad_source_sink:
                            f5.write(bad_source_sink_method.group() + '\n')

                # find good G2B/B2G source and sink methods
                if re.search(r'(((public|private)(.*)(\b(good)(G2B|B2G)\d*(Source|Sink)\b))(\n*)[\s\S]+?(return)$)', file_to_string, re.MULTILINE):
                    result_good_source_sink_G2B_B2G = re.finditer(r'(((public|private)(.*)(\b(good)(G2B|B2G)\d*(Source|Sink)\b))(\n*)[\s\S]+?(return)$)', file_to_string, re.MULTILINE)       
                    with open(good_methods_by_class_file, "a") as f6:
                        for method in result_good_source_sink_G2B_B2G:
                            f6.write(method.group() + '\n')
                    
                # find helper Good extra methods
                if re.search(r'((public|private)(.*)(\b(helper(.+))(Good\d*)\b)(\n*)[\s\S]+?(return)$)', file_to_string, re.MULTILINE): 
                    result_helper_extra_good = re.finditer(r'((public|private)(.*)(\b(helper(.+))(Good\d*)\b)(\n*)[\s\S]+?(return)$)', file_to_string, re.MULTILINE)      
                    with open(good_methods_by_class_file, "a") as f7:
                        for helper_good_extra_method in result_helper_extra_good:
                            f7.write(helper_good_extra_method.group() + '\n')
                
                # find helper Bad extra methods
                if re.search(r'((public|private)(.*)(\b(helper(.+))(Bad\d*)\b)(\n*)[\s\S]+?(return)$)', file_to_string, re.MULTILINE):
                    result_helper_extra_bad = re.finditer(r'((public|private)(.*)(\b(helper(.+))(Bad\d*)\b)(\n*)[\s\S]+?(return)$)', file_to_string, re.MULTILINE)       
                    with open(bad_methods_by_class_file, "a") as f8:
                        for helper_bad_extra_method in result_helper_extra_bad:
                            f8.write(helper_bad_extra_method.group() + '\n')

                file.close()


def remove_main():
    clean_text_files = []
    find_files(clean_text_files, dirs=[clean_folder], extensions=['.txt']) # find all class files in the directory 
    for clean_file_pathname in clean_text_files:
        write_clean_file = open(clean_file_pathname, "r+")
        clean_file_to_string = write_clean_file.read()
        if re.search(r'((public\sstatic\svoid\smain)(.*)(\n*)(.+\n)+(return)*?$)', clean_file_to_string, re.MULTILINE):
            result_clean_main = re.search(r'((public\sstatic\svoid\smain)(.*)(\n*)(.+\n)+(return)*?$)', clean_file_to_string, re.MULTILINE)
            clean_res = clean_file_to_string.replace(str(result_clean_main.group()), "")
            write_clean_file.truncate(0)
            write_clean_file.seek(0)
            write_clean_file.write(clean_res)
        write_clean_file.close()

    vuln_text_files = []
    find_files(vuln_text_files, dirs=[vuln_folder], extensions=['.txt']) # find all class files in the directory 
    for vuln_file_pathname in vuln_text_files:
        write_vuln_file = open(vuln_file_pathname, "r+")
        vuln_file_to_string = write_vuln_file.read()
        if re.search(r'((public\sstatic\svoid\smain)(.*)(\n*)(.+\n)+(return)*?$)', vuln_file_to_string, re.MULTILINE):
            result_vuln_main = re.search(r'((public\sstatic\svoid\smain)(.*)(\n*)(.+\n)+(return)*?$)', vuln_file_to_string, re.MULTILINE)
            vuln_res = vuln_file_to_string.replace(str(result_vuln_main.group()), "")
            write_vuln_file.truncate(0)
            write_vuln_file.seek(0)
            write_vuln_file.write(vuln_res)
        write_vuln_file.close()

match_methods()
remove_main()


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
