from subprocess import call
import os

directory = 'D:/After4thYear/MSc Applied Cyber Security/Research Project/tests/Juliet_Test_Suite_v1.3_for_Java/Java/src/testcases/'     # Directory
output_dir = 'D:/After4thYear/MSc Applied Cyber Security/Research Project/tests/JavaByteCodeGenerator/Bytecode.txt'    # the txt or other file

my_output = open(output_dir, 'w')     # creates file if it does not exist & empties it if it does

def find_files( files, dirs=[], extensions=[]): # recursively find files in directories
    new_dirs = []
    for d in dirs:
        try:
            new_dirs += [ os.path.join(d, f) for f in os.listdir(d) ]
        except OSError:
            if os.path.splitext(d)[1] in extensions:
                files.append(d)

    if new_dirs:
        find_files(files, new_dirs, extensions)
    else:
        return

files = []
find_files( files, dirs=[directory], extensions=['.class'] ) # find all class files in the directory 
for file in files:
    call(["javap", "-c", file], stdout=my_output, universal_newlines=True) # convert class files to bytecode
        
my_output.close()
print ('Done :)')
