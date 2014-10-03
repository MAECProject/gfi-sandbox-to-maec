#***************************************************#
#                                                   #
#      GFI Sandbox -> MAEC XML Converter Script     #
#                                                   #
# Copyright (c) 2014 - The MITRE Corporation        #
#                                                   #
#***************************************************#

#BY USING THE GFI SANDBOX TO MAEC SCRIPT, YOU SIGNIFY YOUR ACCEPTANCE OF THE TERMS AND 
#CONDITIONS OF USE.  IF YOU DO NOT AGREE TO THESE TERMS, DO NOT USE THE GFI TO MAEC SCRIPT.

#For more information, please refer to the LICENSE.txt file.

#GFI Sandbox Converter Script
#Copyright 2014, MITRE Corp
#v0.23 - BETA
#Updated 10/3/2014

from __init__ import generate_package_from_report_filepath
import sys
import os
import traceback

#Create a MAEC output file from a GFI Sandbox input file.
def create_maec(inputfile, outpath, verbose_error_mode):

    if os.path.isfile(inputfile):    
        try:
            package = generate_package_from_report_filepath(inputfile)
            #Finally, Export the results
            package.to_xml_file(outpath, {"https://github.com/MAECProject/gfi-sandbox-to-maec":"GFISandboxToMAEC"})

            print "Wrote to " + outpath

        except Exception, err:
           print('\nError: %s\n' % str(err))
           if verbose_error_mode:
                traceback.print_exc()
    else:
        print('\nError: Input file not found or inaccessible.')
        return


#Print the usage text    
def usage():
    print USAGE_TEXT
    sys.exit(1)
    
USAGE_TEXT = """
GFI Sandbox XML Output --> MAEC XML Converter Utility
v0.23 BETA // Supports MAEC v4.1 and CybOX v2.1

Usage: python gfisandbox_to_maec.py <special arguments> -i <input gfi sandbox xml output> -o <output maec xml file>
       OR -d <directory name>

Special arguments are as follows (all are optional):
-v : verbose error mode (prints tracebacks of any errors during execution).

"""    

def main():
    verbose_error_mode = 0
    infilename = ''
    outfilename = ''
    directoryname = ''
    
    #Get the command-line arguments
    args = sys.argv[1:]
    
    if len(args) < 2:
        usage()
        sys.exit(1)
        
    for i in range(0,len(args)):
        if args[i] == '-v':
            verbose_error_mode = 1
        elif args[i] == '-i':
            infilename = args[i+1]
        elif args[i] == '-o':
            outfilename = args[i+1]
        elif args[i] == '-d':
          directoryname = args[i+1]

    if directoryname != '':
        for filename in os.listdir(directoryname):
            if '.xml' not in filename:
                pass
            else:
                print filename
                outfilename = filename.rstrip('.xml') + '_gfi_maec.xml'
                create_maec(os.path.join(directoryname, filename), outfilename,
                    verbose_error_mode)

    #Basic input file checking
    elif infilename != '' and outfilename != '':
        create_maec(infilename, outfilename, verbose_error_mode)
    print 'Done'
        
if __name__ == "__main__":
    main()
