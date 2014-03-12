#***************************************************#
#                                                   #
#      GFI Sandbox -> MAEC XML Converter Script     #
#                                                   #
# Copyright (c) 2014 - The MITRE Corporation        #
#                                                   #
#***************************************************#

#BY USING THE GFI SANDBOX TO MAEC SCRIPT, YOU SIGNIFY YOUR ACCEPTANCE OF THE TERMS AND 
#CONDITIONS OF USE.  IF YOU DO NOT AGREE TO THESE TERMS, DO NOT USE THE GFI TO MAEC SCRIPT.

#For more information, please refer to the terms.txt file.

#GFI Sandbox Converter Script
#Copyright 2014, MITRE Corp
#v0.22 - BETA
#Updated 03/06/2014 for MAEC v4.1 and CybOX v2.1

import gfi_parser as gparser
from maec.package.package import Package
import sys
import os
import traceback

#Create a MAEC output file from a GFI Sandbox input file.
def create_maec(inputfile, outpath, verbose_error_mode):

    if os.path.isfile(inputfile):    

        #Create the main parser object
        parser = gparser.parser()

        try:
            open_file = parser.open_file(inputfile)
            
            if not open_file:
                print('\nError: Error in parsing input file. Please check to ensure that it is valid XML and conforms to the GFI Sandbox output schema.')
                return
            
            #Parse the file to get the actions and processes
            parser.parse_document()

            #Create the MAEC package
            package = Package()

            #Add the analysis
            package.add_malware_subject(parser.malware_subject)

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
v0.22 BETA // Supports MAEC v4.1 and CybOX v2.1

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
