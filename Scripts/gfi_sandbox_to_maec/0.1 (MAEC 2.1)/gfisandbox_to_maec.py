#***************************************************#
#                                                   #
#      GFI Sandbox -> MAEC XML Converter Script     #
#                                                   #
# Copyright (c) 2012 - The MITRE Corporation        #
#                                                   #
#***************************************************#

#BY USING THE GFI SANDBOX TO MAEC SCRIPT, YOU SIGNIFY YOUR ACCEPTANCE OF THE TERMS AND 
#CONDITIONS OF USE.  IF YOU DO NOT AGREE TO THESE TERMS, DO NOT USE THE GFI TO MAEC SCRIPT.

#For more information, please refer to the terms.txt file.

#GFI Sandbox -> MAEC Converter Script
#Copyright 2012, MITRE Corp
#Ivan Kirillov//ikirillov@mitre.org
#v0.1 - beta


import gfi_parser
import maec_helper
import sys
import os
import traceback

#Print the usage text    
def usage():
    print USAGE_TEXT
    sys.exit(1)
    
USAGE_TEXT = """
GFI Sandbox XML Output --> MAEC XML Converter Utility
v0.1 BETA
Generates valid MAEC v2.1 content

Usage: python gfisandbox_to_maec.py <special arguments> -i <input gfi sandbox xml output> -o <output maec xml file>

Special arguments are as follows (all are optional):
-s : print statistics regarding number of actions converted.
-v : verbose error mode (prints tracebacks of any errors during execution).
"""    
def main():
    verbose_error_mode = 0
    stat_mode = 0
    stat_actions = 0
    infilename = ''
    outfilename = ''
    
    #Get the command-line arguments
    args = sys.argv[1:]
    
    if len(args) < 4:
        usage()
        sys.exit(1)
        
    for i in range(0,len(args)):
        if args[i] == '-v':
            verbose_error_mode = 1
        elif args[i] == '-i':
            infilename = args[i+1]
        elif args[i] == '-o':
            outfilename = args[i+1]
        elif args[i] == '-s':
            stat_mode = 1
            
    #Basic input file checking
    if os.path.isfile(infilename):    
        #Create the main parser object
        parser = gfi_parser.parser()
        try:
            open_file = parser.open_file(infilename)
            
            if not open_file:
                print('\nError: Error in parsing input file. Please check to ensure that it is valid XML and conforms to the GFI Sandbox output schema.')
                sys.exit(1)
            
            #Parse the file to get the actions and processes
            print '\nParsing input file and generating MAEC objects...\n'
            parser.parse_document()
    
            #Create the MAEC bundle
            bundle = maec_helper.maec_bundle(parser.generator, 2.1)
            
            #Add the analysis
            bundle.add_analysis(parser.maec_analysis)
            
            #Add all applicable actions to the bundle
            for key, value in parser.actions.items():
                for action in value:
                    bundle.add_action(action, key)
                    stat_actions += 1
            #Add all applicable objects to the bundle
            for key, value in parser.objects.items():
                for object in value:
                    bundle.add_object(object, key)
            bundle.build_maec_bundle()
            ##Finally, Export the results
            bundle.export(outfilename)
            
            if stat_mode:
                print '\n---- Statistics ----'
                print str(stat_actions) + ' actions converted'
                #print str(converter.stat_behaviors) + ' behaviors extracted'
        except Exception, err:
           print('\nError: %s\n' % str(err))
           if verbose_error_mode:
                traceback.print_exc()
    else:
        print('\nError: Input file not found or inaccessible.')
        sys.exit(1)
        
if __name__ == "__main__":
    main()    