#****************************************************
#
#      ThreatExpert -> MAEC XML Converter Script
#
# Copyright (c) 2011 - The MITRE Corporation
#
#****************************************************

#BY USING THE THREATEXPERT TO MAEC SCRIPT, YOU SIGNIFY YOUR ACCEPTANCE OF THE TERMS AND 
#CONDITIONS OF USE.  IF YOU DO NOT AGREE TO THESE TERMS, DO NOT USE THE THREATEXPERT
#TO MAEC SCRIPT.

#For more information, please refer to the terms.txt file.

#ThreatExpert Converter Script
#Copyright 2011, MITRE Corp
#Ivan Kirillov//ikirillov@mitre.org
#v0.9 - beta

import threatexpert_parser as teparser
import maecv11 as maec
import maec_types as maec_types
import sys
import os
import traceback

#Print the usage text    
def usage():
    print USAGE_TEXT
    sys.exit(1)
    
USAGE_TEXT = """
ThreatExpert XML Output --> MAEC XML Converter Utility
v0.9 BETA

Usage: python threatexpert_to_maec.py <special arguments> -i <input threatexpert xml output> -o <output maec xml file>

Special arguments are as follows (all are optional):
-s : print statistics regarding number of actions and objects converted.
-v : verbose error mode (prints tracebacks of any errors during execution).

"""    
def main():
    verbose_error_mode = 0
    stat_mode = 0
    stat_actions = 0
    stat_objects = 0
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
        parser = teparser.parser()
        try:
            parser.open_file(infilename)
            #Parse the file to get the actions and processes
            print '\nParsing input file and generating MAEC objects...\n'
            parser.parse_document()
    
            #Create the MAEC bundle
            bundle = maec_types.maec_bundle(parser.generator, 1.1)
            
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
                    stat_objects += 1
            bundle.build_maec_bundle()
            ##Finally, Export the results
            bundle.export(outfilename)
            
            if stat_mode:
                print '\n---- Statistics ----'
                print str(stat_actions) + ' actions converted'
                print str(stat_objects) + ' objects generated'
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