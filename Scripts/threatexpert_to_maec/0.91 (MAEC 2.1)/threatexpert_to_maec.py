#****************************************************
#
#      ThreatExpert -> MAEC XML Converter Script
#
#      Copyright (c) 2012 - The MITRE Corporation
#
#****************************************************

#BY USING THE THREATEXPERT TO MAEC SCRIPT, YOU SIGNIFY YOUR ACCEPTANCE OF THE TERMS AND 
#CONDITIONS OF USE.  IF YOU DO NOT AGREE TO THESE TERMS, DO NOT USE THE THREATEXPERT
#TO MAEC SCRIPT.

#For more information, please refer to the terms.txt file.

#ThreatExpert Converter Script
#Copyright 2012, MITRE Corp
#Ivan Kirillov//ikirillov@mitre.org
#v0.91 - BETA
#Generates valid MAEC v2.1/CybOX v1.0 draft content

import threatexpert_parser as teparser
import maec_2_1 as maec
import maec_helper as maec_helper
import sys
import os
import traceback

#Create a MAEC output file from a ThreatExpert input file
def create_maec(inputfile, outputfile, verbose_error_mode, stat_mode):
    stat_actions = 0

    if os.path.isfile(inputfile):    
        #Create the main parser object
        parser = teparser.parser()
        try:
            open_file = parser.open_file(inputfile)
            
            if not open_file:
                print('\nError: Error in parsing input file. Please check to ensure that it is valid XML and conforms to the ThreatExpert output schema.')
                return
            
            #Parse the file to get the actions and processes
            parser.parse_document()
    
            #Create the MAEC bundle
            bundle = maec_helper.maec_bundle(parser.generator, 2.1)
            
            #Add the analysis
            for analysis in parser.maec_analyses:
                bundle.add_analysis(analysis)
            
            #Add all applicable actions to the bundle
            for key, value in parser.actions.items():
                for action in value:
                    bundle.add_action(action, key)
                    stat_actions += 1
  
            bundle.build_maec_bundle()
            #Finally, Export the results
            bundle.export(outputfile)
            
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
        return

#Print the usage text    
def usage():
    print USAGE_TEXT
    sys.exit(1)
    
USAGE_TEXT = """
ThreatExpert XML Output --> MAEC XML Converter Utility
v0.91 BETA // Supports MAEC v2.1 and CybOX v1.0 draft

Usage: python threatexpert_to_maec.py <special arguments> -i <input threatexpert xml output> -o <output maec xml file> 
       OR python threatexpert_to_maec.py <special arguments> -d <directory>

Special arguments are as follows (all are optional):
-s : print statistics regarding number of actions converted.
-v : verbose error mode (prints tracebacks of any errors during execution).

"""    
def main():
    verbose_error_mode = 0
    stat_mode = 0
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
        elif args[i] == '-s':
            stat_mode = 1
    
    if directoryname != '':
        for filename in os.listdir(directoryname):
            if '.xml' not in filename:
                pass
            else:
                outfilename = filename.rstrip('.xml') + '_maec.xml'
                create_maec(os.path.join(directoryname, filename), outfilename, verbose_error_mode, stat_mode)
    #Basic input file checking
    elif infilename != '' and outfilename != '':
        create_maec(infilename, outfilename, verbose_error_mode, stat_mode)
        
if __name__ == "__main__":
    main()    