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
from maec.package.package import Package
from maec.utils import MAECNamespaceParser
import sys
import os
import traceback

#Create a MAEC output file from a ThreatExpert input file
def create_maec(inputfile, outpath, verbose_error_mode, stat_mode):
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
            package = Package(parser.generator.generate_package_id())
            
            #Add the analysis
            for subject in parser.maec_subjects:
                package.add_malware_subject(subject)
  
            package_bindings_obj = package.to_obj()
            #Finally, Export the results
            outfile = open(outpath, 'w')
            package_bindings_obj.export(outfile, 0, namespacedef_=MAECNamespaceParser(package_bindings_obj).get_namespace_schemalocation_str())
            
            print "Wrote to " + outpath
            
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
v0.92 BETA // Supports MAEC v4.0 and CybOX v2.0

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