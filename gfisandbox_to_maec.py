#***************************************************#
#                                                   #
#      GFI Sandbox -> MAEC XML Converter Script     #
#                                                   #
# Copyright (c) 2014 - The MITRE Corporation        #
#                                                   #
#***************************************************#

# BY USING THE GFI SANDBOX TO MAEC SCRIPT, YOU SIGNIFY YOUR ACCEPTANCE OF THE TERMS AND 
# CONDITIONS OF USE.  IF YOU DO NOT AGREE TO THESE TERMS, DO NOT USE THE GFI TO MAEC SCRIPT.

# For more information, please refer to the LICENSE.txt file.

# GFI Sandbox Converter Script
# Copyright 2014, MITRE Corp
# v0.23 - BETA
# Updated 10/13/2014

__version__ = 0.23

import sys
import os
import traceback
import argparse
from __init__ import generate_package_from_report_filepath
from maec.misc.options import ScriptOptions

# Create a MAEC output file from a GFI Sandbox input file.
def create_maec(inputfile, outpath, verbose_error_mode, options):
    """Create the MAEC output from an input GFI Sandbox XML file"""  
    try:
        package = generate_package_from_report_filepath(inputfile, options)
        # Finally, Export the results
        package.to_xml_file(outpath, {"https://github.com/MAECProject/gfi-sandbox-to-maec":"GFISandboxToMAEC"})

    except Exception, err:
        print('\nError: %s\n' % str(err))
        if verbose_error_mode:
            traceback.print_exc()

# Print the usage text    
def usage():
    print USAGE_TEXT
    sys.exit(1)
    
USAGE_TEXT = """
GFI Sandbox XML Output --> MAEC XML Converter Utility
v0.23 BETA // Supports MAEC v4.1 and CybOX v2.1

Usage: python gfisandbox_to_maec.py <special arguments> -i <input gfi sandbox xml output OR directory> -o <output maec xml file OR directory>

Special arguments are as follows (all are optional):
-v : verbose error mode (prints tracebacks of any errors during execution).

"""    

def main():
    parser = argparse.ArgumentParser(description="GFI Sandbox to MAEC Translator v" + str(__version__))
    parser.add_argument("input", help="the name of the input GFI XML file OR directory of files to translate to MAEC")
    parser.add_argument("output", help="the name of the MAEC XML file OR directory to which the output will be written")
    parser.add_argument("--verbose", "-v", help="enable verbose error output mode", action="store_true", default=False)
    parser.add_argument("--deduplicate", "-dd", help="deduplicate the MAEC output (Objects only)", action="store_true", default=False)
    parser.add_argument("--normalize", "-n", help="normalize the MAEC output (Objects only)", action="store_true", default=False)
    parser.add_argument("--dereference", "-dr", help="dereference the MAEC output (Objects only)", action="store_true", default=False)
    args = parser.parse_args()

    
    # Build up the options instance based on the command-line input
    options = ScriptOptions()
    options.deduplicate_bundles = args.deduplicate
    options.normalize_bundles = args.normalize
    options.dereference_bundles = args.dereference

    # Test if the input is a directory or file
    if os.path.isfile(args.input):
        outfilename = args.output
        # Test if the output is a directory
        # If so, concatenate "_maec.xml" to the input filename
        # and use this as the output filename
        if os.path.isdir(args.output):
            outfilename = os.path.join(args.output, str(os.path.basename(args.input))[:-4] + "_maec.xml")
        # If we're dealing with a single file, just call create_maec()
        create_maec(args.input, outfilename, args.verbose, options)
    # If a directory was specified, perform the corresponding conversion
    elif os.path.isdir(args.input):
        # Iterate and try to parse/convert each file in the directory
        for filename in os.listdir(args.input):
            # Only handle XML files
            if str(filename)[-3:] != "xml":
                print str("Error: {0} does not appear to be an XML file. Skipping.\n").format(filename)
                continue
            outfilename = str(filename)[:-4] + "_maec.xml"
            create_maec(os.path.join(args.input, filename), os.path.join(args.output, outfilename), args.verbose, options)

        
if __name__ == "__main__":
    main()
