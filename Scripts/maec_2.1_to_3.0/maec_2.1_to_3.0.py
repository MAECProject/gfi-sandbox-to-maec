#MAEC v2.1 to 3.0 converter
#Generates valid MAEC 3.0 Packages/Bundles from an input MAEC v2.1 file
#v0.1 BETA

import maec_converter
import sys

#Print the usage text    
def usage():
    print USAGE_TEXT
    sys.exit(1)
    
USAGE_TEXT = """
MAEC 2.1 --> MAEC 3.0 XML Converter Utility
v0.1 BETA // Generates MAEC Package or Bundle output from an input MAEC v2.1 Bundle
Converts Behaviors, Actions, and Objects

Usage: python maec_2.1_to_3.0.py <optional flags> -i <maec 2.1 xml file> -o <maec 3.0 xml file>

Available Optional Flags:
    -v: Verbose output mode. Prints out extra information on behavior and also tracebacks for errors.
    -f: Forced output mode. Forces the converter to generate a particular type of MAEC output. Possible values are 'bundle' or 'package' for the MAEC Bundle or package, respectively.
"""

def main():
    infilename = ''
    outfilename = ''
    verbose_mode = None
    output_mode = None
    #Get the command-line arguments
    args = sys.argv[1:]
    
    if len(args) < 4:
        usage()
        sys.exit(1)
        
    for i in range(0,len(args)):
        if args[i] == '-i':
            infilename = args[i+1]
        elif args[i] == '-o':
            outfilename = args[i+1]
        elif args[i] == '-v':
            verbose_mode = True
        elif args[i] == '-f':
            output_mode = args[i+1]
            if output_mode not in ['bundle','package']:
                print("Error: invalid option for forced output mode. The value must be either 'package' or 'bundle'")

    converter = maec_converter.converter(infilename, outfilename, verbose_mode, output_mode)
    #Parse the input MAEC 2.1 and generate the output MAEC 3.0
    converter.convert_maec()
        
if __name__ == "__main__":
    main()    
