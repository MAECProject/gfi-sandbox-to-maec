import gfi_parser as gfiparser
from maec.package.package import Package

def generate_package_from_parser(input_parser):
    # Parse the file and perform the translation into MAEC
    input_parser.parse_document()

    # Create the MAEC Package
    package = Package()
    
    # Add the Malware Subject
    package.add_malware_subject(input_parser.malware_subject)
        
    return package
    
def generate_package_from_report_filepath(input_path):
    parser = gfiparser.parser()
    open_file = parser.open_file(input_path)
    
    if not open_file:
        print('\nError: Error in parsing input file. Please check to ensure that it is valid XML and conforms to the GFI Sandbox output schema.')
        return
    
    return generate_package_from_parser(parser)

def generate_package_from_report_string(input_string):
    parser = gfiparser.parser()
    parser.use_input_string(input_string)
    
    return generate_package_from_parser(parser)
