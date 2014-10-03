import gfi_parser as gfiparser
from maec.package.package import Package

def generate_package_from_parser(input_parser, options = None):
    # Parse the file and perform the translation into MAEC
    input_parser.parse_document()

    # Create the MAEC Package
    package = Package()
    
    # Get the Malware Subject
    malware_subject = input_parser.malware_subject

    # Check for the existence of the options structure and if any are set
    # If so, perform the appropriate actions
    if options:
        if options.normalize_bundles:
            malware_subject.normalize_bundles()
        if options.deduplicate_bundles:
            malware_subject.deduplicate_bundles()
        if options.dereference_bundles:
            malware_subject.dereference_bundles()
        
    # Add the Malware Subject
    package.add_malware_subject(malware_subject)

    return package
    
def generate_package_from_report_filepath(input_path, options = None):
    parser = gfiparser.parser()
    
    if not parser.open_file(input_path):
        print('\nError: Error in parsing input file. Please check to ensure that it is valid XML and conforms to the GFI Sandbox output schema.')
        return
    
    return generate_package_from_parser(parser, options)

def generate_package_from_report_string(input_string, options = None):
    parser = gfiparser.parser()
    parser.use_input_string(input_string)
    
    return generate_package_from_parser(parser, options)
