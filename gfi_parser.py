# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# For more information, please refer to the terms.txt file.

#GFI Sandbox Converter Script
#Updated 02/24/2014 for MAEC v4.1 and CybOX v2.1

#GFI main parser class
#For use in extracting data from XML GFI output
from maec.bundle.bundle import Bundle
from maec.bundle.bundle_reference import BundleReference
from maec.bundle.action_reference_list import ActionReferenceList, ActionReference
from maec.bundle.malware_action import MalwareAction
from maec.bundle.av_classification import AVClassification, AVClassifications
from maec.bundle.process_tree import ProcessTree, ProcessTreeNode
from maec.package.package import Package
from maec.package.analysis import Analysis, DynamicAnalysisMetadata
from maec.package.malware_subject import MalwareSubject
import maec.utils
from cybox.utils import Namespace
from cybox.core.object import Object
from cybox.core.associated_object import AssociatedObject
from cybox.common import ToolInformation, StructuredText
import gfi.filesystem_section
import gfi.registry_section
import gfi.process_section
import gfi.virtualmemory_section
import gfi.filemapping_section
import gfi.thread_section
import gfi.sysobject_section
import gfi.system_section
import gfi.service_section
import gfi.user_section
import gfi.share_section
import gfi.module_section
import gfi.networkoperation_section
import gfi.networkpacket_section
import gfi.mapped_modules
import gfi_sandbox
import inspect
import traceback
import sys

class parser:
    def __init__(self):

        # Instantiate the ID generator class (for automatic ID generation) with
        # our example namespace.
        NS = Namespace("https://github.com/MAECProject/gfi-sandbox-to-maec", "GFISandboxToMAEC")
        maec.utils.set_id_namespace(NS)

        #Setup the MAEC components
        self.tool_id = maec.utils.idgen.create_id(prefix="tool")
        self.malware_subject = MalwareSubject()
        self.bundle = Bundle(None, False, "4.1", "dynamic analysis tool output")
        self.scanner_bundle = None
        self.process_tree = ProcessTree()
        self.__setup_components()

    #Open and read-in the GFI Sandbox output file
    #This assumes that we're dealing with an XML file
    def open_file(self, infilename):
        try:
            self.analysis = gfi_sandbox.parse(infilename)
            if self.analysis == None:
                return False
            else:
                return True
        except Exception, err:
           print('\nError: %s\n' % str(err))
           traceback.print_exc()
    
    #Parse the GFI XML document
    def parse_document(self):

        #Get the processes captured in the analysis
        processes = self.analysis.get_processes()
        calltree = self.analysis.get_calltree()
        running_processes = self.analysis.get_running_processes()

        #Handle the analysis information
        self.__handle_analysis()

        #Add the Malware Instance Object Attributes to the Subject
        self.__add_malware_instance_object_attributes()

        #Handle each process and create the corresponding MAEC entities
        for process in processes.get_process():
            try:
                monitor_reason = process.get_monitor_reason()
                parent_pid = str(process.get_parent_pid())
                if monitor_reason == 'AnalysisTarget':
                    self.process_tree.set_root_process(self.__handle_process(process))
                    #Handle the scanner (AV Classification) section, just for the malware instance for now
                    self.__handle_scanner_section(process.get_scanner_section())
                elif parent_pid is not '0' and monitor_reason == 'CreatedProcess':
                    self.process_tree.root_process.add_spawned_process(self.__handle_process(process), parent_pid)
                elif parent_pid is not '0' and monitor_reason == 'InjectedThread':
                    self.process_tree.root_process.add_injected_process(self.__handle_process(process), parent_pid)
                elif parent_pid is not '0':
                    self.process_tree.root_process.add_spawned_process(self.__handle_process(process), parent_pid)
            except Exception, err:
                print('\nError: %s\n' % str(err))
                traceback.print_exc()
        return
    
    #"Private" methods
    def __setup_components(self):
        #Build the MAEC Components
        #self.maec_package.add_malware_subject(self.malware_subject)
        self.malware_subject.add_findings_bundle(self.bundle)
        self.bundle.set_process_tree(self.process_tree)
        #Setup the Action Collections
        self.bundle.add_named_action_collection("File System Actions")
        self.bundle.add_named_action_collection("Service Actions")
        self.bundle.add_named_action_collection("Registry Actions")
        self.bundle.add_named_action_collection("GUI Actions")
        self.bundle.add_named_action_collection("Network Actions")
        self.bundle.add_named_action_collection("Process Memory Actions")
        self.bundle.add_named_action_collection("Process Actions")
        self.bundle.add_named_action_collection("Module Actions")
        self.bundle.add_named_action_collection("System Actions")
        self.bundle.add_named_action_collection("Internet Actions")
        self.bundle.add_named_action_collection("Filemapping Actions")
        self.bundle.add_named_action_collection("Thread Actions")
        self.bundle.add_named_action_collection("Synchronization Actions")
        self.bundle.add_named_action_collection("Driver Actions")
        self.bundle.add_named_action_collection("User Actions")
        self.bundle.add_named_action_collection("Network Share Actions")

    #Handle a GFI process object
    #Extract applicable elements and process them
    def __handle_process(self, process):
        action_id_list = []
        #First, create the process tree node object
        process_tree_node = self.__create_process_tree_node_object(process)
        #Next, handle all of the included actions
        #self.__handle_stored_modified_files(process.get_stored_modified_files(), process_tree_node)
        #self.__handle_mapped_modules(process.get_mapped_modules(), process_tree_node)
        self.__handle_gfi_sandbox_section(process.get_filesystem_section(), gfi.filesystem_section.filesystem_section_handler(), 
                                          process_tree_node, 'File System Actions', action_id_list)
        self.__handle_gfi_sandbox_section(process.get_registry_section(), gfi.registry_section.registry_section_handler(),
                                          process_tree_node, 'Registry Actions', action_id_list)
        self.__handle_gfi_sandbox_section(process.get_process_section(), gfi.process_section.process_section_handler(),
                                          process_tree_node, 'Process Actions', action_id_list)
        self.__handle_gfi_sandbox_section(process.get_virtualmemory_section(), gfi.virtualmemory_section.virtualmemory_section_handler(),
                                          process_tree_node, 'Process Memory Actions', action_id_list)
        self.__handle_gfi_sandbox_section(process.get_mapped_modules(), gfi.mapped_modules.mapped_modules_handler(),
                                          process_tree_node, 'Process Memory Actions', action_id_list)
        self.__handle_gfi_sandbox_section(process.get_filemapping_section(), gfi.filemapping_section.filemapping_section_handler(),
                                          process_tree_node, 'Filemapping Actions', action_id_list)
        self.__handle_gfi_sandbox_section(process.get_thread_section(), gfi.thread_section.thread_section_handler(),
                                          process_tree_node, 'Thread Actions', action_id_list)
        self.__handle_gfi_sandbox_section(process.get_sysobject_section(), gfi.sysobject_section.sysobject_section_handler(),
                                          process_tree_node, 'Synchronization Actions', action_id_list)
        self.__handle_gfi_sandbox_section(process.get_system_section(), gfi.system_section.system_section_handler(),
                                          process_tree_node, 'System Actions', action_id_list)
        self.__handle_gfi_sandbox_section(process.get_service_section(), gfi.service_section.service_section_handler(),
                                          process_tree_node, 'Service Actions', action_id_list)
        self.__handle_gfi_sandbox_section(process.get_user_section(), gfi.user_section.user_section_handler(),
                                          process_tree_node, 'User Actions', action_id_list)
        self.__handle_gfi_sandbox_section(process.get_share_section(), gfi.share_section.share_section_handler(),
                                          process_tree_node, 'Network Share Actions', action_id_list)
        self.__handle_gfi_sandbox_section(process.get_module_section(), gfi.module_section.module_section_handler(),
                                          process_tree_node, 'Module Actions', action_id_list)
        self.__handle_gfi_sandbox_section(process.get_networkpacket_section(), gfi.networkpacket_section.networkpacket_section_handler(),
                                          process_tree_node, 'Network Actions', action_id_list)
        self.__handle_gfi_sandbox_section(process.get_networkoperation_section(), gfi.networkoperation_section.networkoperation_section_handler(),
                                          process_tree_node, 'Network Actions', action_id_list)
        #self.__handle_gfi_sandbox_section(process.get_checkpoint_section(), process_tree_node)
        #self.__handle_gfi_sandbox_section(process.get_com_section(), process_tree_node)
        #self.__handle_gfi_sandbox_section(process.get_error_section(), process_tree_node)
        #self.__handle_gfi_sandbox_section(process.get_connection_section(), process_tree_node)
        #Construct the list of Initiated Actions
        process_tree_node.initiated_actions = ActionReferenceList.from_list(action_id_list)
        return process_tree_node

    #Create and add the process object to the MAEC object list
    def __create_process_tree_node_object(self, process):
        process_attributes = {}
        process_attributes['id'] = maec.utils.idgen.create_id(prefix="process_tree_node")
        process_attributes['image_info'] = {}
        process_attributes['image_info']['file_name'] = process.get_filename()
        if process.get_commandline() != None: process_attributes['image_info']['command_line'] = process.get_commandline()
        if process.get_pid() != None: process_attributes['pid'] = process.get_pid()
        if process.get_parent_pid() != None: process_attributes['parent_pid'] = process.get_parent_pid()
        if process.get_username() != None: process_attributes['username'] = process.get_username()
        if process.get_start_time() != None: process_attributes['creation_time'] = self.__normalize_datetime(process.get_start_time())
        #Handle any AV classifications that were reported
        #av_classifications = self.__handle_scanner_section(process.get_scanner_section())
        #if av_classifications is not None:
        #    process_attributes['av_classifications'] = av_classifications
        #Create the object
        return ProcessTreeNode.from_dict(process_attributes)
    
    #Process the analysis metadata and create the corresponding MAEC analysis object
    def __handle_analysis(self):
        #Get the required attributes
        version = self.analysis.get_version()
        time = self.analysis.get_time()
        commandline = self.analysis.get_commandline()
        #Create the MAEC Analysis Object
        analysis = Analysis(maec.utils.idgen.create_id(prefix="analysis"), "dynamic", "triage", [BundleReference.from_dict({'bundle_idref': self.bundle.id})])
        analysis.summary = StructuredText("GFI Sandbox dynamic analysis of the malware instance object.")
        analysis.start_datetime = self.__normalize_datetime(time)
        if commandline:
            analysis.dynamic_analysis_metadata = DynamicAnalysisMetadata.from_dict({"command_line" : commandline})
        analysis.add_tool(ToolInformation.from_dict({"id": self.tool_id,
                                                     "name": "GFI Sandbox",
                                                     "version": version,
                                                     "vendor": "http://www.threattracksecurity.com/"}))
        self.malware_subject.add_analysis(analysis)
    
    #Add the Malware Instance Object Attributes to the Malware Subject
    def __add_malware_instance_object_attributes(self):
        md5 = self.analysis.get_md5()
        sha1 = self.analysis.get_sha1()
        filename = self.analysis.get_filename()
        hashes_list = [{"type": "MD5", "simple_hash_value": md5},
                      {"type": "SHA1", "simple_hash_value": sha1}]
        object_dict = {"id": maec.utils.idgen.create_id(prefix="object"),
                       "properties": {"xsi:type":"FileObjectType",
                                      "file_name": filename,
                                      "hashes": hashes_list}
                        }
        self.malware_subject.set_malware_instance_object_attributes(Object.from_dict(object_dict))
    
    def __handle_gfi_sandbox_section(self, section, section_handler, process_tree_node, action_collection_name, action_id_list):
        if section:
            for name, method in inspect.getmembers(section, inspect.ismethod):
                if name.find('get_') == 0 and name[4:] in section_handler.action_mappings.keys():
                    for sandbox_action in getattr(section, name)():
                        maec_action = self.__handle_action(section_handler,
                            sandbox_action)
                        if not maec_action.action_arguments:
                            maec_action.action_arguments = None
                        self.bundle.add_action(maec_action, action_collection_name)
                        action_id_list.append({'action_id':maec_action.id_})
    
    #Special method for handling AV classifications reported for the process
    def __handle_scanner_section(self, scanner_section):
        if scanner_section and scanner_section.get_scanner():
            self.scanner_bundle = Bundle(maec.utils.idgen.create_id(prefix="bundle"), False, "4.1", "static analysis tool output")
            for scanner in scanner_section.get_scanner():
                av_classification = {}
                av_classification['vendor'] = scanner.get_name()
                av_classification['engine_version'] = scanner.get_application_version()
                av_classification['definition_version'] = scanner.get_signature_file_version()
                try:
                    av_classification['classification_name'] = scanner.get_additional_info().rstrip().strip('"')
                except AttributeError:
                    pass
                self.scanner_bundle.add_av_classification(AVClassification.from_dict(av_classification))
            #Add the corresponding Analysis to the Subject
            scanner_analysis = Analysis(maec.utils.idgen.create_id(prefix="analysis"), "static", "triage", [BundleReference.from_dict({"bundle_idref": self.scanner_bundle.id})])
            scanner_analysis.summary = StructuredText("GFI Sandbox AV scanner results for the malware instance object.")
            scanner_analysis.add_tool(ToolInformation.from_dict({"idref": self.tool_id}))
            self.malware_subject.add_analysis(scanner_analysis)
            self.malware_subject.add_findings_bundle(self.scanner_bundle)

    #Handle a single GFI action and convert it to its MAEC representation
    def __handle_action(self, section, action):
        object_attributes = {'id':maec.utils.idgen.create_id(prefix="object")}
        action_attributes = {'id':maec.utils.idgen.create_id(prefix="action")}
        #Handle the Action Status
        try:
            status = action.get_result()
            if status:
                action_attributes['action_status'] = 'Fail'
            else:
                action_attributes['action_status'] = 'Success'
        except AttributeError:
             pass
        #Get the name of the action
        action_name = action.__class__.__name__
        #Get the mapping dictionary for the action
        action_mappings = section.get_action_mappings().get(action_name)
        #Process the common object attributes
        section.handle_common_object_attributes(object_attributes, action_mappings)
        #Create the object
        object = section.handle_object_attributes(action, object_attributes, action_attributes, action_mappings)
        #Process the common action attributes
        section.handle_common_action_attributes(object, action_attributes, action_mappings)
        #Populate the action attributes
        section.handle_action_attributes(action, object, action_attributes, action_mappings)
        return MalwareAction.from_dict(action_attributes)

    #Return a normalized (ISO8601 compatible) datetime string
    def __normalize_datetime(self, datetime):
        split_datetime = datetime.split(' ')
        weekday = split_datetime[0]
        day = split_datetime[1]
        month = split_datetime[2]
        year = split_datetime[3]
        time = split_datetime[4]
        offset = split_datetime[5]
        iso_datetime = year + '-' + self.__month_mapping(month) + '-' + day + 'T' + time
        return iso_datetime

    def __month_mapping(self, month):
        if 'Jan' in month:
            return '01'
        elif 'Feb' in month:
            return '02'
        elif 'Mar' in month:
            return '03'
        elif 'Apr' in month:
            return '04'
        elif 'May' in month:
            return '05'
        elif 'Jun' in month:
            return '06'
        elif 'Jul' in month:
            return '07'
        elif 'Aug' in month:
            return '08'
        elif 'Sep' in month:
            return '09'
        elif 'Oct' in month:
            return '10'
        elif 'Nov' in month:
            return '11'
        elif 'Dec' in month:
            return '12'

