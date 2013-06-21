#Copyright (c) 2012, The MITRE Corporation
#All rights reserved.

#ThreatExpert Converter Script
#Ivan Kirillov//ikirillov@mitre.org

#ThreatExpert main parser class
#For use in extracting data from XML ThreatExpert output
import cybox.utils as utils
from maec.utils import MAECNamespaceParser
from maec.bundle.bundle import Bundle
from maec.bundle.malware_action import MalwareAction
from maec.bundle.av_classification import AVClassification, AVClassifications
from maec.package.analysis import Analysis
from maec.package.malware_subject import MalwareSubject
from maec.bundle.behavior import Behavior
from maec.id_generator import Generator
from cybox.core.object import Object
from cybox.core.associated_object import AssociatedObject
from cybox.common.tools import ToolInformation



import threatexpert as threatexpert
import traceback

class parser:
    
    def __init__(self):
        #array for storing actions
        #self.actions = []
        #the subject of the analysis (typically a PE binary)
        self.analysis_subject_md5 = ''
        self.analysis_subject_sha1 = ''
        #variable for keeping tab on the number of actions we parsed out
        self.number_of_actions = 0
        #the report object of the ThreatExpert XML document
        self.report_object = None
        #generator
        self.generator = None
        self.actions = None
        #the actions for the current subreport
        self.subreport_actions = None
        self.maec_object = None
        self.maec_action = None
        self.maec_actions = {}
        self.maec_objects = {}
        self.maec_behaviors = {}
        self.maec_subjects = []
        self.analysis_subject_md5 = None
        self.analysis_subject_path = None
        self.analysis_subject_name = None
        self.tool_id = None
        self.initiator_id = None
        self.subject_id_list = []
        
    #"Public" methods
    
    #Open and read-in the ThreatExpert output file
    #This assumes that we're dealing with a XML file
    def open_file(self, infilename):
        try: 
            self.report_object = threatexpert.parse(infilename)
            return 1
        except Exception, err:
           print('\nError: %s\n' % str(err))
           return 0
       

           
    #Parse the XML document
    #Extract processes, actions, and information about the analysis subject
    def parse_document(self):
        id_map = {}
        #Setup the generator
        self.generator = Generator('threatexpert_to_maec')
        
        #Get the subreports
        subreports = self.report_object.get_subreports()
        for subreport in subreports.get_subreport():
            #Setup the subreport actions array
            self.subreport_actions = []
            
            #Setup the action/object dictionaries
            self.__setup_dictionaries()
            
            #Get and process the analysis metadata
            submission_summary = subreport.get_submission_summary()
            if submission_summary is not None:
                submission_details = submission_summary.get_submission_details()
                if submission_details is not None:
                    sample_info_coll = submission_details.get_sample_info_collection()
                    if sample_info_coll is not None:
                        sample_info = sample_info_coll.get_sample_info()

                        malware_subject = self.__create_malware_subject_object(subreport, sample_info[0], subreports, id_map)
                        
                        av_aliases = self.__get_av_aliases(sample_info[0])
                        self.tool_id = malware_subject.analyses[0].tools[0].id_
            
            #Get and process the technical details
            techdetails = subreport.get_technical_details()
            if techdetails is not None:
                self.__process_technical_details(techdetails)

            
            #Add all applicable actions to the bundle
            self.bundle_obj = Bundle(self.generator.generate_bundle_id(), False)
            for key, value in self.actions.items():
                if len(value) > 0:
                    self.bundle_obj.add_named_action_collection(key, self.generator.generate_action_collection_id())
                for action in value:
                    self.bundle_obj.add_action(action, key)
                    
            for alias in av_aliases:
                self.bundle_obj.add_av_classification(AVClassification.from_dict(alias))
            
            if submission_summary.get_flag_collection() is not None:
                flag_list = submission_summary.get_flag_collection().get_flag()
                for flag in flag_list:
                    self.bundle_obj.add_behavior(Behavior(self.generator.generate_behavior_id(), flag.description))
            
            malware_subject.add_findings_bundle(self.bundle_obj)
            
            malware_subject.analyses[0].set_findings_bundle(self.bundle_obj.id)
            
            self.maec_subjects.append(malware_subject)
            
           

    # Create an analysis subject object, used in maec_helper.maec_analysis
    def __create_malware_subject_object(self, analysis_subject, general_info, analysis_subjects, id_map):
        # TODO: get file info
        #first, extract the info from the object
        md5 = None
        sha1 = None
        file_size = None
        packer = None
        arguments = None
        exit_code = None
        dll_dependencies = None
        if general_info.get_md5() != None: 
            md5 = general_info.get_md5()
        if general_info.get_sha1() != None: sha1 = general_info.get_sha1()
        if general_info.get_filesize() != None: file_size = general_info.get_filesize()                  
        if general_info.get_packer() != None: packer = general_info.get_packer()
        
         
        #create the analysis subject object
        malware_subject_object = MalwareSubject(self.generator.generate_malware_subject_id())
        
        #Create the file object and add the attributes
        object_dict = {}
        object_dict['id'] = self.generator.generate_object_id()
        self.subject_id_list.append(object_dict['id'])
        
        file_dict = {}
        file_dict['xsi:type'] = 'WindowsExecutableFileObjectType'
        if file_size != None:
            file_dict['size_in_bytes'] = file_size
        if packer != None and len(packer.strip()) > 0:
            split_packer = packer.split(' ')
            if len(split_packer) == 2:
                packer = { 'name' : split_packer[0], 'version' : split_packer[1] }
            else:
                packer = { 'name' : split_packer[0] }
            file_dict['packer_list'] = [packer]
        if md5 != None or sha1 != None:
            hashes = []
            if md5 != None:
                hash_dict =  {'type' : {'value' :'MD5', 'datatype' : 'string', 'force_datatype' : True},
                              'simple_hash_value': {'value' : md5}
                             }
                hashes.append(hash_dict)
            if sha1 != None:
                hash_dict =  {'type' : {'value' :'SHA1', 'datatype' : 'string', 'force_datatype' : True},
                              'simple_hash_value': {'value' : sha1}
                             }
                hashes.append(hash_dict)
            if len(hashes) > 0:
                file_dict['hashes'] = hashes
        if dll_dependencies != None:
            pe_attributes = {}
            pe_imports = []
            for loaded_dll in dll_dependencies.get_loaded_dll():
                pe_import = {}
                pe_import[file_name] = loaded_dll.get_full_name()
                pe_import['virtual_address'] = loaded_dll.get_base_address().lstrip('0x')
                pe_import['delay_load'] = not bool(int(loaded_dll.get_is_load_time_dependency()))
                pe_imports.append(pe_import)
            if pe_imports.hasContent_():
                pe_attributes['imports'] = pe_imports
            if pe_attributes.hasContent_():
                file_object['pe_attributes'] = pe_attributes
        
        # create the analysis and add it to the subject
        analysis = Analysis(self.generator.generate_analysis_id())
        analysis.type = 'triage'
        analysis.method = 'dynamic'
        analysis.add_tool(ToolInformation.from_dict({'id' : self.generator.generate_tool_id(),
                           'vendor' : 'ThreatExpert',
                           'name' : 'ThreatExpert' }))
        
        if arguments != None:
            analysis.set_command_line(arguments.strip())
        if exit_code != None:
            analysis.set_exit_code(exit_code)
            
        malware_subject_object.add_analysis(analysis)
        
        #set the object as the defined object
        object_dict['properties'] = file_dict
        
        #bind the object to the analysis subject object
        malware_subject_object.set_malware_instance_object_attributes(Object.from_dict(object_dict))
        
        return malware_subject_object
                
    #accessor methods
    def get_processes(self):
        return self.processes
    
    def get_actions(self):
        return self.actions

    def get_analysis_subject(self):
        return self.analysis_subject

    def get_number_of_actions(self):
        return self.number_of_actions
        
    #"Private" methods
    #Create and instantiate the keys in the action dictionary
    def __setup_action_dictionary(self):
        actions = {}
        actions['File Actions'] = []
        actions['IPC Actions'] = []
        actions['Service Actions'] = []
        actions['Registry Actions'] = []
        actions['Network Actions'] = []
        actions['Memory Actions'] = []
        actions['Process Actions'] = []
        actions['Module Actions'] = []
        actions['System Actions'] = []
        actions['Driver Actions'] = []
        
        self.actions = actions

    #Setup both dictionaries
    def __setup_dictionaries(self):
        self.__setup_action_dictionary()

    #Parse the technical details in the report
    #This is where the majority of the content resides
    #To do: add support for MAEC behavior generation for certain elements (e.g. filestosearch)
    def __process_technical_details(self, techdetails):
        if techdetails.get_added_files() is not None: self.__process_added_files_type(techdetails.get_added_files(),'file')
        if techdetails.get_added_hidden_files() is not None: self.__process_added_files_type(techdetails.get_added_hidden_files(),'file')
        if techdetails.get_added_streams() is not None: self.__process_added_files_type(techdetails.get_added_streams(),'stream')
        if techdetails.get_added_hidden_streams() is not None: self.__process_added_files_type(techdetails.get_added_hidden_streams(),'stream')
        if techdetails.get_deleted_files() is not None: self.__process_filenames_notes_type(techdetails.get_deleted_files(), 'delete')
        if techdetails.get_modified_files() is not None: self.__process_filenames_notes_type(techdetails.get_modified_files(), 'modify')
        #Revisit - CybOX does not currently support directories
        #if techdetails.get_added_directories() is not None: self.__process_dirnames_notes_type(techdetails.get_added_directories(), 'create')
        #if techdetails.get_added_hidden_directories() is not None: self.__process_dirnames_notes_type(techdetails.get_added_hidden_directories(), 'create')
        #if techdetails.get_deleted_directories() is not None: self.__process_dirnames_notes_type(techdetails.get_deleted_directories(), 'create')
        if techdetails.get_added_processes() is not None: self.__process_added_processes_type(techdetails.get_added_processes())
        if techdetails.get_added_hidden_processes() is not None: self.__process_added_hidden_processes_type(techdetails.get_added_hidden_processes())
        if techdetails.get_injected_mempages() is not None: self.__process_injected_mempages_type(techdetails.get_injected_mempages())
        #Revisit - determine what this means and how to represent it in CybOX
        #if techdetails.get_added_modules() is not None: self.__process_added_modules_type(techdetails.get_added_modules())
        if techdetails.get_added_services() is not None: self.__process_added_services_type(techdetails.get_added_services())
        if techdetails.get_modified_services() is not None: self.__process_modified_services_type(techdetails.get_modified_services())
        if techdetails.get_added_drivers() is not None: self.__process_added_drivers_type(techdetails.get_added_drivers())
        if techdetails.get_added_syscallhooks() is not None: self.__process_added_syscallhooks_type(techdetails.get_added_syscallhooks())
        #Revisit - CybOX does not currently support IRP hooks
        #if techdetails.get_irp_hooks() is not None: self.__process_irp_hooks(techdetails.get_irp_hooks())
        if techdetails.get_added_regkeys() is not None: self.__process_regkeys_type(techdetails.get_added_regkeys(), 'create')
        if techdetails.get_added_hidden_regkeys() is not None: self.__process_regkeys_type(techdetails.get_added_hidden_regkeys(), 'create')
        if techdetails.get_deleted_regkeys() is not None: self.__process_regkeys_type(techdetails.get_deleted_regkeys(), 'delete')
        if techdetails.get_added_regvalues() is not None: self.__process_regvalues_structures_type(techdetails.get_added_regvalues(), 'create')
        if techdetails.get_added_hidden_regvalues() is not None: self.__process_regvalues_structures_type(techdetails.get_added_hidden_regvalues(), 'create')
        if techdetails.get_deleted_regvalues() is not None: self.__process_regvalues_structures_type(techdetails.get_deleted_regvalues(), 'delete')
        if techdetails.get_modified_regvalues() is not None: self.__process_regvalues_structures_type(techdetails.get_modified_regvalues(), 'modify')
        if techdetails.get_mutexes() is not None: self.__process_mutexes_type(techdetails.get_mutexes())
        if techdetails.get_open_ports() is not None: self.__process_open_ports_type(techdetails.get_open_ports())
        if techdetails.get_gethostbyname_api() is not None: self.__process_gethostbyname_api_type(techdetails.get_gethostbyname_api())
        if techdetails.get_connect_ip_api() is not None: self.__process_connect_ip_api_type(techdetails.get_connect_ip_api())
        if techdetails.get_internetconnect_api() is not None: self.__process_internetconnect_api_type(techdetails.get_internetconnect_api())
        # HTTP is experimental
        if techdetails.get_getrequests() is not None: self.__process_getrequests_type(techdetails.get_getrequests(), techdetails.get_internetconnect_api())
        if techdetails.get_urlrequests() is not None: self.__process_urls_type(techdetails.get_urlrequests(), 'get')
        if techdetails.get_internetopenurl_api() is not None: self.__process_urls_type(techdetails.get_internetopenurl_api(), 'open')
        if techdetails.get_urldownloadtofile_api() is not None: self.__process_urldownloadtofile_api_type(techdetails.get_urldownloadtofile_api())
        if techdetails.get_ftpgetfile_api() is not None: self.__process_urls_type(techdetails.get_ftpgetfile_api(), 'open')
        if techdetails.get_setwindowshook_api() is not None: self.__process_setwindowshook_api_type(techdetails.get_setwindowshook_api()) #stub
        if techdetails.get_wnetaddconnection_api() is not None: self.__process_wnetaddconnection_api_type(techdetails.get_wnetaddconnection_api()) #stub
        if techdetails.get_procnames_to_terminate() is not None: self.__process_procnames_to_terminate_type(techdetails.get_procnames_to_terminate())
    
    def __process_added_files_type(self, added_files, type):
        if added_files.get_added_files_collection() is not None:
            files_collection = added_files.get_added_files_collection()
            for file_object in files_collection.get_added_file():
                file_attributes = {}
                associated_object_dict = { 'id' : self.generator.generate_object_id() }
                
                file_size = file_object.get_filesize() 
                if file_size != None: file_attributes['size_in_bytes'] = file_size
                
                md5 = file_object.get_md5()
                sha1 = file_object.get_sha1()
                if md5 != None or sha1 != None:
                    hashes = []
                    if md5 != None:
                        hash_dict =  {'type' : {'value' :'MD5', 'datatype' : 'string', 'force_datatype' : True},
                                      'simple_hash_value': {'value' : md5}
                                     }
                        hashes.append(hash_dict)
                    if sha1 != None:
                        hash_dict =  {'type' : {'value' :'SHA1', 'datatype' : 'string', 'force_datatype' : True},
                                      'simple_hash_value': {'value' : sha1}
                                     }
                        hashes.append(hash_dict)
                    if len(hashes) > 0:
                        file_attributes['hashes'] = hashes
                
                filenames = file_object.get_filenames_collection()
                if file_object.get_packer() is not None : file_attributes['packer'] = file_object.get_packer() 
                
                # TODO: attach aliases to files that have them
                #associated_object_dict['domain-specific_object_attributes'] = self.__get_av_aliases(file_object)

                for filename in filenames.get_filename():                    
                    if 'sample #1]' in filename:
                        associated_object_dict['idref'] = self.subject_id_list[0]
                    else:
                        file_attributes['xsi:type'] = "FileObjectType"
                        file_attributes['file_path'] = { 'value' : filename, 'fully_qualified' : False }
                        
                        if type == 'file':
                            file_attributes['type'] = 'File'
                        elif type == 'stream':
                            file_attributes['type'] = 'Other' 
                            
                        associated_object_dict['properties'] = file_attributes
                        associated_object_dict['association_type'] = {'value' : 'output', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}
                    
                    #Generate the MAEC action
                    action_attributes = {}
                    action_attributes['id'] = self.generator.generate_malware_action_id()
                    if type == 'file':
                        action_attributes['name'] = {'value' : 'create file', 'xsi:type' : 'maecVocabs:FileActionNameVocab-1.0'}
                    elif type == 'stream':
                        action_attributes['name'] = {'value' : 'create file alternate data stream', 'xsi:type' : 'maecVocabs:FileActionNameVocab-1.0'}
                    action_attributes['tool_id'] = self.tool_id
                    action_attributes['associated_objects'] = [associated_object_dict]
                    fs_action = MalwareAction.from_dict(action_attributes)
                    self.actions.get('File Actions').append(fs_action)
                    self.subreport_actions.append(fs_action.id)

    def __process_filenames_notes_type(self, filenames_notes, type):
        if filenames_notes.get_filenames_collection() is not None:
            files_collection = filenames_notes.get_filenames_collection()
            for filename in files_collection.get_filename():
                file_attributes = {}
                associated_object_dict = { 'id' : self.generator.generate_object_id() }
                file_attributes['xsi:type'] = "FileObjectType"
                file_attributes['file_path'] = { 'value' : filename, 'fully_qualified' : False }
                file_attributes['type'] = 'File'
                
                associated_object_dict['properties'] = file_attributes
                associated_object_dict['association_type'] = {'value' : 'output', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}
                    
                #Generate the MAEC action
                action_attributes = {}
                action_attributes['id'] = self.generator.generate_malware_action_id()
                if type == 'delete':
                    action_attributes['name'] = {'value' : 'delete file', 'xsi:type' : 'maecVocabs:FileActionNameVocab-1.0'}
                elif type == 'modify':
                    action_attributes['name'] = {'value' : 'modify file', 'xsi:type' : 'maecVocabs:FileActionNameVocab-1.0'}
                action_attributes['tool_id'] = self.tool_id
                action_attributes['associated_objects'] = [associated_object_dict]
                fs_action = MalwareAction.from_dict(action_attributes)
                self.actions.get('File Actions').append(fs_action)
                self.subreport_actions.append(fs_action.id)

    def __process_dirnames_notes_type(self, dirnames_notes, type):
        if dirnames_notes.get_dirnames_collection() is not None:
            dirnames_collection = dirnames_notes.get_dirnames_collection()
            for dirname in dirnames_collection.get_dirname():
                dir_attributes = {}
                associated_object_dict = { 'id' : self.generator.generate_object_id() }
                file_attributes['xsi:type'] = "FileObjectType"
                dir_attributes['file_path'] = { 'value' : dirname, 'force_datatype' : True }
                dir_attributes['type'] = 'Directory'
                
                associated_object_dict['properties'] = dir_attibutes
                associated_object_dict['association_type'] = 'Affected'
                
                #Generate the MAEC action
                action_attributes = {}
                action_attributes['id'] = self.generator.generate_malware_action_id()
                if type == 'create':
                    action_attributes['name'] = {'value' : 'create directory', 'xsi:type' : 'maecVocabs:DirectoryActionNameVocab-1.0'}
                elif type == 'delete':
                    action_attributes['name'] = {'value' : 'delete directory', 'xsi:type' : 'maecVocabs:DirectoryActionNameVocab-1.0'}
                action_attributes['tool_id'] = self.tool_id
                action_attributes['associated_objects'] = [associated_object_dict]
                fs_action = self.maec_action.create_action(action_attributes)
                self.actions.get('File Actions').append(fs_action)
                self.subreport_actions.append(fs_action.id)

    def __process_added_processes_type(self, added_processes):
        if added_processes.get_added_processes_collection() is not None:
            processes_collection = added_processes.get_added_processes_collection()
            for process in processes_collection.get_added_process():
                process_attributes = {}
                associated_object_dict = { 'id' : self.generator.generate_object_id() }
                second_associated_object_dict = None
                process_attributes['xsi:type'] = 'WindowsProcessObjectType'
                if process.get_process_name() == '[filename of the sample #1]':
                    if self.analysis_subject_name is not None:
                        process_attributes['name'] = self.analysis_subject_name
                else:
                    process_attributes['name'] = process.get_process_name()
                
                process_attributes['image_info'] = {}
                if process.get_process_filename() == '[file and pathname of the sample #1]':
                    if self.analysis_subject_path is not None:
                        process_attributes['image_info']['path'] = { 'value' : self.analysis_subject_path + '\\' + self.analysis_subject_name, 'force_datatype' : True }
                        process_attributes['image_info']['file_name'] = { 'value' : self.analysis_subject_name, 'force_datatype' : True }
                    else:
                        # HACK: we need to refer to the unnamed malware analysis subject,
                        # HACK: but there is no way for a Process element to refer to a File element (only file *names*)
                        # HACK: so add associated file object as an associated object
                        second_associated_object_dict = { 'idref' : self.subject_id_list[0] }
                        second_associated_object_dict['association_type'] = {'value' : 'input', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}
                        
                else:
                    process_attributes['image_info']['path'] = { 'value' : process.get_process_filename() }
                    
                associated_object_dict['association_type'] = {'value' : 'output', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}
                associated_object_dict['properties'] = process_attributes
                
                #Generate the MAEC action
                action_attributes = {}
                action_attributes['id'] = self.generator.generate_malware_action_id()
                action_attributes['name'] = {'value' : 'create process', 'xsi:type' : 'maecVocabs:ProcessActionNameVocab-1.0'}
                action_attributes['associated_objects'] = []
                if second_associated_object_dict is None:
                    action_attributes['associated_objects'].append(associated_object_dict)
                else:
                    action_attributes['associated_objects'].append(second_associated_object_dict)
                action_attributes['tool_id'] = self.tool_id
                process_action = MalwareAction.from_dict(action_attributes)
                self.actions.get('Process Actions').append(process_action)
                self.subreport_actions.append(process_action.id)

    def __process_added_hidden_processes_type(self, added_hidden_processes):
        if added_hidden_processes.get_added_hidden_processes_collection() is not None:
            processes_collection = added_hidden_processes.get_added_hidden_processes_collection()
            for process in processes_collection.get_added_hidden_process():
                process_attributes = {}
                associated_object_dict = { 'id' : self.generator.generate_object_id() }
                process_attributes['xsi:type'] = 'WindowsProcessObjectType'
                if process.get_process_name() == '[filename of the sample #1]':
                    if self.analysis_subject_name is not None:
                        process_attributes['name'] = self.analysis_subject_name
                else:
                    process_attributes['name'] = process.get_process_name()
                    
                associated_object_dict['properties'] = process_attributes
                associated_object_dict['association_type'] = {'value' : 'output', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}
                
                #Generate the MAEC action
                action_attributes = {}
                action_attributes['id'] = self.generator.generate_malware_action_id()
                action_attributes['name'] = {'value' : 'create process', 'xsi:type' : 'maecVocabs:ProcessActionNameVocab-1.0'}
                action_attributes['associated_objects'] = [associated_object_dict]
                action_attributes['tool_id'] = self.tool_id
                process_action = MalwareAction.from_dict(action_attributes)
                self.actions.get('Process Actions').append(process_action)
                self.subreport_actions.append(process_action.id)
                
    def __process_injected_mempages_type(self, injected_mempages):
        for mempage in injected_mempages.get_injected_mempages_collection().get_injected_mempage():
            # we want to specify what process this page is getting injected into
            process_attributes = {}
            first_associated_object_dict = { 'id' : self.generator.generate_object_id() }
            second_associated_object_dict = { 'id' : self.generator.generate_object_id() }
            
            process_attributes['xsi:type'] = 'WindowsProcessObjectType'
            process_attributes['name'] = mempage.get_process_name()
            process_attributes['image_info'] = {'path' : { 'value' : mempage.get_process_filename() } }
            first_associated_object_dict['properties'] = process_attributes
            first_associated_object_dict['association_type'] = {'value' : 'output', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}

            mempage_attributes = {}
            mempage_attributes['xsi:type'] = 'MemoryObjectType'
            mempage_attributes['region_size'] = mempage.get_allocated_size()
            second_associated_object_dict['properties'] = mempage_attributes
            second_associated_object_dict['association_type'] = {'value' : 'input', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}
            
            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['id'] = self.generator.generate_malware_action_id()
            action_attributes['name'] = {'value' : 'write to process memory', 'xsi:type' : 'maecVocabs:ProcessMemoryActionNameVocab-1.0'}
            action_attributes['associated_objects'] = [first_associated_object_dict, second_associated_object_dict]

            action_attributes['tool_id'] = self.tool_id #static
            memory_action = MalwareAction.from_dict(action_attributes)
            self.actions.get('Memory Actions').append(memory_action)
            self.subreport_actions.append(memory_action.id)

    #Revisit
    def __process_added_modules_type(self, added_modules):
        if added_modules.get_added_modules_collection() is not None:
            modules_collection = added_modules.get_added_modules_collection()
            for module in modules_collection.get_added_module():
                module_attributes = {}
                associated_object_dict = { 'id' : self.generator.generate_object_id() }
                module_attributes['xsi:type'] = 'LibraryObjectType'
                module_attributes['name'] = module.get_module_name()
                module_attributes['path'] = module.get_module_filename()
                associated_object_dict['properties'] = module_attributes
                associated_object_dict['association_type'] = {'value' : 'output', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}
                
                #Generate the MAEC action
                action_attributes = {}
                action_attributes['id'] = self.generator.generate_malware_action_id()
                action_attributes['name'] = {'value' : 'load library', 'xsi:type' : 'maecVocabs:LibraryActionNameVocab-1.0'}
                action_attributes['associated_objects'] = [associated_object_dict]
                action_attributes['tool_id'] = self.tool_id
                module_action = MalwareAction.from_dict(action_attributes)
                self.actions.get('Module Actions').append(module_action)
                self.subreport_actions.append(module_action.id)

    def __process_added_services_type(self, added_services):
        if added_services.get_added_services_collection() is not None:
            added_services_collection = added_services.get_added_services_collection()
            for service in added_services_collection.get_added_service():
                associated_object_dict = { 'id' : self.generator.generate_object_id() }
                service_attributes = {}
                try:
                    service_attributes['xsi:type'] = 'WindowsServiceObjectType'
                    service_attributes['name'] = service.get_service_name()
                    service_attributes['display_name'] = service.get_display_name()
                    service_attributes['image_info'] = {'path' : service.get_service_filename() }
                    service_attributes['status'] = service.get_status()
                    
                    associated_object_dict['properties'] = service_attributes
                    associated_object_dict['association_type'] = {'value' : 'output', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}
                except AttributeError:
                    pass
                
                #Generate the MAEC action
                action_attributes = {}
                action_attributes['id'] = self.generator.generate_malware_action_id()
                action_attributes['name'] = {'value' : 'create service', 'xsi:type' : 'maecVocabs:ServiceActionNameVocab-1.0'}
                action_attributes['associated_objects'] = [associated_object_dict]
                action_attributes['tool_id'] = self.tool_id
                service_action = MalwareAction.from_dict(action_attributes)
                self.actions.get('Service Actions').append(service_action)
                self.subreport_actions.append(service_action.id)

    def __process_modified_services_type(self, modified_services):
        if modified_services.get_modified_services_collection() is not None:
            modified_services_collection = modified_services.get_modified_services_collection()
            for service in modified_services_collection.get_modified_service():
                service_attributes = {}
                associated_object_dict = { 'id' : self.generator.generate_object_id() }
                try:
                    service_attributes['xsi:type'] = 'WindowsServiceObjectType'
                    service_attributes['name'] = service.get_service_name()
                    #service_attributes['display_name'] = service.get_display_name()
                    service_attributes['image_info'] = {'file_name' : service.get_service_filename() }
                    service_attributes['status'] = service.get_status()
                except AttributeError:
                    pass
                finally:
                    associated_object_dict['properties'] = service_attributes
                    associated_object_dict['association_type'] = {'value' : 'output', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}
                #Generate the MAEC action
                action_attributes = {}
                action_attributes['id'] = self.generator.generate_malware_action_id()
                action_attributes['name'] = {'value' : 'modify service configuration', 'xsi:type' : 'maecVocabs:ServiceActionNameVocab-1.0'}
                action_attributes['associated_objects'] = [associated_object_dict]
                action_attributes['tool_id'] = self.tool_id
                service_action = MalwareAction.from_dict(action_attributes)
                self.actions.get('Service Actions').append(service_action)
                self.subreport_actions.append(service_action.id)

    def __process_added_drivers_type(self, added_drivers): #stub
        if added_drivers.get_added_drivers_collection() is not None:
            for added_driver in added_drivers.get_added_drivers_collection().get_added_driver():
                associated_object_dict = { 'id' : self.generator.generate_object_id() }
                driver_attributes = {}
                driver_attributes['xsi:type'] = 'WindowsDriverObjectType'
                driver_attributes['driver_name'] = added_driver.driver_name
                driver_attributes['custom_properties'] = [{'name' : 'Driver_File_Path',
                                                           'value' : added_driver.driver_filename }]
                
                associated_object_dict['properties'] = driver_attributes
                associated_object_dict['association_type'] = {'value' : 'output', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}
                
                action_attributes = {}
                action_attributes['id'] = self.generator.generate_malware_action_id()
                action_attributes['name'] = {'value' : 'load driver', 'xsi:type': 'maecVocabs:DeviceDriverActionNameVocab-1.0' }
                action_attributes['associated_objects'] = [associated_object_dict]
                action_attributes['tool_id'] = self.tool_id
                hook_action = MalwareAction.from_dict(action_attributes)
                self.actions.get('Driver Actions').append(hook_action)
                self.subreport_actions.append(hook_action.id)
        return
    
    def __process_added_syscallhooks_type(self, added_syscallhooks):
        if added_syscallhooks.get_added_syscallhooks_collection() is not None:
            added_syscallhooks_collection = added_syscallhooks.get_added_syscallhooks_collection()
            for added_syscallhook in added_syscallhooks_collection.get_added_syscallhook():
                hook_attributes = {}
                associated_object_dict = { 'id' : self.generator.generate_object_id() }
                hook_attributes['xsi:type'] = 'WindowsKernelHookObjectType'
                hook_attributes['hooked_function'] = added_syscallhook.syscall
                hook_attributes['hooking_module'] = added_syscallhook.driver_name
                
                associated_object_dict['properties'] = hook_attributes
                associated_object_dict['association_type'] = {'value' : 'input', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}
                
                action_attributes = {}
                action_attributes['id'] = self.generator.generate_malware_action_id()
                action_attributes['name'] = {'value' : 'add system call hook', 'xsi:type': 'maecVocabs:HookingActionNameEnum-1.0' }
                action_attributes['associated_objects'] = [associated_object_dict]
                action_attributes['tool_id'] = self.tool_id
                hook_action = MalwareAction.from_dict(action_attributes)
                self.actions.get('System Actions').append(hook_action)
                self.subreport_actions.append(hook_action.id)
    
    def __process_regkeys_type(self, regkeys, type):
        for regkey in regkeys.get_regkey():
            regkey_attributes = {}
            associated_object_dict = { 'id' : self.generator.generate_object_id() }
            split_regkey = regkey.split('\\')
            regkey_attributes['hive'] = split_regkey[0]
            actual_key = ''
            for i in range(1, len(split_regkey)):
                actual_key += (split_regkey[i] + '\\')
            actual_key = actual_key.rstrip('\\')
            regkey_attributes['xsi:type'] = "WindowsRegistryKeyObjectType"
            regkey_attributes['key'] = actual_key
            regkey_attributes['type'] = 'Key/Key Group'
            
            associated_object_dict['properties'] = regkey_attributes
            associated_object_dict['association_type'] = {'value' : 'output', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}
            
            #Generate the MAEC action
            action_attributes = {}
            action_attributes['id'] = self.generator.generate_malware_action_id()
            if type == 'create':
                action_attributes['name'] = {'value' : 'create registry key', 'xsi:type' : 'maecVocabs:RegistryActionNameVocab-1.0'}
            elif type == 'delete':
                action_attributes['name'] = {'value' : 'delete registry key', 'xsi:type' : 'maecVocabs:RegistryActionNameVocab-1.0'}
            action_attributes['associated_objects'] = [associated_object_dict]
            action_attributes['tool_id'] = self.tool_id
            reg_action = MalwareAction.from_dict(action_attributes)
            self.actions.get('Registry Actions').append(reg_action)
            self.subreport_actions.append(reg_action.id)

    def __process_regvalues_structures_type(self, regvalues, type):
        if regvalues.get_regvalues_structure() is not None:
            reg_values = regvalues.get_regvalues_structure()
            for regvalue in reg_values:
                regkey = regvalue.get_regkey()
                regkey_attributes = {}
                associated_object_dict = { 'id' : self.generator.generate_object_id() }
                split_regkey = regkey.split('\\')
                regkey_attributes['hive'] = split_regkey[0]
                actual_key = ''
                for i in range(1, len(split_regkey)):
                    actual_key += (split_regkey[i] + '\\')
                actual_key = actual_key.rstrip('\\')
                regkey_attributes['xsi:type'] = "WindowsRegistryKeyObjectType"
                regkey_attributes['key'] = actual_key
                regkey_attributes['type'] = 'Key/Key Group'
                regvalues_collection = regvalue.get_regvalues_collection()
                value_list = []
                for regvalue in regvalues_collection.get_regvalue():
                    data =regvalue.get_contents()
                    if data is not None and data.startswith("\"") and data.endswith("\""):
                        data = data[1:-1]  # strip quotes
                        
                    if data == "":
                        regkey_attributes['values'] = [{ 'name' : regvalue.get_value() }]
                    else:
                        regkey_attributes['values'] = [{ 'name' : regvalue.get_value(),
                                                         'data' : data }]
                
                    associated_object_dict['properties'] = regkey_attributes
                    associated_object_dict['association_type'] = {'value' : 'output', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}
                    
                    #Generate the MAEC action
                    action_attributes = {}
                    action_attributes['id'] = self.generator.generate_malware_action_id()
                    if type == 'create':
                        action_attributes['name'] = {'value' : 'create registry key value', 'xsi:type' : 'maecVocabs:RegistryActionNameVocab-1.0'}
                    elif type == 'delete':
                        action_attributes['name'] = {'value' : 'delete registry key value', 'xsi:type' : 'maecVocabs:RegistryActionNameVocab-1.0'}
                    elif type == 'modify':
                        action_attributes['name'] = {'value' : 'modify registry key', 'xsi:type' : 'maecVocabs:RegistryActionNameVocab-1.0'}
                    action_attributes['associated_objects'] = [associated_object_dict]
                    action_attributes['tool_id'] = self.tool_id
                    reg_action = MalwareAction.from_dict(action_attributes)
                    self.actions.get('Registry Actions').append(reg_action)
                    self.subreport_actions.append(reg_action.id)

    def __process_mutexes_type(self, mutexes):
        for mutex in mutexes.get_mutex():
            mutex_attributes = {}
            associated_object_dict = { 'id' : self.generator.generate_object_id() }
            mutex_attributes['xsi:type'] = "WindowsMutexObjectType"
            mutex_attributes['name']  = mutex
            mutex_attributes['type'] = 'Mutex'
            associated_object_dict['properties'] = mutex_attributes
            associated_object_dict['association_type'] = {'value' : 'output', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}
            
            #Generate the MAEC action
            action_attributes = {}
            action_attributes['id'] = self.generator.generate_malware_action_id()
            action_attributes['name'] = {'value' : 'create mutex', 'xsi:type' : 'maecVocabs:SynchronizationActionNameVocab-1.0'}
            action_attributes['associated_objects'] = [associated_object_dict]
            action_attributes['tool_id'] = self.tool_id
            mutex_action = MalwareAction.from_dict(action_attributes)
            self.actions.get('IPC Actions').append(mutex_action)
            self.subreport_actions.append(mutex_action.id)

    def __process_open_ports_type(self, openports):
        if openports.get_open_ports_collection() is not None:
            open_ports_collection = openports.get_open_ports_collection()
            for open_port in open_ports_collection.get_open_port():
                port_attributes = {}
                associated_object_dict = { 'id' : self.generator.generate_object_id() }
                port_attributes['xsi:type'] = 'PortObjectType'
                port_attributes['port_value'] = { 'value' : open_port.get_port_number(), 'force_datatype' : True }
                port_attributes['layer4_protocol'] = { 'value' : open_port.get_protocol(), 'datatype' : 'string', 'force_datatype' : True }
                
                associated_object_dict['properties'] = port_attributes
                associated_object_dict['association_type'] = {'value' : 'output', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}
                
                #Generate the MAEC action
                action_attributes = {}
                action_attributes['id'] = self.generator.generate_malware_action_id()
                action_attributes['name'] = {'value' : 'open port', 'xsi:type' : 'maecVocabs:NetworkActionNameVocab-1.0'}
                action_attributes['associated_objects'] = [associated_object_dict]
                action_attributes['tool_id'] = self.tool_id
                port_action = MalwareAction.from_dict(action_attributes)
                self.actions.get('Network Actions').append(port_action)
                self.subreport_actions.append(port_action.id)

    def __process_gethostbyname_api_type(self, hosts):
        for host in hosts.get_host():
            host_attributes = {}
            associated_object_dict = { 'id' : self.generator.generate_object_id() }
            
            host_attributes['xsi:type'] = 'URIObjectType'
            host_attributes['value'] = { 'value' : host, 'force_datatype' : True }
            
            associated_object_dict['properties'] = host_attributes
            associated_object_dict['association_type'] = {'value' : 'input', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}
            
            #Generate the MAEC action
            action_attributes = {}
            action_attributes['id'] = self.generator.generate_malware_action_id()
            action_attributes['name'] = {'value' : 'get host by name', 'xsi:type' : 'maecVocabs:SocketActionNameVocab-1.0'}
            action_attributes['associated_objects'] = [associated_object_dict]
            action_attributes['tool_id'] = self.tool_id
            host_action = MalwareAction.from_dict(action_attributes)
            self.actions.get('Network Actions').append(host_action)
            self.subreport_actions.append(host_action.id)

    def __process_connect_ip_api_type(self, connect_ips):
        for connect_ip in connect_ips.get_connect_ip():
            first_associated_object_dict = { 'id' : self.generator.generate_object_id() }
            second_associated_object_dict = { 'id' : self.generator.generate_object_id() }
            
            ip_attributes = {}
            ip_attributes['xsi:type'] = 'AddressObjectType'
            ip_attributes['address_value'] = { 'value' : connect_ip.get_ip(), 'force_datatype' : True }
            if ':' in connect_ip.get_ip():
                ip_attributes['category'] = 'ipv6-addr'
            else:
                ip_attributes['category'] = 'ipv4-addr'
            first_associated_object_dict['properties'] = ip_attributes
            first_associated_object_dict['association_type'] = {'value' : 'input', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}
            
            port_attributes = {}
            port_attributes['xsi:type'] = 'PortObjectType'
            port_attributes['port_value'] = { 'value' : connect_ip.get_port_number(), 'force_datatype' : True }
            second_associated_object_dict['properties'] = port_attributes
            second_associated_object_dict['association_type'] = {'value' : 'input', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}
            
            action_attributes = {}
            action_attributes['id'] = self.generator.generate_malware_action_id()
            action_attributes['name'] = {'value' : 'connect to ip', 'xsi:type' : 'maecVocabs:NetworkActionNameVocab-1.0'}
            action_attributes['associated_objects'] = [first_associated_object_dict, second_associated_object_dict]
            action_attributes['tool_id'] = self.tool_id #static
            connect_action = MalwareAction.from_dict(action_attributes)
            self.actions.get('Network Actions').append(connect_action)
            self.subreport_actions.append(connect_action.id)
    
    def __process_internetconnect_api_type(self, internetconnects):
        for internetconnect in internetconnects.get_internetconnect():
            first_associated_object_dict = { 'id' : self.generator.generate_object_id() }
            second_associated_object_dict = { 'id' : self.generator.generate_object_id() }
            
            url_attributes = {}
            url_attributes['xsi:type'] = 'URIObjectType'
            url_attributes['value'] = {'value' : internetconnect.get_server(), 'force_datatype' : True } 
            
            first_associated_object_dict['properties'] = url_attributes
            first_associated_object_dict['association_type'] = {'value' : 'input', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}
            
            port_attributes = {}
            port_attributes['xsi:type'] = 'PortObjectType'
            port_attributes['port_value'] = { 'value' : internetconnect.get_port_number(), 'force_datatype' : True }
            
            second_associated_object_dict['properties'] = port_attributes
            second_associated_object_dict['association_type'] = {'value' : 'input', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}
            
            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['id'] = self.generator.generate_malware_action_id()
            action_attributes['name'] = {'value' : 'connect to url', 'xsi:type' : 'maecVocabs:NetworkActionNameVocab-1.0'}
            action_attributes['associated_objects'] = [first_associated_object_dict, second_associated_object_dict]
            action_attributes['tool_id'] = self.tool_id #static
            internet_action = MalwareAction.from_dict(action_attributes)
            self.actions.get('Network Actions').append(internet_action)
            self.subreport_actions.append(internet_action.id)

    def __process_getrequests_type(self, requests, internetconnects):
        for internetconnect in internetconnects.get_internetconnect():
            for request in requests.get_request():
                session_attributes = {}
                request_attributes = {}
                associated_object_dict = { 'id' : self.generator.generate_object_id() }
                request_attributes['http_request_line'] = { 'http_method' : { 'value' : 'GET', 'force_datatype' : True }, 'value' : request }
                request_attributes['http_request_header'] = { 'parsed_header' : {
                                                            'host' : {
                                                                'domain_name' : { 'value' : internetconnect.get_server(), 'force_datatype' : True },
                                                                'port' : { 'port_value' : { 'value' : 80, 'force_datatype' : True }, 'xsi:type' : 'PortObjectType' }
                                                            }             
                                                        }}
                session_attributes['xsi:type'] = 'HTTPSessionObjectType'
                session_attributes['http_request_responses'] = [{'http_request_response' : request_attributes }]
                
                associated_object_dict['properties'] = session_attributes
                associated_object_dict['association_type'] = {'value' : 'output', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}
                
                #create the action (that operated on the object)
                action_attributes = {}
                action_attributes['id'] = self.generator.generate_malware_action_id()
                action_attributes['name'] = {'value' : 'send http get request', 'xsi:type' : 'maecVocabs:HTTPActionNameVocab-1.0'}
                action_attributes['associated_objects'] = [associated_object_dict]
                action_attributes['tool_id'] = self.tool_id #static
                internet_action = MalwareAction.from_dict(action_attributes)
                self.actions.get('Network Actions').append(internet_action)
                self.subreport_actions.append(internet_action.id)
        

    def __process_urls_type(self, urls, type):
        for url in urls.get_url():
            url_attributes = {}
            associated_object_dict = { 'id' : self.generator.generate_object_id() }
            url_attributes['xsi:type'] = 'URIObjectType'
            url_attributes['value'] = { 'value' : url, 'force_datatype' : True }
            
            associated_object_dict['properties'] = url_attributes
            associated_object_dict['association_type'] = {'value' : 'input', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}
            
            
            #Generate the MAEC action
            action_attributes = {}
            action_attributes['id'] = self.generator.generate_malware_action_id()
            if type == 'get':
                action_attributes['name'] = { 'value' : 'connect to url', 'xsi:type' : 'maecVocabs:NetworkActionNameVocab-1.0' } 
            elif type == 'open':
                action_attributes['name'] = { 'value' : 'connect to url', 'xsi:type' : 'maecVocabs:NetworkActionNameVocab-1.0' } 
            action_attributes['associated_objects'] = [associated_object_dict]
            action_attributes['tool_id'] = self.tool_id
            url_action = MalwareAction.from_dict(action_attributes)
            self.actions.get('Network Actions').append(url_action)
            self.subreport_actions.append(url_action.id)

    def __process_urldownloadtofile_api_type(self, urldownloadtofile):
        if urldownloadtofile.get_urldownloadtofile_collection() is not None:
            urldownloadtofile_collection = urldownloadtofile.get_urldownloadtofile_collection()
            for url in urldownloadtofile_collection.get_urldownloadtofile():
                first_associated_object_dict = { 'id' : self.generator.generate_object_id() }
                second_associated_object_dict = { 'id' : self.generator.generate_object_id() }
                file_attributes = {}
                url_attributes = {}
                url_string = url.get_url()
                filename = url.get_filename()
                file_attributes['xsi:type'] = 'FileObjectType'
                file_attributes['file_path'] = { 'value' : filename, 'force_datatype' : True }
                
                first_associated_object_dict['properties'] = file_attributes
                first_associated_object_dict['association_type'] = {'value' : 'output', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}
                
                
                url_attributes['xsi:type'] = 'URIObjectType'
                url_attributes['value'] = { 'value' : url_string, 'force_datatype' : True }
                
                second_associated_object_dict['properties'] = url_attributes
                second_associated_object_dict['association_type'] = {'value' : 'input', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}
                
                #Generate the MAEC action
                action_attributes = {}
                action_attributes['id'] = self.generator.generate_malware_action_id()
                action_attributes['name'] = {'value' : 'download file', 'xsi:type' : 'maecVocabs:NetworkActionNameVocab-1.0'}
                action_attributes['associated_objects'] = [first_associated_object_dict, second_associated_object_dict]
                action_attributes['tool_id'] = self.tool_id
                url_file_action = MalwareAction.from_dict(action_attributes)
                self.actions.get('Network Actions').append(url_file_action)
                self.subreport_actions.append(url_file_action.id)

    def __process_setwindowshook_api_type(self, windowshooks):
        # TODO: not complete
        '''for windowshook in windowshooks:
            module_attributes = {}
            associated_object_dict = { 'id' : self.generator.generate_object_id() }
            module_attributes['xsi:type'] = 'LibraryObjectType'
            module_attributes['name'] = windowshook.exports #TODO: use exports correctly
            module_attributes['file_name'] = windowshook.module_filename
            associated_object_dict['properties'] = module_attributes
            associated_object_dict['association_type'] = {'value' : 'input', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}
            
            #Generate the MAEC action
            action_attributes = {}
            action_attributes['id'] = self.generator.generate_malware_action_id()
            action_attributes['undefined_name'] = {'value' : 'load library', 'xsi:type' : 'maecVocabs:LibraryActionNameVocab-1.0'} 
            action_attributes['associated_objects'] = [associated_object_dict]
            action_attributes['tool_id'] = self.tool_id
            module_action = MalwareAction.from_dict(action_attributes)
            self.actions.get('System Actions').append(module_action) #TODO: check if this is correct
            self.subreport_actions.append(module_action.id)'''
        

        return
    
    def __process_wnetaddconnection_api_type(self, wnetaddconnections):
        for wnetaddconnection in wnetaddconnections:
            share_attributes = {}
            associated_object_dict = { 'id' : self.generator.generate_object_id() }
            
            share_attributes['xsi:type'] = 'WindowsNetworkShareObjectType'
            share_attributes['netname'] = { 'value' : wnetaddconnection.remote_name, 'force_datatype' : True }
            share_attributes['local_path'] = { 'value' : wnetaddconnection.local_name, 'force_datatype' : True }
            share_attributes['type'] = { 'value' : wnetaddconnection.resource_type, 'force_datatype' : True }
            associated_object_dict['properties'] = share_attributes
            associated_object_dict['association_type'] = {'value' : 'input', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}
            
            action_attributes = {}
            action_attributes['id'] = self.generator.generate_malware_action_id()
            action_attributes['name'] = {'value' : 'add connection to network share', 'xsi:type' : 'maecVocabs:NetworkShareActionNameVocab-1.0'}
            action_attributes['associated_objects'] = [associated_object_dict]
            action_attributes['tool_id'] = self.tool_id
            connect_action = MalwareAction.from_dict(action_attributes)
            self.actions.get('Network Actions').append(connect_action)
            self.subreport_actions.append(connect_action.get_id())
        return
    
    def __process_procnames_to_terminate_type(self, procnames):
        for procname in procnames.get_procname():
            process_attributes = {}
            process_attributes['xsi:type'] = "ProcessObjectType"
            process_attributes['name'] = { 'value' : procname, 'force_datatype' : True }
            associated_object_dict['properties'] = process_attributes
            associated_object_dict['association_type'] = {'value' : 'output', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}

            # Create the action
            action_attributes = {}
            action_attributes['id'] = self.generator.generate_malware_action_id()
            action_attributes['name'] = {'value' : 'kill process', 'xsi:type' : 'maecVocabs:ProcessActionNameVocab-1.0'}
            action_attributes['associated_objects'] = [associated_object_dict]
            action_attributes['tool_id'] = self.tool_id
            process_action = MalwareAction.from_dict(action_attributes)
            self.actions.get('Process Actions').append(process_action)
            self.subreport_actions.append(process_action.id)
    
    def __get_av_aliases(self, object):
        
        #av_classification_objects = maec.Classifications()
        av_classification_objects = [] 

        #Go through each type of av_alias and add it (if existing)
        if object.get_alias_kav() is not None:
            for alias in object.get_alias_kav().split(", "):
                av_classification_object = { 'classification_name' : alias, 'vendor' : 'Kaspersky' }
                av_classification_objects.append(av_classification_object)
        if object.get_alias_nav() is not None:
            for alias in object.get_alias_nav().split(", "):
                av_classification_object = { 'classification_name' : alias, 'vendor' : 'Norton' }
                av_classification_objects.append(av_classification_object)
        if object.get_alias_nai() is not None:
            for alias in object.get_alias_nai().split(", "):
                av_classification_object = { 'classification_name' : alias, 'vendor' : 'McAfee' }
                av_classification_objects.append(av_classification_object)
        if object.get_alias_trend() is not None:
            for alias in object.get_alias_trend().split(", "):
                av_classification_object = { 'classification_name' : alias, 'vendor' : 'Trend Micro' }
                av_classification_objects.append(av_classification_object)
        if object.get_alias_sophos() is not None:
            for alias in object.get_alias_sophos().split(", "):
                av_classification_object = { 'classification_name' : alias, 'vendor' : 'Sophos' }
                av_classification_objects.append(av_classification_object)
        if object.get_alias_microsoft() is not None:
            for alias in object.get_alias_microsoft().split(", "):
                av_classification_object = { 'classification_name' : object.get_alias_microsoft(), 'vendor' : 'Microsoft' }
                av_classification_objects.append(av_classification_object)
        if object.get_alias_ikarus() is not None:
            for alias in object.get_alias_ikarus().split(", "):
                av_classification_object = { 'classification_name' : object.get_alias_ikarus(), 'vendor' : 'Ikarus' }
                av_classification_objects.append(av_classification_object)
        if object.get_alias_ahnlab() is not None:
            for alias in object.get_alias_ahnlab().split(", "):
                av_classification_object = { 'classification_name' : object.get_alias_ahnlab(), 'vendor' : 'AhnLab' }
                av_classification_objects.append(av_classification_object)
        return av_classification_objects
        