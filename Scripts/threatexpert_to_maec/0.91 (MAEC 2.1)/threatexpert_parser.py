#Copyright (c) 2012, The MITRE Corporation
#All rights reserved.

#ThreatExpert Converter Script
#Ivan Kirillov//ikirillov@mitre.org

#ThreatExpert main parser class
#For use in extracting data from XML ThreatExpert output
import maec_2_1 as maec
import maec_helper
import threatexpert as threatexpert
import cybox.cybox_1_0 as cybox
import cybox.common_types_1_0 as common
import cybox.file_object_1_2 as fileobj
import cybox.win_executable_file_object_1_2 as winexecobj
import cybox.process_object_1_2 as processobj
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
        self.maec_analyses = []
        self.analysis_subject_md5 = None
        self.analysis_subject_path = None
        self.analysis_subject_name = None
        self.tool_id = None
        self.initiator_id = None
        
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
        self.generator = maec_helper.generator('threatexpert_to_maec')
        #Setup the object class
        self.maec_object = maec_helper.maec_object(self.generator)
        #Setup the action class
        self.maec_action = maec_helper.maec_action(self.generator)
        #Setup the action/object dictionaries
        self.__setup_dictionaries()
        #Get the subreports
        subreports = self.report_object.get_subreports()
        for subreport in subreports.get_subreport():
            #Setup the subreport actions array
            self.subreport_actions = []
            #Get and process the analysis metadata
            submission_summary = subreport.get_submission_summary()
            if submission_summary is not None:
                submission_details = submission_summary.get_submission_details()
                if submission_details is not None:
                    sample_info_coll = submission_details.get_sample_info_collection()
                    if sample_info_coll is not None:
                        sample_info = sample_info_coll.get_sample_info()

                        analysis_subject_object = self.__create_analysis_subject_object(subreport, sample_info[0], subreports, id_map)
                        
                        #Create and append the maec analysis object
                        analysis = maec_helper.maec_analysis(self.generator, analysis_subject_object, 'ThreatExpert', 'ThreatExpert')
                        self.maec_analyses.append(analysis.get_analysis_object())
                        
                        self.tool_id = analysis.get_tool_id()
            
            #Get and process the technical details
            techdetails = subreport.get_technical_details()
            if techdetails is not None:
                self.__process_technical_details(techdetails)

            #add the action references to the analysis findings           
            action_references = maec.Action_References()
            for action_id in self.subreport_actions:
                action_reference = maec.cybox.ActionReferenceType(action_id = action_id)
                action_references.add_Action_Reference(action_reference)
            analysis.get_analysis_object().set_Findings(maec.AnalysisFindingsType(Actions=action_references))

    # Create an analysis subject object, used in maec_helper.maec_analysis
    def __create_analysis_subject_object(self, analysis_subject, general_info, analysis_subjects, id_map):
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
            self.analysis_subject_md5 = md5
        if general_info.get_sha1() != None: sha1 = general_info.get_sha1()
        if general_info.get_filesize() != None: file_size = general_info.get_filesize()                  
        if general_info.get_packer() != None: packer = general_info.get_packer()
        
        av_aliases = self.__get_av_aliases(general_info) 
        #create the analysis subject object
        analysis_subject_object = maec.AnalysisSubjectType()
        
        #Create the file object and add the attributes
        cybox_object = cybox.ObjectType(id=self.generator.generate_obj_id(), type_='File')
        file_object = winexecobj.WindowsExecutableFileObjectType()
        file_object.set_anyAttributes_({'xsi:type' : 'WinExecutableFileObj:WindowsExecutableFileObjectType'})

        if file_size != None:
            size = common.UnsignedLongObjectAttributeType(datatype='UnsignedLong', valueOf_=file_size)
            file_object.set_Size_In_Bytes(size)
        if av_aliases != None:
            cybox_object.set_Domain_specific_Object_Attributes(av_aliases) 
        if packer != None and len(packer.strip()) > 0:
            split_packer = packer.split(' ')
            packer_list = fileobj.PackerListType()
            if len(split_packer) == 2:
                packer = fileobj.PackerAttributesType(Name=common.StringObjectAttributeType(datatype='String', valueOf_=split_packer[0]), Version=common.StringObjectAttributeType(datatype='String', valueOf_=split_packer[1]))
            else:
                packer = fileobj.PackerAttributesType(Name=common.StringObjectAttributeType(datatype='String', valueOf_=split_packer[0]))
            packer_list.add_Packer(packer)
            file_object.set_Packer_List(packer_list)
        if md5 != None or sha1 != None:
            hashes = common.HashListType()
            if md5 != None:
                hash_value = common.HexBinaryObjectAttributeType(datatype='hexBinary', valueOf_=md5)
                hash_type = common.HashNameType(datatype='String', valueOf_='MD5')
                hash = common.HashType(Simple_Hash_Value=hash_value, Type=hash_type)
                hashes.add_Hash(hash)
            if sha1 != None:
                hash_value = common.HexBinaryObjectAttributeType(datatype='hexBinary', valueOf_=sha1)
                hash_type = common.HashNameType(datatype='String', valueOf_='SHA1')
                hash = common.HashType(Simple_Hash_Value=hash_value, Type=hash_type)
                hashes.add_Hash(hash)
            file_object.set_Hashes(hashes)
        if dll_dependencies != None:
            pe_attributes = winexecobj.PEAttributesType()
            pe_imports = winexecobj.PEImportListType()
            for loaded_dll in dll_dependencies.get_loaded_dll():
                pe_import = winexecobj.PEImportType()
                pe_import.set_File_Name(common.StringObjectAttributeType(datatype='String', valueOf_=loaded_dll.get_full_name()))
                pe_import.set_Virtual_Address(common.HexBinaryObjectAttributeType(datatype='hexBinary', valueOf_=loaded_dll.get_base_address().lstrip('0x')))
                pe_import.set_delay_load(not bool(int(loaded_dll.get_is_load_time_dependency())))
                pe_imports.add_Import(pe_import)
            if pe_imports.hasContent_():
                pe_attributes.set_Imports(pe_imports)
            if pe_attributes.hasContent_():
                file_object.set_PE_Attributes(pe_attributes)
        
        #add the specific analysis subject attributes
        if arguments != None:
            analysis_subject_object.set_Command_Line(arguments.strip())
        if exit_code != None:
            analysis_subject_object.set_Exit_Code(exit_code)
        
        #set the object as the defined object
        cybox_object.set_Defined_Object(file_object)
        
        #bind the object to the analysis subject object
        analysis_subject_object.set_Object(cybox_object)
        
        return analysis_subject_object
                
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
        actions['file_system'] = []
        actions['ipc'] = []
        actions['service'] = []
        actions['registry'] = []
        actions['gui'] = []
        actions['network'] = []
        actions['memory'] = []
        actions['process'] = []
        actions['module'] = []
        actions['system'] = []
        actions['internet'] = []
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
        #if techdetails.get_added_drivers() is not None: self.__process_added_drivers_type(techdetails.get_added_drivers()) #deprecated?
        if techdetails.get_added_syscallhooks() is not None: self.__process_added_syscallhooks_type(techdetails.get_added_syscallhooks()) #stub
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
        #Revisit - CybOX does not currently support HTTP get requests
        #if techdetails.get_getrequests() is not None: self.__process_getrequests_type(techdetails.get_getrequests())
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
                file_attributes['md5'] = file_object.get_md5()
                if file_object.get_sha1() is not None:
                    file_attributes['sha1'] = file_object.get_sha1()
                filenames = file_object.get_filenames_collection()
                if file_object.get_packer() is not None : file_attributes['packer'] = file_object.get_packer() 
                file_attributes['av_aliases'] = self.__get_av_aliases(file_object)
                for filename in filenames.get_filename():
                    split_filename = filename.split('\\')
                    actual_filename = split_filename[len(split_filename)-1]
                    filepath = filename.rstrip(actual_filename)
                    if 'sample #1]' in filename:
                        actual_filename = None
                    file_attributes['filename'] = actual_filename
                    file_attributes['filepath'] = filepath
                    if type == 'file':
                        file_attributes['type'] = 'File'
                    elif type == 'stream':
                        file_attributes['type'] = 'Other' 
                    file_attributes['association'] = 'Affected'
                    #Generate the MAEC objects and actions
                    #First, create the object
                    fs_object = self.maec_object.create_file_system_object(file_attributes)
                    #Next, create the action (that operated on the object)
                    action_attributes = {}
                    if type == 'file':
                        action_attributes['defined_action_name'] = 'Create File'
                    elif type == 'stream':
                        action_attributes['undefined_action_name'] = 'Create NTFS Alternate Data Stream'
                    action_attributes['action_type'] = 'create'
                    action_attributes['object'] = fs_object
                    action_attributes['tool_id'] = self.tool_id
                    fs_action = self.maec_action.create_action(action_attributes)
                    self.actions.get('file_system').append(fs_action)
                    self.subreport_actions.append(fs_action.get_id())

    def __process_filenames_notes_type(self, filenames_notes, type):
        if filenames_notes.get_filenames_collection() is not None:
            files_collection = filenames_notes.get_filenames_collection()
            for filename in files_collection.get_filename():
                file_attributes = {}
                split_filename = filename.split('\\')
                actual_filename = split_filename[len(split_filename)-1]
                filepath = filename.rstrip(actual_filename)
                file_attributes['filename'] = actual_filename
                file_attributes['filepath'] = filepath
                file_attributes['type'] = 'File'
                file_attributes['association'] = 'Affected'
                #Generate the MAEC objects and actions
                #First, create the object
                fs_object = self.maec_object.create_file_system_object(file_attributes)
                #Next, create the action (that operated on the object)
                action_attributes = {}
                if type == 'delete':
                    action_attributes['defined_action_name'] = 'Delete File'
                    action_attributes['action_type'] = 'Remove/Delete'
                elif type == 'modify':
                    action_attributes['defined_action_name'] = 'Modify File'
                    action_attributes['action_type'] = 'modify'
                action_attributes['object'] = fs_object
                action_attributes['tool_id'] = self.tool_id
                fs_action = self.maec_action.create_action(action_attributes)
                self.actions.get('file_system').append(fs_action)
                self.subreport_actions.append(fs_action.get_id())

    def __process_dirnames_notes_type(self, dirnames_notes, type):
        if dirnames_notes.get_dirnames_collection() is not None:
            dirnames_collection = dirnames_notes.get_dirnames_collection()
            for dirname in dirnames_collection.get_dirname():
                dir_attributes = {}
                dir_attributes['filepath'] = dirname
                dir_attributes['type'] = 'Directory'
                dir_attributes['association'] = 'Affected'
                #Generate the MAEC objects and actions
                #First, create the object
                dir_object = self.maec_object.create_file_system_object(dir_attributes)
                #Next, create the action (that operated on the object)
                action_attributes = {}
                if type == 'create':
                    action_attributes['defined_action_name'] = 'Create Directory'
                    action_attributes['action_type'] = 'create'
                elif type == 'delete':
                    action_attributes['defined_action_name'] = 'Delete Directory'
                    action_attributes['action_type'] = 'Remove/Delete'
                action_attributes['object'] = dir_object
                action_attributes['tool_id'] = self.tool_id
                fs_action = self.maec_action.create_action(action_attributes)
                self.actions.get('file_system').append(fs_action)
                self.subreport_actions.append(fs_action.get_id())

    def __process_added_processes_type(self, added_processes):
        if added_processes.get_added_processes_collection() is not None:
            processes_collection = added_processes.get_added_processes_collection()
            for process in processes_collection.get_added_process():
                process_attributes = {}
                if process.get_process_name() == '[filename of the sample #1]':
                    if self.analysis_subject_name is not None:
                        process_attributes['name'] = self.analysis_subject_name
                else:
                    process_attributes['name'] = process.get_process_name()
                
                if process.get_process_filename() == '[file and pathname of the sample #1]':
                    if self.analysis_subject_path is not None:
                        process_attributes['filename'] = self.analysis_subject_path + '\\' + self.analysis_subject_name
                else:
                    process_attributes['filename'] = process.get_process_filename()
                process_attributes['association'] = 'Affected'
                #Generate the MAEC objects and actions
                #First, create the object
                process_object = self.maec_object.create_process_object(process_attributes)
                #Next, create the action (that operated on the object)
                action_attributes = {}
                action_attributes['defined_action_name'] = 'Create Process'
                action_attributes['action_type'] = 'create'
                action_attributes['object'] = process_object
                action_attributes['tool_id'] = self.tool_id
                process_action = self.maec_action.create_action(action_attributes)
                self.actions.get('process').append(process_action)
                self.subreport_actions.append(process_action.get_id())

    def __process_added_hidden_processes_type(self, added_hidden_processes):
        if added_hidden_processes.get_added_hidden_processes_collection() is not None:
            processes_collection = added_hidden_processes.get_added_hidden_processes_collection()
            for process in processes_collection.get_added_hidden_process():
                process_attributes = {}
                if process.get_process_name() == '[filename of the sample #1]':
                    if self.analysis_subject_name is not None:
                        process_attributes['name'] = self.analysis_subject_name
                else:
                    process_attributes['name'] = process.get_process_name()
                process_attributes['association'] = 'Affected'
                #Generate the MAEC objects and actions
                #First, create the object
                process_object = self.maec_object.create_process_object(process_attributes)
                #Next, create the action (that operated on the object)
                action_attributes = {}
                action_attributes['defined_action_name'] = 'Create Process'
                action_attributes['action_type'] = 'create'
                action_attributes['object'] = process_object
                action_attributes['tool_id'] = self.tool_id
                process_action = self.maec_action.create_action(action_attributes)
                self.actions.get('process').append(process_action)
                self.subreport_actions.append(process_action.get_id())
                
    def __process_injected_mempages_type(self, injected_mempages):
        for mempage in injected_mempages.get_injected_mempages_collection().get_injected_mempage():
            # we want to specify what process this page is getting injected into
            process_attributes = {}
            process_attributes['name'] = mempage.get_process_name()
            process_attributes['filename'] = mempage.get_process_filename()
            process_attributes['association'] = 'Affected'
            process_object = self.maec_object.create_process_object(process_attributes)

            mempage_attributes = {}
            mempage_attributes['size'] = mempage.get_allocated_size()
            mempage_attributes['association'] = 'Utilized'
            mempage_object = self.maec_object.create_memory_object(mempage_attributes)
            
            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['undefined_action_name'] = 'Inject Memory Page'
            action_attributes['action_type'] = 'create'
            action_attributes['object'] = mempage_object
            action_attributes['secondary_object'] = process_object

            action_attributes['tool_id'] = self.tool_id #static
            memory_action = self.maec_action.create_action(action_attributes)
            self.actions.get('memory').append(memory_action)
            self.subreport_actions.append(memory_action.get_id())

    #Revisit
    def __process_added_modules_type(self, added_modules):
        if added_modules.get_added_modules_collection() is not None:
            modules_collection = added_modules.get_added_modules_collection()
            for module in modules_collection.get_added_module():
                module_attributes = {}
                module_attributes['name'] = module.get_module_name()
                module_attributes['filename'] = module.get_module_filename()
                module_attributes['association'] = 'Affected'
                #Generate the MAEC objects and actions
                #First, create the object
                module_object = self.maec_object.create_module_object(module_attributes)
                #Next, create the action (that operated on the object)
                action_attributes = {}
                action_attributes['undefined_action_name'] = 'Create Module'
                action_attributes['action_type'] = 'create'
                action_attributes['object'] = module_object
                action_attributes['tool_id'] = self.tool_id
                module_action = self.maec_action.create_action(action_attributes)
                self.actions.get('module').append(module_action)
                self.subreport_actions.append(module_action.get_id())

    def __process_added_services_type(self, added_services):
        if added_services.get_added_services_collection() is not None:
            added_services_collection = added_services.get_added_services_collection()
            for service in added_services_collection.get_added_service():
                service_attributes = {}
                try:
                    service_attributes['name'] = service.get_service_name()
                    service_attributes['display_name'] = service.get_display_name()
                    service_attributes['filename'] = service.get_service_filename()
                    service_attributes['service_status'] = service.get_status()
                    service_attributes['association'] = 'Affected'
                except AttributeError:
                    pass
                #Generate the MAEC objects and actions
                #First, create the object
                service_object = self.maec_object.create_service_object(service_attributes)
                #Next, create the action (that operated on the object)
                action_attributes = {}
                action_attributes['defined_action_name'] = 'Create Service'
                action_attributes['action_type'] = 'create'
                action_attributes['object'] = service_object
                action_attributes['tool_id'] = self.tool_id
                service_action = self.maec_action.create_action(action_attributes)
                self.actions.get('service').append(service_action)
                self.subreport_actions.append(service_action.get_id())

    def __process_modified_services_type(self, modified_services):
        if modified_services.get_modified_services_collection() is not None:
            modified_services_collection = modified_services.get_modified_services_collection()
            for service in modified_services_collection.get_modified_service():
                service_attributes = {}
                try:
                    service_attributes['name'] = service.get_service_name()
                    service_attributes['display_name'] = service.get_display_name()
                    service_attributes['filename'] = service.get_service_filename()
                    service_attributes['service_status'] = service.get_status()
                    service_attributes['association'] = 'Affected'
                except AttributeError:
                    pass
                #Generate the MAEC objects and actions
                #First, create the object
                service_object = self.maec_object.create_win_service_object(service_attributes)
                #Next, create the action (that operated on the object)
                action_attributes = {}
                action_attributes['defined_action_name'] = 'Modify Service'
                action_attributes['action_type'] = 'modify'
                action_attributes['object'] = service_object
                action_attributes['tool_id'] = self.tool_id
                service_action = self.maec_action.create_action(action_attributes)
                self.actions.get('service').append(service_action)
                self.subreport_actions.append(service_action.get_id())

    #def __process_added_drivers_type(self, added_drivers): #stub
        #print "added drivers " + added_drivers
        #return
    
    def __process_added_syscallhooks_type(self, added_syscallhooks):
        if added_syscallhooks.get_added_syscallhooks_collection() is not None:
            added_syscallhooks_collection = added_syscallhooks.get_added_syscallhooks_collection()
            for added_syscallhook in added_syscallhooks_collection.get_added_syscallhook():
                driver_attributes = {}
                driver_attributes['filename'] = added_syscallhook.driver_filename
                driver_attributes['association'] = "Utilized" 
                driver_object = self.maec_object.create_win_driver_object(driver_attributes)
            
                # TODO: add syscall that is getting hooked
                action_attributes = {}
                action_attributes['undefined_action_name'] = 'Add System Call Hook'
                action_attributes['action_type'] = 'create'
                action_attributes['object'] = driver_object
                action_attributes['tool_id'] = self.tool_id
                hook_action = self.maec_action.create_action(action_attributes)
                self.actions.get('system').append(hook_action) #TODO: check if this is correct
                self.subreport_actions.append(hook_action.get_id())
    
    def __process_regkeys_type(self, regkeys, type):
        for regkey in regkeys.get_regkey():
            regkey_attributes = {}
            split_regkey = regkey.split('\\')
            regkey_attributes['hive'] = split_regkey[0]
            actual_key = ''
            for i in range(1, len(split_regkey)):
                actual_key += (split_regkey[i] + '\\')
            actual_key = actual_key.rstrip('\\')
            regkey_attributes['key'] = actual_key
            regkey_attributes['type'] = 'Key/Key Group'
            regkey_attributes['association'] = 'Affected'
            #Generate the MAEC objects and actions
            #First, create the object
            reg_object = self.maec_object.create_registry_object(regkey_attributes)
            #Next, create the action (that operated on the object)
            action_attributes = {}
            if type == 'create':
                action_attributes['defined_action_name'] = 'Create Registry Key'
                action_attributes['action_type'] = 'create'
            elif type == 'delete':
                action_attributes['defined_action_name'] = 'Delete Registry Key'
                action_attributes['action_type'] = 'Remove/Delete'
            action_attributes['object'] = reg_object
            action_attributes['tool_id'] = self.tool_id
            reg_action = self.maec_action.create_action(action_attributes)
            self.actions.get('registry').append(reg_action)
            self.subreport_actions.append(reg_action.get_id())

    def __process_regvalues_structures_type(self, regvalues, type):
        if regvalues.get_regvalues_structure() is not None:
            reg_values = regvalues.get_regvalues_structure()
            for regvalue in reg_values:
                regkey = regvalue.get_regkey()
                regkey_attributes = {}
                split_regkey = regkey.split('\\')
                regkey_attributes['hive'] = split_regkey[0]
                actual_key = ''
                for i in range(1, len(split_regkey)):
                    actual_key += (split_regkey[i] + '\\')
                actual_key = actual_key.rstrip('\\')
                regkey_attributes['key'] = actual_key
                regkey_attributes['type'] = 'Key/Key Group'
                regvalues_collection = regvalue.get_regvalues_collection()
                for regvalue in regvalues_collection.get_regvalue():
                    regkey_attributes['value'] = regvalue.get_value()
                    regkey_attributes['valuedata'] = regvalue.get_contents()
                    regkey_attributes['association'] = 'Affected'
                    #Generate the MAEC objects and actions
                    #First, create the object
                    reg_object = self.maec_object.create_registry_object(regkey_attributes)
                    #Next, create the action (that operated on the object)
                    action_attributes = {}
                    if type == 'create':
                        action_attributes['undefined_action_name'] = 'Create Registry Key Value'
                        action_attributes['action_type'] = 'create'
                    elif type == 'delete':
                        action_attributes['defined_action_name'] = 'Delete Registry Key Value'
                        action_attributes['action_type'] = 'Remove/Delete'
                    elif type == 'modify':
                        action_attributes['undefined_action_name'] = 'Modify Registry Key Value'
                        action_attributes['action_type'] = 'modify'
                    action_attributes['object'] = reg_object
                    action_attributes['tool_id'] = self.tool_id
                    reg_action = self.maec_action.create_action(action_attributes)
                    self.actions.get('registry').append(reg_action)
                    self.subreport_actions.append(reg_action.get_id())

    def __process_mutexes_type(self, mutexes):
        for mutex in mutexes.get_mutex():
            mutex_attributes = {}
            mutex_attributes['name']  = mutex
            mutex_attributes['type'] = 'Mutex'
            mutex_attributes['association'] = 'Affected'
            #Generate the MAEC objects and actions
            #First, create the object
            mutex_object = self.maec_object.create_mutex_object(mutex_attributes)
            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['defined_action_name'] = 'Create Mutex'
            action_attributes['action_type'] = 'create'
            action_attributes['object'] = mutex_object
            action_attributes['tool_id'] = self.tool_id
            mutex_action = self.maec_action.create_action(action_attributes)
            self.actions.get('ipc').append(mutex_action)
            self.subreport_actions.append(mutex_action.get_id())

    def __process_open_ports_type(self, openports):
        if openports.get_open_ports_collection() is not None:
            open_ports_collection = openports.get_open_ports_collection()
            for open_port in open_ports_collection.get_open_port():
                port_attributes = {}
                port_attributes['port']  = open_port.get_port_number()
                port_attributes['protocol'] = open_port.get_protocol()
                port_attributes['type'] = 'Port'
                port_attributes['association'] = 'Affected'
                #Generate the MAEC objects and actions
                #First, create the object
                port_object = self.maec_object.create_socket_object(port_attributes)
                #Next, create the action (that operated on the object)
                action_attributes = {}
                action_attributes['defined_action_name'] = 'Open Port'
                action_attributes['action_type'] = 'Open'
                action_attributes['object'] = port_object
                action_attributes['tool_id'] = self.tool_id
                port_action = self.maec_action.create_action(action_attributes)
                self.actions.get('network').append(port_action)
                self.subreport_actions.append(port_action.get_id())

    def __process_gethostbyname_api_type(self, hosts):
        for host in hosts.get_host():
            host_attributes = {}
            host_attributes['type'] = 'URI'
            host_attributes['uri'] = host
            host_attributes['association'] = 'Utilized'
            #Generate the MAEC objects and actions
            #First, create the object
            host_object = self.maec_object.create_internet_object(host_attributes)
            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['defined_action_name'] = 'Get Host By Name'
            action_attributes['action_type'] = 'get'
            action_attributes['object'] = host_object
            action_attributes['tool_id'] = self.tool_id
            host_action = self.maec_action.create_action(action_attributes)
            self.actions.get('internet').append(host_action)
            self.subreport_actions.append(host_action.get_id())

    def __process_connect_ip_api_type(self, connect_ips):
        for connect_ip in connect_ips.get_connect_ip():
            ip_attributes = {}
            ip_attributes['address_value'] = connect_ip.get_ip()
            if ':' in connect_ip.get_ip():
                ip_attributes['category'] = 'ipv6-addr'
            else:
                ip_attributes['category'] = 'ipv4-addr'
            ip_attributes['association'] = 'Utilized'
            
            port_attributes = {}
            port_attributes['type'] = 'Port'
            port_attributes['value'] = connect_ip.get_port_number()
            port_attributes['association'] = 'Utilized'

            ip_object = self.maec_object.create_address_object(ip_attributes)
            port_object = self.maec_object.create_port_object(port_attributes)
            
            action_attributes = {}
            action_attributes['undefined_action_name'] = 'Connect to IP'
            action_attributes['action_type'] = 'Connect'
            action_attributes['object'] = ip_object
            action_attributes['secondary_object'] = port_object
            action_attributes['tool_id'] = self.tool_id #static
            connect_action = self.maec_action.create_action(action_attributes)
            self.actions.get('internet').append(connect_action)
            self.subreport_actions.append(connect_action.get_id())
    
    def __process_internetconnect_api_type(self, internetconnects):
        for internetconnect in internetconnects.get_internetconnect():
            url_attributes = {}
            url_attributes['type'] = 'URI'
            url_attributes['uri'] = internetconnect.get_server()
            url_attributes['association'] = 'Utilized'
            port_attributes = {}
            port_attributes['type'] = 'Port'
            port_attributes['value'] = internetconnect.get_port_number()
            port_attributes['association'] = 'Utilized'
            
            url_object = self.maec_object.create_internet_object(url_attributes)
            port_object = self.maec_object.create_port_object(port_attributes)
            
            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['undefined_action_name'] = 'Connect to URL'
            action_attributes['action_type'] = 'Connect'
            action_attributes['object'] = url_object
            action_attributes['secondary_object'] = port_object
            port_attributes['association'] = 'Utilized'

            action_attributes['tool_id'] = self.tool_id #static
            internet_action = self.maec_action.create_action(action_attributes)
            self.actions.get('internet').append(internet_action)
            self.subreport_actions.append(internet_action.get_id())

    def __process_urls_type(self, urls, type):
        for url in urls.get_url():
            url_attributes = {}
            url_attributes['type'] = 'URI'
            url_attributes['uri'] = url
            url_attributes['association'] = 'Utilized'
            #Generate the MAEC objects and actions
            #First, create the object
            url_object = self.maec_object.create_internet_object(url_attributes)
            #Next, create the action (that operated on the object)
            action_attributes = {}
            if type == 'get':
                action_attributes['undefined_action_name'] = 'Get URL'
                action_attributes['action_type'] = 'get'
            elif type == 'open':
                action_attributes['undefined_action_name'] = 'Access URL'
                action_attributes['action_type'] = 'Access'
            action_attributes['object'] = url_object
            action_attributes['tool_id'] = self.tool_id
            url_action = self.maec_action.create_action(action_attributes)
            self.actions.get('internet').append(url_action)
            self.subreport_actions.append(url_action.get_id())

    def __process_urldownloadtofile_api_type(self, urldownloadtofile):
        if urldownloadtofile.get_urldownloadtofile_collection() is not None:
            urldownloadtofile_collection = urldownloadtofile.get_urldownloadtofile_collection()
            for url in urldownloadtofile_collection.get_urldownloadtofile():
                url_file_attributes = {}
                url_string = url.get_url()
                filename = url.get_filename()
                split_filename = filename.split('\\')
                actual_filename = split_filename[len(split_filename)-1]
                url_file_attributes['filename'] = actual_filename
                url_file_attributes['filepath'] = filename.rstrip(actual_filename)
                url_file_attributes['origin'] = url_string
                url_file_attributes['association'] = 'Affected'
                #Generate the MAEC objects and actions
                #First, create the object
                url_file_object = self.maec_object.create_file_system_object(url_file_attributes)
                #Next, create the action (that operated on the object)
                action_attributes = {}
                action_attributes['undefined_action_name'] = 'Download File'
                action_attributes['action_type'] = 'download'
                action_attributes['object'] = url_file_object
                action_attributes['tool_id'] = self.tool_id
                url_file_action = self.maec_action.create_action(action_attributes)
                self.actions.get('internet').append(url_file_action)
                self.subreport_actions.append(url_file_action.get_id())

    def __process_setwindowshook_api_type(self, windowshooks):
        # TODO: not complete
        '''for windowshook in windowshooks:
            module_attributes = {}
            module_attributes['path'] = windowshook.module_filename
            #module_attributes['name'] = windowshook.exports #TODO: use exports correctly
            module_attributes['association'] = "Utilized" 
            module_object = self.maec_object.create_library_object(module_attributes)
            
            action_attributes = {}
            action_attributes['undefined_action_name'] = 'Add Windows Hook'
            action_attributes['action_type'] = 'create'
            action_attributes['object'] = mutex_object
            action_attributes['tool_id'] = self.tool_id
            action_attributes['initiator_id'] = self.initiator_id
            hook_action = self.maec_action.create_action(action_attributes)
            self.actions.get('system').append(hook_action) #TODO: check if this is correct
            self.subreport_actions.append(hook_action.get_id())'''
        return
    
    def __process_wnetaddconnection_api_type(self, wnetaddconnections):
        for wnetaddconnection in wnetaddconnections:
            share_attributes = {}
            share_attributes['netname'] = wnetaddconnection.remote_name;
            share_attributes['local_path'] = wnetaddconnection.local_name
            share_attributes['type'] = wnetaddconnection.resource_type
            share_attributes['association'] = 'Utilized'
            share_object = create_win_network_share_object(share_attributes)
            
            action_attributes['undefined_action_name'] = 'Add connection to network share'
            action_attributes['action_type'] = 'connect'
            action_attributes['object'] = share_object
            action_attributes['tool_id'] = self.tool_id
            connect_action = self.maec_action.create_action(action_attributes)
            self.actions.get('internet').append(url_action)
            self.subreport_actions.append(connect_action.get_id())
        return
    
    def __process_procnames_to_terminate_type(self, procnames):
        for procname in procnames.get_procname():
            process_attributes = {}
            process_attributes['name'] = procname
            process_attributes['association'] = 'Affected'
            #Generate the MAEC objects and actions
            #First, create the object
            process_object = self.maec_object.create_process_object(process_attributes)

            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['defined_action_name'] = 'Kill Process'
            action_attributes['action_type'] = 'kill'
            action_attributes['object'] = process_object
            action_attributes['tool_id'] = self.tool_id
            process_action = self.maec_action.create_action(action_attributes)
            self.actions.get('process').append(process_action)
            self.subreport_actions.append(process_action.get_id())
    
    def __get_av_aliases(self, object):
        
        #av_classification_objects = maec.Classifications()
        av_classification_objects = maec.AVClassificationsType()

        #Go through each type of av_alias and add it (if existing)
        av_classification_object = {}
        
        if object.get_alias_kav() is not None:
            av_classification_object = maec.mmdef.classificationObject(classificationName=object.get_alias_kav(), companyName='Kaspersky', id=self.generator.generate_id(), type_='dirty')
            av_classification_objects.add_AV_Classification(av_classification_object)
        if object.get_alias_nav() is not None:
            av_classification_object = maec.mmdef.classificationObject(classificationName=object.get_alias_nav(), companyName='Norton', id=self.generator.generate_id(), type_='dirty')
            av_classification_objects.add_AV_Classification(av_classification_object)
        if object.get_alias_nai() is not None:
            av_classification_object = maec.mmdef.classificationObject(classificationName=object.get_alias_nai(), companyName='McAfee', id=self.generator.generate_id(), type_='dirty')
            av_classification_objects.add_AV_Classification(av_classification_object)
        if object.get_alias_trend() is not None:
            av_classification_object = maec.mmdef.classificationObject(classificationName=object.get_alias_trend(), companyName='Trend Micro', id=self.generator.generate_id(), type_='dirty')
            av_classification_objects.add_AV_Classification(av_classification_object)
        if object.get_alias_sophos() is not None:
            av_classification_object = maec.mmdef.classificationObject(classificationName=object.get_alias_sophos(), companyName='Sophos', id=self.generator.generate_id(), type_='dirty')
            av_classification_objects.add_AV_Classification(av_classification_object)
        if object.get_alias_microsoft() is not None:
            av_classification_object = maec.mmdef.classificationObject(classificationName=object.get_alias_microsoft(), companyName='Microsoft', id=self.generator.generate_id(), type_='dirty')
            av_classification_objects.add_AV_Classification(av_classification_object)
        if object.get_alias_ikarus() is not None:
            av_classification_object = maec.mmdef.classificationObject(classificationName=object.get_alias_ikarus(), companyName='Ikarus', id=self.generator.generate_id(), type_='dirty')
            av_classification_objects.add_AV_Classification(av_classification_object)
        if object.get_alias_ahnlab() is not None:
            av_classification_object = maec.mmdef.classificationObject(classificationName=object.get_alias_ahnlab(), companyName='AhnLab', id=self.generator.generate_id(), type_='dirty')
            av_classification_objects.add_AV_Classification(av_classification_object)
        if av_classification_objects.hasContent_():
            av_classification_objects.set_type_('maec:AVClassificationsType')
            return av_classification_objects
        else:
            return None
        