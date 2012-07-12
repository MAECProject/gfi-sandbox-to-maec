#Copyright (c) 2011, The MITRE Corporation
#All rights reserved.

#ThreatExpert Converter Script
#Ivan Kirillov//ikirillov@mitre.org

#ThreatExpert main parser class
#For use in extracting data from XML ThreatExpert output
import maecv11 as maec
import maec_types as maec_types
import threatexpert as threatexpert

class parser:
    
    def __init__(self):
        #array for storing actions
        self.actions = []
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
        self.objects = None
        self.maec_object = None
        self.maec_action = None
        self.maec_actions = {}
        self.maec_objects = {}
        self.maec_behaviors = {}
        self.maec_analysis = None
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
        except Exception, err:
           print('\nError: %s\n' % str(err))
           
    #Parse the XML document
    #Extract processes, actions, and information about the analysis subject
    def parse_document(self):
        #Setup the generator
        self.generator = maec_types.generator('threatexpert_to_maec')
        #Setup the object class
        self.maec_object = maec_types.maec_object(self.generator)
        #Setup the action class
        self.maec_action = maec_types.maec_action(self.generator)
        #Setup the action/object dictionaries
        self.__setup_dictionaries()
        #Get the subreports
        subreports = self.report_object.get_subreports()
        for subreport in subreports.get_subreport():
            #Get the analysis data
            submission_summary = subreport.get_submission_summary()
            if submission_summary != None:
                submission_details = submission_summary.get_submission_details()
                if submission_details != None:
                    sample_info_coll = submission_details.get_sample_info_collection()
                    if sample_info_coll != None:
                        sample_info = sample_info_coll.get_sample_info()
                        analysis_subject_md5 = sample_info[0].get_md5()
                        self.analysis_subject_md5 = analysis_subject_md5
                        analysis_subject_sha1 = sample_info[0].get_sha1()
                        analysis_subject_size = sample_info[0].get_filesize()
                        av_aliases = self.__get_av_aliases(sample_info[0])
                        packer = None
                        if sample_info[0].get_packer() != None:
                            packer = sample_info[0].get_packer()
                        #create the maec analysis object
                        analysis = maec_types.maec_analysis(self.generator, analysis_subject_md5, analysis_subject_sha1,
                                                            analysis_subject_size, packer, av_aliases, 'ThreatExpert', 'ThreatExpert')
                        analysis.create_analysis()
                        self.maec_analysis = analysis.get_analysis_object()
                        self.tool_id = analysis.get_tool_id()
                        self.initiator_id = analysis.get_analysis_file_object().get_id()
                        self.objects.get('file_system').append(analysis.get_analysis_file_object())
            #Get the technical details
            techdetails = subreport.get_technical_details()
            if techdetails != None:
                self.__process_technical_details(techdetails)
                
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
    def __setup_dictionaries(self):
        #setup the actions
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
        
        #setup the objects
        objects = {}
        objects['file_system'] = []
        objects['ipc'] = []
        objects['service'] = []
        objects['registry'] = []
        objects['gui'] = []
        objects['network'] = []
        objects['memory'] = []
        objects['process'] = []
        objects['module'] = []
        objects['system'] = []
        objects['internet'] = []
        self.objects = objects
        
    #Parse the technical details in the report
    #This is where the majority of the content resides
    #To do: add support for MAEC behavior generation for certain elements (e.g. filestosearch)
    def __process_technical_details(self, techdetails):
        if techdetails.get_added_files() != None: self.__process_added_files_type(techdetails.get_added_files(),'file')
        if techdetails.get_added_hidden_files() != None: self.__process_added_files_type(techdetails.get_added_hidden_files(),'file')
        if techdetails.get_added_streams() != None: self.__process_added_files_type(techdetails.get_added_streams(),'stream')
        if techdetails.get_added_hidden_streams() != None: self.__process_added_files_type(techdetails.get_added_hidden_streams(),'stream')
        if techdetails.get_deleted_files() != None: self.__process_filenames_notes_type(techdetails.get_deleted_files(), 'delete')
        if techdetails.get_modified_files() != None: self.__process_filenames_notes_type(techdetails.get_modified_files(), 'modify')
        if techdetails.get_added_directories() != None: self.__process_dirnames_notes_type(techdetails.get_added_directories(), 'create')
        if techdetails.get_added_hidden_directories() != None: self.__process_dirnames_notes_type(techdetails.get_added_hidden_directories(), 'create')
        if techdetails.get_deleted_directories() != None: self.__process_dirnames_notes_type(techdetails.get_deleted_directories(), 'create')
        if techdetails.get_added_processes() != None: self.__process_added_processes_type(techdetails.get_added_processes())
        if techdetails.get_added_hidden_processes() != None: self.__process_added_hidden_processes_type(techdetails.get_added_hidden_processes())
        if techdetails.get_added_modules() != None: self.__process_added_modules_type(techdetails.get_added_modules())
        if techdetails.get_added_services() != None: self.__process_added_services_type(techdetails.get_added_services())
        if techdetails.get_modified_services() != None: self.__process_modified_services_type(techdetails.get_modified_services())
        if techdetails.get_added_regkeys() != None: self.__process_regkeys_type(techdetails.get_added_regkeys(), 'create')
        if techdetails.get_added_hidden_regkeys() != None: self.__process_regkeys_type(techdetails.get_added_hidden_regkeys(), 'create')
        if techdetails.get_deleted_regkeys() != None: self.__process_regkeys_type(techdetails.get_deleted_regkeys(), 'delete')
        if techdetails.get_added_regvalues() != None: self.__process_regvalues_structures_type(techdetails.get_added_regvalues(), 'create')
        if techdetails.get_added_hidden_regvalues() != None: self.__process_regvalues_structures_type(techdetails.get_added_hidden_regvalues(), 'create')
        if techdetails.get_deleted_regvalues() != None: self.__process_regvalues_structures_type(techdetails.get_deleted_regvalues(), 'delete')
        if techdetails.get_modified_regvalues() != None: self.__process_regvalues_structures_type(techdetails.get_modified_regvalues(), 'modify')
        if techdetails.get_mutexes() != None: self.__process_mutexes_type(techdetails.get_mutexes())
        if techdetails.get_open_ports() != None: self.__process_open_ports_type(techdetails.get_open_ports())
        if techdetails.get_gethostbyname_api() != None: self.__process_gethostbyname_api_type(techdetails.get_gethostbyname_api())
        if techdetails.get_urlrequests() != None: self.__process_urls_type(techdetails.get_urlrequests(), 'get')
        if techdetails.get_internetopenurl_api() != None: self.__process_urls_type(techdetails.get_internetopenurl_api(), 'open')
        if techdetails.get_urldownloadtofile_api() != None: self.__process_urldownloadtofile_api_type(techdetails.get_urldownloadtofile_api())
        if techdetails.get_procnames_to_terminate() != None: self.__process_procnames_to_terminate_type(techdetails.get_procnames_to_terminate())
        return
    
    def __process_added_files_type(self, added_files, type):
        if added_files.get_added_files_collection() != None:
            files_collection = added_files.get_added_files_collection()
            for file_object in files_collection.get_added_file():
                file_attributes = {}
                file_attributes['md5'] = file_object.get_md5()
                file_attributes['sha1'] = file_object.get_sha1()
                filenames = file_object.get_filenames_collection()
                if file_object.get_packer() != None : file_attributes['packer'] = file_object.get_packer() 
                file_attributes['av_aliases'] = self.__get_av_aliases(file_object)
                for filename in filenames.get_filename():
                    split_filename = filename.split('\\')
                    actual_filename = split_filename[len(split_filename)-1]
                    filepath = filename.rstrip(actual_filename)
                    if file_object.get_md5() == self.analysis_subject_md5:
                        if filename != ('[file and pathname of the sample #1]' or  '[filename of the sample #1]'):
                            if self.analysis_subject_name == None:
                                self.analysis_subject_name = actual_filename
                                self.analysis_subject_path = filename.rstrip(actual_filename)
                        else:
                            if self.analysis_subject_name != None:
                                actual_filename = self.analysis_subject_name
                                filepath = self.analysis_subject_path
                    file_attributes['filename'] = actual_filename
                    file_attributes['filepath'] = filepath
                    if type == 'file':
                        file_attributes['type'] = 'File'
                    elif type == 'stream':
                        file_attributes['type'] = 'Other'
                    #Generate the MAEC objects and actions
                    #First, create the object
                    fs_object = self.maec_object.create_file_system_object(file_attributes)
                    self.objects.get('file_system').append(fs_object)
                    #Next, create the action (that operated on the object)
                    action_attributes = {}
                    if type == 'file':
                        action_attributes['action_name'] = 'create_file'
                    elif type == 'stream':
                        action_attributes['action_name'] = 'create_stream'
                    action_attributes['action_type'] = 'create'
                    action_attributes['object_id'] = fs_object.get_id()
                    action_attributes['tool_id'] = self.tool_id
                    action_attributes['initiator_id'] = self.initiator_id
                    fs_action = self.maec_action.create_action(action_attributes)
                    self.actions.get('file_system').append(fs_action)
    
    def __process_filenames_notes_type(self, filenames_notes, type):
        if filenames_notes.get_filenames_collection() != None:
            files_collection = filenames_notes.get_filenames_collection()
            for filename in files_collection.get_filename():
                file_attributes = {}
                split_filename = filename.split('\\')
                actual_filename = split_filename[len(split_filename)-1]
                filepath = filename.rstrip(actual_filename)
                file_attributes['filename'] = actual_filename
                file_attributes['filepath'] = filepath
                if type == 'file':
                    file_attributes['type'] = 'File'
                elif type == 'stream':
                    file_attributes['type'] = 'Other'
                file_attributes['type'] = 'File'
                #Generate the MAEC objects and actions
                #First, create the object
                fs_object = self.maec_object.create_file_system_object(file_attributes)
                self.objects.get('file_system').append(fs_object)
                #Next, create the action (that operated on the object)
                action_attributes = {}
                if type == 'delete':
                    action_attributes['action_name'] = 'delete_file'
                    action_attributes['action_type'] = 'Remove/Delete'
                elif type == 'modify':
                    action_attributes['action_name'] = 'modify_file'
                    action_attributes['action_type'] = 'modify'
                action_attributes['object_id'] = fs_object.get_id()
                action_attributes['tool_id'] = self.tool_id
                action_attributes['initiator_id'] = self.initiator_id
                fs_action = self.maec_action.create_action(action_attributes)
                self.actions.get('file_system').append(fs_action)
    
    def __process_dirnames_notes_type(self, dirnames_notes, type):
        if dirnames_notes.get_dirnames_collection() != None:
            dirnames_collection = dirnames_notes.get_dirnames_collection()
            for dirname in dirnames_collection.get_dirname():
                dir_attributes = {}
                dir_attributes['filepath'] = dirname
                dir_attributes['type'] = 'Directory'
                #Generate the MAEC objects and actions
                #First, create the object
                dir_object = self.maec_object.create_file_system_object(dir_attributes)
                self.objects.get('file_system').append(dir_object)
                #Next, create the action (that operated on the object)
                action_attributes = {}
                if type == 'create':
                    action_attributes['action_name'] = 'create_directory'
                    action_attributes['action_type'] = 'create'
                elif type == 'delete':
                    action_attributes['action_name'] = 'delete_directory'
                    action_attributes['action_type'] = 'Remove/Delete'
                action_attributes['object_id'] = dir_object.get_id()
                action_attributes['tool_id'] = self.tool_id
                action_attributes['initiator_id'] = self.initiator_id
                fs_action = self.maec_action.create_action(action_attributes)
                self.actions.get('file_system').append(fs_action)
    
    def __process_added_processes_type(self, added_processes):
        if added_processes.get_added_processes_collection() != None:
            processes_collection = added_processes.get_added_processes_collection()
            for process in processes_collection.get_added_process():
                process_attributes = {}
                if process.get_process_name() == '[filename of the sample #1]':
                    if self.analysis_subject_name != None:
                        process_attributes['name'] = self.analysis_subject_name
                else:
                    process_attributes['name'] = process.get_process_name()
                
                if process.get_process_filename() == '[file and pathname of the sample #1]':
                    if self.analysis_subject_path != None:
                        process_attributes['filename'] = self.analysis_subject_path + '\\' + self.analysis_subject_name
                else:
                    process_attributes['filename'] = process.get_process_filename()
                #Generate the MAEC objects and actions
                #First, create the object
                process_object = self.maec_object.create_process_object(process_attributes)
                self.objects.get('process').append(process_object)
                #Next, create the action (that operated on the object)
                action_attributes = {}
                action_attributes['action_name'] = 'create_process'
                action_attributes['action_type'] = 'create'
                action_attributes['object_id'] = process_object.get_id()
                action_attributes['tool_id'] = self.tool_id
                action_attributes['initiator_id'] = self.initiator_id
                process_action = self.maec_action.create_action(action_attributes)
                self.actions.get('process').append(process_action)
    
    def __process_added_hidden_processes_type(self, added_hidden_processes):
        if added_hidden_processes.get_added_hidden_processes_collection() != None:
            processes_collection = added_hidden_processes.get_added_hidden_processes_collection()
            for process in processes_collection.get_added_hidden_process():
                process_attributes = {}
                if process.get_process_name() == '[filename of the sample #1]':
                    if self.analysis_subject_name != None:
                        process_attributes['name'] = self.analysis_subject_name
                else:
                    process_attributes['name'] = process.get_process_name()
                #Generate the MAEC objects and actions
                #First, create the object
                process_object = self.maec_object.create_process_object(process_attributes)
                self.objects.get('process').append(process_object)
                #Next, create the action (that operated on the object)
                action_attributes = {}
                action_attributes['action_name'] = 'create_process'
                action_attributes['action_type'] = 'create'
                action_attributes['object_id'] = process_object.get_id()
                action_attributes['tool_id'] = self.tool_id
                action_attributes['initiator_id'] = self.initiator_id
                process_action = self.maec_action.create_action(action_attributes)
                self.actions.get('process').append(process_action)
    
    def __process_added_modules_type(self, added_modules):
        if added_modules.get_added_modules_collection() != None:
            modules_collection = added_modules.get_added_modules_collection()
            for module in modules_collection.get_added_module():
                module_attributes = {}
                module_attributes['name'] = module.get_module_name()
                module_attributes['filename'] = module.get_module_filename()
                #Generate the MAEC objects and actions
                #First, create the object
                module_object = self.maec_object.create_module_object(module_attributes)
                self.objects.get('module').append(module_object)
                #Next, create the action (that operated on the object)
                action_attributes = {}
                action_attributes['action_name'] = 'create_module'
                action_attributes['action_type'] = 'create'
                action_attributes['object_id'] = module_object.get_id()
                action_attributes['tool_id'] = self.tool_id
                action_attributes['initiator_id'] = self.initiator_id
                module_action = self.maec_action.create_action(action_attributes)
                self.actions.get('module').append(module_action)
    
    def __process_added_services_type(self, added_services):
        if added_services.get_added_services_collection() != None:
            added_services_collection = added_services.get_added_services_collection()
            for service in added_services_collection.get_added_service():
                service_attributes = {}
                service_attributes['name'] = service.get_service_name()
                service_attributes['displayname'] = service.get_display_name()
                service_attributes['filename'] = service.get_service_filename()
                #Generate the MAEC objects and actions
                #First, create the object
                service_object = self.maec_object.create_service_object(service_attributes)
                self.objects.get('service').append(service_object)
                #Next, create the action (that operated on the object)
                action_attributes = {}
                action_attributes['action_name'] = 'create_service'
                action_attributes['action_type'] = 'create'
                action_attributes['object_id'] = service_object.get_id()
                action_attributes['tool_id'] = self.tool_id
                action_attributes['initiator_id'] = self.initiator_id
                service_action = self.maec_action.create_action(action_attributes)
                self.actions.get('service').append(service_action)
    
    def __process_modified_services_type(self, modified_services):
        if modified_services.get_modified_services_collection() != None:
            modified_services_collection = modified_services.get_modified_services_collection()
            for service in modified_services_collection.get_modified_service():
                service_attributes = {}
                service_attributes['name'] = service.get_service_name()
                service_attributes['displayname'] = service.get_display_name()
                service_attributes['filename'] = service.get_service_filename()
                #Generate the MAEC objects and actions
                #First, create the object
                service_object = self.maec_object.create_service_object(service_attributes)
                self.objects.get('service').append(service_object)
                #Next, create the action (that operated on the object)
                action_attributes = {}
                action_attributes['action_name'] = 'modify_service'
                action_attributes['action_type'] = 'modify'
                action_attributes['object_id'] = service_object.get_id()
                action_attributes['tool_id'] = self.tool_id
                action_attributes['initiator_id'] = self.initiator_id
                service_action = self.maec_action.create_action(action_attributes)
                self.actions.get('service').append(service_action)
    
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
            #Generate the MAEC objects and actions
            #First, create the object
            reg_object = self.maec_object.create_registry_object(regkey_attributes)
            self.objects.get('registry').append(reg_object)
            #Next, create the action (that operated on the object)
            action_attributes = {}
            if type == 'create':
                action_attributes['action_name'] = 'create_registrykey'
                action_attributes['action_type'] = 'create'
            elif type == 'delete':
                action_attributes['action_name'] = 'delete_registrykey'
                action_attributes['action_type'] = 'Remove/Delete'
            action_attributes['object_id'] = reg_object.get_id()
            action_attributes['tool_id'] = self.tool_id
            action_attributes['initiator_id'] = self.initiator_id
            reg_action = self.maec_action.create_action(action_attributes)
            self.actions.get('registry').append(reg_action)
    
    def __process_regvalues_structures_type(self, regvalues, type):
        if regvalues.get_regvalues_structure() != None:
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
                    #Generate the MAEC objects and actions
                    #First, create the object
                    reg_object = self.maec_object.create_registry_object(regkey_attributes)
                    self.objects.get('registry').append(reg_object)
                    #Next, create the action (that operated on the object)
                    action_attributes = {}
                    if type == 'create':
                        action_attributes['action_name'] = 'create_registrykeyvalue'
                        action_attributes['action_type'] = 'create'
                    elif type == 'delete':
                        action_attributes['action_name'] = 'delete_registrykeyvalue'
                        action_attributes['action_type'] = 'Remove/Delete'
                    elif type == 'modify':
                        action_attributes['action_name'] = 'modify_registrykeyvalue'
                        action_attributes['action_type'] = 'modify'
                    action_attributes['object_id'] = reg_object.get_id()
                    action_attributes['tool_id'] = self.tool_id
                    action_attributes['initiator_id'] = self.initiator_id
                    reg_action = self.maec_action.create_action(action_attributes)
                    self.actions.get('registry').append(reg_action)
    
    def __process_mutexes_type(self, mutexes):
        for mutex in mutexes.get_mutex():
            mutex_attributes = {}
            mutex_attributes['name']  = mutex
            mutex_attributes['type'] = 'Mutex'
            #Generate the MAEC objects and actions
            #First, create the object
            mutex_object = self.maec_object.create_ipc_object(mutex_attributes)
            self.objects.get('ipc').append(mutex_object)
            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['action_name'] = 'create_mutex'
            action_attributes['action_type'] = 'create'
            action_attributes['object_id'] = mutex_object.get_id()
            action_attributes['tool_id'] = self.tool_id
            action_attributes['initiator_id'] = self.initiator_id
            mutex_action = self.maec_action.create_action(action_attributes)
            self.actions.get('ipc').append(mutex_action)
    
    def __process_open_ports_type(self, openports):
        if openports.get_open_ports_collection() != None:
            open_ports_collection = openports.get_open_ports_collection()
            for open_port in open_ports_collection.get_open_port():
                port_attributes = {}
                port_attributes['port']  = open_port.get_port_number()
                port_attributes['protocol'] = open_port.get_protocol()
                port_attributes['type'] = 'Port'
                #Generate the MAEC objects and actions
                #First, create the object
                port_object = self.maec_object.create_network_object(port_attributes)
                self.objects.get('network').append(port_object)
                #Next, create the action (that operated on the object)
                action_attributes = {}
                action_attributes['action_name'] = 'open_port'
                action_attributes['action_type'] = 'Access/Open'
                action_attributes['object_id'] = port_object.get_id()
                action_attributes['tool_id'] = self.tool_id
                action_attributes['initiator_id'] = self.initiator_id
                port_action = self.maec_action.create_action(action_attributes)
                self.actions.get('network').append(port_action)
    
    def __process_gethostbyname_api_type(self, hosts):
        for host in hosts.get_host():
            host_attributes = {}
            host_attributes['type'] = 'URI'
            host_attributes['uri'] = host
            #Generate the MAEC objects and actions
            #First, create the object
            host_object = self.maec_object.create_internet_object(host_attributes)
            self.objects.get('internet').append(host_object)
            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['action_name'] = 'get_host_by_name'
            action_attributes['action_type'] = 'get'
            action_attributes['object_id'] = host_object.get_id()
            action_attributes['tool_id'] = self.tool_id
            action_attributes['initiator_id'] = self.initiator_id
            host_action = self.maec_action.create_action(action_attributes)
            self.actions.get('internet').append(host_action)
    
    def __process_urls_type(self, urls, type):
        for url in urls.get_url():
            url_attributes = {}
            url_attributes['type'] = 'URI'
            url_attributes['uri'] = url
            #Generate the MAEC objects and actions
            #First, create the object
            url_object = self.maec_object.create_internet_object(url_attributes)
            self.objects.get('internet').append(url_object)
            #Next, create the action (that operated on the object)
            action_attributes = {}
            if type == 'get':
                action_attributes['action_name'] = 'get_url'
                action_attributes['action_type'] = 'get'
            elif type == 'open':
                action_attributes['action_name'] = 'open_url'
                action_attributes['action_type'] = 'Access/Open'
            action_attributes['object_id'] = url_object.get_id()
            action_attributes['tool_id'] = self.tool_id
            action_attributes['initiator_id'] = self.initiator_id
            url_action = self.maec_action.create_action(action_attributes)
            self.actions.get('internet').append(url_action)
            
    def __process_urldownloadtofile_api_type(self, urldownloadtofile):
        if urldownloadtofile.get_urldownloadtofile_collection() != None:
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
                #Generate the MAEC objects and actions
                #First, create the object
                url_file_object = self.maec_object.create_file_system_object(url_file_attributes)
                self.objects.get('file_system').append(url_file_object)
                #Next, create the action (that operated on the object)
                action_attributes = {}
                action_attributes['action_name'] = 'download_file'
                action_attributes['action_type'] = 'download'
                action_attributes['object_id'] = url_file_object.get_id()
                action_attributes['tool_id'] = self.tool_id
                action_attributes['initiator_id'] = self.initiator_id
                url_file_action = self.maec_action.create_action(action_attributes)
                self.actions.get('internet').append(url_file_action)
                
    def __process_procnames_to_terminate_type(self, procnames):
        for procname in procnames.get_procname():
            process_attributes = {}
            process_attributes['name'] = procname
            #Generate the MAEC objects and actions
            #First, create the object
            process_object = self.maec_object.create_process_object(process_attributes)
            self.objects.get('process').append(process_object)
            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['action_name'] = 'kill_process'
            action_attributes['action_type'] = 'kill'
            action_attributes['object_id'] = process_object.get_id()
            action_attributes['tool_id'] = self.tool_id
            action_attributes['initiator_id'] = self.initiator_id
            process_action = self.maec_action.create_action(action_attributes)
            self.actions.get('process').append(process_action)
        
    
    def __get_av_aliases(self, object):
        av_classification_objects = maec.Classifications()
        #Go through each type of av_alias and add it (if existing)
        if object.get_alias_kav() != None:
            av_classification_object = maec.classificationObject(classificationName=object.get_alias_kav(), companyName='Kaspersky', id=self.generator.generate_id(), type_='dirty')
            av_classification_objects.add_Classification(av_classification_object)
        if object.get_alias_nav() != None:
            av_classification_object = maec.classificationObject(classificationName=object.get_alias_nav(), companyName='Norton', id=self.generator.generate_id(), type_='dirty')
            av_classification_objects.add_Classification(av_classification_object)
        if object.get_alias_nai() != None:
            av_classification_object = maec.classificationObject(classificationName=object.get_alias_nai(), companyName='McAfee', id=self.generator.generate_id(), type_='dirty')
            av_classification_objects.add_Classification(av_classification_object)
        if object.get_alias_trend() != None:
            av_classification_object = maec.classificationObject(classificationName=object.get_alias_trend(), companyName='Trend Micro', id=self.generator.generate_id(), type_='dirty')
            av_classification_objects.add_Classification(av_classification_object)
        if object.get_alias_sophos() != None:
            av_classification_object = maec.classificationObject(classificationName=object.get_alias_sophos(), companyName='Sophos', id=self.generator.generate_id(), type_='dirty')
            av_classification_objects.add_Classification(av_classification_object)
        if object.get_alias_microsoft() != None:
            av_classification_object = maec.classificationObject(classificationName=object.get_alias_microsoft(), companyName='Microsoft', id=self.generator.generate_id(), type_='dirty')
            av_classification_objects.add_Classification(av_classification_object)
        if object.get_alias_ikarus() != None:
            av_classification_object = maec.classificationObject(classificationName=object.get_alias_ikarus(), companyName='Ikarus', id=self.generator.generate_id(), type_='dirty')
            av_classification_objects.add_Classification(av_classification_object)
        if object.get_alias_ahnlab() != None:
            av_classification_object = maec.classificationObject(classificationName=object.get_alias_ahnlab(), companyName='AhnLab', id=self.generator.generate_id(), type_='dirty')
            av_classification_objects.add_Classification(av_classification_object)
        if av_classification_objects.hasContent_():
            return av_classification_objects
        else:
            return None