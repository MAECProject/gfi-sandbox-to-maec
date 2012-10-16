#GFI Sandbox -> MAEC Translator
#GFI Parser
#v0.1

import gfi_sandbox
import maec_helper
import traceback
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

class parser:
    def __init__(self):
        self.analysis = None
        self.generator = None
        self.maec_object = None
        self.maec_action = None
        self.maec_analysis = None
        self.actions = None
        self.tool_id = None
        self.__setup_dictionaries()

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
        #Setup the generator
        self.generator = maec_helper.generator('gfi_sandbox_to_maec')
        #Setup the object class
        self.maec_object = maec_helper.maec_object(self.generator)
        #Setup the action class
        self.maec_action = maec_helper.maec_action(self.generator)
        #Get the processes captured in the analysis
        processes = self.analysis.get_processes()
        calltree = self.analysis.get_calltree()
        running_processes = self.analysis.get_running_processes()
        #Handle the analysis information
        self.__handle_analysis()
        #Handle each process and create the corresponding MAEC entities
        for process in processes.get_process():
            try:
                self.__handle_process(process)
            except Exception, err:
                print('\nError: %s\n' % str(err))
                traceback.print_exc()
        return
    
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
        actions['filemapping'] = []
        actions['thread'] = []
        actions['sysobject'] = []
        actions['driver'] = []
        actions['user'] = []
        actions['share'] = []
        actions['module'] = []
        self.actions = actions
        
        #setup the objects
        objects = {}
        objects['process'] = []
        self.objects = objects
        
    #Handle a GFI process object
    #Extract applicable elements and process them
    def __handle_process(self, process):
        #First, create the process object
        process_object = self.__create_process_object(process)
        self.objects.get('process').append(process_object)
        process_object_id = process_object.get_id()
        #Next, handle all of the included actions
        self.__handle_stored_modified_files(process.get_stored_modified_files(), process_object_id)
        self.__handle_mapped_modules(process.get_mapped_modules(), process_object_id)
        self.__handle_filesystem_section(process.get_filesystem_section(), process_object_id)
        self.__handle_registry_section(process.get_registry_section(), process_object_id)
        self.__handle_process_section(process.get_process_section(), process_object_id)
        self.__handle_virtualmemory_section(process.get_virtualmemory_section(), process_object_id)
        self.__handle_filemapping_section(process.get_filemapping_section(), process_object_id)
        self.__handle_thread_section(process.get_thread_section(), process_object_id)
        self.__handle_sysobject_section(process.get_sysobject_section(), process_object_id)
        self.__handle_system_section(process.get_system_section(), process_object_id)
        self.__handle_service_section(process.get_service_section(), process_object_id)
        self.__handle_user_section(process.get_user_section(), process_object_id)
        self.__handle_share_section(process.get_share_section(), process_object_id)
        self.__handle_module_section(process.get_module_section(), process_object_id)
        self.__handle_networkpacket_section(process.get_networkpacket_section(), process_object_id)
        self.__handle_networkoperation_section(process.get_networkoperation_section(), process_object_id)
        self.__handle_checkpoint_section(process.get_checkpoint_section(), process_object_id)
        self.__handle_com_section(process.get_com_section(), process_object_id)
        self.__handle_error_section(process.get_error_section(), process_object_id)
        self.__handle_connection_section(process.get_connection_section(), process_object_id)
    
    #Create and add the process object to the MAEC object list
    def __create_process_object(self, process):
        process_attributes = {}
        process_attributes['filename'] = process.get_filename()
        if process.get_commandline() != None: process_attributes['cmd_line'] = process.get_commandline()
        if process.get_pid() != None: process_attributes['pid'] = process.get_pid()
        if process.get_parent_pid() != None: process_attributes['parentpid'] = process.get_parent_pid()
        if process.get_username() != None: process_attributes['username'] = process.get_username()
        if process.get_start_time() != None: process_attributes['start_time'] = self.__normalize_datetime(process.get_start_time())
        #Handle any AV classifications that were reported
        av_classifications = self.__handle_scanner_section(process.get_scanner_section())
        if av_classifications is not None:
            process_attributes['av_classifications'] = av_classifications
        #Create the object
        process_object = self.maec_object.create_process_object(process_attributes)
        return process_object
    
    #Process the analysis metadata and create the corresponding MAEC analysis object
    def __handle_analysis(self):
        #Get the required attributes
        version = self.analysis.get_version()
        filename = self.analysis.get_filename()
        time = self.analysis.get_time()
        commandline = self.analysis.get_commandline()
        analysis_subject_object = self.__create_analysis_subject()
        #Create the maec analysis object
        analysis = maec_helper.maec_analysis(self.generator, None, 'GFI Sandbox', 'GFI Software', version)
        analysis.set_analysis_subject(analysis_subject_object, commandline)
        self.maec_analysis = analysis.get_analysis_object()
        self.tool_id = analysis.get_tool_id()
        return
    
    def __create_analysis_subject(self):
        object_attributes = {}
        object_attributes['filename'] = self.analysis.get_filename()
        if self.analysis.get_md5() != None: object_attributes['md5'] = self.analysis.get_md5()
        if self.analysis.get_sha1() != None: object_attributes['sha1'] = self.analysis.get_sha1()
        return self.maec_object.create_file_system_object(object_attributes)
    
    def __handle_stored_modified_files(self, stored_modified_files, process_object_id):
        if stored_modified_files != None:
            pass
        return

    def __handle_mapped_modules(self, mapped_modules, process_object_id):
        if mapped_modules != None:
            pass
        return
    
    def __handle_filesystem_section(self, filesystem_section, process_object_id):
        if filesystem_section != None:
            fs_section = gfi.filesystem_section.filesystem_section_handler(self.maec_object, process_object_id, self.tool_id)
            for fs_action in filesystem_section.get_create_file():
                self.actions.get('file_system').append(self.__handle_action(fs_section, fs_action))
            for fs_action in filesystem_section.get_create_namedpipe():
                self.actions.get('file_system').append(self.__handle_action(fs_section, fs_action))
            for fs_action in filesystem_section.get_create_mailslot():
                self.actions.get('file_system').append(self.__handle_action(fs_section, fs_action))
            for fs_action in filesystem_section.get_open_file():
                self.actions.get('file_system').append(self.__handle_action(fs_section, fs_action))
            for fs_action in filesystem_section.get_read_file():
                self.actions.get('file_system').append(self.__handle_action(fs_section, fs_action))
            for fs_action in filesystem_section.get_write_file():
                self.actions.get('file_system').append(self.__handle_action(fs_section, fs_action))
            for fs_action in filesystem_section.get_copy_file():
                self.actions.get('file_system').append(self.__handle_action(fs_section, fs_action))
            for fs_action in filesystem_section.get_move_file():
                self.actions.get('file_system').append(self.__handle_action(fs_section, fs_action))
            for fs_action in filesystem_section.get_delete_file():
                self.actions.get('file_system').append(self.__handle_action(fs_section, fs_action))
            for fs_action in filesystem_section.get_find_file():
                self.actions.get('file_system').append(self.__handle_action(fs_section, fs_action))
            for fs_action in filesystem_section.get_get_file_attributes():
                self.actions.get('file_system').append(self.__handle_action(fs_section, fs_action))
            for fs_action in filesystem_section.get_set_file_attributes():
                self.actions.get('file_system').append(self.__handle_action(fs_section, fs_action))
    
    def __handle_registry_section(self, registry_section, process_object_id):
        if registry_section != None:
            reg_section = gfi.registry_section.registry_section_handler(self.maec_object, process_object_id, self.tool_id)
            for reg_action in registry_section.get_open_key():
                self.actions.get('registry').append(self.__handle_action(reg_section, reg_action))
            for reg_action in registry_section.get_create_key():
                self.actions.get('registry').append(self.__handle_action(reg_section, reg_action))
            for reg_action in registry_section.get_delete_key():
                self.actions.get('registry').append(self.__handle_action(reg_section, reg_action))
            for reg_action in registry_section.get_enum_keys():
                self.actions.get('registry').append(self.__handle_action(reg_section, reg_action))
            for reg_action in registry_section.get_set_value():
                self.actions.get('registry').append(self.__handle_action(reg_section, reg_action))
            for reg_action in registry_section.get_delete_value():
                self.actions.get('registry').append(self.__handle_action(reg_section, reg_action))
            for reg_action in registry_section.get_query_key_info():
                self.actions.get('registry').append(self.__handle_action(reg_section, reg_action))
            for reg_action in registry_section.get_query_value():
                self.actions.get('registry').append(self.__handle_action(reg_section, reg_action))
            for reg_action in registry_section.get_enum_values():
                self.actions.get('registry').append(self.__handle_action(reg_section, reg_action))
    
    def __handle_process_section(self, process_section, process_object_id):
        if process_section != None:
            proc_section = gfi.process_section.process_section_handler(self.maec_object, process_object_id, self.tool_id)
            for proc_action in process_section.get_create_process():
                self.actions.get('process').append(self.__handle_action(proc_section, proc_action))
            for proc_action in process_section.get_create_process_as_user():
                self.actions.get('process').append(self.__handle_action(proc_section, proc_action))
            for proc_action in process_section.get_open_process():
                self.actions.get('process').append(self.__handle_action(proc_section, proc_action))
            for proc_action in process_section.get_kill_process():
                self.actions.get('process').append(self.__handle_action(proc_section, proc_action))
            for proc_action in process_section.get_enumerate_processes():
                self.actions.get('process').append(self.__handle_action(proc_section, proc_action))
            for proc_action in process_section.get_impersonate_process():
                self.actions.get('process').append(self.__handle_action(proc_section, proc_action)) 
    
    def __handle_virtualmemory_section(self, virtualmemory_section, process_object_id):
        if virtualmemory_section != None:
            vmem_section = gfi.virtualmemory_section.virtualmemory_section_handler(self.maec_object, process_object_id, self.tool_id)
            for vmem_action in virtualmemory_section.get_alloc_memory():
                self.actions.get('memory').append(self.__handle_action(vmem_section, vmem_action))
            for vmem_action in virtualmemory_section.get_free_memory():
                self.actions.get('memory').append(self.__handle_action(vmem_section, vmem_action))
            for vmem_action in virtualmemory_section.get_read_memory():
                self.actions.get('memory').append(self.__handle_action(vmem_section, vmem_action))
            for vmem_action in virtualmemory_section.get_write_memory():
                self.actions.get('memory').append(self.__handle_action(vmem_section, vmem_action))
            for vmem_action in virtualmemory_section.get_query_memory():
                self.actions.get('memory').append(self.__handle_action(vmem_section, vmem_action))
    
    def __handle_filemapping_section(self, filemapping_section, process_object_id):
        if filemapping_section != None:
            filemap_section = gfi.filemapping_section.filemapping_section_handler(self.maec_object, process_object_id, self.tool_id)
            for filemap_action in filemapping_section.get_create_file_mapping():
                self.actions.get('filemapping').append(self.__handle_action(filemap_section, filemap_action))
            for filemap_action in filemapping_section.get_open_file_mapping():
                self.actions.get('filemapping').append(self.__handle_action(filemap_section, filemap_action))
            for filemap_action in filemapping_section.get_map_view_of_file():
                self.actions.get('filemapping').append(self.__handle_action(filemap_section, filemap_action))
    
    def __handle_thread_section(self, thread_section, process_object_id):
        if thread_section != None:
            thrd_section = gfi.thread_section.thread_section_handler(self.maec_object, process_object_id, self.tool_id)
            for thrd_action in thread_section.get_create_thread():
                self.actions.get('thread').append(self.__handle_action(thrd_section, thrd_action))
            for thrd_action in thread_section.get_kill_thread():
                self.actions.get('thread').append(self.__handle_action(thrd_section, thrd_action))
            for thrd_action in thread_section.get_get_thread_context():
                self.actions.get('thread').append(self.__handle_action(thrd_section, thrd_action))
            for thrd_action in thread_section.get_queue_user_apc():
                self.actions.get('thread').append(self.__handle_action(thrd_section, thrd_action))
            for thrd_action in thread_section.get_enumerate_threads():
                self.actions.get('thread').append(self.__handle_action(thrd_section, thrd_action))
            for thrd_action in thread_section.get_impersonate_thread():
                self.actions.get('thread').append(self.__handle_action(thrd_section, thrd_action))
            for thrd_action in thread_section.get_revert_thread_to_self():
                self.actions.get('thread').append(self.__handle_action(thrd_section, thrd_action))
            #for thrd_action in thread_section.get_hide_from_debugger(): #TODO - support this as a behavior?
                #pass
    
    def __handle_sysobject_section(self, sysobject_section, process_object_id):
        if sysobject_section != None:
           sysobj_section = gfi.sysobject_section.sysobject_section_handler(self.maec_object, process_object_id, self.tool_id)
           for sysobj_action in sysobject_section.get_create_mutex():
               self.actions.get('sysobject').append(self.__handle_action(sysobj_section, sysobj_action))
           for sysobj_action in sysobject_section.get_open_mutex():
               self.actions.get('sysobject').append(self.__handle_action(sysobj_section, sysobj_action))
           for sysobj_action in sysobject_section.get_add_scheduled_task():
               self.actions.get('sysobject').append(self.__handle_action(sysobj_section, sysobj_action))
    
    def __handle_system_section(self, system_section, process_object_id):
        if system_section != None:
            sys_section = gfi.system_section.system_section_handler(self.maec_object, process_object_id, self.tool_id)
            for sys_action in system_section.get_shutdown_system():
                self.actions.get('system').append(self.__handle_action(sys_section, sys_action))
            for sys_action in system_section.get_sleep():
                self.actions.get('system').append(self.__handle_action(sys_section, sys_action))
            for sys_action in system_section.get_get_computer_name():
                self.actions.get('system').append(self.__handle_action(sys_section, sys_action))
            for sys_action in system_section.get_get_system_time():
                self.actions.get('system').append(self.__handle_action(sys_section, sys_action))
            for sys_action in system_section.get_get_local_time():
                self.actions.get('system').append(self.__handle_action(sys_section, sys_action))
            for sys_action in system_section.get_set_system_time():
                self.actions.get('system').append(self.__handle_action(sys_section, sys_action))
            for sys_action in system_section.get_enumerate_handles():
                self.actions.get('system').append(self.__handle_action(sys_section, sys_action))
            for sys_action in system_section.get_enumerate_system_modules():
                self.actions.get('system').append(self.__handle_action(sys_section, sys_action))
            #for sys_action in system_section.get_check_for_debugger(): #TODO - Classify this as a behavior?
                #self.actions.get('system').append(self.__handle_action(sys_section, sys_action))
            #for sys_action in system_section.get_check_for_kernel_debugger(): #TODO - Classify this as a behavior?
                #self.actions.get('system').append(self.__handle_action(sys_section, sys_action))
            for sys_action in system_section.get_get_global_flags():
                self.actions.get('system').append(self.__handle_action(sys_section, sys_action))
            for sys_action in system_section.get_set_global_flags():
                self.actions.get('system').append(self.__handle_action(sys_section, sys_action))
            #for sys_action in system_section.get_debug_control():
                #self.actions.get('system').append(self.__handle_action(sys_section, sys_action))
        
    def __handle_service_section(self, service_section, process_object_id):
        if service_section != None:
            serv_section = gfi.service_section.service_section_handler(self.maec_object, process_object_id, self.tool_id)
            for serv_action in service_section.get_enumerate_services():
                self.actions.get('service').append(self.__handle_action(serv_section, serv_action))
            for serv_action in service_section.get_open_service():
                self.actions.get('service').append(self.__handle_action(serv_section, serv_action))
            for serv_action in service_section.get_create_service():
                self.actions.get('service').append(self.__handle_action(serv_section, serv_action))
            for serv_action in service_section.get_remove_service():
                self.actions.get('service').append(self.__handle_action(serv_section, serv_action))
            for serv_action in service_section.get_start_service():
                self.actions.get('service').append(self.__handle_action(serv_section, serv_action))
            for serv_action in service_section.get_config_service():
                self.actions.get('service').append(self.__handle_action(serv_section, serv_action))
            for serv_action in service_section.get_control_driver():
                self.actions.get('driver').append(self.__handle_action(serv_section, serv_action))
            for serv_action in service_section.get_load_driver():
                self.actions.get('driver').append(self.__handle_action(serv_section, serv_action))
            for serv_action in service_section.get_unload_driver():
                self.actions.get('driver').append(self.__handle_action(serv_section, serv_action))
            for serv_action in service_section.get_load_and_call_driver():
                self.actions.get('driver').append(self.__handle_action(serv_section, serv_action))

    def __handle_user_section(self, user_section, process_object_id):
        if user_section != None:
            usr_section = gfi.user_section.user_section_handler(self.maec_object, process_object_id, self.tool_id)
            for usr_action in user_section.get_logon_as_user():
                self.actions.get('user').append(self.__handle_action(usr_section, usr_action))
            for usr_action in user_section.get_add_user():
                self.actions.get('user').append(self.__handle_action(usr_section, usr_action))
            for usr_action in user_section.get_remove_user():
                self.actions.get('user').append(self.__handle_action(usr_section, usr_action))
            for usr_action in user_section.get_enumerate_users():
                self.actions.get('user').append(self.__handle_action(usr_section, usr_action))
            for usr_action in user_section.get_get_username():
                self.actions.get('user').append(self.__handle_action(usr_section, usr_action))
            for usr_action in user_section.get_get_user_info():
                self.actions.get('user').append(self.__handle_action(usr_section, usr_action))

    def __handle_share_section(self, share_section, process_object_id):
        if share_section != None:
            shr_section = gfi.share_section.share_section_handler(self.maec_object, process_object_id, self.tool_id)
            for shr_action in share_section.get_add_share():
                self.actions.get('share').append(self.__handle_action(shr_section, shr_action))
            for shr_action in share_section.get_remove_share():
                self.actions.get('share').append(self.__handle_action(shr_section, shr_action))
            for shr_action in share_section.get_enumerate_shares():
                self.actions.get('share').append(self.__handle_action(shr_section, shr_action))
            for shr_action in share_section.get_connect_to_share():
                self.actions.get('share').append(self.__handle_action(shr_section, shr_action))
            for shr_action in share_section.get_disconnect_from_share():
                self.actions.get('share').append(self.__handle_action(shr_section, shr_action))

    def __handle_module_section(self, module_section, process_object_id):
        if module_section != None:
            mod_section = gfi.module_section.module_section_handler(self.maec_object, process_object_id, self.tool_id)
            for mod_action in module_section.get_mapping_module():
                self.actions.get('module').append(self.__handle_action(mod_section, mod_action))
            #for mod_action in module_section.get_module_mapped():
                #self.actions.get('module').append(self.__handle_action(mod_section, mod_action)) #TODO - determine how this differs from the previous action
            for mod_action in module_section.get_load_module():
                self.actions.get('module').append(self.__handle_action(mod_section, mod_action))
            for mod_action in module_section.get_unload_module():
                self.actions.get('module').append(self.__handle_action(mod_section, mod_action))
            for mod_action in module_section.get_enumerate_dlls():
                self.actions.get('module').append(self.__handle_action(mod_section, mod_action))
            for mod_action in module_section.get_get_proc_address():
                self.actions.get('module').append(self.__handle_action(mod_section, mod_action))
            for mod_action in module_section.get_install_winhook_proc():
                self.actions.get('module').append(self.__handle_action(mod_section, mod_action))

    #TODO - populate this section after the CybOX network connection object is created
    def __handle_networkpacket_section(self, networkpacket_section, process_object_id):
        if networkpacket_section != None:
            pass
        return

    def __handle_networkoperation_section(self, networkoperation_section, process_object_id):
        if networkoperation_section != None:
            netop_section = gfi.networkoperation_section.networkoperation_section_handler(self.maec_object, process_object_id, self.tool_id)
            for netop_action in networkoperation_section.get_icmp_request():
                self.actions.get('network').append(self.__handle_action(netop_section, netop_action))
            for netop_action in networkoperation_section.get_dns_request_by_addr():
                self.actions.get('network').append(self.__handle_action(netop_section, netop_action))
            for netop_action in networkoperation_section.get_dns_request_by_name():
                self.actions.get('network').append(self.__handle_action(netop_section, netop_action))
    
    #TODO - determine what this signifies?
    def __handle_checkpoint_section(self, checkpoint_section, process_object_id):
        if checkpoint_section != None:
            pass
        return

    #TODO - populate this section after the CybOX COM object is created
    def __handle_com_section(self, com_section, process_object_id):
        if com_section != None:
            pass
        return
    
    #TODO - add support in MAEC for errors (as part of the Analysis_Object?)
    def __handle_error_section(self, error_section, process_object_id):
        if error_section != None:
            pass
        return
    
    #TODO - populate this section after the CybOX connection & layer 7 objects are added
    def __handle_connection_section(self, connection_section, process_object_id):
        if connection_section != None:
            pass
        return
    
    #Special method for handling AV classifications reported for the process
    def __handle_scanner_section(self, scanner_section):
        if scanner_section != None and scanner_section.hasContent_():
            av_classifications = []
            for scanner in scanner_section.get_scanner():
                av_classification = {}
                av_classification['company'] = scanner.get_name()
                av_classification['application_version'] = scanner.get_application_version()
                av_classification['signature_version'] = scanner.get_signature_file_version()
                try:
                    av_classification['classification'] = scanner.get_additional_info().rstrip()
                except AttributeError:
                    pass
                av_classifications.append(av_classification)
            return self.maec_object.create_av_classifications(av_classifications)
        else:
            return None

    #Handle a single GFI action and convert it to its MAEC representation
    def __handle_action(self, section, action):
        object_attributes = {}
        action_attributes = {}
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
        action = self.maec_action.create_action(action_attributes)
        return action

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

