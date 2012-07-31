#Anubis main parser class
#For use in extracting data from XML Anubis output

#Copyright (c) 2012, The MITRE Corporation
#All rights reserved.

#Anubis Converter Script v0.92

import maec_2_1 as maec
import maec_helper
import anubis_v2 as anubis
import cybox.cybox_1_0 as cybox
import cybox.common_types_1_0 as common
import cybox.file_object_1_2 as fileobj
import cybox.win_executable_file_object_1_2 as winexecobj
import cybox.process_object_1_2 as processobj

class parser:
    def __init__(self):
        #array for storing actions
        self.actions = []
        #the subject of the analysis (typically a PE binary)
        self.analysis_subject_md5 = ''
        self.analysis_subject_sha1 = ''
        #variable for keeping tab on the number of actions we parsed out
        self.number_of_actions = 0
        #the analysis object of the Anubis XML document
        self.analysis_object = None
        self.parent_process_id = 0
        self.version = ''
        #action ids
        self. action_ids = []
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
        
    #"Public" methods
    
    #Open and read-in the Anubis output file
    #This assumes that we're dealing with a XML file
    def open_file(self, infilename):
        try:
            self.analysis_object = anubis.parse(infilename)
            if self.analysis_object == None:
                return False
            else:
                return True
        except Exception, err:
           print('\nError: %s\n' % str(err))
           
    #Parse the XML document
    #Extract processes, actions, and information about the analysis subject
    def parse_document(self):
        #Setup the generator
        self.generator = maec_helper.generator('anubis_to_maec')
        #Setup the object class
        self.maec_object = maec_helper.maec_object(self.generator)
        #Setup the action class
        self.maec_action = maec_helper.maec_action(self.generator)
        #Setup the action/object dictionaries
        self.__setup_dictionaries()
        #Get the analysis config
        config = self.analysis_object.get_configuration()
        self.version = config.get_ttanalyze_version().get_prog_version()
        #Get the analysis subjects
        analysis_subjects = self.analysis_object.get_analysis_subject()
        #create the process tree and do the additional processing
        self.__create_process_tree(analysis_subjects)
        return 1
                
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
        actions['driver'] = []
        self.actions = actions
        
        #setup the objects
        objects = {}
        objects['process'] = []
        self.objects = objects
        
    #parse each process, create the process tree, and add any discovered actions/objects
    def __create_process_tree(self, analysis_subjects):
        id_map = {}
        process_objects = []
        tool_id = None
        analysis_object = None
        #loop first to create the objects themselves
        for analysis_subject in analysis_subjects:
            general_info = analysis_subject.get_general()
            analysis_reason = general_info.get_analysis_reason()
            
            #create and setup the analysis object if this is the primary subject
            if analysis_reason.lower().count("primary analysis subject") > 0 or analysis_reason.lower().count("primary analysis target") > 0:
                analysis_subject_object = self.__create_analysis_subject_object(analysis_subject, general_info, analysis_subjects, id_map)
                #create the maec analysis object
                analysis = maec_helper.maec_analysis(self.generator, analysis_subject_object, 'TTAnalyze', 'ISECLab', self.version)
                analysis.create_analysis()
                analysis_object = analysis.get_analysis_object()
                self.tool_id = analysis.get_tool_id()
                self.maec_analysis = analysis.get_analysis_object()
            else:
                process_object = self.__create_secondary_subject_object(analysis_subject, general_info, analysis_subjects, id_map)
                process_objects.append(process_object)
        
        #loop again to add any children to each process object
        for analysis_subject in analysis_subjects:
            general_info = analysis_subject.get_general()
            obj_id = general_info.get_id()
            current_maec_id = id_map.get(obj_id)
            for process_object in process_objects:
                maec_id = process_object.get_id() 
                if maec_id == current_maec_id:
                    #self.__add_process_children(obj_id, process_object, analysis_subjects, id_map)
                    self.objects.get('process').append(process_object)
            #finally, process any activities discovered for this process
            if analysis_subject.get_activities() != None:
                self.__process_activities(analysis_subject.get_activities(), current_maec_id)
        
        #add the action references to the analysis findings
        action_references = maec.Action_References()
        for action_id in self.action_ids:
            action_references.add_Action_Reference(maec.cybox.ActionReferenceType(action_id=action_id))
        analysis_object.set_Findings(maec.AnalysisFindingsType(Actions=action_references))
        
    def __create_analysis_subject_object(self, analysis_subject, general_info, analysis_subjects, id_map):
        #first, extract the info from the object
        obj_id = general_info.get_id()
        parent_obj_id = general_info.get_parent_id()
        file = general_info.get_virtual_fn()
        path = general_info.get_virtual_path()
        self.parent_process_id = general_info.get_id()
        md5 = None
        sha1 = None
        file_size = None
        packer = None
        arguments = None
        exit_code = None
        dll_dependencies = None
        if general_info.get_md5() != None: md5 = general_info.get_md5()
        if general_info.get_sha1() != None: sha1 = general_info.get_sha1()
        if general_info.get_file_size() != None: file_size = general_info.get_file_size()
        if general_info.get_arguments() != None: arguments = general_info.get_arguments()
        if general_info.get_exit_code() != None: exit_code = general_info.get_exit_code()
        if analysis_subject.get_sigbuster() != None: packer = analysis_subject.get_sigbuster()
        if analysis_subject.get_dll_dependencies() != None: dll_dependencies = analysis_subject.get_dll_dependencies()
        av_aliases = self.__get_av_aliases(analysis_subject) 
        
        #create the analysis subject object
        analysis_subject_object = maec.AnalysisSubjectType()
        
        #create the file object and add the attributes
        cybox_object = cybox.ObjectType(id=self.generator.generate_obj_id(), type_='File')
        file_object = winexecobj.WindowsExecutableFileObjectType()
        file_object.set_anyAttributes_({'xsi:type' : 'WinExecutableFileObj:WindowsExecutableFileObjectType'})
        file_name = common.StringObjectAttributeType(datatype='String', valueOf_=file)
        file_object.set_File_Name(file_name)
        file_path = common.StringObjectAttributeType(datatype='String', valueOf_=path)
        file_object.set_File_Path(file_path)
        if file_size != None:
            size = common.UnsignedLongObjectAttributeType(datatype='UnsignedLong', valueOf_=file_size)
            file_object.set_Size_In_Bytes(size)
        if av_aliases != None:
            cybox_object.set_Domain_specific_Object_Attributes(av_aliases) 
        if packer != None:
            split_packer = packer.split(' ')
            packer_list = fileobj.PackerListType()
            packer = fileobj.PackerAttributesType(Name=common.StringObjectAttributeType(datatype='String', valueOf_=split_packer[0]), Version=common.StringObjectAttributeType(datatype='String', valueOf_=split_packer[1]))
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
        
        #add the object to the id map
        id_map[obj_id] = cybox_object.get_id()
        
        return analysis_subject_object
    
    def __create_secondary_subject_object(self, analysis_subject, general_info, analysis_subjects, id_map):
        #first, extract the info from the object
        obj_id = general_info.get_id()
        parent_obj_id = general_info.get_parent_id()
        file = general_info.get_virtual_fn()
        path = general_info.get_virtual_path()
        self.parent_process_id = general_info.get_id()
        md5 = None
        sha1 = None
        file_size = None
        packer = None
        arguments = None
        exit_code = None
        dll_dependencies = None
        if general_info.get_md5() != None: md5 = general_info.get_md5()
        if general_info.get_sha1() != None: sha1 = general_info.get_sha1()
        if general_info.get_file_size() != None: file_size = general_info.get_file_size()
        if general_info.get_arguments() != None: arguments = general_info.get_arguments()
        if general_info.get_exit_code() != None: exit_code = general_info.get_exit_code()
        if analysis_subject.get_sigbuster() != None: packer = analysis_subject.get_sigbuster()
        if analysis_subject.get_dll_dependencies() != None: dll_dependencies = analysis_subject.get_dll_dependencies()

        #create the process object and add the attributes
        cybox_object = cybox.ObjectType(type_='Process', id=self.generator.generate_obj_id())
        process_object = processobj.ProcessObjectType()
        process_object.set_anyAttributes_({'xsi:type' : 'ProcessObj:ProcessObjectType'})
        image_path = common.StringObjectAttributeType(datatype='String', valueOf_=path)
        image_info = processobj.ImageInfoType()
        image_info.set_Path(image_path)
        if arguments != None:
            image_info.set_Command_Line(common.StringObjectAttributeType(datatype='String', valueOf_=arguments))
        process_object.set_Image_Info(image_info)
        
        if parent_obj_id != 1:
            #obj_reference = maec.ObjectReferenceType(type_='Object', object_id=id_map.get(parent_obj_id))
            related_objects = cybox.RelatedObjectsType()
            related_object = cybox.RelatedObjectType(idref=id_map.get(parent_obj_id), relationship='Child_Of')
            related_objects.add_Related_Object(related_object)
            cybox_object.set_Related_Objects(related_objects)
        
        #set the object as the defined object
        cybox_object.set_Defined_Object(process_object)
        
        #add the object to the id map
        id_map[obj_id] = cybox_object.get_id()
        
        return cybox_object
    
    def __add_process_children(self, object_id, process_object, analysis_subjects, id_map):
        for analysis_subject in analysis_subjects:
            general_info = analysis_subject.get_general()
            obj_id = general_info.get_id()
            parent_obj_id = general_info.get_parent_id()
            if obj_id != object_id:
                if parent_obj_id == object_id:
                    related_objects = process_object.get_Related_Objects()
                    if related_objects == None:
                        related_objects = cybox.RelatedObjectsType()
                    related_object = cybox.RelatedObjectType(idref=id_map.get(obj_id), Relationship='Child_Of')
                    related_objects.add_Related_Object(related_object)
                    process_object.set_Related_Objects(related_objects)
        return
    
    def __process_activities(self, activities, current_maec_id):
        if activities.get_file_activities() != None:
            for file_activity in activities.get_file_activities():
                self.__process_file_activities(file_activity, current_maec_id)
        if activities.get_registry_activities() != None:
            for registry_activity in activities.get_registry_activities():
                self.__process_registry_activities(registry_activity, current_maec_id)
        if activities.get_service_activities() != None:
            for service_activity in activities.get_service_activities():
                self.__process_service_activities(service_activity, current_maec_id)
        if activities.get_network_activities() != None:
            for network_activity in activities.get_network_activities():
                self.__process_network_activities(network_activity, current_maec_id)
        if activities.get_process_activities() != None:
            for process_activity in activities.get_process_activities():
                self.__process_process_activities(process_activity, current_maec_id)                 
        if activities.get_misc_activities() != None:
            for misc_activity in activities.get_misc_activities():
                self.__process_misc_activities(misc_activity, current_maec_id)
        
    def __process_file_activities(self, file_activity, current_maec_id):
        for deleted_file in file_activity.get_file_deleted():
            file_attributes = {}
            filename = deleted_file.get_name()
            if filename.count(',') > 0:
                split_filename = filename.split(',')[0].split('\\')
                filename = filename.split(',')[0]
            else:
                split_filename = filename.split('\\')
            actual_filename = split_filename[len(split_filename)-1]
            filepath = filename.rstrip(actual_filename)
            file_attributes['filename'] = actual_filename
            file_attributes['filepath'] = filepath
            if split_filename[0] == 'PIPE' or filename.lower().count('pipe') > 0:
                file_attributes['type'] = 'NamedPipe'
            else:
                file_attributes['type'] = 'File'
            file_attributes['association'] = 'Affected'
            #Generate the MAEC objects and actions
            #First, create the object
            if file_attributes.get('type') == 'File':
                fs_object = self.maec_object.create_file_system_object(file_attributes)
            elif file_attributes.get('type') == 'NamedPipe':
                fs_object = self.maec_object.create_pipe_object(file_attributes)

            #Next, create the action (that operated on the object)
            action_attributes = {}
            if split_filename[0] == 'PIPE' or filename.lower().count('pipe') > 0:
                action_attributes['defined_action_name'] = 'Delete Named Pipe'
            else:
                action_attributes['defined_action_name'] = 'Delete File'
            action_attributes['action_type'] = 'Remove/Delete'
            action_attributes['object'] = fs_object
            action_attributes['initiator_id'] = current_maec_id
            action_attributes['tool_id'] = self.tool_id
            action_attributes['context'] = 'Host'
            fs_action = self.maec_action.create_action(action_attributes)
            self.actions.get('file_system').append(fs_action)
            self.action_ids.append(fs_action.get_id())
            
        for created_file in file_activity.get_file_created():
            file_attributes = {}
            filename = created_file.get_name()
            if filename.count(',') > 0:
                split_filename = filename.split(',')[0].split('\\')
                filename = filename.split(',')[0]
            else:
                split_filename = filename.split('\\')
            actual_filename = split_filename[len(split_filename)-1]
            filepath = filename.rstrip(actual_filename)
            file_attributes['filename'] = actual_filename
            file_attributes['filepath'] = filepath
            if split_filename[0] == 'PIPE' or filename.lower().count('pipe') > 0:
                file_attributes['type'] = 'NamedPipe'
            else:
                file_attributes['type'] = 'File'
            file_attributes['association'] = 'Affected'
            #Generate the MAEC objects and actions
            #First, create the object
            if file_attributes.get('type') == 'File':
                fs_object = self.maec_object.create_file_system_object(file_attributes)
            elif file_attributes.get('type') == 'NamedPipe':
                fs_object = self.maec_object.create_pipe_object(file_attributes)

            #Next, create the action (that operated on the object)
            action_attributes = {}
            if split_filename[0] == 'PIPE' or filename.lower().count('pipe') > 0:
                action_attributes['defined_action_name'] = 'Create Named Pipe'
            else:
                action_attributes['defined_action_name'] = 'Create File'
            action_attributes['action_type'] = 'Create'
            action_attributes['object'] = fs_object
            action_attributes['initiator_id'] = current_maec_id
            action_attributes['tool_id'] = self.tool_id
            action_attributes['context'] = 'Host'
            fs_action = self.maec_action.create_action(action_attributes)
            self.actions.get('file_system').append(fs_action)
            self.action_ids.append(fs_action.get_id())
            
        for read_file in file_activity.get_file_read():
            file_attributes = {}
            filename = read_file.get_name()
            if filename.count(',') > 0:
                split_filename = filename.split(',')[0].split('\\')
                filename = filename.split(',')[0]
            else:
                split_filename = filename.split('\\')
            actual_filename = split_filename[len(split_filename)-1]
            filepath = filename.rstrip(actual_filename)
            file_attributes['filename'] = actual_filename
            file_attributes['filepath'] = filepath
            if split_filename[0] == 'PIPE' or filename.lower().count('pipe') > 0:
                file_attributes['type'] = 'NamedPipe'
            else:
                file_attributes['type'] = 'File'
            file_attributes['association'] = 'Utilized'
            #Generate the MAEC objects and actions
            #First, create the object
            if file_attributes.get('type') == 'File':
                fs_object = self.maec_object.create_file_system_object(file_attributes)
            elif file_attributes.get('type') == 'NamedPipe':
                fs_object = self.maec_object.create_pipe_object(file_attributes)

            #Next, create the action (that operated on the object)
            action_attributes = {}
            if split_filename[0] == 'PIPE':
                action_attributes['defined_action_name'] = 'Read From Named Pipe'
            else:
                action_attributes['defined_action_name'] = 'Read File'
            action_attributes['action_type'] = 'Read'
            action_attributes['object'] = fs_object
            action_attributes['initiator_id'] = current_maec_id
            action_attributes['tool_id'] = self.tool_id
            action_attributes['context'] = 'Host'
            fs_action = self.maec_action.create_action(action_attributes)
            self.actions.get('file_system').append(fs_action)
            self.action_ids.append(fs_action.get_id())
            
        for modified_file in file_activity.get_file_modified():
            file_attributes = {}
            filename = modified_file.get_name()
            if filename.count(',') > 0:
                split_filename = filename.split(',')[0].split('\\')
                filename = filename.split(',')[0]
            else:
                split_filename = filename.split('\\')
            actual_filename = split_filename[len(split_filename)-1]
            filepath = filename.rstrip(actual_filename)
            file_attributes['filename'] = actual_filename
            file_attributes['filepath'] = filepath
            if split_filename[0] == 'PIPE' or filename.lower().count('pipe') > 0:
                file_attributes['type'] = 'NamedPipe'
            else:
                file_attributes['type'] = 'File'
            file_attributes['association'] = 'Affected'
            #Generate the MAEC objects and actions
            #First, create the object
            if file_attributes.get('type') == 'File':
                fs_object = self.maec_object.create_file_system_object(file_attributes)
            elif file_attributes.get('type') == 'NamedPipe':
                fs_object = self.maec_object.create_pipe_object(file_attributes)

            #Next, create the action (that operated on the object)
            action_attributes = {}
            if split_filename[0] == 'PIPE':
                action_attributes['defined_action_name'] = 'Modify Named Pipe'
            else:
                action_attributes['defined_action_name'] = 'Modify File'
            action_attributes['action_type'] = 'modify'
            action_attributes['object'] = fs_object
            action_attributes['initiator_id'] = current_maec_id
            action_attributes['tool_id'] = self.tool_id
            action_attributes['context'] = 'Host'
            fs_action = self.maec_action.create_action(action_attributes)
            self.actions.get('file_system').append(fs_action)
            self.action_ids.append(fs_action.get_id())
            
        for created_link in file_activity.get_link_created():
            file_attributes = {}
            filename = created_link.get_existing_file()
            if filename.count(',') > 0:
                split_filename = filename.split(',')[0].split('\\')
                filename = filename.split(',')[0]
            else:
                split_filename = filename.split('\\')
            actual_filename = split_filename[len(split_filename)-1]
            filepath = filename.rstrip(actual_filename)
            file_attributes['filename'] = actual_filename
            file_attributes['filepath'] = filepath
            file_attributes['linkname'] = created_link.get_link_name()

            #Generate the MAEC objects and actions
            #First, create the object
            fs_object = self.maec_object.create_file_system_object(file_attributes)

            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['defined_action_name'] = 'Create Symbolic Link'
            action_attributes['action_type'] = 'Create'
            action_attributes['object'] = fs_object
            action_attributes['initiator_id'] = current_maec_id
            action_attributes['tool_id'] = self.tool_id
            action_attributes['context'] = 'Host'
            fs_action = self.maec_action.create_action(action_attributes)
            self.actions.get('file_system').append(fs_action)
            self.action_ids.append(fs_action.get_id())
            
        for fs_control in file_activity.get_fs_control_communication():
            file_attributes = {}
            filename = fs_control.get_file()
            if filename.count(',') > 0:
                split_filename = filename.split(',')[0].split('\\')
                filename = filename.split(',')[0]
            else:
                split_filename = filename.split('\\')
            actual_filename = split_filename[len(split_filename)-1]
            filepath = filename.rstrip(actual_filename)
            file_attributes['filename'] = actual_filename
            if len(filepath) > 1:
                file_attributes['filepath'] = filepath
            if split_filename[0] == 'PIPE' or filename.lower().count('pipe') > 0:
                file_attributes['type'] = 'NamedPipe'
            else:
                file_attributes['type'] = 'File'
            file_attributes['controlcode'] = fs_control.get_control_code()
            file_attributes['association'] = 'Affected'
            #Generate the MAEC objects and actions
            #First, create the object
            if file_attributes.get('type') == 'File':
                fs_object = self.maec_object.create_file_system_object(file_attributes)
            elif file_attributes.get('type') == 'NamedPipe':
                fs_object = self.maec_object.create_pipe_object(file_attributes)

            #Next, create the action (that operated on the object)
            action_attributes = {}
            if split_filename[0] == 'PIPE':
                action_attributes['undefined_action_name'] = 'Send Control Code to Pipe'
            else:
                action_attributes['defined_action_name'] = 'Send Control Code to File'
            action_attributes['action_type'] = 'Send'
            action_attributes['object'] = fs_object
            action_attributes['initiator_id'] = current_maec_id
            action_attributes['tool_id'] = self.tool_id
            action_attributes['context'] = 'Host'
            fs_action = self.maec_action.create_action(action_attributes)
            self.actions.get('file_system').append(fs_action)
            self.action_ids.append(fs_action.get_id())

        for device_control in file_activity.get_device_control_communication():
            file_attributes = {}
            filename = device_control.get_file()
            if filename.count(',') > 0:
                split_filename = filename.split(',')[0].split('\\')
                filename = filename.split(',')[0]
            else:
                split_filename = filename.split('\\')
            actual_filename = split_filename[len(split_filename)-1]
            filepath = filename.rstrip(actual_filename)
            file_attributes['filename'] = actual_filename
            if len(filepath) > 1:
                file_attributes['filepath'] = filepath 
            file_attributes['controlcode'] = device_control.get_control_code()
            file_attributes['association'] = 'Affected'
            #Generate the MAEC objects and actions
            #First, create the object
            fs_object = self.maec_object.create_file_system_object(file_attributes)

            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['undefined_action_name'] = 'Send Control Code to Device'
            action_attributes['action_type'] = 'Send'
            action_attributes['object'] = fs_object
            action_attributes['initiator_id'] = current_maec_id
            action_attributes['tool_id'] = self.tool_id
            action_attributes['context'] = 'Host'
            fs_action = self.maec_action.create_action(action_attributes)
            self.actions.get('file_system').append(fs_action)
            self.action_ids.append(fs_action.get_id())
        
        
        #for created_directory in file_activity.get_directory_created(): #revisit - cybox currently doesn't support directories
        #    file_attributes = {}
        #    file_attributes['filename'] = created_directory.get_name()
        #    file_attributes['type'] = 'Directory'
        #    #Generate the MAEC objects and actions
        #    #First, create the object
        #    fs_object = self.maec_object.create_file_system_object(file_attributes)
        #    self.objects.get('file_system').append(fs_object)
        #    #Next, create the action (that operated on the object)
        #    action_attributes = {}
        #    action_attributes['action_name'] = 'create_directory'
        #    action_attributes['action_type'] = 'create'
        #    action_attributes['object_id'] = fs_object.get_id()
        #    action_attributes['initiator_id'] = current_maec_id
        #    action_attributes['tool_id'] = self.tool_id
        #    fs_action = self.maec_action.create_action(action_attributes)
        #    self.actions.get('file_system').append(fs_action)
            
        #for deleted_directory in file_activity.get_directory_removed(): #revisit - cybox currently doesn't support directories
        #    file_attributes = {}
        #    file_attributes['filename'] = deleted_directory.get_name()
        #    file_attributes['type'] = 'Directory'
        #    #Generate the MAEC objects and actions
        #    #First, create the object
        #    fs_object = self.maec_object.create_file_system_object(file_attributes)
        #    self.objects.get('file_system').append(fs_object)
        #    #Next, create the action (that operated on the object)
        #    action_attributes = {}
        #    action_attributes['action_name'] = 'delete_directory'
        #    action_attributes['action_type'] = 'Remove/Delete'
        #    action_attributes['object_id'] = fs_object.get_id()
        #    action_attributes['initiator_id'] = current_maec_id
        #    action_attributes['tool_id'] = self.tool_id
        #    fs_action = self.maec_action.create_action(action_attributes)
        #    self.actions.get('file_system').append(fs_action)
                
        for renamed_file in file_activity.get_file_renamed():
            file_attributes_old = {}
            filename_old = renamed_file.get_old_name()
            split_filename_old = filename_old.split('\\')
            actual_filename_old = split_filename_old[len(split_filename_old)-1]
            filepath_old = filename_old.rstrip(actual_filename_old)
            file_attributes_old['filename'] = actual_filename_old
            file_attributes_old['filepath'] = filepath_old
            file_attributes_old['type'] = 'File'
            file_attributes_old['association'] = 'Affected'
            file_attributes_new = {}
            filename_new = renamed_file.get_new_name()
            split_filename_new = filename_new.split('\\')
            actual_filename_new = split_filename_new[len(split_filename_new)-1]
            filepath_new = filename_new.rstrip(actual_filename_new)
            file_attributes_new['filename'] = actual_filename_new
            file_attributes_new['filepath'] = filepath_new
            file_attributes_new['type'] = 'File'
            file_attributes_new['association'] = 'Returned'
            #Generate the MAEC objects and actions
            #First, create the objects
            fs_object_old = self.maec_object.create_file_system_object(file_attributes_old)
            fs_object_new = self.maec_object.create_file_system_object(file_attributes_new)

            #Next, create the action (that operated on the objects)
            action_attributes = {}
            action_attributes['defined_action_name'] = 'Rename File'
            action_attributes['action_type'] = 'Modify'
            action_attributes['filename_old'] = actual_filename_old
            action_attributes['filename_new'] = actual_filename_new
            action_attributes['object_old'] = fs_object_old
            action_attributes['object_new'] = fs_object_new
            action_attributes['initiator_id'] = current_maec_id
            action_attributes['tool_id'] = self.tool_id
            action_attributes['context'] = 'Host'
            fs_action = self.maec_action.create_action(action_attributes)
            self.actions.get('file_system').append(fs_action)
            self.action_ids.append(fs_action.get_id())
    
    def __process_registry_activities(self, registry_activity, current_maec_id):
        for created_regkey in registry_activity.get_reg_key_created():
            regkey_attributes = {}
            split_name = created_regkey.get_name().split('\\')
            regkey_attributes['hive'] = self.__map_reg_hive_string(split_name[0])
            actual_key = ''
            for i in range(1, len(split_name)):
                actual_key += (split_name[i] + '\\')
            actual_key = actual_key.rstrip('\\')
            regkey_attributes['key'] = actual_key
            regkey_attributes['type'] = 'Key/Key Group'
            regkey_attributes['association'] = 'Affected'
            #Generate the MAEC objects and actions
            #First, create the object
            reg_object = self.maec_object.create_registry_object(regkey_attributes)

            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['defined_action_name'] = 'Create Registry Key'
            action_attributes['action_type'] = 'create'
            action_attributes['object'] = reg_object
            action_attributes['initiator_id'] = current_maec_id
            action_attributes['tool_id'] = self.tool_id
            action_attributes['context'] = 'Host'
            reg_action = self.maec_action.create_action(action_attributes)
            self.actions.get('registry').append(reg_action)
            self.action_ids.append(reg_action.get_id())
            
        for opened_regkey in registry_activity.get_reg_key_created_or_opened():
            regkey_attributes = {}
            split_name = opened_regkey.get_name().split('\\')
            regkey_attributes['hive'] = self.__map_reg_hive_string(split_name[0])
            actual_key = ''
            for i in range(1, len(split_name)):
                actual_key += (split_name[i] + '\\')
            actual_key = actual_key.rstrip('\\')
            regkey_attributes['key'] = actual_key
            regkey_attributes['type'] = 'Key/Key Group'
            regkey_attributes['association'] = 'Utilized'
            #Generate the MAEC objects and actions
            #First, create the object
            reg_object = self.maec_object.create_registry_object(regkey_attributes)

            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['defined_action_name'] = 'Open Registry Key'
            action_attributes['action_type'] = 'Open'
            action_attributes['object'] = reg_object
            action_attributes['initiator_id'] = current_maec_id
            action_attributes['tool_id'] = self.tool_id
            action_attributes['context'] = 'Host'
            reg_action = self.maec_action.create_action(action_attributes)
            self.actions.get('registry').append(reg_action)
            self.action_ids.append(reg_action.get_id())
        
        for deleted_regkey in registry_activity.get_reg_key_deleted():
            regkey_attributes = {}
            split_name = deleted_regkey.get_name().split('\\')
            regkey_attributes['hive'] = self.__map_reg_hive_string(split_name[0])
            actual_key = ''
            for i in range(1, len(split_name)):
                actual_key += (split_name[i] + '\\')
            actual_key = actual_key.rstrip('\\')
            regkey_attributes['key'] = actual_key
            regkey_attributes['type'] = 'Key/Key Group'
            regkey_attributes['association'] = 'Affected'
            #Generate the MAEC objects and actions
            #First, create the object
            reg_object = self.maec_object.create_registry_object(regkey_attributes)

            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['defined_action_name'] = 'Delete Registry Key'
            action_attributes['action_type'] = 'Remove/Delete'
            action_attributes['object'] = reg_object
            action_attributes['initiator_id'] = current_maec_id
            action_attributes['tool_id'] = self.tool_id
            action_attributes['context'] = 'Host'
            reg_action = self.maec_action.create_action(action_attributes)
            self.actions.get('registry').append(reg_action)
            self.action_ids.append(reg_action.get_id())
        
        for deleted_regkeyvalue in registry_activity.get_reg_value_deleted():
            regkey_attributes = {}
            split_name = deleted_regkeyvalue.get_key().split('\\')
            regkey_attributes['hive'] = self.__map_reg_hive_string(split_name[0])
            actual_key = ''
            for i in range(1, len(split_name)):
                actual_key += (split_name[i] + '\\')
            actual_key = actual_key.rstrip('\\')
            regkey_attributes['key'] = actual_key
            regkey_attributes['value'] = deleted_regkeyvalue.get_value_name()
            regkey_attributes['type'] = 'Key/Key Group'
            regkey_attributes['association'] = 'Affected'
            #Generate the MAEC objects and actions
            #First, create the object
            reg_object = self.maec_object.create_registry_object(regkey_attributes)

            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['defined_action_name'] = 'Delete Registry Key Value'
            action_attributes['action_type'] = 'Remove/Delete'
            action_attributes['object'] = reg_object
            action_attributes['initiator_id'] = current_maec_id
            action_attributes['tool_id'] = self.tool_id
            action_attributes['context'] = 'Host'
            reg_action = self.maec_action.create_action(action_attributes)
            self.actions.get('registry').append(reg_action)
            self.action_ids.append(reg_action.get_id())
            
        for modified_regvalue in registry_activity.get_reg_value_modified():
            regkey_attributes = {}
            split_name = modified_regvalue.get_key().split('\\')
            regkey_attributes['hive'] = self.__map_reg_hive_string(split_name[0])
            actual_key = ''
            for i in range(1, len(split_name)):
                actual_key += (split_name[i] + '\\')
            actual_key = actual_key.rstrip('\\')
            regkey_attributes['key'] = actual_key
            regkey_attributes['value'] = modified_regvalue.get_value_name()
            regkey_attributes['valuedata'] = modified_regvalue.get_value_data()
            regkey_attributes['type'] = 'Key/Key Group'
            regkey_attributes['association'] = 'Affected'
            #Generate the MAEC objects and actions
            #First, create the object
            reg_object = self.maec_object.create_registry_object(regkey_attributes)

            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['defined_action_name'] = 'Write Registry Key Value'
            action_attributes['action_type'] = 'Modify'
            action_attributes['object'] = reg_object
            action_attributes['initiator_id'] = current_maec_id
            action_attributes['tool_id'] = self.tool_id
            action_attributes['context'] = 'Host'
            reg_action = self.maec_action.create_action(action_attributes)
            self.actions.get('registry').append(reg_action)
            self.action_ids.append(reg_action.get_id())
        
        for read_regvalue in registry_activity.get_reg_value_read():
            regkey_attributes = {}
            split_name = read_regvalue.get_key().split('\\')
            regkey_attributes['hive'] = self.__map_reg_hive_string(split_name[0])
            actual_key = ''
            for i in range(1, len(split_name)):
                actual_key += (split_name[i] + '\\')
            actual_key = actual_key.rstrip('\\')
            regkey_attributes['key'] = actual_key
            regkey_attributes['value'] = read_regvalue.get_value_name()
            regkey_attributes['valuedata'] = read_regvalue.get_value_data()
            regkey_attributes['type'] = 'Key/Key Group'
            regkey_attributes['association'] = 'Utilized'
            #Generate the MAEC objects and actions
            #First, create the object
            reg_object = self.maec_object.create_registry_object(regkey_attributes)

            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['defined_action_name'] = 'Read Registry Key Value'
            action_attributes['action_type'] = 'Read'
            action_attributes['object'] = reg_object
            action_attributes['initiator_id'] = current_maec_id
            action_attributes['tool_id'] = self.tool_id
            action_attributes['context'] = 'Host'
            reg_action = self.maec_action.create_action(action_attributes)
            self.actions.get('registry').append(reg_action)
            self.action_ids.append(reg_action.get_id())
            
        for monitored_regkey in registry_activity.get_reg_key_monitored():
            regkey_attributes = {}
            split_name = read_regvalue.get_key().split('\\')
            regkey_attributes['hive'] = self.__map_reg_hive_string(split_name[0])
            actual_key = ''
            for i in range(1, len(split_name)):
                actual_key += (split_name[i] + '\\')
            actual_key = actual_key.rstrip('\\')
            regkey_attributes['key'] = actual_key
            regkey_attributes['value'] = read_regvalue.get_value_name()
            regkey_attributes['valuedata'] = read_regvalue.get_value_data()
            regkey_attributes['type'] = 'Key/Key Group'
            regkey_attributes['association'] = 'Utilized'
            #Generate the MAEC objects and actions
            #First, create the object
            reg_object = self.maec_object.create_registry_object(regkey_attributes)

            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['defined_action_name'] = 'Monitor Registry Key'
            action_attributes['action_type'] = 'Scan'
            action_attributes['object'] = reg_object
            action_attributes['initiator_id'] = current_maec_id
            action_attributes['tool_id'] = self.tool_id
            action_attributes['context'] = 'Host'
            reg_action = self.maec_action.create_action(action_attributes)
            self.actions.get('registry').append(reg_action)
            self.action_ids.append(reg_action.get_id())
            
    def __map_reg_hive_string(self, input):
        if input == 'HKU':
            return 'HKEY_USERS'
        elif input == 'HKLM':
            return 'HKEY_LOCAL_MACHINE'
        elif input == 'HKCR':
            return 'HKEY_CLASSES_ROOT'
        elif input == 'HKCC':
            return 'HKEY_CURRENT_CONFIG'
        elif input == 'HKCU':
            return 'HKEY_CURRENT_USER'
            
    def __process_service_activities(self, service_activity, current_maec_id):
        for started_service in service_activity.get_service_started():
            service_attributes = {}
            service_attributes['name'] = started_service.get_name()
            service_attributes['association'] = 'Affected'
            #Generate the MAEC objects and actions
            #First, create the object
            service_object = self.maec_object.create_service_object(service_attributes)

            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['defined_action_name'] = 'Start Service'
            action_attributes['action_type'] = 'Start'
            action_attributes['object'] = service_object
            action_attributes['initiator_id'] = current_maec_id
            action_attributes['tool_id'] = self.tool_id
            action_attributes['context'] = 'Host'
            service_action = self.maec_action.create_action(action_attributes)
            self.actions.get('service').append(service_action)
            self.action_ids.append(service_action.get_id())
        
        for created_service in service_activity.get_service_created():
            service_attributes = {}
            service_attributes['name'] = created_service.get_name()
            service_attributes['filename'] = created_service.get_path()
            service_attributes['association'] = 'Affected'
            #Generate the MAEC objects and actions
            #First, create the object
            service_object = self.maec_object.create_service_object(service_attributes)

            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['defined_action_name'] = 'Create Service'
            action_attributes['action_type'] = 'Create'
            action_attributes['object'] = service_object
            action_attributes['initiator_id'] = current_maec_id
            action_attributes['tool_id'] = self.tool_id
            action_attributes['context'] = 'Host'
            service_action = self.maec_action.create_action(action_attributes)
            self.actions.get('service').append(service_action)
            self.action_ids.append(service_action.get_id())
            
        for deleted_service in service_activity.get_service_deleted():
            service_attributes = {}
            service_attributes['name'] = deleted_service.get_name()
            service_attributes['association'] = 'Affected'
            #Generate the MAEC objects and actions
            #First, create the object
            service_object = self.maec_object.create_service_object(service_attributes)

            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['defined_action_name'] = 'Delete Service'
            action_attributes['action_type'] = 'Remove/Delete'
            action_attributes['object'] = service_object
            action_attributes['initiator_id'] = current_maec_id
            action_attributes['tool_id'] = self.tool_id
            action_attributes['context'] = 'Host'
            service_action = self.maec_action.create_action(action_attributes)
            self.actions.get('service').append(service_action)
            self.action_ids.append(service_action.get_id())
        
        for changed_service in service_activity.get_service_changed():
            service_attributes = {}
            service_attributes['name'] = changed_service.get_name()
            service_attributes['association'] = 'Affected'
            #Generate the MAEC objects and actions
            #First, create the object
            service_object = self.maec_object.create_service_object(service_attributes)

            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['defined_action_name'] = 'Modify Service'
            action_attributes['action_type'] = 'Modify'
            action_attributes['object'] = service_object
            action_attributes['initiator_id'] = current_maec_id
            action_attributes['tool_id'] = self.tool_id
            action_attributes['context'] = 'Host'
            service_action = self.maec_action.create_action(action_attributes)
            self.actions.get('service').append(service_action)
            self.action_ids.append(service_action.get_id())

        for control_code in service_activity.get_service_control_code():
            service_attributes = {}
            service_attributes['name'] = control_code.get_service()
            service_attributes['controlcode'] = control_code.get_control_code()
            service_attributes['association'] = 'Affected'
            #Generate the MAEC objects and actions
            #First, create the object
            service_object = self.maec_object.create_service_object(service_attributes)

            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['defined_action_name'] = 'Modify Service'
            action_attributes['action_type'] = 'Send'
            action_attributes['object'] = service_object
            action_attributes['initiator_id'] = current_maec_id
            action_attributes['tool_id'] = self.tool_id
            action_attributes['context'] = 'Host'
            service_action = self.maec_action.create_action(action_attributes)
            self.actions.get('service').append(service_action)
            self.action_ids.append(service_action.get_id())
            
    def __process_network_activities(self, network_activity, current_maec_id): 
        for sockets in network_activity.get_sockets():
            for socket in sockets.get_socket():
                socket_attributes = {}
                socket_attributes['remote_port']  = socket.get_foreign_port()
                socket_attributes['remote_address'] = socket.get_foreign_ip()
                socket_attributes['local_port']  = socket.get_local_port()
                socket_attributes['local_address'] = socket.get_local_ip()
                socket_attributes['islistening'] = socket.get_is_listening()
                socket_attributes['protocol'] = ''
                socket_attributes['socket_type'] = socket.get_type()
                socket_attributes['type'] = 'Socket'
                socket_attributes['association'] = 'Affected'
                #Generate the MAEC objects and actions
                #First, create the object
                socket_object = self.maec_object.create_socket_object(socket_attributes)

                #Next, create the action (that operated on the object)
                action_attributes = {}
                action_attributes['defined_action_name'] = 'Create Socket'
                action_attributes['action_type'] = 'Create'
                action_attributes['object'] = socket_object
                action_attributes['initiator_id'] = current_maec_id
                action_attributes['tool_id'] = self.tool_id
                action_attributes['context'] = 'Network'
                action_attributes['networkprotocol'] = 'TCP/IP'
                socket_action = self.maec_action.create_action(action_attributes)
                self.actions.get('network').append(socket_action)
                self.action_ids.append(socket_action.get_id())
                
    def __process_process_activities(self, process_activity, current_maec_id):
        for created_process in process_activity.get_process_created():
            process_attributes = {}
            process_attributes['filename'] = created_process.get_exe_name()
            process_attributes['cmd_line'] = created_process.get_cmd_line()
            process_attributes['association'] = 'Affected'
            #Generate the MAEC objects and actions
            #First, create the object
            process_object = self.maec_object.create_process_object(process_attributes)

            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['defined_action_name'] = 'Create Process'
            action_attributes['action_type'] = 'Create'
            action_attributes['object'] = process_object
            action_attributes['initiator_id'] = current_maec_id
            action_attributes['tool_id'] = self.tool_id
            action_attributes['context'] = 'Host'
            process_action = self.maec_action.create_action(action_attributes)
            self.actions.get('process').append(process_action)
            self.action_ids.append(process_action.get_id())
            
        for killed_process in process_activity.get_process_killed():
            process_attributes = {}
            process_attributes['name'] = killed_process.get_name()
            process_attributes['association'] = 'Affected'
            #Generate the MAEC objects and actions
            #First, create the object
            process_object = self.maec_object.create_process_object(process_attributes)

            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['defined_action_name'] = 'Kill Process'
            action_attributes['action_type'] = 'Kill'
            action_attributes['object'] = process_object
            action_attributes['initiator_id'] = current_maec_id
            action_attributes['tool_id'] = self.tool_id
            action_attributes['context'] = 'Host'
            process_action = self.maec_action.create_action(action_attributes)
            self.actions.get('process').append(process_action)
            self.action_ids.append(process_action.get_id())
        
        for created_remote_thread in process_activity.get_remote_thread_created():
            process_attributes = {}
            process_attributes['filename'] = created_remote_thread.get_process()
            process_attributes['association'] = 'Affected'
            #Generate the MAEC objects and actions
            #First, create the object
            process_object = self.maec_object.create_process_object(process_attributes)

            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['defined_action_name'] = 'Create Remote Thread in Process'
            action_attributes['action_type'] = 'Create'
            action_attributes['object'] = process_object
            action_attributes['initiator_id'] = current_maec_id
            action_attributes['tool_id'] = self.tool_id
            action_attributes['context'] = 'Host'
            process_action = self.maec_action.create_action(action_attributes)
            self.actions.get('process').append(process_action)
            self.action_ids.append(process_action.get_id())
            
        for mem_read in process_activity.get_foreign_mem_area_read():
            process_attributes = {}
            process_attributes['filename'] = mem_read.get_process()
            process_attributes['association'] = 'Utilized'
            #Generate the MAEC objects and actions
            #First, create the object
            process_object = self.maec_object.create_process_object(process_attributes)

            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['defined_action_name'] = 'Read From Process Memory'
            action_attributes['action_type'] = 'Read'
            action_attributes['object'] = process_object
            action_attributes['initiator_id'] = current_maec_id
            action_attributes['tool_id'] = self.tool_id
            action_attributes['context'] = 'Host'
            process_action = self.maec_action.create_action(action_attributes)
            self.actions.get('process').append(process_action)
            self.action_ids.append(process_action.get_id())
            
        for mem_write in process_activity.get_foreign_mem_area_read():
            process_attributes = {}
            process_attributes['filename'] = mem_write.get_process()
            process_attributes['association'] = 'Affected'
            #Generate the MAEC objects and actions
            #First, create the object
            process_object = self.maec_object.create_process_object(process_attributes)

            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['defined_action_name'] = 'Write to Process Virtual Memory'
            action_attributes['action_type'] = 'Write'
            action_attributes['object'] = process_object
            action_attributes['initiator_id'] = current_maec_id
            action_attributes['tool_id'] = self.tool_id
            action_attributes['context'] = 'Host'
            process_action = self.maec_action.create_action(action_attributes)
            self.actions.get('process').append(process_action)
            self.action_ids.append(process_action.get_id())
            
    def __process_misc_activities(self, misc_activity, current_maec_id):
        for created_mutex in misc_activity.get_mutex_created():
            mutex_attributes = {}
            mutex_attributes['name']  = created_mutex.get_name()
            mutex_attributes['association'] = 'Affected'
            #Generate the MAEC objects and actions
            #First, create the object
            mutex_object = self.maec_object.create_mutex_object(mutex_attributes)

            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['defined_action_name'] = 'Create Mutex'
            action_attributes['action_type'] = 'Create'
            action_attributes['object'] = mutex_object
            action_attributes['initiator_id'] = current_maec_id
            action_attributes['tool_id'] = self.tool_id
            action_attributes['context'] = 'Host'
            mutex_action = self.maec_action.create_action(action_attributes)
            self.actions.get('ipc').append(mutex_action)
            self.action_ids.append(mutex_action.get_id())
    
        for loaded_driver in misc_activity.get_driver_loaded():
            driver_attributes = {}
            driver_attributes['name']  = loaded_driver.get_name()
            driver_attributes['association'] = 'Affected'
            #Generate the MAEC objects and actions
            #First, create the object
            driver_object = self.maec_object.create_driver_object(driver_attributes)

            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['defined_action_name'] = 'Load Driver'
            action_attributes['action_type'] = 'Load'
            action_attributes['object'] = driver_object
            action_attributes['initiator_id'] = current_maec_id
            action_attributes['tool_id'] = self.tool_id
            action_attributes['context'] = 'Host'
            driver_action = self.maec_action.create_action(action_attributes)
            self.actions.get('driver').append(driver_action)
            self.action_ids.append(driver_action.get_id())

        for unloaded_driver in misc_activity.get_driver_unloaded():
            driver_attributes = {}
            driver_attributes['name']  = unloaded_driver.get_name()
            driver_attributes['association'] = 'Affected'
            #Generate the MAEC objects and actions
            #First, create the object
            driver_object = self.maec_object.create_driver_object(driver_attributes)

            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['defined_action_name'] = 'Unload Driver'
            action_attributes['action_type'] = 'Unload'
            action_attributes['object'] = driver_object
            action_attributes['initiator_id'] = current_maec_id
            action_attributes['tool_id'] = self.tool_id
            action_attributes['context'] = 'Host'
            driver_action = self.maec_action.create_action(action_attributes)
            self.actions.get('driver').append(driver_action)
            self.action_ids.append(driver_action.get_id())
    
    def __get_av_aliases(self, object):
        av_classifications = maec.AVClassificationsType()
        ikarus_scanner = object.get_ikarus_scanner()
        if ikarus_scanner != None:
            for sig in ikarus_scanner.get_sig():
                name = sig.get_name()
                av_classification_object = maec.mmdef.classificationObject(classificationName=name, companyName='Ikarus', id='av-classification-1', type_='dirty')
                av_classifications.add_AV_Classification(av_classification_object)
        #Go through each type of av_alias and add it (if existing)
        if av_classifications.hasContent_():
            av_classifications.set_type_('maec:AVClassificationsType')
            return av_classifications
        else:
            return None