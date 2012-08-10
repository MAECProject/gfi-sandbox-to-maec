#GFI Sandbox User Section Handler
#v0.1
import section

class module_section_handler(section.section_handler):

    def __init__(self, maec_object, initiator_id, tool_id):
        super(module_section_handler,self).__init__(initiator_id, tool_id)
        self.maec_object = maec_object
        self.__populate_action_mappings()
    
    #Handle the module object oriented attributes
    def handle_object_attributes(self, action, object_attributes, action_attributes, action_mappings):
        try:
            filename = action.get_filename()
            split_filename = filename.split('\\')
            actual_filename = split_filename[len(split_filename)-1]
            filepath = filename.rstrip(actual_filename)
            object_attributes['name'] = actual_filename
            object_attributes['path'] = filepath
        except AttributeError:
            pass
        try:
            object_attributes['internal_name'] = action.get_internal_name()
        except AttributeError:
            pass
        try:
            object_attributes['pid'] = action.get_target_pid()
        except AttributeError:
            pass
        #Get the method encoded in the mappings dictionary to create the defined object
        method = action_mappings.get('object_method')
        #Create and return the object
        if method != 'n/a':
            object = getattr(self.maec_object,method)(object_attributes)
            return object
        else:
            return None

    #Handle the action specific attributes correctly
    def handle_action_attributes(self, action, object, action_attributes, action_mappings):
        action_arguments = []
        try:
            ordinal = action.get_ordinal()
            if len(str(ordinal)) > 0:
                argument_dict = {}
                argument_dict['undefined_argument_name'] = 'Function Ordinal'
                argument_dict['argument_value'] = ordinal
                action_arguments.append(argument_dict)
        except AttributeError:
            pass
        try:
            function = action.get_function()
            if len(str(function)) > 0:
                argument_dict = {}
                argument_dict['undefined_argument_name'] = 'Function Name'
                argument_dict['argument_value'] = function
                action_arguments.append(argument_dict)
        except AttributeError:
            pass
        try:
            hook_id = action.get_hook_id()
            if len(str(hook_id)) > 0:
                argument_dict = {}
                argument_dict['undefined_argument_name'] = 'Hook Type'
                argument_dict['argument_value'] = hook_id
                action_arguments.append(argument_dict)
        except AttributeError:
            pass
        #Set any action arguments
        action_attributes['action_arguments'] = action_arguments
        #Set the action context
        action_attributes['context'] = 'Host'

    #Create the GFI Sandbox -> MAEC/CybOX Action Mappings
    def __populate_action_mappings(self):
         self.action_mappings['mapping_module'] = {'action_type':'Map', 'action_name_type':'undefined_action_name', 'action_name':'Map Library', 'object_type':'Library', 'object_method':'create_library_object', 'object_association':'Utilized'}
         self.action_mappings['module_mapped'] = {'action_type':'Map', 'action_name_type':'defined_action_name', 'action_name':'Map File', 'object_type':'Library', 'object_method':'create_library_object', 'object_association':'Utilized'} #How is this different from mapping_module?
         self.action_mappings['load_module'] = {'action_type':'Load', 'action_name_type':'undefined_action_name', 'action_name':'Load Module', 'object_type':'Library', 'object_method':'create_library_object', 'object_association':'Utilized'}
         self.action_mappings['unload_module'] = {'action_type':'Unload', 'action_name_type':'undefined_action_name', 'action_name':'Unload Module', 'object_type':'Library', 'object_method':'create_library_object', 'object_association':'Utilized'}
         self.action_mappings['enumerate_dlls'] = {'action_type':'Enumerate', 'action_name_type':'undefined_action_name', 'action_name':'Enumerate DLLs', 'object_type':'Library', 'object_method':'create_win_process_object', 'object_association':'Utilized'}
         self.action_mappings['get_proc_address'] = {'action_type':'Get', 'action_name_type':'defined_action_name', 'action_name':'Get Function Address', 'object_type':'Library', 'object_method':'create_library_object', 'object_association':'Utilized'}
         self.action_mappings['install_winhook_proc'] = {'action_type':'Install', 'action_name_type':'undefined_action_name', 'action_name':'Install Hook Procedure', 'object_type':'Library', 'object_method':'create_library_object', 'object_association':'Utilized'}    