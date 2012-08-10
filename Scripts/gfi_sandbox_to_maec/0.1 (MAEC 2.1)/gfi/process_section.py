#GFI Sandbox Process Section Handler
#v0.1
import section

class process_section_handler(section.section_handler):

    def __init__(self, maec_object, initiator_id, tool_id):
        super(process_section_handler,self).__init__(initiator_id, tool_id)
        self.maec_object = maec_object
        self.__populate_action_mappings()
    
    #Handle the file object oriented attributes
    def handle_object_attributes(self, action, object_attributes, action_attributes, action_mappings):
        #Handle the process object attributes
        try:
            object_attributes['pid'] = action.get_target_pid()
        except AttributeError:
            pass
        try:
            object_attributes['parentpid'] = action.get_parent_pid()
        except AttributeError:
            pass
        try:
            object_attributes['filename'] = action.get_image_filename()
        except AttributeError:
            pass
        try:
            object_attributes['command_line'] = action.get_command_line()
        except AttributeError:
            pass
        try:
            object_attributes['username'] = action.get_username()
        except AttributeError:
            pass
        try:
            object_attributes['sid'] = action.get_token_sid()
        except AttributeError:
            pass
        #Get the method encoded in the mappings dictionary to create the defined object
        method = action_mappings.get('object_method')
        #Create and return the object
        object = getattr(self.maec_object,method)(object_attributes)
        return object

    #Handle the action specific attributes correctly
    def handle_action_attributes(self, action, object, action_attributes, action_mappings):
        #Populate any action arguments
        action_arguments = []
        try:
            split_access_mode = action.get_desired_access().split(' ')
            for access_mode in split_access_mode:
                if len(access_mode) > 0:
                    argument_dict = {}
                    argument_dict['defined_argument_name'] = 'Access Mode'
                    argument_dict['argument_value'] = access_mode
                    action_arguments.append(argument_dict)
        except AttributeError:
            pass
        try:
            split_creation_options = action.get_creation_flags().split(' ')
            for creation_flag in split_creation_options:
                if len(creation_flag) > 0:
                    argument_dict = {}
                    argument_dict['defined_argument_name'] = 'Creation Flags'
                    argument_dict['argument_value'] = creation_flag
                    action_arguments.append(argument_dict)
        except AttributeError:
            pass
        #Set any action arguments
        action_attributes['action_arguments'] = action_arguments
        #Set the action context
        action_attributes['context'] = 'Host'

    #Create the GFI Sandbox -> MAEC/CybOX Action Mappings
    def __populate_action_mappings(self):
         self.action_mappings['create_process'] = {'action_type':'Create', 'action_name_type':'defined_action_name', 'action_name':'Create Process', 'object_type':'Process', 'object_method':'create_win_process_object', 'object_association':'Affected'}
         self.action_mappings['create_process_as_user'] = {'action_type':'Create', 'action_name_type':'defined_action_name', 'action_name':'Create Process as User', 'object_type':'Process', 'object_method':'create_win_process_object', 'object_association':'Affected'}
         self.action_mappings['open_process'] = {'action_type':'Open', 'action_name_type':'defined_action_name', 'action_name':'Open Process', 'object_type':'Process', 'object_method':'create_win_process_object', 'object_association':'Utilized'}
         self.action_mappings['kill_process'] = {'action_type':'Open', 'action_name_type':'defined_action_name', 'action_name':'Kill Process', 'object_type':'Process', 'object_method':'create_win_process_object', 'object_association':'Affected'}
         self.action_mappings['enumerate_processes'] = {'action_type':'Enumerate', 'action_name_type':'defined_action_name', 'action_name':'Enumerate Processes', 'object_type':'Process', 'object_method':'create_win_process_object', 'object_association':'Utilized'}
         self.action_mappings['impersonate_process'] = {'action_type':'Impersonate', 'action_name_type':'defined_action_name', 'action_name':'Impersonate Process', 'object_type':'Process', 'object_method':'create_win_process_object', 'object_association':'Utilized'}