#GFI Sandbox Process Section Handler
#v0.2
import section

class process_section_handler(section.section_handler):

    def __init__(self):
        super(process_section_handler,self).__init__()
        self.__populate_action_mappings()
    
    #Handle the file object oriented attributes
    def handle_object_attributes(self, action, object_attributes, action_attributes, action_mappings):
        image_info_dict = {}
        #Handle the process object attributes
        try:
            object_attributes['properties']['pid'] = action.get_target_pid()
        except AttributeError:
            pass
        try:
            object_attributes['properties']['parent_pid'] = action.get_parent_pid()
        except AttributeError:
            pass
        try:
            if action.get_image_filename():
                image_info_dict['file_name'] = action.get_image_filename()
        except AttributeError:
            pass
        try:
            if action.get_command_line():
                image_info_dict['command_line'] = action.get_command_line()
        except AttributeError:
            pass
        try:
            object_attributes['properties']['username'] = action.get_username()
        except AttributeError:
            pass
        try:
            object_attributes['properties']['security_id'] = action.get_token_sid()
        except AttributeError:
            pass
        if image_info_dict.keys():
            object_attributes['properties']['image_info'] = image_info_dict
        return object_attributes

    #Handle the action specific attributes correctly
    def handle_action_attributes(self, action, object, action_attributes, action_mappings):
        #Populate any action arguments
        action_arguments = []
        try:
            split_access_mode = action.get_desired_access().split(' ')
            for access_mode in split_access_mode:
                if len(access_mode) > 0:
                    argument_dict = {}
                    argument_dict['argument_name'] = {'value': 'Access Mode', 'xsi:type': 'cyboxVocabs:ActionArgumentNameVocab-1.0'}
                    argument_dict['argument_value'] = access_mode
                    action_arguments.append(argument_dict)
        except AttributeError:
            pass
        try:
            split_creation_options = action.get_creation_flags().split(' ')
            for creation_flag in split_creation_options:
                if len(creation_flag) > 0:
                    argument_dict = {}
                    argument_dict['argument_name'] = {'value': 'Creation Flags', 'xsi:type': 'cyboxVocabs:ActionArgumentNameVocab-1.0'}
                    argument_dict['argument_value'] = creation_flag
                    action_arguments.append(argument_dict)
        except AttributeError:
            pass
        #Set any action arguments
        action_attributes['action_arguments'] = action_arguments

    #Create the GFI Sandbox -> MAEC/CybOX Action Mappings
    def __populate_action_mappings(self):
         self.action_mappings['create_process'] = {'action_name': {'value':'create process',
                                                                   'xsi:type':'maecVocabs:ProcessActionNameVocab-1.0'}, 'xsi:type':'WindowsProcessObjectType', 'object_association':'output'}
         self.action_mappings['create_process_as_user'] = {'action_name':{'value':'create process as user',
                                                                          'xsi:type':'maecVocabs:ProcessActionNameVocab-1.0'}, 'xsi:type':'WindowsProcessObjectType','object_association':'output'}
         self.action_mappings['open_process'] = {'action_name':{'value':'open process',
                                                                'xsi:type':'maecVocabs:ProcessActionNameVocab-1.0'}, 'xsi:type':'WindowsProcessObjectType', 'object_association':'input'}
         self.action_mappings['kill_process'] = {'action_name':{'value':'kill process',
                                                                'xsi:type':'maecVocabs:ProcessActionNameVocab-1.0'}, 'xsi:type':'WindowsProcessObjectType', 'object_association':'input'}
         self.action_mappings['enumerate_processes'] = {'action_name':{'value':'enumerate processes',
                                                                       'xsi:type':'maecVocabs:ProcessActionNameVocab-1.0'}, 'xsi:type':'WindowsProcessObjectType', 'object_association':'input'}
         self.action_mappings['impersonate_process'] = {'action_name':{'value':'impersonate process',
		                                                               'xsi:type':'maecVocabs:ProcessThreadActionNameVocab-1.0'}, 'xsi:type':'WindowsProcessObjectType', 'object_association':'input'}