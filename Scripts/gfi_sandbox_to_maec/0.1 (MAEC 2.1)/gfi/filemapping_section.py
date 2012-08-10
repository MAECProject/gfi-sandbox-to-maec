#GFI Sandbox File Mapping Section Handler
#v0.1
import section

class filemapping_section_handler(section.section_handler):

    def __init__(self, maec_object, initiator_id, tool_id):
        super(filemapping_section_handler,self).__init__(initiator_id, tool_id)
        self.maec_object = maec_object
        self.__populate_action_mappings()
    
    #Handle the file object oriented attributes
    def handle_object_attributes(self, action, object_attributes, action_attributes, action_mappings):
        secondary_object_attributes = {}
        try:
            secondary_object_attributes['id'] = int(action.get_file_handle(),16)
            secondary_object_attributes['type'] = 'File'
            secondary_object_attributes['association'] = 'Utilized'
        except AttributeError:
            pass
        try:
            object_attributes['id'] = int(action.get_mapping_handle(),16)
            object_attributes['type'] = 'FileMapping'
        except AttributeError:
            pass
        #Get the method encoded in the mappings dictionary to create the defined object
        method = action_mappings.get('object_method')
        #Create the secondary object (file mapping handle) that is returned by the action
        secondary_object = getattr(self.maec_object,method)(secondary_object_attributes)
        if secondary_object.hasContent_():
            action_attributes['object_new'] = secondary_object
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
            split_protection = action.get_protection().split(' ')
            for protection in split_protection:
                if len(protection) > 0:
                    argument_dict = {}
                    argument_dict['undefined_argument_name'] = 'Protection'
                    argument_dict['argument_value'] = protection
                    action_arguments.append(argument_dict)
        except AttributeError:
            pass
        try:
            target_pid = action.get_target_pid()
            if len(str(target_pid)) > 0:
                argument_dict = {}
                argument_dict['undefined_argument_name'] = 'Target PID'
                argument_dict['argument_value'] = target_pid
                action_arguments.append(argument_dict)
        except AttributeError:
            pass
        try:
            offset = action.get_mapping_offset()
            if len(str(offset)) > 0:
                argument_dict = {}
                argument_dict['undefined_argument_name'] = 'Mapping Offset'
                argument_dict['argument_value'] = offset
                action_arguments.append(argument_dict)
        except AttributeError:
            pass
        #Set any action arguments
        action_attributes['action_arguments'] = action_arguments
        #Set the action context
        action_attributes['context'] = 'Host'

    #Create the GFI Sandbox -> MAEC/CybOX Action Mappings
    def __populate_action_mappings(self):
         self.action_mappings['create_file_mapping'] = {'action_type':'Map', 'action_name_type':'defined_action_name', 'action_name':'Map File', 'object_type':'File', 'object_method':'create_win_handle_object', 'object_association':'Returned'}
         self.action_mappings['open_file_mapping'] = {'action_type':'Open', 'action_name_type':'undefined_action_name', 'action_name':'Open File Mapping', 'object_type':'File', 'object_method':'create_win_handle_object', 'object_association':'Utilized'}
         self.action_mappings['map_view_of_file'] = {'action_type':'Map', 'action_name_type':'undefined_action_name', 'action_name':'Map View of File', 'object_type':'File', 'object_method':'create_win_handle_object', 'object_association':'Utilized'}
     