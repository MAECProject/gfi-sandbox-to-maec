#GFI Sandbox Registry Section Handler
#v0.1
import section

class registry_section_handler(section.section_handler):

    def __init__(self, maec_object, initiator_id, tool_id):
        super(registry_section_handler,self).__init__(initiator_id, tool_id)
        self.maec_object = maec_object
        self.__populate_action_mappings()
    
    #Handle the file object oriented attributes
    def handle_object_attributes(self, action, object_attributes, action_attributes, action_mappings):
        #Handle the registry key
        regkey = action.get_key_name()
        normalizedkey = regkey.split('\\',2)[2]
        splitkey = normalizedkey.split('\\',1)
        if len(splitkey) == 2:
            object_attributes['hive'] = self.__map_hivename(splitkey[0])
            object_attributes['key'] = splitkey[1]
        else:
            object_attributes['key'] = splitkey[0]
        try:
            object_attributes['value'] = action.get_value_name()
        except AttributeError:
            pass
        try:
            valuedata = action.get_data().rstrip('(UNICODE_0x00000000)')
            #Handle special cases where the data is not actually included
            if '_data]' not in valuedata:
                object_attributes['valuedata'] = action.get_data().rstrip('(UNICODE_0x00000000)')
        except AttributeError:
            pass
        try:
            object_attributes['valuedatatype'] = action.get_data_type()
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
            split_creation_options = action.get_create_options().split(' ')
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
         self.action_mappings['open_key'] = {'action_type':'Open', 'action_name_type':'defined_action_name', 'action_name':'Open Registry Key', 'object_type':'Key/Key Group', 'object_method':'create_registry_object', 'object_association':'Utilized'}
         self.action_mappings['create_key'] = {'action_type':'Create', 'action_name_type':'defined_action_name', 'action_name':'Create Registry Key', 'object_type':'Key/Key Group', 'object_method':'create_registry_object', 'object_association':'Affected'}
         self.action_mappings['delete_key'] = {'action_type':'Remove/Delete', 'action_name_type':'defined_action_name', 'action_name':'Delete Registry Key', 'object_type':'Key/Key Group', 'object_method':'create_registry_object', 'object_association':'Affected'}
         self.action_mappings['enum_keys'] = {'action_type':'Enumerate', 'action_name_type':'defined_action_name', 'action_name':'Enumerate Registry Key Values', 'object_type':'Key/Key Group', 'object_method':'create_registry_object', 'object_association':'Utilized'}
         self.action_mappings['set_value'] = {'action_type':'Write', 'action_name_type':'defined_action_name', 'action_name':'Write Registry Key Value', 'object_type':'Key/Key Group', 'object_method':'create_registry_object', 'object_association':'Affected'}
         self.action_mappings['delete_value'] = {'action_type':'Remove/Delete', 'action_name_type':'defined_action_name', 'action_name':'Delete Registry Key Value', 'object_type':'Key/Key Group', 'object_method':'create_registry_object', 'object_association':'Affected'}
         self.action_mappings['query_key_info'] = {'action_type':'Query', 'action_name_type':'undefined_action_name', 'action_name':'Query Registry Key Info', 'object_type':'Key/Key Group', 'object_method':'create_registry_object', 'object_association':'Utilized'}
         self.action_mappings['query_value'] = {'action_type':'Read', 'action_name_type':'defined_action_name', 'action_name':'Read Registry Key Value', 'object_type':'Key/Key Group', 'object_method':'create_registry_object', 'object_association':'Utilized'}
         self.action_mappings['enum_values'] = {'action_type':'Enumerate', 'action_name_type':'defined_action_name', 'action_name':'Enumerate Registry Key Values', 'object_type':'Key/Key Group', 'object_method':'create_registry_object', 'object_association':'Utilized'}

    def __map_hivename(self, hivename):
        if hivename.lower() == 'machine':
            return 'HKEY_LOCAL_MACHINE'
        elif hivename.lower() == 'user':
            return 'HKEY_CURRENT_USER'