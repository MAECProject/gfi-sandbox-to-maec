#GFI Sandbox Registry Section Handler
#v0.1
import section

class registry_section_handler(section.section_handler):

    def __init__(self):
        super(registry_section_handler,self).__init__()
        self.__populate_action_mappings()
    
    #Handle the file object oriented attributes
    def handle_object_attributes(self, action, object_attributes, action_attributes, action_mappings):
        #Handle the registry key
        regkey = action.get_key_name()
        normalizedkey = regkey.split('\\',2)[2]
        splitkey = normalizedkey.split('\\',1)
        value_dict = {}
        if len(splitkey) == 2:
            object_attributes['properties']['hive'] = self.__map_hivename(splitkey[0])
            object_attributes['properties']['key'] = splitkey[1]
        else:
            object_attributes['properties']['key'] = splitkey[0]
        try:
            value_dict['name'] = action.get_value_name()
        except AttributeError:
            pass
        try:
            valuedata = action.get_data().rstrip('(UNICODE_0x00000000)')
            #Handle special cases where the data is not actually included
            if '_data]' not in valuedata:
                value_dict['data'] = action.get_data().rstrip('(UNICODE_0x00000000)')
        except AttributeError:
            pass
        try:
            value_dict['datatype'] = action.get_data_type()
        except AttributeError:
            pass
        #Set the Registry Key Value, if applicable
        if value_dict: object_attributes['properties']['values'] = [value_dict]
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
            split_creation_options = action.get_create_options().split(' ')
            for creation_flag in split_creation_options:
                if len(creation_flag) > 0:
                    argument_dict = {}
                    argument_dict['defined_argument_name'] = {'value': 'Creation Flags', 'xsi:type': 'cyboxVocabs:ActionArgumentNameVocab-1.0'}
                    argument_dict['argument_value'] = creation_flag
                    action_arguments.append(argument_dict)
        except AttributeError:
            pass
        #Set any action arguments
        action_attributes['action_arguments'] = action_arguments

    #Create the GFI Sandbox -> MAEC/CybOX Action Mappings
    def __populate_action_mappings(self):
         self.action_mappings['open_key'] = {'action_name':{'value':'open registry key',
                                                            'xsi:type':'maecVocabs:RegistryActionNameVocab-1.0'},'xsi:type':'WindowsRegistryKeyObjectType', 'object_association':'input'}
         self.action_mappings['create_key'] = {'action_name':{'value':'create registry key',
                                                              'xsi:type':'maecVocabs:RegistryActionNameVocab-1.0'}, 'xsi:type':'WindowsRegistryKeyObjectType', 'object_association':'output'}
         self.action_mappings['delete_key'] = {'action_name':{'value':'delete registry key',
                                                              'xsi:type':'maecVocabs:RegistryActionNameVocab-1.0'}, 'xsi:type':'WindowsRegistryKeyObjectType', 'object_association':'input'}
         self.action_mappings['enum_keys'] = {'action_name':{'value':'enumerate registry key subkeys',
                                                            'xsi:type':'maecVocabs:RegistryActionNameVocab-1.0'}, 'xsi:type':'WindowsRegistryKeyObjectType', 'object_association':'input'}
         self.action_mappings['set_value'] = {'action_name':{'value':'modify registry key value',
                                                            'xsi:type':'maecVocabs:RegistryActionNameVocab-1.0'}, 'xsi:type':'WindowsRegistryKeyObjectType', 'object_association':'input'}
         self.action_mappings['delete_value'] = {'action_name':{'value':'delete registry key value',
                                                                'xsi:type':'maecVocabs:RegistryActionNameVocab-1.0'}, 'xsi:type':'WindowsRegistryKeyObjectType', 'object_association':'input'}
         self.action_mappings['query_key_info'] = {'action_name':{'value':'get registry key attributes',
                                                                  'xsi:type':'maecVocabs:RegistryActionNameVocab-1.0'}, 'xsi:type':'WindowsRegistryKeyObjectType', 'object_association':'input'}
         self.action_mappings['query_value'] = {'action_name':{'value':'read registry key value',
                                                               'xsi:type':'maecVocabs:RegistryActionNameVocab-1.0'}, 'xsi:type':'WindowsRegistryKeyObjectType', 'object_association':'input'}
         self.action_mappings['enum_values'] = {'action_name':{'value':'enumerate registry key values',
                                                               'xsi:type':'maecVocabs:RegistryActionNameVocab-1.0'}, 'xsi:type':'WindowsRegistryKeyObjectType', 'object_association':'input'}

    def __map_hivename(self, hivename):
        if hivename.lower() == 'machine':
            return 'HKEY_LOCAL_MACHINE'
        elif hivename.lower() == 'user':
            return 'HKEY_CURRENT_USER'