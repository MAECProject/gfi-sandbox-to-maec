#GFI Sandbox Service Section Handler
#v0.1
import section

class service_section_handler(section.section_handler):
    def __init__(self, generator):
        super(service_section_handler,self).__init__()
        self.generator = generator
        self.__populate_action_mappings()
    
    #Handle the service object oriented attributes
    def handle_object_attributes(self, action, object_attributes, action_attributes, action_mappings):
        secondary_object_attributes = {'id':self.generator.generate_object_id()}
        secondary_object_attributes['properties'] = {}
        secondary_object_attributes['properties']['xsi:type'] = action_mappings['xsi:type']
        secondary_object_attributes['association_type'] = {'value':'output', 'xsi:type':'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}

        image_info_dict = {}
        secondary_image_info_dict = {}
        try:
            object_attributes['properties']['startup_type'] = action.get_start_type()
        except AttributeError:
            pass
        try:
            object_attributes['properties']['service_type'] = action.get_service_type()
        except AttributeError:
            pass
        try:
            object_attributes['properties']['service_name'] = action.get_service_name()
        except AttributeError:
            pass
        try:
            object_attributes['properties']['display_name'] = action.get_display_name()
        except AttributeError:
            pass
        try:
            if action.get_filename():
                image_info_dict['file_name'] = action.get_filename()
                #Corner case for Driver Objects
                object_attributes['properties']['driver_name'] = action.get_filename() 
        except AttributeError:
            pass
        try:
            if action.get_group_name():
                object_attributes['properties']['group_name'] = action.get_group_name() 
        except AttributeError:
           pass
        try:
            object_attributes['properties']['started_as'] = action.get_account_name()
        except AttributeError:
            pass
        try:
            object_attributes['properties']['account_password'] = action.get_account_password() #TODO - add this to the CybOX object?
        except AttributeError:
           pass
        try:
            object_attributes['properties']['controlcode'] = action.get_control()
        except AttributeError:
           pass
        try:
            secondary_object_attributes['properties']['display_name'] = action.get_new_display_name()
        except AttributeError:
           pass
        try:
            if action.get_new_group_name():
                secondary_object_attributes['properties']['group_name'] = action.get_new_group_name()
        except AttributeError:
           pass
        try:
            if action.get_new_filename():
                secondary_image_info_dict['filename'] = action.get_new_filename()
        except AttributeError:
           pass

        if image_info_dict.keys():
            object_attributes['properties']['image_info'] = image_info_dict

        #Create the secondary object, if applicable
        if len(secondary_object_attributes['properties'].keys()) > 2:
            if secondary_image_info_dict.keys():
                secondary_object_attributes['properties']['image_info'] = secondary_image_info_dict
            return [object_attributes, secondary_object_attributes]

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
            controlcode = action.get_control()
            argument_dict = {}
            argument_dict['argument_name'] = {'value': 'Control Code', 'xsi:type': 'cyboxVocabs:ActionArgumentNameVocab-1.0'}
            argument_dict['argument_value'] = controlcode
            action_arguments.append(argument_dict)
        except AttributeError:
            pass
        #Set any action arguments
        action_attributes['action_arguments'] = action_arguments

    #Create the GFI Sandbox -> MAEC/CybOX Action Mappings
    def __populate_action_mappings(self):
         self.action_mappings['enumerate_services'] = {'action_name':{'value':'enumerate services',
                                                                      'xsi:type':'maecVocabs:ServiceActionNameVocab-1.0'}, 'xsi:type':'WindowsServiceObjectType', 'object_association':'input'}
         self.action_mappings['open_service'] = {'action_name':{'value':'open service',
                                                                'xsi:type':'maecVocabs:ServiceActionNameVocab-1.0'}, 'xsi:type':'WindowsServiceObjectType', 'object_association':'input'}
         self.action_mappings['create_service'] = {'action_name':{'value':'create service',
                                                                  'xsi:type':'maecVocabs:ServiceActionNameVocab-1.0'}, 'xsi:type':'WindowsServiceObjectType', 'object_association':'output'}
         self.action_mappings['remove_service'] = {'action_name':{'value':'delete service',
                                                                  'xsi:type':'maecVocabs:ServiceActionNameVocab-1.0'}, 'xsi:type':'WindowsServiceObjectType', 'object_association':'input'}
         self.action_mappings['start_service'] = {'action_name':{'value':'start service',
                                                                 'xsi:type':'maecVocabs:ServiceActionNameVocab-1.0'}, 'xsi:type':'WindowsServiceObjectType', 'object_association':'input'}
         self.action_mappings['config_service'] = {'action_name':{'value':'modify service configuration',
                                                                  'xsi:type':'maecVocabs:ServiceActionNameVocab-1.0'}, 'xsi:type':'WindowsServiceObjectType', 'object_association':'input'}
         self.action_mappings['control_driver'] = {'action_name':{'value':'send control code to service',
                                                                  'xsi:type':'maecVocabs:ServiceActionNameVocab-1.0'}, 'xsi:type':'WindowsServiceObjectType', 'object_association':'input'}
         self.action_mappings['load_driver'] = {'action_name':{'value':'load driver',
                                                               'xsi:type':'maecVocabs:DeviceDriverActionNameVocab-1.0'}, 'xsi:type':'WindowsDriverObjectType', 'object_association':'input'}
         self.action_mappings['unload_driver'] = {'action_name':{'value':'unload driver',
                                                                 'xsi:type':'maecVocabs:DeviceDriverActionNameVocab-1.0'}, 'xsi:type':'WindowsDriverObjectType', 'object_association':'input'}
         self.action_mappings['load_and_call_driver'] = {'action_name':{'value':'load and call driver',
                                                                        'xsi:type':'maecVocabs:DeviceDriverActionNameVocab-1.0'}, 'xsi:type':'WindowsDriverObjectType', 'object_association':'input'}