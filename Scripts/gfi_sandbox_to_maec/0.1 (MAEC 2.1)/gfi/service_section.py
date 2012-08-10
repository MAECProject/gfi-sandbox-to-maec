#GFI Sandbox Service Section Handler
#v0.1
import section

class service_section_handler(section.section_handler):
    def __init__(self, maec_object, initiator_id, tool_id):
        super(service_section_handler,self).__init__(initiator_id, tool_id)
        self.maec_object = maec_object
        self.__populate_action_mappings()
    
    #Handle the service object oriented attributes
    def handle_object_attributes(self, action, object_attributes, action_attributes, action_mappings):
        secondary_object_attributes = {}
        try:
            object_attributes['startup_type'] = action.get_start_type()
        except AttributeError:
            pass
        try:
            object_attributes['service_type'] = action.get_service_type()
        except AttributeError:
            pass
        try:
            object_attributes['service_name'] = action.get_service_name()
        except AttributeError:
            pass
        try:
            object_attributes['display_name'] = action.get_display_name()
        except AttributeError:
            pass
        try:
            object_attributes['filename'] = action.get_filename() #TODO - add this to the CybOX object (service and driver)
        except AttributeError:
            pass
        try:
            object_attributes['group_name'] = action.get_group_name() #TODO - add this to the CybOX object
        except AttributeError:
           pass
        try:
            object_attributes['started_as'] = action.get_account_name()
        except AttributeError:
            pass
        try:
            object_attributes['account_password'] = action.get_account_password() #TODO - add this to the CybOX object?
        except AttributeError:
           pass
        try:
            object_attributes['controlcode'] = action.get_control()
        except AttributeError:
           pass
        try:
            secondary_object_attributes['display_name'] = action.get_new_display_name()
        except AttributeError:
           pass
        try:
            secondary_object_attributes['group_name'] = action.get_new_group_name()
        except AttributeError:
           pass
        try:
            secondary_object_attributes['filename'] = action.get_new_filename()
        except AttributeError:
           pass

        #Get the method encoded in the mappings dictionary to create the defined object
        method = action_mappings.get('object_method')

        #Create the state_change effect related objects
        if len(secondary_object_attributes.keys()) > 0:
            effect_attributes = {}
            secondary_object = getattr(self.maec_object,method)(secondary_object_attributes)
            new_defined_object = secondary_object.get_Defined_Object()
            effect_attributes['type'] = 'state change'
            effect_attributes['new_defined_object'] = new_defined_object
            object_attributes['effect'] = effect_attributes

        if method != 'n/a':
            object = getattr(self.maec_object,method)(object_attributes)
            return object
        else:
            return None

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
            service_type = action.get_service_type()
            if len(service_type) > 0:
                argument_dict = {}
                argument_dict['undefined_argument_name'] = 'Service Type'
                argument_dict['argument_value'] = service_type
                action_arguments.append(argument_dict)
        except AttributeError:
            pass
        try:
            service_state = action.get_service_state()
            if len(service_state) > 0:
                argument_dict = {}
                argument_dict['undefined_argument_name'] = 'Service State'
                argument_dict['argument_value'] = service_state
                action_arguments.append(argument_dict)
        except AttributeError:
            pass
        try:
            group_name = action.get_group_name()
            if len(group_name) > 0:
                argument_dict = {}
                argument_dict['undefined_argument_name'] = 'Group Name'
                argument_dict['argument_value'] = group_name
                action_arguments.append(argument_dict)
        except AttributeError:
            pass
        #Set any action arguments
        action_attributes['action_arguments'] = action_arguments
        #Set the action context
        action_attributes['context'] = 'Host'

    #Create the GFI Sandbox -> MAEC/CybOX Action Mappings
    def __populate_action_mappings(self):
         self.action_mappings['enumerate_services'] = {'action_type':'Enumerate', 'action_name_type':'defined_action_name', 'action_name':'Enumerate Services', 'object_type':'Service', 'object_method':'n/a', 'object_association':'Affected'}
         self.action_mappings['open_service'] = {'action_type':'Open', 'action_name_type':'defined_action_name', 'action_name':'Open Service', 'object_type':'Service', 'object_method':'create_win_service_object', 'object_association':'Utilized'}
         self.action_mappings['create_service'] = {'action_type':'Create', 'action_name_type':'defined_action_name', 'action_name':'Create Service', 'object_type':'Service', 'object_method':'create_win_service_object', 'object_association':'Affected'}
         self.action_mappings['remove_service'] = {'action_type':'Remove/Delete', 'action_name_type':'defined_action_name', 'action_name':'Delete Service', 'object_type':'Service', 'object_method':'create_win_service_object', 'object_association':'Affected'}
         self.action_mappings['start_service'] = {'action_type':'Start', 'action_name_type':'defined_action_name', 'action_name':'Start Service', 'object_type':'Service', 'object_method':'create_win_service_object', 'object_association':'Affected'}
         self.action_mappings['config_service'] = {'action_type':'Configure', 'action_name_type':'defined_action_name', 'action_name':'Configure Service', 'object_type':'Service', 'object_method':'create_win_service_object', 'object_association':'Affected'}
         self.action_mappings['control_driver'] = {'action_type':'Control', 'action_name_type':'defined_action_name', 'action_name':'Send Control Code to Service', 'object_type':'Service', 'object_method':'create_win_service_object', 'object_association':'Affected'}
         self.action_mappings['load_driver'] = {'action_type':'Load', 'action_name_type':'defined_action_name', 'action_name':'Load Driver', 'object_type':'Other', 'object_method':'create_win_driver_object', 'object_association':'Affected'}
         self.action_mappings['unload_driver'] = {'action_type':'Load', 'action_name_type':'defined_action_name', 'action_name':'Unload Driver', 'object_type':'Other', 'object_method':'create_win_driver_object', 'object_association':'Affected'}
         self.action_mappings['load_and_call_driver'] = {'action_type':'Load', 'action_name_type':'undefined_action_name', 'action_name':'Load and Call Driver', 'object_type':'Other', 'object_method':'create_win_driver_object', 'object_association':'Affected'}