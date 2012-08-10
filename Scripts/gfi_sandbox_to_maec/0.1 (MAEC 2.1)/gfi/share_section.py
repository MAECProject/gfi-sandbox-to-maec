#GFI Sandbox Share Section Handler
#v0.1
import section

class share_section_handler(section.section_handler):

    def __init__(self, maec_object, initiator_id, tool_id):
        super(share_section_handler,self).__init__(initiator_id, tool_id)
        self.maec_object = maec_object
        self.__populate_action_mappings()
    
    #Handle the file object oriented attributes
    def handle_object_attributes(self, action, object_attributes, action_attributes, action_mappings):
        try:
            object_attributes['netname'] = action.get_resource()
        except AttributeError:
            pass
        try:
            object_attributes['local_path'] = action.get_local_filename()
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
        try:
          hostname = action.get_server()
          if len(server) > 0:
              argument_dict = {}
              argument_dict['undefined_argument_name'] = 'Hostname'
              argument_dict['argument_value'] = hostname
              action_arguments.append(argument_dict)
        except AttributeError:
             pass
        #Set the action context
        action_attributes['context'] = 'Host'

    #Create the GFI Sandbox -> MAEC/CybOX Action Mappings
    def __populate_action_mappings(self):
         self.action_mappings['add_share'] = {'action_type':'Create', 'action_name_type':'undefined_action_name', 'action_name':'Add Network Share', 'object_type':'Other', 'object_method':'create_win_network_share_object', 'object_association':'Affected'}
         self.action_mappings['remove_share'] = {'action_type':'Remove/Delete', 'action_name_type':'undefined_action_name', 'action_name':'Remove Network Share', 'object_type':'Other', 'object_method':'create_win_network_share_object', 'object_association':'Affected'}
         self.action_mappings['enumerate_shares'] = {'action_type':'Enumerate', 'action_name_type':'undefined_action_name', 'action_name':'Enumerate Network Shares', 'object_type':'Other', 'object_method':'n/a', 'object_association':'Affected'}
         self.action_mappings['connect_to_share'] = {'action_type':'Connect', 'action_name_type':'undefined_action_name', 'action_name':'Connect to Network Share', 'object_type':'Other', 'object_method':'create_win_network_share_object', 'object_association':'Utilized'}
         self.action_mappings['disconnect_from_share'] = {'action_type':'Disconnect', 'action_name_type':'undefined_action_name', 'action_name':'Disconnect from Network Share', 'object_type':'Other', 'object_method':'create_win_network_share_object', 'object_association':'Utilized'}