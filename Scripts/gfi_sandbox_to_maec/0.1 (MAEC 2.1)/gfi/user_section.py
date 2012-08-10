#GFI Sandbox User Section Handler
#v0.1
import section

class user_section_handler(section.section_handler):

    def __init__(self, maec_object, initiator_id, tool_id):
        super(user_section_handler,self).__init__(initiator_id, tool_id)
        self.maec_object = maec_object
        self.__populate_action_mappings()
    
    #Handle the file object oriented attributes
    def handle_object_attributes(self, action, object_attributes, action_attributes, action_mappings):
        try:
            object_attributes['username'] = action.get_username()
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
          server = action.get_server()
          if len(server) > 0:
              argument_dict = {}
              argument_dict['undefined_argument_name'] = 'Server'
              argument_dict['argument_value'] = server
              action_arguments.append(argument_dict)
        except AttributeError:
             pass
        #Set the action context
        action_attributes['context'] = 'Host'

    #Create the GFI Sandbox -> MAEC/CybOX Action Mappings
    def __populate_action_mappings(self):
         self.action_mappings['logon_as_user'] = {'action_type':'Login/Logon', 'action_name_type':'undefined_action_name', 'action_name':'Logon as User', 'object_type':'Other', 'object_method':'create_win_user_object', 'object_association':'Affected'}
         self.action_mappings['add_user'] = {'action_type':'Add', 'action_name_type':'undefined_action_name', 'action_name':'Add User', 'object_type':'Other', 'object_method':'create_win_user_object', 'object_association':'Affected'}
         self.action_mappings['remove_user'] = {'action_type':'Remove/Delete', 'action_name_type':'undefined_action_name', 'action_name':'Remove User', 'object_type':'Other', 'object_method':'create_win_user_object', 'object_association':'Affected'}
         self.action_mappings['enumerate_users'] = {'action_type':'Enumerate', 'action_name_type':'undefined_action_name', 'action_name':'Enumerate Users', 'object_type':'Other', 'object_method':'n/a', 'object_association':'Affected'}
         self.action_mappings['get_username'] = {'action_type':'Get', 'action_name_type':'undefined_action_name', 'action_name':'Get Username', 'object_type':'Other', 'object_method':'n/a', 'object_association':'Affected'}
         self.action_mappings['get_user_info'] = {'action_type':'Get', 'action_name_type':'undefined_action_name', 'action_name':'Get User Info', 'object_type':'Other', 'object_method':'create_win_user_object', 'object_association':'Utilized'}