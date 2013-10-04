#GFI Sandbox User Section Handler
#v0.2
import section

class user_section_handler(section.section_handler):

    def __init__(self):
        super(user_section_handler,self).__init__()
        self.__populate_action_mappings()
    
    #Handle the User Account Object oriented attributes
    def handle_object_attributes(self, action, object_attributes, action_attributes, action_mappings):
        try:
            if action.get_username():
                object_attributes['properties']['username'] = action.get_username()
        except AttributeError:
            pass
        try:
            if action.get_domain():
                object_attributes['properties']['custom_properties'] = [{'name':'Domain', 'value':action.get_domain()}]
        except AttributeError:
            pass
        return object_attributes

    #Handle the action specific attributes correctly
    def handle_action_attributes(self, action, object, action_attributes, action_mappings):
        try:
          server = action.get_server()
          if len(server) > 0:
              argument_dict = {}
              argument_dict['argument_name'] = {'value': 'Server', 'xsi:type':'cyboxVocabs:ActionArgumentNameVocab-1.0'}
              argument_dict['argument_value'] = server
              action_arguments.append(argument_dict)
        except AttributeError:
             pass

    #Create the GFI Sandbox -> MAEC/CybOX Action Mappings
    def __populate_action_mappings(self):
         self.action_mappings['logon_as_user'] = {'action_name':{'value':'logon as user',
                                                                 'xsi:type':'maecVocabs:UserActionNameVocab-1.0'}, 'xsi:type':'WindowsUserAccountObjectType', 'object_association':'input'}
         self.action_mappings['add_user'] = {'action_name':{'value':'add user',
                                                            'xsi:type':'maecVocabs:UserActionNameVocab-1.0'}, 'xsi:type':'WindowsUserAccountObjectType', 'object_association':'output'}
         self.action_mappings['remove_user'] = {'action_name':{'value':'delete user',
                                                               'xsi:type':'maecVocabs:UserActionNameVocab-1.0'}, 'xsi:type':'WindowsUserAccountObjectType', 'object_association':'input'}
         self.action_mappings['enumerate_users'] = {'action_name':{'value':'enumerate users',
                                                                   'xsi:type':'maecVocabs:UserActionNameVocab-1.0'}, 'xsi:type':'WindowsUserAccountObjectType', 'object_association':'input'}
         self.action_mappings['get_username'] = {'action_name':{'value':'get username'}, 'xsi:type':'WindowsUserAccountObjectType', 'object_association':'input'}
         self.action_mappings['get_user_info'] = {'action_name':{'value':'get user attributes',
                                                                 'xsi:type':'maecVocabs:UserActionNameVocab-1.0'}, 'xsi:type':'WindowsUserAccountObjectType', 'object_association':'input'}