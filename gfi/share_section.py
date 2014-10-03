#GFI Sandbox Share Section Handler
#v0.2
import section

class share_section_handler(section.section_handler):

    def __init__(self):
        super(share_section_handler,self).__init__()
        self.__populate_action_mappings()
    
    #Handle the Network Share Object oriented attributes
    def handle_object_attributes(self, action, object_attributes, action_attributes, action_mappings):
        try:
            if action.get_resource():
                object_attributes['properties']['netname'] = action.get_resource()
        except AttributeError:
            pass
        try:
            if action.get_local_filename():
                object_attributes['properties']['local_path'] = action.get_local_filename()
        except AttributeError:
            pass
        return object_attributes

    #Handle the action specific attributes correctly
    def handle_action_attributes(self, action, object, action_attributes, action_mappings):
        try:
          hostname = action.get_server()
          if len(server) > 0:
              argument_dict = {}
              argument_dict['argument_name'] = {'value' : 'Hostname', 'xsi:type' : None}
              argument_dict['argument_value'] = hostname
              action_arguments.append(argument_dict)
        except AttributeError:
             pass

    #Create the GFI Sandbox -> MAEC/CybOX Action Mappings
    def __populate_action_mappings(self):
         self.action_mappings['add_share'] = {'action_name':{'value':'add network share',
                                                             'xsi:type':'maecVocabs:NetworkShareActionNameVocab-1.0'}, 'xsi:type':'WindowsNetworkShareObjectType', 'object_association':'output'}
         self.action_mappings['remove_share'] = {'action_name':{'value':'delete share',
                                                                'xsi:type':'maecVocabs:NetworkShareActionNameVocab-1.0'}, 'xsi:type':'WindowsNetworkShareObjectType', 'object_association':'input'}
         self.action_mappings['enumerate_shares'] = {'action_name':{'value':'enumerate network shares',
                                                                    'xsi:type':'maecVocabs:NetworkShareActionNameVocab-1.0'}, 'xsi:type':'WindowsNetworkShareObjectType', 'object_association':'input'}
         self.action_mappings['connect_to_share'] = {'action_name':{'value':'connect to network share',
                                                                    'xsi:type':'maecVocabs:NetworkShareActionNameVocab-1.0'}, 'xsi:type':'WindowsNetworkShareObjectType', 'object_association':'input'}
         self.action_mappings['disconnect_from_share'] = {'action_name':{'value':'disconnect from network share',
                                                                         'xsi:type':'maecVocabs:NetworkShareActionNameVocab-1.0'}, 'xsi:type':'WindowsNetworkShareObjectType', 'object_association':'input'}