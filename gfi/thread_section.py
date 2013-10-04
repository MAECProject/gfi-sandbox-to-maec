#GFI Sandbox Thread Section Handler
#v0.2
import section

class thread_section_handler(section.section_handler):

    def __init__(self, generator):
        super(thread_section_handler,self).__init__()
        self.generator = generator
        self.__populate_action_mappings()
    
    #Handle the file object oriented attributes
    def handle_object_attributes(self, action, object_attributes, action_attributes, action_mappings):
        process_object_attributes = {}
        if action.get_target_pid() and str(action.get_target_pid()) is not '0':
            process_object_attributes = {'id' : self.generator.generate_object_id()}
            process_object_attributes['properties'] = {}
            process_object_attributes['properties']['pid'] = action.get_target_pid()
            process_object_attributes['properties']['xsi:type'] = 'WindowsProcessObjectType'
            process_object_attributes['association_type'] = {}
            process_object_attributes['association_type']['value'] = 'input'
            process_object_attributes['association_type']['xsi:type'] = 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'
        try:
            if action.get_target_tid():
                object_attributes['properties']['thread_id'] = action.get_target_tid()
        except AttributeError:
            pass
        try:
            if action.get_token_sid():
                object_attributes['properties']['security_attributes'] = action.get_token_sid()
        except AttributeError:
            pass
        if process_object_attributes:
            return [object_attributes, process_object_attributes]
        else:
            return object_attributes

    #Handle the action specific attributes correctly
    def handle_action_attributes(self, action, object, action_attributes, action_mappings):
        #Populate any action arguments
        action_arguments = []
        try:
            code_address = action.get_code_address()
            argument_dict = {}
            argument_dict['argument_name'] = {'value': 'Code Address', 'xsi:type': 'cyboxVocabs:ActionArgumentNameVocab-1.0'}
            argument_dict['argument_value'] = code_address
            action_arguments.append(argument_dict)
        except AttributeError:
            pass
        try:
            parameter_address = action.get_parameter_address()
            argument_dict = {}
            argument_dict['argument_name'] = {'value': 'Parameter Address', 'xsi:type': 'cyboxVocabs:ActionArgumentNameVocab-1.0'}
            argument_dict['argument_value'] = parameter_address
            action_arguments.append(argument_dict)
        except AttributeError:
            pass
        #Set any action arguments
        action_attributes['action_arguments'] = action_arguments

    #Create the GFI Sandbox -> MAEC/CybOX Action Mappings
    def __populate_action_mappings(self):
         self.action_mappings['create_thread'] = {'action_name':{'value':'create thread',
                                                                 'xsi:type':'maecVocabs:ProcessThreadActionNameVocab-1.0'}, 'xsi:type':'WindowsThreadObjectType', 'object_association':'output'}
         self.action_mappings['kill_thread'] = {'action_name':{'value':'kill thread',
                                                               'xsi:type':'maecVocabs:ProcessThreadActionNameVocab-1.0'}, 'xsi:type':'WindowsThreadObjectType', 'object_association':'input'}
         self.action_mappings['get_thread_context'] = {'action_name':{'value':'get thread context',
                                                                      'xsi:type':'maecVocabs:ProcessThreadActionNameVocab-1.0'}, 'xsi:type':'WindowsThreadObjectType', 'object_association':'input'}
         self.action_mappings['set_thread_context'] = {'action_name':{'value':'set thread context',
                                                                      'xsi:type':'maecVocabs:ProcessThreadActionNameVocab-1.0'}, 'xsi:type':'WindowsThreadObjectType', 'object_association':'input'}
         self.action_mappings['queue_user_apc'] = {'action_name':{'value':'queue apc in thread',
                                                                  'xsi:type':'maecVocabs:ProcessThreadActionNameVocab-1.0'}, 'xsi:type':'WindowsThreadObjectType', 'object_association':'input'}
         self.action_mappings['enumerate_threads'] = {'action_name':{'value':'enumerate threads',
                                                                     'xsi:type':'maecVocabs:ProcessThreadActionNameVocab-1.0'}, 'xsi:type':'WindowsThreadObjectType', 'object_association':'input'}
         self.action_mappings['impersonate_thread'] = {'action_name':{'value':'impersonate thread'}, 'xsi:type':'WindowsThreadObjectType', 'object_association':'input'}
         self.action_mappings['revert_thread_to_self'] = {'action_name':{'value':'revert thread to self',
                                                                         'xsi:type':'maecVocabs:ProcessThreadActionNameVocab-1.0'}, 'xsi:type':'WindowsThreadObjectType', 'object_association':'input'}
         self.action_mappings['hide_from_debugger'] = {'action_name':{'value':'hide thread from debugger'}, 'xsi:type':'WindowsThreadObjectType', 'object_association':'input'}