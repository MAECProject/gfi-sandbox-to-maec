#GFI Sandbox System Section Handler
#v0.2
import section

class system_section_handler(section.section_handler):
    def __init__(self):
        super(system_section_handler,self).__init__()
        self.__populate_action_mappings()
    
    #Handle the file object oriented attributes
    def handle_object_attributes(self, action, object_attributes, action_attributes, action_mappings):
        global_flag_list = []
        try:
            time = ''
            action_name = action_mappings.get('action_name')
            split_time = action.get_time().split(' ')
            if len(split_time) == 2:
                time = split_time[1]
            elif len(split_time) == 1:
                time = split_time[0]
            if 'system' in action_name['value']:
                object_attributes['properties']['system_time'] = time
            elif 'local' in action_name['value']:
                object_attributes['properties']['local_time'] = time
        except AttributeError:
            pass
        try:
            for global_flag in action.get_global_flags().split(' '):
                global_flag_list.append({'symbolic_name':global_flag})
            object_attributes['properties']['global_flag_list'] = global_flag_list
        except AttributeError:
            pass
        return object_attributes

    #Handle the action specific attributes correctly
    def handle_action_attributes(self, action, object, action_attributes, action_mappings):
        #Populate any action arguments
        action_arguments = []
        try:
            split_flags = action.get_flags.split(' ')
            for flag in split_flags:
                if len(flag) > 0:
                    argument_dict = {}
                    argument_dict['argument_name'] = {'value': 'Shutdown Flag', 'xsi:type': 'cyboxVocabs:ActionArgumentNameVocab-1.0'}
                    argument_dict['argument_value'] = str(flag)
                    action_arguments.append(argument_dict)
        except AttributeError:
            pass
        try:
            sleep_time = action.get_milliseconds()
            if len(str(sleep_time)) > 0:
                argument_dict = {}
                argument_dict['argument_name'] = {'value': 'Sleep Time (ms)', 'xsi:type': 'cyboxVocabs:ActionArgumentNameVocab-1.0'}
                argument_dict['argument_value'] = str(sleep_time)
                action_arguments.append(argument_dict)
        except AttributeError:
            pass
        #Set any action arguments
        action_attributes['action_arguments'] = action_arguments

    #Create the GFI Sandbox -> MAEC/CybOX Action Mappings
    def __populate_action_mappings(self):
         self.action_mappings['shutdown_system'] = {'action_name':{'value':'shutdown system',
                                                                   'xsi:type':'maecVocabs:SystemActionNameVocab-1.0'}, 'xsi:type':'WindowsSystemObjectType', 'object_association':'input'}
         self.action_mappings['sleep'] = {'action_name':{'value':'sleep system',
                                                         'xsi:type':'maecVocabs:SystemActionNameVocab-1.0'}, 'xsi:type':'WindowsSystemObjectType', 'object_association':'input'}
         self.action_mappings['get_computer_name'] = {'action_name':{'value':'get netbios name',
                                                                     'xsi:type':'maecVocabs:SystemActionNameVocab-1.0'}, 'xsi:type':'WindowsSystemObjectType', 'object_association':'output'}
         self.action_mappings['get_system_time'] = {'action_name':{'value':'get system time',
                                                                   'xsi:type':'maecVocabs:SystemActionNameVocab-1.0'}, 'xsi:type':'WindowsSystemObjectType', 'object_association':'output'}
         self.action_mappings['get_local_time'] = {'action_name':{'value':'get system local time',
                                                                   'xsi:type':'maecVocabs:SystemActionNameVocab-1.0'}, 'xsi:type':'WindowsSystemObjectType', 'object_association':'output'}
         self.action_mappings['set_system_time'] = {'action_name':{'value':'set system time',
                                                                   'xsi:type':'maecVocabs:SystemActionNameVocab-1.0'}, 'xsi:type':'WindowsSystemObjectType', 'object_association':'input'}
         self.action_mappings['enumerate_handles'] = {'action_name':{'value':'enumerate system handles',
                                                                     'xsi:type':'maecVocabs:SystemActionNameVocab-1.0'}, 'xsi:type':'WindowsSystemObjectType', 'object_association':'input'}
         self.action_mappings['enumerate_system_modules'] = {'action_name':{'value':'enumerate system modules', 
		                                                                    'xsi:type' : None}, 'xsi:type':'WindowsSystemObjectType', 'object_association':'input'}
         self.action_mappings['check_for_debugger'] = {'action_name':{'value':'check for remote debugger',
                                                                     'xsi:type':'maecVocabs:DebuggingActionNameVocab-1.0'}, 'xsi:type':'WindowsSystemObjectType', 'object_association':'input'} 
         self.action_mappings['check_for_kernel_debugger'] = {'action_name':{'value':'check for kernel debugger',
                                                                             'xsi:type':'maecVocabs:DebuggingActionNameVocab-1.0'}, 'xsi:type':'WindowsSystemObjectType', 'object_association':'input'} 
         self.action_mappings['get_global_flags'] = {'action_name':{'value':'get system global flags',
                                                                    'xsi:type':'maecVocabs:SystemActionNameVocab-1.0'}, 'xsi:type':'WindowsSystemObjectType', 'object_association':'output'}
         self.action_mappings['set_global_flags'] = {'action_name':{'value':'set system global flags',
                                                                    'xsi:type':'maecVocabs:SystemActionNameVocab-1.0'}, 'xsi:type':'WindowsSystemObjectType', 'object_association':'input'}
         #self.action_mappings['debug_control'] = {'action_type':'Set', 'action_name_type':'defined_action_name', 'action_name':'Set System Global Flags', 'object_type':'System', 'object_method':'create_win_system_object', 'object_association':'Utilized'} #TODO: Determine what this means?