#GFI Sandbox System Section Handler
#v0.1
import section

class system_section_handler(section.section_handler):
    def __init__(self, maec_object, initiator_id, tool_id):
        super(system_section_handler,self).__init__(initiator_id, tool_id)
        self.maec_object = maec_object
        self.__populate_action_mappings()
    
    #Handle the file object oriented attributes
    def handle_object_attributes(self, action, object_attributes, action_attributes, action_mappings):
        try:
            time = ''
            action_name = action_mappings.get('action_name')
            split_time = action.get_time().split(' ')
            if len(split_time) == 2:
                time = split_time[1]
            elif len(split_time) == 1:
                time = split_time[0]
            if 'System' in action_name:
                object_attributes['system_time'] = time
            elif 'Local' in action_name:
                object_attributes['local_time'] = time
        except AttributeError:
            pass
        try:
            object_attributes['global_flags'] = action.get_global_flags().split(' ')
        except AttributeError:
            pass
        #Get the method encoded in the mappings dictionary to create the defined object
        method = action_mappings.get('object_method')
        if method != 'n/a':
            #Create and return the object
            object = getattr(self.maec_object,method)(object_attributes)
            return object
        else:
            return None

    #Handle the action specific attributes correctly
    def handle_action_attributes(self, action, object, action_attributes, action_mappings):
        #Populate any action arguments
        action_arguments = []
        try:
            split_flags = action.get_flags.split(' ')
            for flag in split_flags:
                if len(flag) > 0:
                    argument_dict = {}
                    argument_dict['undefined_argument_name'] = 'Shutdown Flag'
                    argument_dict['argument_value'] = flag
                    action_arguments.append(argument_dict)
        except AttributeError:
            pass
        try:
            sleep_time = action.get_milliseconds()
            if len(str(sleep_time)) > 0:
                argument_dict = {}
                argument_dict['undefined_argument_name'] = 'Sleep Time (ms)'
                argument_dict['argument_value'] = sleep_time
                action_arguments.append(argument_dict)
        except AttributeError:
            pass
        #Set any action arguments
        action_attributes['action_arguments'] = action_arguments
        #Set the action context
        action_attributes['context'] = 'Host'

    #Create the GFI Sandbox -> MAEC/CybOX Action Mappings
    def __populate_action_mappings(self):
         self.action_mappings['shutdown_system'] = {'action_type':'Stop', 'action_name_type':'undefined_action_name', 'action_name':'Shutdown System', 'object_type':'System', 'object_method':'n/a', 'object_association':'Affected'}
         self.action_mappings['sleep'] = {'action_type':'Suspend', 'action_name_type':'undefined_action_name', 'action_name':'Sleep System', 'object_type':'System', 'object_method':'n/a', 'object_association':'Affected'}
         self.action_mappings['get_computer_name'] = {'action_type':'Get', 'action_name_type':'undefined_action_name', 'action_name':'Get System NetBIOS Name', 'object_type':'System', 'object_method':'n/a', 'object_association':'Utilized'}
         self.action_mappings['get_system_time'] = {'action_type':'Get', 'action_name_type':'defined_action_name', 'action_name':'Get System Time', 'object_type':'System', 'object_method':'create_win_system_object', 'object_association':'Utilized'}
         self.action_mappings['get_local_time'] = {'action_type':'Get', 'action_name_type':'undefined_action_name', 'action_name':'Get System Local Time', 'object_type':'System', 'object_method':'create_win_system_object', 'object_association':'Utilized'}
         self.action_mappings['set_system_time'] = {'action_type':'Set', 'action_name_type':'defined_action_name', 'action_name':'Set System Time', 'object_type':'System', 'object_method':'create_win_system_object', 'object_association':'Affected'}
         self.action_mappings['enumerate_handles'] = {'action_type':'Enumerate', 'action_name_type':'undefined_action_name', 'action_name':'Enumerate System Handles', 'object_type':'System', 'object_method':'n/a', 'object_association':'Utilized'}
         self.action_mappings['enumerate_system_modules'] = {'action_type':'Enumerate', 'action_name_type':'undefined_action_name', 'action_name':'Enumerate System Modules', 'object_type':'System', 'object_method':'n/a', 'object_association':'Utilized'}
         #self.action_mappings['check_for_debugger'] = {'action_type':'Enumerate', 'action_name_type':'undefined_action_name', 'action_name':'Enumerate System Modules', 'object_type':'System', 'object_method':'create_win_system_object', 'object_association':'Affected'} #Behavior?
         #self.action_mappings['check_for_kernel_debugger'] = {'action_type':'Enumerate', 'action_name_type':'undefined_action_name', 'action_name':'Enumerate System Modules', 'object_type':'System', 'object_method':'create_win_system_object', 'object_association':'Affected'} #Behavior?
         self.action_mappings['get_global_flags'] = {'action_type':'Get', 'action_name_type':'defined_action_name', 'action_name':'Get System Global Flags', 'object_type':'System', 'object_method':'create_win_system_object', 'object_association':'Utilized'}
         self.action_mappings['set_global_flags'] = {'action_type':'Set', 'action_name_type':'defined_action_name', 'action_name':'Set System Global Flags', 'object_type':'System', 'object_method':'create_win_system_object', 'object_association':'Utilized'}
         #self.action_mappings['debug_control'] = {'action_type':'Set', 'action_name_type':'defined_action_name', 'action_name':'Set System Global Flags', 'object_type':'System', 'object_method':'create_win_system_object', 'object_association':'Utilized'} 