#GFI Sandbox Thread Section Handler
#v0.1
import section

class thread_section_handler(section.section_handler):

    def __init__(self, maec_object, initiator_id, tool_id):
        super(thread_section_handler,self).__init__(initiator_id, tool_id)
        self.maec_object = maec_object
        self.__populate_action_mappings()
    
    #Handle the file object oriented attributes
    def handle_object_attributes(self, action, object_attributes, action_attributes, action_mappings):
        process_object_attributes = {}
        process_object_attributes['pid'] = action.get_target_pid()
        process_object_attributes['association'] = action_mappings.get('object_association')
        try:
            object_attributes['tid'] = action.get_target_tid()
        except AttributeError:
            pass
        #Create the process object that contains the thread
        process_object = self.maec_object.create_win_process_object(process_object_attributes)
        #Add the process object to the action attributes
        action_attributes['object_old'] = process_object
        #Get the method encoded in the mappings dictionary to create the defined object
        method = action_mappings.get('object_method')
        #Create and return the object
        object = getattr(self.maec_object,method)(object_attributes)
        return object

    #Handle the action specific attributes correctly
    def handle_action_attributes(self, action, object, action_attributes, action_mappings):
        #Populate any action arguments
        action_arguments = []
        try:
            code_address = action.get_code_address()
            argument_dict = {}
            argument_dict['undefined_argument_name'] = 'Code Address'
            argument_dict['argument_value'] = code_address
            action_arguments.append(argument_dict)
        except AttributeError:
            pass
        try:
            parameter_address = action.get_parameter_address()
            argument_dict = {}
            argument_dict['undefined_argument_name'] = 'Parameter Address'
            argument_dict['argument_value'] = parameter_address
            action_arguments.append(argument_dict)
        except AttributeError:
            pass
        #Set any action arguments
        action_attributes['action_arguments'] = action_arguments
        #Set the action context
        action_attributes['context'] = 'Host'

    #Create the GFI Sandbox -> MAEC/CybOX Action Mappings
    def __populate_action_mappings(self):
         self.action_mappings['create_thread'] = {'action_type':'Create', 'action_name_type':'defined_action_name', 'action_name':'Create Thread', 'object_type':'Thread', 'object_method':'create_win_thread_object', 'object_association':'Affected'}
         self.action_mappings['kill_thread'] = {'action_type':'Kill', 'action_name_type':'defined_action_name', 'action_name':'Kill Thread', 'object_type':'Thread', 'object_method':'create_win_thread_object', 'object_association':'Affected'}
         self.action_mappings['get_thread_context'] = {'action_type':'Get', 'action_name_type':'defined_action_name', 'action_name':'Get Thread Context', 'object_type':'Thread', 'object_method':'create_win_thread_object', 'object_association':'Utilized'}
         self.action_mappings['set_thread_context'] = {'action_type':'Set', 'action_name_type':'defined_action_name', 'action_name':'Set Thread Context', 'object_type':'Thread', 'object_method':'create_win_thread_object', 'object_association':'Affected'}
         self.action_mappings['queue_user_apc'] = {'action_type':'Queue', 'action_name_type':'defined_action_name', 'action_name':'Queue APC in Thread', 'object_type':'Thread', 'object_method':'create_win_thread_object', 'object_association':'Affected'}
         self.action_mappings['enumerate_threads'] = {'action_type':'Enumerate', 'action_name_type':'defined_action_name', 'action_name':'Enumerate Threads', 'object_type':'Thread', 'object_method':'create_win_thread_object', 'object_association':'Utilized'}
         self.action_mappings['impersonate_thread'] = {'action_type':'Impersonate', 'action_name_type':'undefined_action_name', 'action_name':'Impersonate Thread', 'object_type':'Thread', 'object_method':'create_win_thread_object', 'object_association':'Utilized'}
         self.action_mappings['revert_thread_to_self'] = {'action_type':'Restore', 'action_name_type':'undefined_action_name', 'action_name':'Revert Thread to Self', 'object_type':'Thread', 'object_method':'create_win_thread_object', 'object_association':'Affected'}
         self.action_mappings['hide_from_debugger'] = {'action_type':'Hide', 'action_name_type':'undefined_action_name', 'action_name':'Hide From Debugger', 'object_type':'Thread', 'object_method':'create_win_thread_object', 'object_association':'Affected'}