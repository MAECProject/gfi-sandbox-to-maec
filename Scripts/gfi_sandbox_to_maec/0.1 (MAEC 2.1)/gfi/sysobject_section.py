#GFI Sandbox System Object Section Handler
#v0.1
import section

class sysobject_section_handler(section.section_handler):
    def __init__(self, maec_object, initiator_id, tool_id):
        super(sysobject_section_handler,self).__init__(initiator_id, tool_id)
        self.maec_object = maec_object
        self.__populate_action_mappings()
    
    #Handle the file object oriented attributes
    def handle_object_attributes(self, action, object_attributes, action_attributes, action_mappings):
        try:
            object_attributes['name'] = action.get_name()
        except AttributeError:
            pass
        try:
            object_attributes['servername'] = action.get_task_servername()
        except AttributeError:
            pass
        try:
            object_attributes['command'] = action.get_task_command()
        except AttributeError:
            pass
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
            split_access_mode = action.get_desired_access().split(' ')
            for access_mode in split_access_mode:
                if len(access_mode) > 0:
                    argument_dict = {}
                    argument_dict['defined_argument_name'] = 'Access Mode'
                    argument_dict['argument_value'] = access_mode
                    action_arguments.append(argument_dict)
        except AttributeError:
            pass
        #Set any action arguments
        action_attributes['action_arguments'] = action_arguments
        #Set the action context
        action_attributes['context'] = 'Host'

    #Create the GFI Sandbox -> MAEC/CybOX Action Mappings
    def __populate_action_mappings(self):
         self.action_mappings['create_mutex'] = {'action_type':'Create', 'action_name_type':'defined_action_name', 'action_name':'Create Mutex', 'object_type':'Mutex', 'object_method':'create_mutex_object', 'object_association':'Affected'}
         self.action_mappings['open_mutex'] = {'action_type':'Open', 'action_name_type':'defined_action_name', 'action_name':'Open Mutex', 'object_type':'Mutex', 'object_method':'create_mutex_object', 'object_association':'Utilized'}
         self.action_mappings['add_scheduled_task'] = {'action_type':'Add', 'action_name_type':'defined_action_name', 'action_name':'Add Scheduled Task', 'object_type':'Mutex', 'object_method':'create_win_scheduled_task_object', 'object_association':'Affected'}
