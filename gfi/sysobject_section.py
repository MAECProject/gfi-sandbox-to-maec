#GFI Sandbox System Object Section Handler
#v0.2
import section

class sysobject_section_handler(section.section_handler):
    def __init__(self):
        super(sysobject_section_handler,self).__init__()
        self.__populate_action_mappings()
    
    #Handle the Network Share Object oriented attributes
    def handle_object_attributes(self, action, object_attributes, action_attributes, action_mappings):
        try:
            if action.get_name():
                object_attributes['properties']['name'] = action.get_name()
        except AttributeError:
            pass
        try:
            if action.get_task_servername():
                object_attributes['properties']['servername'] = action.get_task_servername()
        except AttributeError:
            pass
        try:
            lock_held = str(action.get_lock_held())
            if len(lock_held) > 0:
                object_attributes['properties']['custom_properties'] = [{'name':'Lock Held', 'value':str(action.get_lock_held())}]
        except AttributeError:
            pass
        try:
            if action.get_task_command():
                object_attributes['properties']['parameters'] = action.get_task_command() #Not 100% sure about this mapping
        except AttributeError:
            pass
        return object_attributes

    #Handle the action specific attributes correctly
    def handle_action_attributes(self, action, object, action_attributes, action_mappings):
        #Populate any action arguments
        action_arguments = []
        try:
            split_access_mode = action.get_desired_access().split(' ')
            for access_mode in split_access_mode:
                if len(access_mode) > 0:
                    argument_dict = {}
                    argument_dict['argument_name'] = {'value': 'Access Mode', 'xsi:type': 'cyboxVocabs:ActionArgumentNameVocab-1.0'}
                    argument_dict['argument_value'] = access_mode
                    action_arguments.append(argument_dict)
        except AttributeError:
            pass
        #Set any action arguments
        action_attributes['action_arguments'] = action_arguments

    #Create the GFI Sandbox -> MAEC/CybOX Action Mappings
    def __populate_action_mappings(self):
         self.action_mappings['create_mutex'] = {'action_name':{'value':'create mutex',
                                                                'xsi:type':'maecVocabs:SynchronizationActionNameVocab-1.0'}, 'xsi:type':'WindowsMutexObjectType', 'object_association':'output'}
         self.action_mappings['open_mutex'] = {'action_name':{'value':'open mutex',
                                                              'xsi:type':'maecVocabs:SynchronizationActionNameVocab-1.0'}, 'xsi:type':'WindowsMutexObjectType', 'object_association':'input'}
         self.action_mappings['add_scheduled_task'] = {'action_name':{'value':'add scheduled task',
                                                                      'xsi:type':'maecVocabs:SystemActionNameVocab-1.0'}, 'xsi:type':'WindowsTaskObjectType', 'object_association':'output'}
