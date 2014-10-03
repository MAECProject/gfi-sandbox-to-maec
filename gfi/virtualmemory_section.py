#GFI Sandbox Virtual Memory Section Handler
#v0.2
import section

class virtualmemory_section_handler(section.section_handler):

    def __init__(self):
        super(virtualmemory_section_handler,self).__init__()
        self.__populate_action_mappings()
    
    #Handle the file object oriented attributes
    def handle_object_attributes(self, action, object_attributes, action_attributes, action_mappings):
        object_attributes['properties']['pid'] = action.get_target_pid()
        #Handle the virtual memory object attributes
        section_dict = {}
        try:
            section_dict['region_size'] = action.get_size()
        except AttributeError:
            pass
        try:
            address = action.get_address().lstrip('0x')
            if len(address) % 2 == 1:
                address = '0' + address
            section_dict['region_start_address'] = address
        except AttributeError:
            pass
        if section_dict:
            object_attributes['properties']['section_list'] = [section_dict]
        return object_attributes

    #Handle the action specific attributes correctly
    def handle_action_attributes(self, action, object, action_attributes, action_mappings):
        #Populate any action arguments
        action_arguments = []
        try:
            allocation_type = action.get_allocation_type()
            if allocation_type:
                argument_dict = {}
                argument_dict['argument_name'] = {'value': 'Allocation Type', 'xsi:type' : None}
                argument_dict['argument_value'] = allocation_type
                action_arguments.append(argument_dict)
        except AttributeError:
            pass
        try:
            protection = action.get_protection()
            if protection:
                argument_dict = {}
                argument_dict['argument_name'] = {'value': 'Protection', 'xsi:type':'cyboxVocabs:ActionArgumentNameVocab-1.0'}
                argument_dict['argument_value'] = protection
                action_arguments.append(argument_dict)
        except AttributeError:
            pass
        try:
            wanted_address = action.get_wanted_address()
            if wanted_address:
                argument_dict = {}
                argument_dict['argument_name'] = {'value': 'Wanted Address', 'xsi:type' : None}
                argument_dict['argument_value'] = wanted_address
                action_arguments.append(argument_dict)
        except AttributeError:
            pass
        try:
            wanted_size = action.get_wanted_size()
            if wanted_size:
                argument_dict = {}
                argument_dict['argument_name'] = {'value': 'Wanted Size', 'xsi:type' : None}
                argument_dict['argument_value'] = wanted_size
                action_arguments.append(argument_dict)
        except AttributeError:
            pass
        try:
            wanted_target_address = action.get_wanted_address_target()
            if wanted_target_address:
                argument_dict = {}
                argument_dict['argument_name'] = {'value': 'Wanted Target Address', 'xsi:type' : None}
                argument_dict['argument_value'] = wanted_target_address
                action_arguments.append(argument_dict)
        except AttributeError:
            pass
        action_attributes['action_arguments'] = action_arguments

    #Create the GFI Sandbox -> MAEC/CybOX Action Mappings
    def __populate_action_mappings(self):
         self.action_mappings['alloc_memory'] = {'action_name':{'value':'allocate process virtual memory',
                                                                'xsi:type':'maecVocabs:ProcessMemoryActionNameVocab-1.0'}, 'xsi:type':'WindowsProcessObjectType', 'object_association':'input'}
         self.action_mappings['free_memory'] = {'action_name':{'value':'free process virtual memory',
                                                               'xsi:type':'maecVocabs:ProcessMemoryActionNameVocab-1.0'}, 'xsi:type':'WindowsProcessObjectType', 'object_association':'input'}
         self.action_mappings['protect_memory'] = {'action_name':{'value':'modify process virtual memory protection',
                                                                  'xsi:type':'maecVocabs:ProcessMemoryActionNameVocab-1.0'}, 'xsi:type':'WindowsProcessObjectType', 'object_association':'input'}
         self.action_mappings['read_memory'] = {'action_name':{'value':'read from process memory',
                                                               'xsi:type':'maecVocabs:ProcessMemoryActionNameVocab-1.0'}, 'xsi:type':'WindowsProcessObjectType', 'object_association':'input'}
         self.action_mappings['write_memory'] = {'action_name':{'value':'write to process memory',
                                                                'xsi:type':'maecVocabs:ProcessMemoryActionNameVocab-1.0'}, 'xsi:type':'WindowsProcessObjectType', 'object_association':'input'}
         self.action_mappings['query_memory'] = {'action_name':{'value':'query process memory'}, 'xsi:type':'WindowsProcessObjectType', 'object_association':'input'} #Not 100% sure about this action name mapping