#GFI Sandbox Virtual Memory Section Handler
#v0.1
import section

class virtualmemory_section_handler(section.section_handler):

    def __init__(self, maec_object, initiator_id, tool_id):
        super(virtualmemory_section_handler,self).__init__(initiator_id, tool_id)
        self.maec_object = maec_object
        self.__populate_action_mappings()
    
    #Handle the file object oriented attributes
    def handle_object_attributes(self, action, object_attributes, action_attributes, action_mappings):
        object_attributes['pid'] = action.get_target_pid()
        #Handle the virtual memory object attributes
        section_list = []
        try:
            object_attributes['size'] = action.get_size()
        except AttributeError:
            pass
        try:
            address = action.get_address().lstrip('0x')
            if len(address) % 2 == 1:
                address = '0' + address
            object_attributes['address'] = address
        except AttributeError:
            pass
        #Add the memory object to the list and object attributes
        memory_cybox_object = self.maec_object.create_memory_object(object_attributes)
        if memory_cybox_object.hasContent_():
            memory_object = memory_cybox_object.get_Defined_Object()
            section_list.append(memory_object)
        object_attributes['sections'] = section_list
        #Get the method encoded in the mappings dictionary to create the defined object
        method = action_mappings.get('object_method')
        #Create and return the object
        object = getattr(self.maec_object,method)(object_attributes)
        return object

    #Handle the action specific attributes correctly
    def handle_action_attributes(self, action, object, action_attributes, action_mappings):
        #Set the action context
        action_attributes['context'] = 'Host'

    #Create the GFI Sandbox -> MAEC/CybOX Action Mappings
    def __populate_action_mappings(self):
         self.action_mappings['alloc_memory'] = {'action_type':'Allocate', 'action_name_type':'defined_action_name', 'action_name':'Allocate Virtual Memory in Process', 'object_type':'Memory Page', 'object_method':'create_win_process_object', 'object_association':'Affected'}
         self.action_mappings['free_memory'] = {'action_type':'Free', 'action_name_type':'defined_action_name', 'action_name':'Free Process Virtual Memory', 'object_type':'Memory Page', 'object_method':'create_win_process_object', 'object_association':'Affected'}
         self.action_mappings['protect_memory'] = {'action_type':'Modify', 'action_name_type':'defined_action_name', 'action_name':'Protect Virtual Memory', 'object_type':'Memory Page', 'object_method':'create_win_process_object', 'object_association':'Affected'}
         self.action_mappings['read_memory'] = {'action_type':'Read', 'action_name_type':'defined_action_name', 'action_name':'Read From Process Memory', 'object_type':'Memory Page', 'object_method':'create_win_process_object', 'object_association':'Utilized'}
         self.action_mappings['write_memory'] = {'action_type':'Write', 'action_name_type':'defined_action_name', 'action_name':'Write to Process Virtual Memory', 'object_type':'Memory Page', 'object_method':'create_win_process_object', 'object_association':'Affected'}
         self.action_mappings['query_memory'] = {'action_type':'Query', 'action_name_type':'defined_action_name', 'action_name':'Query Process Virtual Memory', 'object_type':'Memory Page', 'object_method':'create_win_process_object', 'object_association':'Utilized'}