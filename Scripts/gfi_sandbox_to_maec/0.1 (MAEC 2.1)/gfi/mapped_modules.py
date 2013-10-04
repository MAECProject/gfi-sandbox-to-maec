#GFI Mapped Modules Handler
#v0.2
import section

class mapped_modules_handler(section.section_handler):

    def __init__(self):
        super(mapped_modules_handler,self).__init__()
        self.__populate_action_mappings()
    
    #Handle the User Account Object oriented attributes
    def handle_object_attributes(self, action, object_attributes, action_attributes, action_mappings):
        try:
            if action.get_filename():
                object_attributes['properties']['name'] = action.get_filename()
        except AttributeError:
            pass
        try:
            if action.get_size():
                object_attributes['properties']['size'] = str(action.get_size())
        except AttributeError:
            pass
        try:
            if action.get_base_address():
                object_attributes['properties']['base_address'] = str(action.get_base_address())
        except AttributeError:
            pass
        return object_attributes

    #Handle the action specific attributes correctly
    def handle_action_attributes(self, action, object, action_attributes, action_mappings):
        return

    #Create the GFI Sandbox -> MAEC/CybOX Action Mappings
    def __populate_action_mappings(self):
         self.action_mappings['mapped_module'] = {'action_name':{'value':'map library into process',
                                                                 'xsi:type':'maecVocabs:ProcessMemoryActionNameVocab-1.0'}, 'xsi:type':'LibraryObjectType', 'object_association':'input'}