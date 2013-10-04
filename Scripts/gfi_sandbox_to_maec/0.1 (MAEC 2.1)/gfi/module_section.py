#GFI Sandbox User Section Handler
#v0.2
import section

class module_section_handler(section.section_handler):

    def __init__(self, generator):
        super(module_section_handler,self).__init__()
        self.generator = generator
        self.__populate_action_mappings()
    
    #Handle the module object oriented attributes
    def handle_object_attributes(self, action, object_attributes, action_attributes, action_mappings):
        secondary_object_attributes = {}
        try:
            filename = action.get_filename()
            if filename:
                split_filename = filename.split('\\')
                actual_filename = split_filename[len(split_filename)-1]
                filepath = filename.rstrip(actual_filename)
                object_attributes['properties']['name'] = actual_filename
                object_attributes['properties']['path'] = filepath
                #Duplicate for Windows File Objects
                object_attributes['properties']['file_name'] = actual_filename
                object_attributes['properties']['file_path'] = filepath
                #Duplicate for Windows Kernel Hook Objects
                object_attributes['properties']['hooked_module'] = filename
        except AttributeError:
            pass
        try:
            if action.get_internal_name():
                object_attributes['properties']['custom_properties'] = [{'name':'Internal Name', 'value':action.get_internal_name()}]
        except AttributeError:
            pass
        try:
            if action.get_function():
                exports_dict = {}
                exports_dict['exported_functions'] = [{'function_name':action.get_function()}]
                object_attributes['properties']['exports'] = exports_dict
                #Duplicate for Windows Kernel Hook Objects
                object_attributes['properties']['hooked_function'] = action.get_function()
        except AttributeError:
            pass
        try:
            if action.get_hook_id():
                object_attributes['properties']['type'] = action.get_hook_id()
        except AttributeError:
            pass
        try:
            if action.get_ordinal():
                exports_dict = {}
                exports_dict['exported_functions'] = [{'ordinal':action.get_ordinal()}]
                secondary_object_attributes['id'] = self.generator.generate_object_id()
                secondary_object_attributes['association_type'] = {}
                secondary_object_attributes['association_type']['value'] = 'input'
                secondary_object_attributes['association_type']['xsi:type'] = 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'
                secondary_object_attributes['properties'] = {}
                secondary_object_attributes['properties']['xsi:type'] = 'WindowsExecutableFileObject'
                secondary_object_attributes['properties']['exports'] = exports_dict
        except AttributeError:
            pass
        if secondary_object_attributes:
            return [object_attributes, secondary_object_attributes]
        else:
            return object_attributes

    #Handle the action specific attributes correctly
    def handle_action_attributes(self, action, object, action_attributes, action_mappings):
        action_arguments = []
        try:
            hook_id = action.get_hook_id()
            if len(str(hook_id)) > 0:
                argument_dict = {}
                argument_dict['argument_name'] = 'Hook Type'
                argument_dict['argument_value'] = hook_id
                action_arguments.append(argument_dict)
        except AttributeError:
            pass

    #Create the GFI Sandbox -> MAEC/CybOX Action Mappings
    def __populate_action_mappings(self):
         self.action_mappings['mapping_module'] = {'action_name':{'value':'map library'}, 'xsi:type':'LibraryObjectType', 'object_association':'input'}
         self.action_mappings['module_mapped'] = {'action_name':{'value':'map library'}, 'xsi:type':'LibraryObjectType', 'object_association':'input'} #How is this different from mapping_module?
         self.action_mappings['load_module'] = {'action_name':{'value':'load library',
                                                               'xsi:type':'maecVocabs:LibraryActionNameVocab-1.0'}, 'xsi:type':'LibraryObjectType', 'object_association':'input'}
         self.action_mappings['unload_module'] = {'action_name':{'value':'free library',
                                                                 'xsi:type':'maecVocabs:LibraryActionNameVocab-1.0'}, 'xsi:type':'LibraryObjectType', 'object_association':'input'}
         self.action_mappings['enumerate_dlls'] = {'action_name':{'value':'enumerate libraries',
                                                                  'xsi:type':'maecVocabs:LibraryActionNameVocab-1.0'}, 'xsi:type':'LibraryObjectType', 'object_association':'input'}
         self.action_mappings['get_proc_address'] = {'action_name':{'value':'get function address',
                                                                    'xsi:type':'maecVocabs:LibraryActionNameVocab-1.0'}, 'xsi:type':'WindowsExecutableFileObject', 'object_association':'input'}
         self.action_mappings['install_winhook_proc'] = {'action_name':{'value':'add windows hook',
                                                                        'xsi:type':'maecVocabs:HookingActionNameVocab-1.0'}, 'xsi:type':'WindowsKernelHookObjectType', 'object_association':'output'}    