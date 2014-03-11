#GFI Sandbox File Mapping Section Handler
#v0.1
import section
import maec.utils


class filemapping_section_handler(section.section_handler):

    def __init__(self):
        super(filemapping_section_handler,self).__init__()
        self.__populate_action_mappings()
    
    #Handle the file object oriented attributes
    def handle_object_attributes(self, action, object_attributes, action_attributes, action_mappings):
        secondary_object_attributes = {}
        try:
            secondary_object_attributes['id'] = maec.utils.idgen.create_id(prefix='object')
            secondary_object_attributes['association_type'] = {}
            secondary_object_attributes['association_type']['value'] = 'input'
            secondary_object_attributes['association_type']['xsi:type'] = 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'
            secondary_object_attributes['properties'] = {}
            secondary_object_attributes['properties']['xsi:type'] = 'WindowsHandleObjectType'
            secondary_object_attributes['properties']['id'] = int(action.get_file_handle(),16)
            secondary_object_attributes['properties']['type'] = 'File'
        except AttributeError:
            pass
        try:
            object_attributes['properties']['id'] = int(action.get_mapping_handle(),16)
            object_attributes['properties']['type'] = 'FileMapping'
        except AttributeError:
            pass
        #Add the mapping name as a custom property #TODO: create a new CybOX Object for Windows File Mappings
        try:
            if action.get_mapping_name():
                object_attributes['properties']['custom_properties'] = [{'value':action.get_mapping_name(), 'name':'Mapping Name'}]
        except AttributeError:
            pass
        if secondary_object_attributes:
            return [object_attributes, secondary_object_attributes]
        else:
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
                    argument_dict['argument_value'] = str(access_mode)
                    action_arguments.append(argument_dict)
        except AttributeError:
            pass
        try:
            split_protection = action.get_protection().split(' ')
            for protection in split_protection:
                if len(protection) > 0:
                    argument_dict = {}
                    argument_dict['argument_name'] = {'value': 'Protection', 'xsi:type': 'cyboxVocabs:ActionArgumentNameVocab-1.0'}
                    argument_dict['argument_value'] = str(protection)
                    action_arguments.append(argument_dict)
        except AttributeError:
            pass
        try:
            offset = action.get_mapping_offset()
            if len(str(offset)) > 0:
                argument_dict = {}
                argument_dict['argument_name'] = {'value': 'Mapping Offset', 'xsi:type': 'cyboxVocabs:ActionArgumentNameVocab-1.0'}
                argument_dict['argument_value'] = str(offset)
                action_arguments.append(argument_dict)
        except AttributeError:
            pass
        try:
            base_address = action.get_base_address()
            if len(str(base_address)) > 0:
                argument_dict = {}
                argument_dict['argument_name'] = {'value': 'Base Address', 'xsi:type': 'cyboxVocabs:ActionArgumentNameVocab-1.0'}
                argument_dict['argument_value'] = str(base_address)
                action_arguments.append(argument_dict)
        except AttributeError:
            pass
        try:
            view_size = action.get_view_size()
            if len(str(view_size)) > 0:
                argument_dict = {}
                argument_dict['argument_name'] = {'value': 'View Size'}
                argument_dict['argument_value'] = str(view_size)
                action_arguments.append(argument_dict)
        except AttributeError:
            pass
        #Set any action arguments
        action_attributes['action_arguments'] = action_arguments

    #Create the GFI Sandbox -> MAEC/CybOX Action Mappings
    def __populate_action_mappings(self):
         self.action_mappings['create_file_mapping'] = {'action_name':{'value':'create file mapping',
                                                                       'xsi:type':'maecVocabs:FileActionNameVocab-1.0'}, 'xsi:type':'WindowsHandleObjectType', 'object_association':'output'}
         self.action_mappings['open_file_mapping'] = {'action_name':{'value':'open file mapping',
                                                                     'xsi:type':'maecVocabs:FileActionNameVocab-1.0'}, 'xsi:type':'WindowsHandleObjectType', 'object_association':'input'}
         self.action_mappings['map_view_of_file'] = {'action_name':{'value':'map view of file'}, 'xsi:type':'WindowsHandleObjectType', 'object_association':'input'}
     
