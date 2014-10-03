#GFI Sandbox Filesystem Section Handler
#v0.2 - BETA
import section
from cybox.core import Object

class filesystem_section_handler(section.section_handler):
    
    def __init__(self):
        super(filesystem_section_handler,self).__init__()
        self.__populate_action_mappings()

    #Handle the file object oriented attributes
    def handle_object_attributes(self, action, object_attributes, action_attributes, action_mappings):
        effect_attributes = {}
        src_filename = action.get_srcfile()
        split_src_filename = src_filename.split('\\')
        actual_src_filename = split_src_filename[len(split_src_filename)-1]
        filepath = src_filename.rstrip(actual_src_filename)
        if len(actual_src_filename) > 0:
            object_attributes['properties']['file_name'] = actual_src_filename
            #For pipes
            object_attributes['properties']['name'] = actual_src_filename
        object_attributes['properties']['file_path'] = filepath
        #TODO: Add support for effects back in a later version
        #effect_attributes['type'] = action.__class__.__name__.split(' ')[0]
        #try:
        #    object_attributes['object_attributes'] = action.get_object_attributes().split(' ')
        #except AttributeError:
        #    pass
        #try:
        #    effect_attributes['offset'] = action.get_offset()
        #except AttributeError:
        #    pass
        #try:
        #    effect_attributes['data_size'] = action.get_length()
        #except AttributeError:
        #    pass
        #object_attributes['effect'] = effect_attributes
        #Add any related objects
        if 'object_relationship' in action_mappings.keys():
            object_attributes['related_objects'] = [self.__handle_related_objects(action, action_mappings)]

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
        try:
            split_share_mode = action.get_share_access().split(' ')
            for share_mode in split_share_mode:
                if len(share_mode) > 0:
                    argument_dict = {}
                    argument_dict['argument_name'] = {'value': 'Share Mode', 'xsi:type': 'cyboxVocabs:ActionArgumentNameVocab-1.0'}
                    argument_dict['argument_value'] = share_mode
                    action_arguments.append(argument_dict)
        except AttributeError:
            pass
        try:
            split_creation_options = action.get_create_options().split(' ')
            for creation_flag in split_creation_options:
                if len(creation_flag) > 0:
                    argument_dict = {}
                    argument_dict['argument_name'] = {'value': 'Creation Flags', 'xsi:type': 'cyboxVocabs:ActionArgumentNameVocab-1.0'}
                    argument_dict['argument_value'] = creation_flag
                    action_arguments.append(argument_dict)
        except AttributeError:
            pass
        try:
            file_information_class = action.get_file_information_class()
            argument_dict = {}
            argument_dict['argument_name'] = {'value' : 'File Information Class', 'xsi:type' : None}
            argument_dict['argument_value'] = file_information_class
            action_arguments.append(argument_dict)
        except AttributeError:
            pass
        #Set any action arguments
        action_attributes['action_arguments'] = action_arguments

    #Handle any related objects that may be involved in the action
    def __handle_related_objects(self, file_action, action_mappings):
        related_object_attributes = {}
        #Get the dst file name, if it exists
        try:
            dst_filename = file_action.get_dstfile()
            split_dst_filename = dst_filename.split('\\')
            actual_dst_filename = split_dst_filename[len(split_dst_filename)-1]
            dst_filepath = dst_filename.rstrip(actual_dst_filename)
            related_object_attributes['properties'] = {}
            related_object_attributes['properties']['file_name'] = actual_dst_filename
            related_object_attributes['properties']['file_path'] = dst_filepath
            related_object_attributes['properties']['xsi:type'] = action_mappings['xsi:type']
            related_object_attributes['relationship'] = action_mappings['object_relationship']
        except AttributeError:
            pass
        return related_object_attributes
        

    #Create the GFI Sandbox -> MAEC/CybOX Action Mappings
    def __populate_action_mappings(self):
         self.action_mappings['create_file'] = {'action_name': {'value':'create file',
                                                                'xsi:type':'maecVocabs:FileActionNameVocab-1.0'}, 'xsi:type':'FileObjectType', 'object_association':'output'}
         self.action_mappings['create_namedpipe'] = {'action_name':{'value' :'create named pipe',
                                                                    'xsi:type' :'maecVocabs:IPCActionNameVocab-1.0'}, 'xsi:type':'WindowsPipeObjectType', 'object_association':'output'}
         self.action_mappings['create_mailslot'] = {'action_name':{'value' :'create mailslot',
                                                                   'xsi:type' :'maecVocabs:IPCActionNameVocab-1.0'}, 'xsi:type':'WindowsMailslotObjectType', 'object_association':'output'}
         self.action_mappings['read_file'] = {'action_name': {'value':'read from file',
                                                              'xsi:type':'maecVocabs:FileActionNameVocab-1.0'}, 'xsi:type':'FileObjectType', 'object_association':'input'}
         self.action_mappings['write_file'] = {'action_name': {'value':'write to file',
                                                                'xsi:type':'maecVocabs:FileActionNameVocab-1.0'}, 'xsi:type':'FileObjectType', 'object_association':'input'}
         self.action_mappings['delete_file'] = {'action_name': {'value':'delete file',
                                                                'xsi:type':'maecVocabs:FileActionNameVocab-1.0'}, 'xsi:type':'FileObjectType', 'object_association':'input'}
         self.action_mappings['open_file'] = {'action_name': {'value':'open file',
                                                                'xsi:type':'maecVocabs:FileActionNameVocab-1.0'}, 'xsi:type':'FileObjectType', 'object_association':'input'}
         self.action_mappings['copy_file'] = {'action_name': {'value':'copy file',
                                                                'xsi:type':'maecVocabs:FileActionNameVocab-1.0'}, 'xsi:type':'FileObjectType', 'object_association':'output', 'object_relationship' : {'value':'Copied_To',
                                                                                                                                                                                                       'xsi:type':'cyboxVocabs:ObjectRelationshipVocab-1.0'}}
         self.action_mappings['move_file'] = {'action_name': {'value':'move file',
                                                              'xsi:type':'maecVocabs:FileActionNameVocab-1.0'}, 'xsi:type':'FileObjectType', 'object_association':'output', 'object_relationship' : {'value':'Moved_To',
                                                                                                                                                                                                     'xsi:type':'cyboxVocabs:ObjectRelationshipVocab-1.0'}}
         self.action_mappings['find_file'] = {'action_name': {'value':'find file',
                                                              'xsi:type':'maecVocabs:FileActionNameVocab-1.0'}, 'xsi:type':'FileObjectType', 'object_association':'input'}
         self.action_mappings['get_file_attributes'] = {'action_name': {'value':'get file attributes',
                                                        'xsi:type':'maecVocabs:FileActionNameVocab-1.0'}, 'xsi:type':'FileObjectType', 'object_association':'input'}
         self.action_mappings['set_file_attributes'] = {'action_name': {'value':'set file attributes',
                                                        'xsi:type':'maecVocabs:FileActionNameVocab-1.0'}, 'xsi:type':'FileObjectType', 'object_association':'input'}
        