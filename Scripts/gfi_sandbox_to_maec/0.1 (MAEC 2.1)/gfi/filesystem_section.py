#GFI Sandbox Filesystem Section Handler
#v0.1
import section

class filesystem_section_handler(section.section_handler):
    
    def __init__(self, maec_object, initiator_id, tool_id):
        super(filesystem_section_handler,self).__init__(initiator_id, tool_id)
        self.maec_object = maec_object
        self.__populate_action_mappings()

    #Handle the file object oriented attributes
    def handle_object_attributes(self, action, object_attributes, action_attributes, action_mappings):
        effect_attributes = {}
        src_filename = action.get_srcfile()
        split_src_filename = src_filename.split('\\')
        actual_src_filename = split_src_filename[len(split_src_filename)-1]
        filepath = src_filename.rstrip(actual_src_filename)
        object_attributes['filename'] = actual_src_filename
        object_attributes['filepath'] = filepath
        effect_attributes['type'] = action.__class__.__name__.split(' ')[0]
        try:
            object_attributes['object_attributes'] = action.get_object_attributes().split(' ')
        except AttributeError:
            pass
        try:
            effect_attributes['offset'] = action.get_offset()
        except AttributeError:
            pass
        try:
            effect_attributes['data_size'] = action.get_length()
        except AttributeError:
            pass
        object_attributes['effect'] = effect_attributes
        #Add any related objects
        object_attributes['related_object'] = self.__handle_related_objects(action, action_mappings)
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
        try:
            split_share_mode = action.get_share_access().split(' ')
            for share_mode in split_share_mode:
                if len(share_mode) > 0:
                    argument_dict = {}
                    argument_dict['defined_argument_name'] = 'Share Mode'
                    argument_dict['argument_value'] = share_mode
                    action_arguments.append(argument_dict)
        except AttributeError:
            pass
        try:
            split_creation_options = action.get_create_options().split(' ')
            for creation_flag in split_creation_options:
                if len(creation_flag) > 0:
                    argument_dict = {}
                    argument_dict['defined_argument_name'] = 'Creation Flags'
                    argument_dict['argument_value'] = creation_flag
                    action_arguments.append(argument_dict)
        except AttributeError:
            pass
        try:
            file_information_class = action.get_file_information_class()
            argument_dict = {}
            argument_dict['undefined_argument_name'] = 'File Information Class'
            argument_dict['argument_value'] = file_information_class
            action_arguments.append(argument_dict)
        except AttributeError:
            pass
        #Set any action arguments
        action_attributes['action_arguments'] = action_arguments
        #Set the action context
        action_attributes['context'] = 'Host'

    #Handle any related objects that may be involved in the action
    def __handle_related_objects(self, file_action, action_mappings):
        related_object_attributes = {}
        related_object = None
        #Get the dst file name, if it exists
        try:
            dst_filename = file_action.get_dstfile()
            split_dst_filename = dst_filename.split('\\')
            actual_dst_filename = split_dst_filename[len(split_dst_filename)-1]
            dst_filepath = dst_filename.rstrip(actual_dst_filename)
            related_object_attributes['filename'] = actual_dst_filename
            related_object_attributes['filepath'] = dst_filepath
            related_object_attributes['type'] = action_mappings.get('object_type')
            #Create and return the object
            method = action_mappings.get('object_method')
            #Call the method encoded in the mappings dictionary to create the cybox object
            cybox_object = getattr(self.maec_object,method)(related_object_attributes)
            #Create the related object using the relationship in the action mappings dictionary and the defined object
            related_object = self.maec_object.create_related_object(cybox_object, action_mappings.get('object_relationship'))
        except AttributeError:
            pass
        return related_object
        

    #Create the GFI Sandbox -> MAEC/CybOX Action Mappings
    def __populate_action_mappings(self):
         self.action_mappings['create_file'] = {'action_type':'Create', 'action_name_type':'defined_action_name', 'action_name':'Create File', 'object_type':'File', 'object_method':'create_file_system_object', 'object_association':'Affected'}
         self.action_mappings['create_namedpipe'] = {'action_type':'Create', 'action_name_type':'defined_action_name', 'action_name':'Create Named Pipe', 'object_type':'NamedPipe', 'object_method':'create_pipe_object', 'object_association':'Affected'}
         self.action_mappings['create_mailslot'] = {'action_type':'Create', 'action_name_type':'defined_action_name', 'action_name':'Create Mailslot', 'object_type':'Mailslot', 'object_method':'create_mailslot_object', 'object_association':'Affected'}
         self.action_mappings['read_file'] = {'action_type':'Read', 'action_name_type':'defined_action_name', 'action_name':'Read File', 'object_type':'File', 'object_method':'create_file_system_object', 'object_association':'Utilized'}
         self.action_mappings['write_file'] = {'action_type':'Write', 'action_name_type':'defined_action_name', 'action_name':'Write to File', 'object_type':'File', 'object_method':'create_file_system_object', 'object_association':'Affected'}
         self.action_mappings['delete_file'] = {'action_type':'Remove/Delete', 'action_name_type':'defined_action_name', 'action_name':'Delete File', 'object_type':'File', 'object_method':'create_file_system_object', 'object_association':'Affected'}
         self.action_mappings['open_file'] = {'action_type':'Open', 'action_name_type':'defined_action_name', 'action_name':'Open File', 'object_type':'File', 'object_method':'create_file_system_object', 'object_association':'Affected'}
         self.action_mappings['create_mailslot'] = {'action_type':'Create', 'action_name_type':'defined_action_name', 'action_name':'Create Mailslot', 'object_type':'Mailslot', 'object_method':'create_mailslot_object', 'object_association':'Affected'}
         self.action_mappings['copy_file'] = {'action_type':'Copy/Duplicate', 'action_name_type':'defined_action_name', 'action_name':'Copy File', 'object_type':'File', 'object_method':'create_file_system_object', 'object_association':'Affected', 'object_relationship':'Copied_To'}
         self.action_mappings['move_file'] = {'action_type':'Move', 'action_name_type':'defined_action_name', 'action_name':'Move File', 'object_type':'File', 'object_method':'create_file_system_object', 'object_association':'Affected', 'object_relationship':'Moved_To'}
         self.action_mappings['find_file'] = {'action_type':'Find', 'action_name_type':'defined_action_name', 'action_name':'Find File', 'object_type':'File', 'object_method':'create_file_system_object', 'object_association':'Utilized'}
         self.action_mappings['get_file_attributes'] = {'action_type':'Get', 'action_name_type':'defined_action_name', 'action_name':'Get File Attributes', 'object_type':'File', 'object_method':'create_file_system_object', 'object_association':'Utilized'}
         self.action_mappings['set_file_attributes'] = {'action_type':'Set', 'action_name_type':'defined_action_name', 'action_name':'Set File Attributes', 'object_type':'File', 'object_method':'create_file_system_object', 'object_association':'Utilized'}
         return
        