#GFI Sandbox Network Operation Section Handler
#v0.1
import section

class networkoperation_section_handler(section.section_handler):

    def __init__(self, maec_object, initiator_id, tool_id):
        super(networkoperation_section_handler,self).__init__(initiator_id, tool_id)
        self.maec_object = maec_object
        self.__populate_action_mappings()
    
    #Handle the network object oriented attributes
    def handle_object_attributes(self, action, object_attributes, action_attributes, action_mappings):
        try:
            object_attributes['address_value'] = action.get_request_address()
            object_attributes['category'] = 'ipv4-addr'
        except AttributeError:
            pass
        try:
            object_attributes['value'] = action.get_request_name()
            object_attributes['type'] = 'Domain Name'
        except AttributeError:
            pass
        try:
            resulting_addresses = action.get_result_addresses()
            if resulting_addresses != 'NONE':
                related_objects = []
                split_addresses = resulting_addresses.split(' ')
                if len(split_addresses) > 1:
                    for address in split_addresses:
                        secondary_object_attributes = {}
                        secondary_object_attributes['category'] = 'ipv4-addr'
                        secondary_object_attributes['address_value'] = address
                        secondary_object = self.maec_object.create_address_object(secondary_object_attributes)
                        related_object = self.maec_object.create_related_object(secondary_object, 'Resolved_To')
                        related_objects.append(related_object)
                else:
                    secondary_object_attributes = {}
                    secondary_object_attributes['category'] = 'ipv4-addr'
                    secondary_object_attributes['address_value'] = split_addresses[0]
                    secondary_object = self.maec_object.create_address_object(secondary_object_attributes)
                    related_object = self.maec_object.create_related_object(secondary_object, 'Resolved_To')
                    related_objects.append(related_object)
                object_attributes['related_objects'] = related_objects
        except AttributeError:
            pass
        try:
            resulting_name = action.get_result_name()
            if resulting_name != 'NONE':
                related_objects = []
                secondary_object_attributes = {}
                secondary_object_attributes['type'] = 'Domain Name'
                secondary_object_attributes['value'] = resulting_name
                secondary_object = self.maec_object.create_uri_object(secondary_object_attributes)
                related_object = self.maec_object.create_related_object(secondary_object, 'Resolved_To')
                related_objects.append(related_object)
                object_attributes['related_objects'] = related_objects
        except AttributeError:
            pass
        #Get the method encoded in the mappings dictionary to create the defined object
        method = action_mappings.get('object_method')
        #Create and return the object
        if method != 'n/a':
            object = getattr(self.maec_object,method)(object_attributes)
            return object
        else:
            return None

    #Handle the action specific attributes correctly
    def handle_action_attributes(self, action, object, action_attributes, action_mappings):
        action_arguments = []
        try:
            status = action.get_result()
            if status.lower() == 'unsuccessful':
                action_attributes['action_status'] = 'Fail'
        except AttributeError:
             pass
        try:
          request_size = action.get_request_size()
          if len(str(request_size)) > 0:
              argument_dict = {}
              argument_dict['undefined_argument_name'] = 'Request Size'
              argument_dict['argument_value'] = request_size
              action_arguments.append(argument_dict)
        except AttributeError:
             pass
        #Set any action arguments
        action_attributes['action_arguments'] = action_arguments
        #Set the action context
        action_attributes['context'] = 'Network'

    #Create the GFI Sandbox -> MAEC/CybOX Action Mappings
    def __populate_action_mappings(self):
         self.action_mappings['icmp_request'] = {'action_type':'Send', 'action_name_type':'undefined_action_name', 'action_name':'Send ICMP Request', 'object_type':'IP Address', 'object_method':'create_address_object', 'object_association':'Utilized'}
         self.action_mappings['dns_request_by_addr'] = {'action_type':'Send', 'action_name_type':'undefined_action_name', 'action_name':'Send Reverse DNS Query', 'object_type':'IP Address', 'object_method':'create_address_object', 'object_association':'Utilized'}
         self.action_mappings['dns_request_by_name'] = {'action_type':'Send', 'action_name_type':'undefined_action_name', 'action_name':'Send DNS Query', 'object_type':'Domain', 'object_method':'create_uri_object', 'object_association':'Utilized'}
