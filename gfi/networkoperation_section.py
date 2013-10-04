#GFI Sandbox Network Operation Section Handler
#v0.2
import section

class networkoperation_section_handler(section.section_handler):

    def __init__(self, generator):
        super(networkoperation_section_handler,self).__init__()
        self.generator = generator
        self.__populate_action_mappings()
    
    #Handle the network object oriented attributes
    def handle_object_attributes(self, action, object_attributes, action_attributes, action_mappings):
        secondary_object_attributes = {}
        try:
            object_attributes['properties']['address_value'] = action.get_request_address()
            object_attributes['properties']['category'] = 'ipv4-addr'
        except AttributeError:
            pass
        try:
            request_uri = action.get_request_name()
            if request_uri:
                 question_dict = {}
                 question_dict['qname'] = {}
                 question_dict['qname']['value'] = request_uri
                 object_attributes['properties']['question'] = question_dict
                #object_attributes['properties']['type'] = 'Domain Name'
        except AttributeError:
            pass
        try:
            resulting_addresses = action.get_result_addresses()
            if resulting_addresses != 'NONE':
                resource_records = []
                split_addresses = resulting_addresses.split(' ')
                if len(split_addresses) > 1:
                    for address in split_addresses:
                        address_attributes = {}
                        address_attributes['category'] = 'ipv4-addr'
                        address_attributes['address_value'] = address
                        resource_records.append({'ip_address':address_attributes})
                else:
                        address_attributes = {}
                        address_attributes['category'] = 'ipv4-addr'
                        address_attributes['address_value'] = resulting_addresses
                        resource_records.append({'ip_address':address_attributes})
                if resource_records:
                    object_attributes['properties']['answer_resource_records'] = resource_records
        except AttributeError:
            pass
        try:
            resulting_name = action.get_result_name()
            if resulting_name != 'NONE':
                secondary_object_attributes = {'id':self.generator.generate_object_id(), 'properties':{}}
                secondary_object_attributes['association_type'] = {}
                secondary_object_attributes['association_type']['value'] = 'output'
                secondary_object_attributes['association_type']['xsi:type'] = 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'
                secondary_object_attributes['properties']['xsi:type'] = 'URIObjectType'
                secondary_object_attributes['properties']['value'] = resulting_name
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
          request_size = action.get_request_size()
          if len(str(request_size)) > 0:
              argument_dict = {}
              argument_dict['argument_name'] = {'value': 'Request Size', 'xsi:type': 'cyboxVocabs:ActionArgumentNameVocab-1.0'}
              argument_dict['argument_value'] = request_size
              action_arguments.append(argument_dict)
        except AttributeError:
             pass
        #Set any action arguments
        action_attributes['action_arguments'] = action_arguments

    #Create the GFI Sandbox -> MAEC/CybOX Action Mappings
    def __populate_action_mappings(self):
         self.action_mappings['icmp_request'] = {'action_name':{'value':'send icmp request',
                                                                'xsi:type':'maecVocabs:NetworkActionNameVocab-1.0'}, 'xsi:type':'AddressObjectType','object_association':'input'}
         self.action_mappings['dns_request_by_addr'] = {'action_name':{'value':'send reverse dns lookup',
                                                                       'xsi:type':'maecVocabs:DNSActionNameVocab-1.0'}, 'xsi:type':'AddressObjectType', 'object_association':'input'}
         self.action_mappings['dns_request_by_name'] = {'action_name':{'value':'send dns query',
                                                                       'xsi:type':'maecVocabs:DNSActionNameVocab-1.0'}, 'xsi:type':'DNSQueryObjectType', 'object_association':'input'}
