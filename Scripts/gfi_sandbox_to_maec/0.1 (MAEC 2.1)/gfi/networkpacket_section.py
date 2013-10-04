#GFI Sandbox Network Packet Section Handler
#v0.2
import section

class networkpacket_section_handler(section.section_handler):

    def __init__(self):
        super(networkpacket_section_handler,self).__init__()
        self.__populate_action_mappings()
    
    #Handle the network object oriented attributes
    def handle_object_attributes(self, action, object_attributes, action_attributes, action_mappings):
        source_socket_address = {}
        destination_socket_address = {}
        try:
            if action.get_local_port():
                source_socket_address['port'] = {'port_value':action.get_local_port()}
        except AttributeError:
             pass
        try:
            if action.get_local_ip():
                source_socket_address['ip_address'] = {'address_value':action.get_local_ip(), 'category':'ipv4-addr'}
        except AttributeError:
             pass
        try:
            if action.get_remote_port():
                destination_socket_address['port'] = {'port_value':action.get_remote_port()}
        except AttributeError:
             pass
        try:
            if action.get_remote_ip():
                destination_socket_address['ip_address'] = {'address_value':action.get_remote_ip(), 'category':'ipv4-addr'}
        except AttributeError:
             pass
        try:
            if action.get_protocol_l3():
                object_attributes['properties']['layer3_protocol'] = {'value':action.get_protocol_l3(), 'force_datatype':True}
        except AttributeError:
             pass
        try:
            if action.get_protocol_l4():
                object_attributes['properties']['layer4_protocol'] = {'value':action.get_protocol_l4(), 'force_datatype':True}
        except AttributeError:
             pass
        try:
            if action.get_remote_hostname():
                object_attributes['properties']['custom_properties'] = [{'value':action.get_remote_hostname(), 'name':'Remote Hostname'}]
        except AttributeError:
             pass
        if source_socket_address:
             object_attributes['properties']['source_socket_address'] = source_socket_address
        if destination_socket_address:
             object_attributes['properties']['destination_socket_address'] = destination_socket_address
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
         self.action_mappings['connect_to_computer'] = {'action_name':{'value':'connect to ip',
                                                        'xsi:type':'maecVocabs:NetworkActionNameVocab-1.0'}, 'xsi:type':'NetworkConnectionObjectType','object_association':'output'}
         self.action_mappings['disconnect_from_computer'] = {'action_name':{'value':'disconnect from ip',
                                                             'xsi:type':'maecVocabs:NetworkActionNameVocab-1.0'}, 'xsi:type':'NetworkConnectionObjectType','object_association':'input'}
         #self.action_mappings['packet_data'] = {'action_name':{'value':'send icmp request', 
         #                                                      'xsi:type':'maecVocabs:NetworkActionNameVocab-1.0'}, 'xsi:type':'NetworkConnectionObjectType','object_association':'input'} #TODO : add support in a future release
         self.action_mappings['listen_for_connection'] = {'action_name':{'value':'listen on port',
                                                          'xsi:type':'maecVocabs:NetworkActionNameVocab-1.0'}, 'xsi:type':'NetworkConnectionObjectType','object_association':'input'}
         self.action_mappings['ping'] = {'action_name':{'value':'send icmp request',
                                                        'xsi:type':'maecVocabs:NetworkActionNameVocab-1.0'}, 'xsi:type':'NetworkConnectionObjectType','object_association':'input'}
