#GFI Sandbox Base Section Handler
#v0.1

class section_handler(object):

    def __init__(self, initiator_id, tool_id):
        self.initiator_id = initiator_id
        self.tool_id = tool_id
        self.action_mappings = {}
    
    def handle_common_action_attributes(self, object, action_attributes, action_mappings):
        action_attributes['initiator_id'] = self.initiator_id
        #action_attributes['tool_id'] = self.tool_id
        #Set the properties from the action dictionary
        action_attributes['action_type'] = action_mappings.get('action_type')
        action_attributes[action_mappings.get('action_name_type')] = action_mappings.get('action_name')
        #Set the primary object that the action operated on
        action_attributes['object'] = object

    def handle_common_object_attributes(self, object_attributes, action_mappings):
        #Set the properties from the mappings dictionary
        object_attributes['type'] = action_mappings.get('object_type')
        object_attributes['association'] = action_mappings.get('object_association')

    def get_action_mappings(self):
        return self.action_mappings

    #Handle the object specific attributes
    def handle_object_attributes(self, action, object_attributes, action_attributes, action_mappings):
        raise NotImplementedError("__handle_object_attributes not implemented")

    #Handle the action specific attributes correctly
    def handle_action_attributes(self, action, object, action_attributes, action_mappings):
        raise NotImplementedError( "__handle_action_attributes not implemented")

    #Create the GFI Sandbox -> MAEC/CybOX Action Mappings
    def __populate_action_mappings(self):
        raise NotImplementedError("__populate_action_mappings not implemented")