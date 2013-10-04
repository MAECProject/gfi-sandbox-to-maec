#GFI Sandbox Base Section Handler
#v0.2

class section_handler(object):

    def __init__(self):
        self.action_mappings = {}
    
    def handle_common_action_attributes(self, object, action_attributes, action_mappings):
        #Set the properties from the action dictionary
        action_attributes['name'] = action_mappings.get('action_name')
        #Set the primary object that the action operated on
        if isinstance(object, list):
            temp_list = []
            for obj in object:
                if len(obj['properties'].keys()) > 1:
                    temp_list.append(obj)
            action_attributes['associated_objects'] = temp_list
        else:
            if len(object['properties'].keys()) > 1:
                action_attributes['associated_objects'] = [object]


    def handle_common_object_attributes(self, object_attributes, action_mappings):
        #Set the properties from the mappings dictionary
        object_attributes['properties'] = {}
        object_attributes['properties']['xsi:type'] = action_mappings.get('xsi:type')
        object_attributes['association_type'] = {}
        object_attributes['association_type']['value'] = action_mappings.get('object_association')
        object_attributes['association_type']['xsi:type'] = 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'

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