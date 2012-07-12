#Copyright (c) 2011, The MITRE Corporation
#All rights reserved.


################################################################################
#MAEC XML --> OVAL XML Generation Script                                       #
#Generates OVAL test/objects from a MAEC XML file                              #
#v0.91                                                                         #
#01/14/2011                                                                    #
#Ivan Kirillov//ikirillov@mitre.org                                            #
#                                                                              #
####Release Notes###############################################################
#Compatible with MAEC schema v1.1                                              #
#Compatible with OVAL 5.x (bindings compiled using 5.7)                        #
#                                                                              #
#Currently supported objects:                                                  #
#*files/directories (Windows only)                                             #
#*registry keys                                                                #
#                                                                              #
#Input: MAEC XML File (Must contain a MAEC bundle type)                        #
#Output: OVAL XML File                                                         #
#################################                                              #
# MAEC - http://maec.mitre.org  #                                              #
# OVAL - http://oval.mitre.org  #                                              #
################################################################################

import sys
import datetime
import time
import os
import maecv11 as maec
import oval57 as oval
import ntpath
import traceback

#Search through each possible MAEC construct for actions
#Process each action found
def parse_actions():
    #Begin by looking for actions defined at the top level of the bundle
    
    #first, look in the behaviors
    top_level_behaviors = maec_bundle.get_Behaviors()
    if top_level_behaviors != None:
        behaviors = top_level_behaviors.get_Behavior()
        for behavior in behaviors:
            parse_behavior(behavior)
            
    #afterwards, look in the actions
    top_level_actions = maec_bundle.get_Actions()
    if top_level_actions != None:
        actions = top_level_actions.get_Action()
        for action in actions:
            process_action(action)
            
    #next, find any defined in MAEC pools
    maec_pools = maec_bundle.get_Pools()
    if maec_pools != None:
        #look in the action_pool
        action_pool = maec_pools.get_Action_Pool()
        if action_pool != None:
            actions = action_pool.get_Action()
            for action in actions:
                process_action(action)
                
        #look in the action_collection_pool
        action_collection_pool = maec_pools.get_Action_Collection_Pool()
        if action_collection_pool != None:
            action_collections = action_collection_pool.get_Action_Collection()
            for action_collection in action_collections:
                parse_action_collection(action_collection)
        
        #look in the behavior pool
        behavior_pool = maec_pools.get_Behavior_Pool()
        if behavior_pool != None:
            behaviors = behavior_pool.get_Behavior()
            for behavior in behaviors:
                parse_behavior(behavior)
                
        #look in the behavior_collection pool
        behavior_collection_pool = maec_pools.get_Behavior_Collection_Pool()
        if behavior_collection_pool != None:
            behavior_collections = behavior_collection_pool.get_Behavior_Collection()
            for behavior_collection in behavior_collections:
                parse_behavior_collection(behavior_collection)
                
#Parse a behavior and extract its constituent actions, if any                
def parse_behavior(behavior):
    behavior_actions = behavior.get_Actions()
    if behavior_actions != None:
        #extract any action collections
        #this is disabled for now, until we resolve the collision between
        #the two 'actions' (the one at the top in the MAEC_bundle, and the one here)
        #behavior_action_collections = behavior_actions.get_Action_Collection()
        #if behavior_action_collections != None:
            #for action_collection in behavior_action_collections:
                #parse_action_collection(action_collection)
        #extract any actions
        behavior_action = behavior_actions.get_Action()
        if behavior_action != None:
            for action in behavior_action:
                process_action(action)
                
#Special function for parsing behavior collections, with recursion
#This is due to the possibility of having multiple nested behavior sub-collections
def parse_behavior_collection(behavior_collection):
    #First, process any behaviors defined in the collection
    behaviors = behavior_collection.get_Behavior()
    for behavior in behaviors:
        process_behavior(behavior)
    #Next, process the sub-collection
    behavior_sub_collection = action_collection.get_Behavior_Sub_Collection()
    if behavior_sub_collection != None:
        for behavior_coll in behavior_sub_collection:
            #Call ourselves recursively to do the processing
            parse_behavior_collection(behavior_coll)
    
#Special function for parsing action collections, with recursion
#This is due to the possibility of having multiple nested action sub-collections
def parse_action_collection(action_collection):
    #First, process any actions defined in the collection
    actions = action_collection.get_Action()
    for action in actions:
        process_action(action)
    #Next, process the sub-collection
    action_sub_collection = action_collection.get_Action_Sub_Collection()
    if action_sub_collection != None:
        for action_coll in action_sub_collection:
            #Call ourselves recursively to do the processing
            parse_action_collection(action_coll)
        
#Process the action
#Determine if it has created any objects
#If so, attempt to extract them
def process_action(action):
    #get the MAEC Action type
    action_type = action.get_type()
    #get the action name
    action_name = action.get_action_name()
    #make sure we're looking at only create actions
    if action_type != 'Create' : return
    #check the action type. for now, we're only looking for created files, directories, and registry keys
    if (action_name.lower().count('file') or action_name.lower().count('key') or action_name.lower().count('directory') or action_name.lower().count('registry')) == 0 : return
    #get the action's effect, if it has one
    action_effect = action.get_Effects()
    if action_effect == None : return
    #parse the action's effect to see if there's an affected_object
    object_id = process_action_effect(action_effect)
    if object_id == 0 : return
    #check to make sure that we haven't written this object yet
    global object_list
    if object_list.count(object_id) == 0:
        #we have the ID of the object, now we have to find it 
        object = find_object(object_id)
        if object == None: return
        #we have the object, now we need to extract its attributes and create the OVAL def
        process_object(object)
        object_list.append(object_id)
 
#Make sure the object has the correct attributes (is valid)
#If so, generate the OVAL definition from it
def process_object(object):
    #determine the object type
    object_type = object.get_type()
    validity = 0
    if object_type == 'File' or object_type == 'Directory':
        validity = check_file_attributes(object)
    elif object_type == 'Key/Key Group':
        validity = check_registrykey_attributes(object, object_type)
    if validity:
        create_oval_objects(object, object_type)

#Look through all possible MAEC structures for the object specified by the object_id    
def find_object(object_id):
    #First, look through all of the actions and their embedded objects
    root_action = maec_bundle.get_Actions()
    maec_pools = maec_bundle.get_Pools()
    
    if root_action != None:
        root_actions = root_action.get_Action()
        for action in root_actions:
            action_objs = action.get_Objects()
            for object in action_objs.get_Object():
                obj_id = object.get_id()
                if obj_id == object_id:
                    return object
                
    action_collection_pool = maec_pools.get_Action_Collection_Pool()
    if action_collection_pool != None:
        action_collections = action_collection_pool.get_Action_Collection()
        for action_collection in action_collections:
            actions = action_collection.get_Action()
            for action in actions:
                action_objs = action.get_Objects()
                if action_objs != None:
                  for object in action_objs.get_Object():
                      obj_id = object.get_id()
                      if obj_id == object_id:
                          return object
                
    action_pool = maec_pools.get_Action_Pool()
    if action_pool != None:
        actions = action_pool.get_Action()
        for action in root_actions:
            action_objs = action.get_Objects()
            if action_objs != None:
              for object in action_objs.get_Object():
                  obj_id = object.get_id()
                  if obj_id == object_id:
                      return object
                
    #Next, look in the object pools
    object_pool = maec_pools.get_Object_Pool()
    if object_pool != None:
        objects = object_pool.get_Object()
        for object in objects:
            obj_id = object.get_id()
            if obj_id == object_id:
                return object
            
    object_collection_pool = maec_pools.get_Object_Collection_Pool()
    if object_collection_pool != None:
        object_collections = object_collection_pool.get_Object_Collection()
        for object_collection in object_collections:
            objects = object_collection.get_Object()
            for object in objects:
                obj_id = object.get_id()
                if obj_id == object_id:
                    return object
    
    return None

#Process an effect and extract an object_id if it exists    
def process_action_effect(action_effect):
    object_id = 0
    #first, process the effects themselves
    effects = action_effect.get_Effect()
    for effect in effects:
        affected_objects = effect.get_Affected_Objects()
        for affected_object in affected_objects.get_Affected_Object():
            obj_reference = affected_object.get_Object_Reference()
            if affected_object.get_effect_type() == 'Object_Created':
                return obj_reference.get_object_id()
    #next, process any effect_references
    #if an effect is not found under in action, it must be in the effect pool
    effect_refs = action_effect.get_Effect_Reference()
    for effect_ref in effect_refs:
        effect_id = effect_ref.get_effect_id()
        object_id = process_effect_reference(effect_id)
    return object_id

#Process a reference to an effect and extract an object_id if it exists        
def process_effect_reference(effect_id):
    maec_pools = maec_bundle.get_Pools()
    effect_pool = maec_pools.get_Effect_Pool()
    for effect in effect_pool:
        #find the effect referenced through the id
        if effect.get_id() == effect_id:
            affected_objects = effect.get_Affected_Objects()
            for affected_object in affected_objects.get_Affected_Object():
                obj_reference = affected_object.get_Object_Reference()
                if affected_object.get_Effect_Type() == 'Object_Created':
                    return obj_reference.get_object_id()
    return 0

#Check MAEC file object attributes
def check_file_attributes(object):
    object_name = object.get_object_name()
    if object_name == None: return 0
    object_file_attributes = object.get_File_System_Object_Attributes()
    if object_file_attributes == None: return 0
    object_path = object_file_attributes.get_Path()
    if object_path == None: return 0
    #if we're still here, then it appears that the file object is valid
    return 1

#Check MAEC registry object attributes
def check_registrykey_attributes(object, object_type):
    registry_object_attributes = object.get_Registry_Object_Attributes()
    if registry_object_attributes == None: return 0
    object_hive = registry_object_attributes.get_Hive()
    object_key = registry_object_attributes.get_Key()
    if object_key == None or object_hive == None : return 0
    if registry_object_attributes.get_Value() != None:
        object_value = registry_object_attributes.get_Value()
        object_value_name = object_value.get_Value_Name()
        if object_value_name == None: return 0
    #if we're still here, then it appears that the registry object is valid
    return 1
    
#Process the MAEC object and create the OVAL objects
#Includes criteria, test, and object
def create_oval_objects(object, object_type):
    #create the test/obj ids
    test_id = 'oval:maec_out:tst:' + str(generate_test_id())
    object_id = 'oval:maec_out:obj:' + str(generate_obj_id())
    
    if object_type == 'File' or object_type == 'Directory':
        #extract the necessary attributes
        file_name = object.get_object_name()
        file_attributes = object.get_File_System_Object_Attributes()
        file_path = file_attributes.get_Path()
        file_path = file_path.get_valueOf_()
        if object_type == 'File':
            split_path = file_path.split('\\')
            file_path = normalize_path(split_path)
        #create the oval test
        test = oval.file_test(version=1, id=test_id, check='all', check_existence='all_exist')
        #create the oval object
        obj = oval.file_object(version=1, id=object_id)
        if object_type == 'File':
            obj.set_filename(file_name)
        obj.set_path(ntpath.normpath(file_path))
        
    elif object_type == 'Key/Key Group':
        #extract the necessary attributes
        registry_attributes = object.get_Registry_Object_Attributes()
        hive = registry_attributes.get_Hive()
        key = registry_attributes.get_Key()
        value_top = None
        #see if there is a registry value, and set it if so
        if registry_attributes.get_Value() != None:
            value_top = registry_attributes.get_Value()
            value = value_top.get_Value_Name()
        #create the oval test
        test = oval.registry_test(version=1, id=test_id, check='all', check_existence='all_exist')
        #create the oval object
        obj = oval.registry_object(version=1, id=object_id)
        obj.set_hive(hive)
        obj.set_key(key)
        if value_top != None:
            obj.set_name(value)
        
    #create the object reference
    object_ref = oval.ObjectRefType()
    object_ref.set_object_ref(object_id)
    #set the test attributes
    test.set_object(object_ref)
        
    #finally, create the oval definition for this test
    create_oval_definition(test_id)  
    #add the object and test to their respective collections
    global oval_objects
    global oval_tests
    oval_objects.add_object(obj)
    oval_tests.add_test(test)
    
#Create the high-level OVAL definition, along with the criteria
#Each OVAL test needs its own definition in order to execute independently
def create_oval_definition(test_id):
    definition_id = 'oval:maec_out:def:' + str(generate_def_id())
    oval_def = oval.DefinitionType(id=definition_id, version='1', classxx='miscellaneous')
    #create the metadata (required)
    metadata = oval.MetadataType()
    metadata.set_description('Existence check for object extracted from MAEC definition')
    metadata.set_title('Object check')
    oval_def.set_metadata(metadata)
    #create the criteria
    criteria = oval.CriteriaType()
    #create the criterion
    #this is what actually references the test
    criterion = oval.CriterionType()
    criterion.set_test_ref(test_id)
    #add the criterion to the criteria
    criteria.add_criterion(criterion)
    #add the criteria to the oval definition
    oval_def.set_criteria(criteria)
    #finally, add the oval definition to the definitions
    global oval_defs
    oval_defs.add_definition(oval_def)
    
##Helper functions##

#Takes a split fully-qualified file path and return a normalized representation
#This consists of the input path minus the file name
def normalize_path(split_path):
    path = ''
    for i in range(0,len(split_path)-1):
        path += split_path[i] + '\\'
    return path

def generate_datetime():
    dtime = datetime.datetime.now().isoformat()
    return dtime

def generate_test_id():
    global test_id_base
    test_id_base += 1
    return test_id_base

def generate_obj_id():
    global obj_id_base
    obj_id_base += 1
    return obj_id_base

def generate_def_id():
    global def_id_base
    def_id_base += 1
    return def_id_base

def usage():
    print USAGE_TEXT
    sys.exit(1)
    
#Global variable declarations go here
USAGE_TEXT = """
MAEC to OVAL Translator v0.91
Usage: python maec_to_oval.py -i <input_maec_file.xml> -o <output_oval_file.xml>

Verbose error mode for printing tracebacks, can be enabled by putting -v as the first argument:
python maec_to_oval.py -v -i <input_maec_file.xml> -o <output_oval_file.xml>
"""
test_id_base = 0    
obj_id_base = 0
def_id_base = 0
#List for keeping track of objects we've already written
object_list = []    
##end helper functions##


def main():
    verbose_error_mode = 0
    #Get the command-line arguments
    args = sys.argv[1:]
    if len(args) == 4:
        if args[0] != '-i' or args[2] != '-o':
            usage()
            sys.exit(1)
        infilename = args[1]
        outfilename = args[3]
    elif len(args) == 5:
        if args[0] != '-v' or args[1] != '-i' or args[3] != '-o':
            usage()
            sys.exit(1)
        infilename = args[2]
        outfilename = args[4]
        verbose_error_mode = 1
    else:
        usage()
        sys.exit(1)
    
    #Check the existence of the input file
    if os.path.isfile(infilename):
        #Get the MAEC bundle object from the document
        #Do some basic error handling here..
        rootObject = None
        try: 
            rootObject = maec.parse(infilename)
        except Exception, err:
           print('\nError: %s\n' % str(err))
           
        #Create the root OVAL document
        ovaldefroot = oval.oval_definitions()
        
        global maec_bundle
        if rootObject != None:
            maec_bundle = rootObject
        else:
            if verbose_error_mode:
                traceback.print_exc()
            print('Error: MAEC Bundle object not found. No OVAL exported.')
            sys.exit(1)
       
        #Setup the OVAL document
        global oval_defs
        global oval_tests
        global oval_objects
        oval_defs = oval.DefinitionsType()
        oval_tests = oval.TestsType()
        oval_objects = oval.ObjectsType()
        
        #Add the generator to the defs
        oval_gen = oval.GeneratorType()
        oval_gen.set_product_name('MAEC XML to OVAL Script')
        oval_gen.set_product_version('1.1')
        oval_gen.set_schema_version('5.7')
        
        #Generate the datetime
        oval_gen.set_timestamp(generate_datetime())
        
        #Call the main parsing function to do all the dirty work
        print "\nExtracting MAEC objects and generating OVAL definitions...\n"
        try:
            parse_actions()
        except Exception, err:
            if verbose_error_mode:
                traceback.print_exc()
            print('\nError: %s\n' % str(err))
            print('Error in parse_actions(). No OVAL exported.')
            sys.exit(1)
            
        #Add the definitions, tests, objects, and generator to the root OVAL document
        ovaldefroot.set_definitions(oval_defs)
        ovaldefroot.set_tests(oval_tests)
        ovaldefroot.set_objects(oval_objects)
        ovaldefroot.set_generator(oval_gen)
        
        #Finally, create the output file and export the OVAL data to it
        #But first, check to make sure that we actually extracted some objects for output
        if len(object_list) > 0:
            outfile = open(outfilename, 'w')
            ovaldefroot.export(outfile, 0, namespacedef_='xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5" xmlns:oval-def="http://oval.mitre.org/XMLSchema/oval-definitions-5" xmlns:win-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#windows" xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://oval.mitre.org/XMLSchema/oval-definitions-5#windows http://oval.mitre.org/language/version5.7/ovaldefinition/complete/windows-definitions-schema.xsd http://oval.mitre.org/XMLSchema/oval-definitions-5 http://oval.mitre.org/language/version5.7/ovaldefinition/complete/oval-definitions-schema.xsd http://oval.mitre.org/XMLSchema/oval-common-5 http://oval.mitre.org/language/version5.7/ovaldefinition/complete/oval-common-schema.xsd"')
            print (str(len(object_list)) + " OVAL definitions exported successfully to: " + outfilename)
        else:
            print "0 valid objects found. No OVAL exported."
    else:
        print "\nError: Input file does not exist."

if __name__ == "__main__":
    main()    
