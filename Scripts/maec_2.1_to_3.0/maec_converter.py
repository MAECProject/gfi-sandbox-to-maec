#MAEC Converter Classes
#Handles conversion of MAEC v2.1/CybOX v1.0 draft content to MAEC v3.0/CybOX v1.0 final compatible content
#Supports Analyses, Behaviors, Actions, and Objects
#v0.1 BETA

import maec_2_1 #bindings
import maec_bundle_3_0 as maec_bundle #bindings
import maec_package_1_0 as maec_package #bindings
import cybox_1_0_draft.process_object_1_2 as process_object_1_2 #bindings
import cybox_1_0_final.win_driver_object_1_2 as win_driver_object_1_2 #bindings
import cybox_1_0_final.file_object_1_3 as file_object_1_3 #bindings
import cybox_1_0_final.user_account_object_1_2 as user_account_object_1_2 #bindings
import cybox_1_0_final.cybox_core_1_0 as cybox_core #bindings
import sys
import traceback

class converter(object):
    def __init__(self, infilename, outfilename, verbose_mode, output_mode = None):
        #Input parameters
        self.infilename = infilename
        self.outfilename = outfilename
        self.verbose_mode = verbose_mode
        self.output_mode = output_mode
        #Private class members
        self.__maec21_bundle = None
        self.__subject_object = None
        self.__namespace = None
        self.__package = None
        self.__maec30_bundle = None
        #The various containers for MAEC Bundle Entities
        self.__analyses = maec_package.AnalysisListType()
        self.__behaviors = maec_bundle.BehaviorListType()
        self.__behavior_collections = maec_bundle.BehaviorCollectionListType()
        self.__actions = maec_bundle.ActionListType()
        self.__action_collections = maec_bundle.ActionCollectionListType()
        self.__objects = maec_bundle.ObjectListType()
        self.__object_collections = maec_bundle.ObjectCollectionListType()
        #A list of the Object types in the document for defining the namespaces, namespace prefixes, and schemalocations
        self.__object_types = []
        self.__object_type_dependencies = []

    #Convert the input MAEC v2.1 file to MAEC v3.0
    #This assumes that the Bundle carries Analyses for the same malware instance
    def convert_maec(self):
        #Parse the input file and get the MAEC Bundle
        try:
            self.__maec21_bundle = maec_2_1.parse(self.infilename)
        except:
             print 'Error occurred when parsing the input MAEC v2.1 XML file'
             if self.verbose_mode:
                 traceback.print_exc()
        try:
            #Find the namespace based on the bundle ID
            self.__get_namespace()
            #Handle any analyses embedded in the Bundle
            self.__handle_analyses()
            #Handle any behaviors embedded in the Bundle
            self.__handle_behaviors()
            #Handle any actions embedded in the Bundle
            self.__handle_actions()
            #Handle any objects embedded in the Bundle
            self.__handle_objects()
            #Create the corresponding MAEC Bundle to be embedded in the Malware Subject in the Package
            self.__create_bundle()
            #Create the corresponding MAEC Package with a single embedded Malware Subject
            self.__create_package()
        except:
           if self.verbose_mode:
                 traceback.print_exc()
        try:
            #Export the Package or Bundle to the output file
            outfile = file(self.outfilename, 'w')
            self.__export_to_file(outfile)
        except:
           if self.verbose_mode:
                 traceback.print_exc()

    #Export the MAEC Data to the specified file
    def __export_to_file(self, outfile):
        #First, write the XML instance declaration
        outfile.write('<?xml version="1.0" encoding="UTF-8"?>\n')
        #Write the Package or Bundle
        if self.output_mode is not None:
            if self.output_mode == 'package':
                if self.verbose_mode:sys.stdout.write('Forcing MAEC Package output.\n')
                if self.__subject_object is not None:
                    if self.verbose_mode:sys.stdout.write('Exporting MAEC Package to ' +  self.outfilename + '...')
                    self.__package.export(outfile, 0, namespacedef_=self.__build_namespaces_schemalocations('package'))
                    if self.verbose_mode:sys.stdout.write('done.\n')
                else:
                    sys.stdout.write('Error: Cannot export to MAEC Package due to missing malware instance object data.\n')
            elif self.output_mode == 'bundle':
                if self.verbose_mode:sys.stdout.write('Forcing MAEC Bundle output.\n')
                if self.verbose_mode:sys.stdout.write('Exporting MAEC Bundle to ' +  self.outfilename + '...')
                self.__maec30_bundle.export(outfile, 0, namespacedef_=self.__build_namespaces_schemalocations('bundle'))
                if self.verbose_mode:sys.stdout.write('done.\n')
        else:
            if self.__subject_object is not None:
                if self.verbose_mode:sys.stdout.write('Exporting MAEC Package to ' +  self.outfilename + '...')
                self.__package.export(outfile, 0, namespacedef_=self.__build_namespaces_schemalocations('package'))
                if self.verbose_mode:sys.stdout.write('done.\n')
            else:
                if self.verbose_mode:sys.stdout.write('Exporting MAEC Bundle to ' +  self.outfilename + '...')
                self.__maec30_bundle.export(outfile, 0, namespacedef_=self.__build_namespaces_schemalocations('bundle'))
                if self.verbose_mode:sys.stdout.write('done.\n')

    #Handle and process the Behaviors contained in the Bundle
    def __handle_behaviors(self):
        #Process any top-level objects
        self.__handle_top_level_behaviors()
        #Process any collections of objects
        self.__handle_behavior_collections()

    #Handle and process any Behaviors in the top-level <Behaviors> element
    def __handle_top_level_behaviors(self):
        if self.__maec21_bundle.get_Behaviors() is not None:
            for behavior in self.__maec21_bundle.get_Behaviors().get_Behavior():
                maec30_behavior = self.__handle_behavior(behavior)
                if maec30_behavior.hasContent_():
                    self.__behaviors.add_Behavior(maec30_behavior)

    def __handle_behavior_collections(self):
        if self.__maec21_bundle.get_Collections() is not None:
            behavior_collections = self.__maec21_bundle.get_Collections().get_Behavior_Collections()
            if behavior_collections is not None:
                for behavior_collection in behavior_collections.get_Behavior_Collection():
                    maec30_behavior_collection = maec_bundle.BehaviorCollectionType()
                    #Add any existing attributes/elements from the old collection
                    self.__handle_base_collection(behavior_collection, maec30_behavior_collection)
                    maec30_behavior_list = maec_bundle.BehaviorListType()
                    behavior_list = behavior_collection.get_Behavior_List()
                    for behavior in behavior_list.get_Behavior():
                        maec30_behavior_list.add_Behavior(self.__handle_behavior(behavior))
                    maec30_behavior_collection.set_Behavior_List(maec30_behavior_list)
                    #Add it to the list
                    self.__behavior_collections.add_Behavior_Collection(maec30_behavior_collection)

    #Handle an individual Behavior
    def __handle_behavior(self, behavior):
        maec30_behavior = maec_bundle.BehaviorType(id=behavior.get_id())
        #Set the attributes
        if behavior.get_ordinal_position() is not None:
            maec30_behavior.set_ordinal_position(behavior.get_ordinal_position())
        if behavior.get_status() is not None:
            maec30_behavior.set_status(behavior.get_status())
        if behavior.get_duration() is not None:
            maec30_behavior.set_duration(behavior.get_duration())
        #Set the elements
        if behavior.get_Purpose() is not None:
            maec30_behavior.set_Purpose(behavior.get_Purpose())
        if behavior.get_Description() is not None:
            maec30_behavior.set_Description(behavior.get_Description())
        if behavior.get_Discovery_Method() is not None:
            maec30_behavior.set_Discovery_Method(behavior.get_Discovery_Method())
        if behavior.get_Actions() is not None:
            maec30_action_composition = maec_bundle.BehavioralActionsType()
            if behavior.get_Actions().get_Action() is not None:
                for action in behavior.get_Actions().get_Action():
                    maec30_action_composition.add_Action(self.__handle_action(action))
            if behavior.get_Actions().get_Action_Reference() is not None:
                for action_reference in behavior.get_Actions().get_Action_Reference():
                    maec30_action_composition.add_Action_Reference(action_reference)
            if behavior.get_Actions().get_Action_Collection() is not None:
                for action_collection in behavior.get_Actions().get_Action_Collection():
                    maec30_action_composition.add_Action_Collection(self.__handle_action_collection(action_collection))
            if maec30_action_composition.hasContent_():
                maec30_behavior.set_Action_Composition(maec30_action_composition)
        if behavior.get_Associated_Code() is not None:
            maec30_behavior.set_Associated_Code(behavior.get_Associated_Code())
        if behavior.get_Relationships() is not None:
            maec30_relationships = maec_bundle.BehaviorRelationshipListType()
            for relationship in behavior.get_Relationships().get_Relationship():
                maec30_relationship = maec_bundle.BehaviorRelationshipType(type_=relationship.get_type())
                for behavior_reference in relationship.get_Behavior_Reference():
                    maec30_behavior_reference = maec_bundle.BehaviorReferenceType(behavior_idref = behavior_reference.get_behavior_id())
                    maec30_relationship.add_Behavior_Reference(maec30_behavior_reference)
                maec30_relationships.add_Relationship(maec30_relationship)
            if maec30_relationships.hasContent_():
                maec30_behavior.set_Relationships(maec30_relationships)
        if maec30_behavior.hasContent_():
            return maec30_behavior

    #Handle and process the Objects contained in the Bundle
    def __handle_objects(self):
        #Process any top-level objects
        self.__handle_top_level_objects()
        #Process any collections of objects
        self.__handle_object_collections()

    #Handle and process any Objects in the top-level <Objects> element
    def __handle_top_level_objects(self):
        if self.__maec21_bundle.get_Objects() is not None:
            for object in self.__maec21_bundle.get_Objects().get_Object():
                maec30_object = self.__handle_object(object)
                if maec30_object.hasContent_():
                    self.__objects.add_Object(maec30_object)

    #Handle and process any object collections
    def __handle_object_collections(self):
        if self.__maec21_bundle.get_Collections() is not None:
            object_collections = self.__maec21_bundle.get_Collections().get_Object_Collections()
            if object_collections is not None:
                for object_collection in object_collections.get_Object_Collection():
                    maec30_object_collection = maec_bundle.ObjectCollectionType()
                    #Add any existing attributes/elements from the old collection
                    self.__handle_base_collection(object_collection, maec30_object_collection)
                    maec30_object_list = maec_bundle.ObjectListType()
                    object_list = object_collection.get_Object_List()
                    for object in object_list.get_Object():
                        maec30_object_list.add_Object(self.__handle_object(object))
                    maec30_object_collection.set_Object_List(maec30_object_list)
                    #Add it to the list
                    self.__object_collections.add_Object_Collection(maec30_object_collection)

    #Handle an individual Object
    def __handle_object(self, object):
        #Modify/set the Object type, if necessary
        if object.get_type() is not None:
            if object.get_type() == 'Key/Key Group':
                object.set_type('Registry Key/Key Group')
            elif object.get_type() == 'Hive':
                object.set_type('Registry Hive')
            elif object.get_type() == 'Dialog':
                object.set_type('GUI Dialobox')
            elif object.get_type() == 'Window':
                object.set_type('GUI Window')
        #Modify/set the domain-specific object attributes (AV Classification), if necessary
        if object.get_Domain_specific_Object_Attributes() is not None:
            av_classifications = object.get_Domain_specific_Object_Attributes()
            maec30_avclassifications = maec_bundle.AVClassificationsType()
            maec30_avclassifications.set_anyAttributes_({'xsi:type':'maecBundle:AVClassificationsType'})
            maec30_domain_specific = maec_bundle.cybox_core_1_0.DomainSpecificObjectAttributesType()
            for av_classification in av_classifications.get_AV_Classification():
                maec30_avclassifications.add_AV_Classification(av_classification)
            object.set_Domain_specific_Object_Attributes(maec30_avclassifications)
        if object.get_Defined_Object() is not None:
            #Check the xsi:type of the object to see if it is one of the ones that have been changed in cybox v1.0 final
            any_attributes = object.get_Defined_Object().get_anyAttributes_()
            for key, value in any_attributes.items():
                if key == '{http://www.w3.org/2001/XMLSchema-instance}type':
                    type_value = value.split(':')[1]
                    #Reset the xsi:type to align with the current set of namespace prefixes
                    namespace_prefix = cybox_core.defined_objects.get(type_value).get('namespace_prefix')
                    namespace_prefix_type = namespace_prefix + ':' + type_value
                    object.get_Defined_Object().set_anyAttributes_({'xsi:type' : namespace_prefix_type})
                    self.__add_object_namespace(type_value)
                    if 'ProcessObjectType' in type_value:
                        process_object = object.get_Defined_Object()
                        if process_object.get_Path() is not None:
                            path = process_object.get_Path()
                            process_object.set_Path(None)
                            if process_object.get_Image_Info() is not None:
                                process_object.get_Image_Info().set_Path(path)
                            else:
                                image_info = process_object_1_2.ImageInfoType()
                                image_info.set_Path(path)
                                process_object.set_Image_Info(image_info)
                        if process_object.get_Current_Working_Directory() is not None:
                            working_directory = process_object.get_Current_Working_Directory()
                            process_object.set_Current_Working_Directory(None)
                            if process_object.get_Image_Info() is not None:
                                process_object.get_Image_Info().set_Current_Directory(working_directory)
                            else:
                                image_info = process_object_1_2.ImageInfoType()
                                image_info.set_Current_Directory(working_directory)
                                process_object.set_Image_Info(image_info)
                        return object
                    elif type_value == 'UserAccountObjectType' or type_value == 'WindowsUserAccountObjectType':
                        user_account_object = object.get_Defined_Object()
                        user_account_object.set_User_ID(None)
                        return object
            return object
        #If there's no Defined Object (which would be odd), just return the object
        else:
            return object

    #Handle and process the actions contained in the Bundle
    def __handle_actions(self):
        #Process any top-level actions
        self.__handle_top_level_actions()
        #Process any collections of actions
        self.__handle_action_collections()

    #Handle and process any actions in the top-level <Actions> element
    def __handle_top_level_actions(self):
        if self.__maec21_bundle.get_Actions() is not None:
            for action in self.__maec21_bundle.get_Actions().get_Action():
                maec30_action = self.__handle_action(action)
                if maec30_action.hasContent_():
                    self.__actions.add_Action(maec30_action)

    #Handle and process any action collections
    def __handle_action_collections(self):
        if self.__maec21_bundle.get_Collections() is not None:
            action_collections = self.__maec21_bundle.get_Collections().get_Action_Collections()
            if action_collections is not None:
                for action_collection in action_collections.get_Action_Collection():
                    maec30_action_collection = self.__handle_action_collection(action_collection)
                    #Add it to the list
                    self.__action_collections.add_Action_Collection(maec30_action_collection)

    #Handle an individual Action Collection
    def __handle_action_collection(self, action_collection):
        maec30_action_collection = maec_bundle.ActionCollectionType()
        #Add any existing attributes/elements from the old collection
        self.__handle_base_collection(action_collection, maec30_action_collection)
        maec30_action_list = maec_bundle.ActionListType()
        action_list = action_collection.get_Action_List()
        for action in action_list.get_Action():
            maec30_action_list.add_Action(self.__handle_action(action))
        maec30_action_collection.set_Action_List(maec30_action_list)
        return maec30_action_collection

    #Handle an individual Action
    def __handle_action(self, action):
        maec30_action = maec_bundle.MalwareActionType()
        #Convert the existing action to its new MAEC v3.0 equivalent
        if action.get_id() is not None:
            maec30_action.set_id(action.get_id())
            maec30_action.set_type(action.get_type())
            #Set the attributes
            if action.get_ordinal_position() is not None:
                maec30_action.set_ordinal_position(action.get_ordinal_position())
            if action.get_action_status() is not None:
                maec30_action.set_action_status(action.get_action_status())
            if action.get_context() is not None:
                maec30_action.set_context(action.get_context())
            if action.get_network_protocol() is not None:
                maec30_action.set_network_protocol(action.get_network_protocol())
            if action.get_timestamp() is not None:
                maec30_action.set_timestamp(action.get_timestamp())
            #Set the elements
            if action.get_Action_Name() is not None:
                action_name = action.get_Action_Name()
                if action_name.get_Defined_Name() is not None:
                    maec30_action.set_name(action_name.get_Defined_Name())
                elif action_name.get_Undefined_Name() is not None:
                    maec30_action.set_undefined_name(action_name.get_Undefined_Name())
            if action.get_Description() is not None:
                maec30_action.set_Description(action.get_Description())
            if action.get_Action_Aliases() is not None:
                maec30_action.set_Action_Aliases(action.get_Action_Aliases())
            if action.get_Action_Arguments() is not None:
                action_arguments = action.get_Action_Arguments()
                maec30_action_arguments = maec_bundle.cybox_core_1_0.ActionArgumentsType()
                for action_argument in action_arguments.get_Action_Argument():
                    maec30_action_argument = maec_bundle.cybox_core_1_0.ActionArgumentType()
                    if action_argument.get_Argument_Name_Defined() is not None:
                        maec30_action_argument.set_defined_argument_name(action_argument.get_Argument_Name_Defined())
                    elif action_argument.get_Argument_Name_Undefined() is not None:
                        maec30_action_argument.set_undefined_argument_name(action_argument.get_Argument_Name_Undefined())
                    if action_argument.get_Argument_Value() is not None:
                        maec30_action_argument.set_argument_value(action_argument.get_Argument_Value())
                    if maec30_action_argument.hasContent_():
                        maec30_action_arguments.add_Action_Argument(maec30_action_argument)
                if maec30_action_arguments.hasContent_():
                    maec30_action.set_Action_Arguments(maec30_action_arguments)
            if action.get_Discovery_Method() is not None:
                #Corner case - if there's only one analysis and one tool referenced in it, then we don't need to set the discovery method
                if len(self.__analyses.get_Analysis()) == 1:
                    if self.__analyses.get_Analysis()[0].get_Tools() is not None and len(self.__analyses.get_Analysis()[0].get_Tools().get_Tool()) == 1:
                        pass
                    else:
                        maec30_action.set_Discovery_Method(action.get_Discovery_Method())
                else:
                    maec30_action.set_Discovery_Method(action.get_Discovery_Method())
            if action.get_Associated_Objects() is not None:
                maec30_associated_objects = maec_bundle.cybox_core_1_0.AssociatedObjectsType()
                for associated_object in action.get_Associated_Objects().get_Associated_Object():
                    maec30_associated_object = self.__handle_object(associated_object)
                    if maec30_associated_object is not None:
                        maec30_associated_objects.add_Associated_Object(maec30_associated_object)
                if maec30_associated_objects.hasContent_():
                    maec30_action.set_Associated_Objects(maec30_associated_objects)
            if action.get_Relationships() is not None:
                maec30_action.set_Relationships(action.get_Relationships())
            if action.get_Frequency() is not None:
                maec30_action.set_Frequency(action.get_Frequency())
            if action.get_Implementation() is not None:
                maec30_implementation = maec_bundle.ActionImplementationType(type_ = action.get_Implementation().get_type())
                if action.get_Implementation().get_id() is not None:
                    maec30_implementation.set_id(action.get_Implementation().get_id())
                if action.get_Implementation().get_Compatible_Platforms() is not None:
                    maec30_platform_list = maec_bundle.PlatformListType()
                    for platform in action.get_Implementation().get_Compatible_Platforms().get_Platform():
                        maec30_platform_list.add_Platform(platform)
                    if maec30_platform_list.hasContent_():
                        maec30_implementation.set_Compatible_Platforms(maec30_platform_list)
                if action.get_Implementation().get_Code() is not None:
                    for code_snippet in action.get_Implementation().get_Code():
                        maec30_implementation.add_Code(code_snippet)
                if maec30_implementation.hasContent_():
                    action.set_Implementation(maec30_implementation)
        elif action.get_idref() is not None:
            maec30_action.set_idref(action.get_idref())
        return maec30_action

    #Handle a base collection (the attributes/elements common to all Collection types)
    def __handle_base_collection(self, maec21_collection, maec30_collection):
        maec30_collection.set_id(maec21_collection.get_id())
        if maec21_collection.get_name() is not None:
            maec30_collection.set_name(maec21_collection.get_name())
        if maec21_collection.get_Affinity_Type() is not None:
            maec30_collection.set_Affinity_Type(maec21_collection.get_Affinity_Type())
        if maec21_collection.get_Affinity_Degree() is not None:
            maec30_collection.set_Affinity_Degree(maec21_collection.get_Affinity_Degree())
        if maec21_collection.get_Description() is not None:
            maec30_collection.set_Description(maec21_collection.get_Description())

    #Handle and process the analyses contained in the Bundle
    def __handle_analyses(self):
        if self.__maec21_bundle.get_Analyses() is not None:
            for analysis in self.__maec21_bundle.get_Analyses().get_Analysis():
                analysis_counter = 1
                maec30_analysis = self.__handle_analysis(analysis)
                analysis_counter += 1
                #If this is the only Analysis, add a Findings Bundle Reference to it
                if len(self.__maec21_bundle.get_Analyses().get_Analysis()) == 1:
                    findings_bundle_reference = maec_bundle.BundleReferenceType(bundle_idref = self.__maec21_bundle.get_id())
                    maec30_analysis.set_Findings_Bundle_Reference(findings_bundle_reference)
                #Add the Analysis to the list
                self.__analyses.add_Analysis(maec30_analysis)
    
    #Handle an individual analysis
    def __handle_analysis(self, analysis):
        maec30_analysis = maec_package.AnalysisType()
        #Grab the analysis subject
        subject = analysis.get_Subject()
        #Try to get the object corresponding to the analysis subject if not already set
        if self.__subject_object == None:
            if subject.get_Object() is not None:
                self.__subject_object = self.__handle_object(subject.get_Object())
            elif subject.get_Object_Reference() is not None:
                #Find the Object being referenced
                self.__subject_object = self.__handle_object(self.__find_object(subject.get_Object_Reference().get_object_id()))
            elif subject.get_URL() is not None:
                self.__subject_object = self.get_URL()
        #Go through and handle each of the Analysis objects and add them to the new Analysis
        #Attributes
        if analysis.get_id() is not None:
            maec30_analysis.set_id(analysis.get_id())
        else:
            #Give the analysis an ID if it doesn't have one
            analysis_id = 'maec-' + self.__namespace + '-ana-' + str(analysis_counter)
            maec30_analysis.set_id(analysis_id)
        if analysis.get_type() is not None:
            if 'Manual' in analysis.get_type():
                maec30_analysis.set_type('Manual')
            else:
                maec30_analysis.set_type(analysis.get_type())
        if analysis.get_method() is not None:
            if 'Combinat' in analysis.get_method():
                maec30_analysis.set_method('Combination')
            else:
                maec30_analysis.set_method(analysis.get_method())
        if analysis.get_start_datetime() is not None:
            maec30_analysis.set_start_datetime(analysis.get_start_datetime())
        if analysis.get_complete_datetime() is not None:
            maec30_analysis.set_complete_datetime(analysis.get_complete_datetime())
        if analysis.get_lastupdate_datetime() is not None:
            maec30_analysis.set_lastupdate_datetime(analysis.get_lastupdate_datetime())
        #Elements
        if analysis.get_Comments() is not None:
            maec30_analysis.set_Comments(analysis.get_Comments())
        if analysis.get_Summary() is not None:
            maec30_analysis.set_Summary(analysis.get_Summary())
        if analysis.get_Analysts() is not None:
            maec30_analysis.set_Analysts(analysis.get_Analysts())
        if analysis.get_Source() is not None:
            source = maec_package.SourceType()
            if analysis.get_Source().get_Name() is not None:
                source.set_Name(analysis.get_Source().get_Name())
            if analysis.get_Source().get_Method() is not None:
                source.set_Method(analysis.get_Source().get_Method())
            if analysis.get_Source().get_Reference() is not None:
                source.set_Reference(analysis.get_Source().get_Reference())
            if analysis.get_Source().get_Organization() is not None:
                source.set_Organization(analysis.get_Source().get_Organization())
            if analysis.get_Source().get_URL() is not None:
                value = analysis.get_Source().get_URL().get_Value().get_valueOf_()
                source.set_URL(value)
            maec30_analysis.set_Source(source)
        if analysis.get_Tools() is not None:
            maec30_tools = maec_package.ToolListType()
            for tool in analysis.get_Tools().get_Tool():
                maec30_tools.add_Tool(tool)
            if maec30_tools.hasContent_():
                maec30_analysis.set_Tools(maec30_tools)
        if analysis.get_Report() is not None:
            maec30_analysis.set_Report(analysis.get_Report())
        if analysis.get_Analysis_Environment() is not None:
            analysis_environment = maec_package.AnalysisEnvironmentType()
            if analysis.get_Analysis_Environment().get_Host_System() is not None:
                if analysis.get_Analysis_Environment().get_Host_System().get_Virtual_Machine() is not None:
                    hypervisor_system = maec_package.HypervisorHostSystemType(VM_Hypervisor = analysis.get_Analysis_Environment().get_Host_System().get_Virtual_Machine())
                    analysis_environment.set_Hypervisor_Host_System(hypervisor_system)
                else:
                    analysis_environment.set_Hypervisor_Host_System(analysis.get_Analysis_Environment().get_Host_System())
            if analysis.get_Analysis_Environment().get_Analysis_Systems() is not None:
                analysis_environment.set_Analysis_Systems(analysis.get_Analysis_Environment().get_Analysis_Systems())
            maec30_analysis.set_Analysis_Environment(analysis_environment)
        return maec30_analysis

    #Find and return a referenced object. This assumes it's not embedded in a Behavior or Action.
    def __find_action(self, action_id):
        if self.__maec21_bundle.get_Objects() is not None:
            for action in self.__maec21_bundle.get_Actions().get_Action():
                if action.get_id() == action_id:
                    return action
        if self.__maec21_bundle.get_Collections() is not None:
            if self.__maec21_bundle.get_Collections().get_Action_Collections() is not None:
                for action_collection in self.__maec21_bundle.get_Collections().get_Action_Collections().get_Action_Collection():
                    self.__find_action_in_collection(action_collection, action_id)

    #Find a referenced object in an object collection; recurse if necessary
    def __find_action_in_collection(self, action_collection, action_id):
        action_list = object_collection.get_Action_List()
        if action_list.get_Action() is not None:
            for object in object_list.get_Obt():
                if object.get_id() == object_id:
                    return object
        if object_list.get_Object_Collection() is not None:
            for object_collection in object_list.get_Object_Collection():
                self.__find_object_in_collection(object_collection, object_id)

    #Find and return a referenced object. This assumes it's not embedded in a Behavior or Action.
    def __find_object(self, object_id):
        if self.__maec21_bundle.get_Objects() is not None:
            for object in self.__maec21_bundle.get_Objects().get_Object():
                if object.get_id() == object_id:
                    return object
        if self.__maec21_bundle.get_Collections() is not None:
            if self.__maec21_bundle.get_Collections().get_Object_Collections() is not None:
                for object_collection in self.__maec21_bundle.get_Collections().get_Object_Collections().get_Object_Collection():
                    self.__find_object_in_collection(object_collection, object_id)

    #Find a referenced object in an object collection; recurse if necessary
    def __find_object_in_collection(self, object_collection, object_id):
        object_list = object_collection.get_Object_List()
        if object_list.get_Object() is not None:
            for object in object_list.get_Obt():
                if object.get_id() == object_id:
                    return object
        if object_list.get_Object_Collection() is not None:
            for object_collection in object_list.get_Object_Collection():
                self.__find_object_in_collection(object_collection, object_id)

    #Get the namespace based on the Bundle ID
    def __get_namespace(self):
        self.__namespace = self.__maec21_bundle.get_id().split('-')[1]

    def __create_package(self):
        #Setup the IDs
        package_id = 'maec-' + self.__namespace + '-pkg-1'
        subject_id = 'maec-' + self.__namespace + '-sub-1'
        #Create the Package
        package = maec_package.PackageType(id=package_id, schema_version=1.0)
        #Create the Subject List
        malware_subjects = maec_package.MalwareSubjectListType()
        #Create the Subject
        malware_subject = maec_package.MalwareSubjectType(id = subject_id)
        #Set its Malware Instance Object Attributes with the subject object we found
        malware_subject.set_Malware_Instance_Object_Attributes(self.__subject_object)
        #Add the analyses to the Subject
        if self.__analyses.hasContent_():
            malware_subject.set_Analyses(self.__analyses)
        #Add the previously created Bundle to the Findings Bundles and then add them to the Subject
        findings_bundles = maec_package.FindingsBundleListType()
        findings_bundles.add_Bundle(self.__maec30_bundle)
        malware_subject.set_Findings_Bundles(findings_bundles)
        #Add the Subject to the list and then add the list to the Package
        malware_subjects.add_Malware_Subject(malware_subject)
        package.set_Malware_Subjects(malware_subjects)
        #Set the Package as the class member
        self.__package = package

    def __create_bundle(self):
        #Create the MAEC Bundle
        bundle = maec_bundle.BundleType(defined_subject = False, id = self.__maec21_bundle.get_id(), schema_version=3.0)
        collections = maec_bundle.CollectionsType()
        #Add the top-level Behaviors from those previously extracted
        if self.__behaviors.hasContent_():
            bundle.set_Behaviors(self.__behaviors)
        #Add the top-level Objects from those previously extracted
        if self.__objects.hasContent_():
            bundle.set_Objects(self.__objects)
        #Add the top-level Actions from those previously extracted
        if self.__actions.hasContent_():
            bundle.set_Actions(self.__actions)
        #Add any collections
        if self.__behavior_collections.hasContent_():
            collections.set_Behavior_Collections(self.__behavior_collections)
        if self.__object_collections.hasContent_():
            collections.set_Object_Collections(self.__object_collections)
        if self.__action_collections.hasContent_():
            collections.set_Action_Collections(self.__action_collections)
        if collections.hasContent_():
            bundle.set_Collections(collections)
        #If the output mode is being forced to Bundle, add the Malware Instance Object Attributes
        if self.output_mode == 'bundle' and self.__subject_object is not None:
            bundle.set_Malware_Instance_Object_Attributes(self.__subject_object)
            bundle.set_defined_subject('True')
        #Set the Bundle as the class member
        self.__maec30_bundle = bundle

    #Build the namespace/schemalocation declaration string
    def __build_namespaces_schemalocations(self, mode):
        output_string = '\n '
        schemalocs = []
        #Add the XSI and CybOX Core/Common namespaces and schemalocation
        output_string += 'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" \n '
        if mode == 'package':
            output_string += 'xmlns:maecPackage="http://maec.mitre.org/XMLSchema/maec-package-1" \n '
        output_string += 'xmlns:maecBundle="http://maec.mitre.org/XMLSchema/maec-bundle-3" \n '
        output_string += 'xmlns:metadata="http://xml/metadataSharing.xsd" \n '
        output_string += 'xmlns:cybox="http://cybox.mitre.org/cybox_v1" \n '
        output_string += 'xmlns:Common="http://cybox.mitre.org/Common_v1" \n '
        if mode == 'package':
            schemalocs.append('http://maec.mitre.org/XMLSchema/maec-package-1 http://maec.mitre.org/language/version3.0/maec-package-schema.xsd')
        elif mode == 'bundle':
            schemalocs.append('http://maec.mitre.org/XMLSchema/maec-bundle-3 http://maec.mitre.org/language/version3.0/maec-bundle-schema.xsd')
        for object_type in self.__object_types:
            namespace_prefix = cybox_core.defined_objects.get(object_type).get('namespace_prefix')
            namespace = cybox_core.defined_objects.get(object_type).get('namespace')
            output_string += ('xmlns:' + namespace_prefix + '=' + '"' + namespace + '"' + ' \n ')
        for object_type_dependency in self.__object_type_dependencies:
            if object_type_dependency not in self.__object_types:
                namespace_prefix = cybox_core.defined_objects.get(object_type_dependency).get('namespace_prefix')
                namespace = cybox_core.defined_objects.get(object_type_dependency).get('namespace')
                output_string += ('xmlns:' + namespace_prefix + '=' + '"' + namespace + '"' + ' \n ')
        output_string += 'xsi:schemaLocation="'
        for object_type in self.__object_types:
            namespace = cybox_core.defined_objects.get(object_type).get('namespace')
            schemalocation = cybox_core.defined_objects.get(object_type).get('schemalocation')
            schemalocs.append(' ' + namespace + ' ' + schemalocation)
        for schemalocation_string in schemalocs:
            if schemalocs.index(schemalocation_string) == (len(schemalocs) - 1):
                output_string += (schemalocation_string + '"')
            else:
                output_string += (schemalocation_string + '\n')
        return output_string

    #Add the object type to the list of object (namespace) types
    def __add_object_namespace(self, object_type):
        if object_type not in self.__object_types:
            #Add the object type
            self.__object_types.append(object_type)
            #Add any dependencies
            if cybox_core.defined_objects.get(object_type).get('dependencies') is not None:
                dependencies = cybox_core.defined_objects.get(object_type).get('dependencies').split(',')
                for dependency in dependencies:
                    if dependency not in self.__object_type_dependencies:
                        self.__object_type_dependencies.append(dependency)