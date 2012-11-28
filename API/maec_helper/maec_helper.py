#MAEC Helper Classes - a rough cut at a MAEC API

#Copyright (c) 2012, The MITRE Corporation
#All rights reserved.

#Compatible with MAEC v3.0
#Last updated 11/27/2012

import maec_bundle_3_0 as maecbundle
import maec_package_1_0 as maecpackage
import cybox.file_object_1_3 as file_object
import cybox.socket_object_1_4 as socket_object
import cybox.process_object_1_3 as process_object
import cybox.address_object_1_2 as address_object
import cybox.uri_object_1_2 as uri_object
import cybox.win_process_object_1_3 as win_process_object
import cybox.win_registry_key_object_1_3 as win_registry_object
import cybox.win_mutex_object_1_2 as win_mutex_object
import cybox.win_driver_object_1_2 as win_driver_object
import cybox.win_service_object_1_3 as win_service_object
import cybox.win_pipe_object_1_2 as win_pipe_object
import cybox.win_file_object_1_3 as win_file_object
import cybox.memory_object_1_2 as memory_object
import cybox.library_object_1_3 as library_object
import cybox.win_kernel_hook_object_1_3 as win_kernel_hook_object
import cybox.port_object_1_3 as port_object
import cybox.uri_object_1_2 as uri_object
import cybox.win_mailslot_object_1_2 as win_mailslot_object
import cybox.win_handle_object_1_3 as win_handle_object
import cybox.win_thread_object_1_3 as win_thread_object
import cybox.win_task_object_1_3 as win_task_object
import cybox.win_system_object_1_2 as win_system_object
import cybox.win_user_account_object_1_3 as win_user_object
import cybox.win_network_share_object_1_3 as win_network_share_object
import cybox.win_executable_file_object_1_3 as win_executable_file_object
import datetime
        
class generator:
    def __init__(self, namespace):
        self.namespace = namespace
        self.general_id_base = 0
        self.pkg_id_base = 0
        self.sub_id_base = 0
        self.bnd_id_base = 0
        self.act_id_base = 0
        self.bhv_id_base = 0
        self.obj_id_base = 0
        self.ana_id_base = 0
        self.tol_id_base = 0
        self.eff_id_base = 0
        self.api_id_base = 0
        self.cde_id_base = 0
        self.imp_id_base = 0
        self.dat_id_base = 0
        self.actc_id_base = 0
        self.bhvc_id_base = 0
        self.effc_id_base = 0
        self.objc_id_base = 0
        self.avclass_id_base = 0
        
    #Methods for generating unique ids
    def generate_id(self):
        self.general_id_base += 1
        return self.general_id_base

    def generate_pkg_id(self):
        self.pkg_id_base += 1
        return 'maec-' + self.namespace + '-pkg-' + str(self.pkg_id_base)

    def generate_sub_id(self):
        self.sub_id_base += 1
        return 'maec-' + self.namespace + '-sub-' + str(self.sub_id_base)
    
    def generate_bnd_id(self):
        self.bnd_id_base += 1
        return 'maec-' + self.namespace + '-bnd-' + str(self.bnd_id_base)
    
    def generate_act_id(self):
        self.act_id_base += 1
        return 'maec-' + self.namespace + '-act-' + str(self.act_id_base)
    
    def generate_bhv_id(self):
        self.bhv_id_base += 1
        return 'maec-' + self.namespace + '-bhv-' + str(self.bhv_id_base)
    
    def generate_obj_id(self):
        self.obj_id_base += 1
        return 'maec-' + self.namespace + '-obj-' + str(self.obj_id_base)
    
    def generate_ana_id(self):
        self.ana_id_base += 1
        return 'maec-' + self.namespace + '-ana-' + str(self.ana_id_base)
    
    def generate_tol_id(self):
        self.tol_id_base += 1
        return 'maec-' + self.namespace + '-tol-' + str(self.tol_id_base)
        
    def generate_eff_id(self):
        self.eff_id_base += 1
        return 'maec-' + self.namespace + '-eff-' + str(self.eff_id_base)
        
    def generate_api_id(self):
        self.api_id_base += 1
        return 'maec-' + self.namespace + '-api-' + str(self.api_id_base)
        
    def generate_cde_id(self):
        self.cde_id_base += 1
        return 'maec-' + self.namespace + '-cde-' + str(self.cde_id_base)
        
    def generate_imp_id(self):
        self.imp_id_base += 1
        return 'maec-' + self.namespace + '-imp-' + str(self.imp_id_base)
        
    def generate_dat_id(self):
        self.dat_id_base += 1
        return 'maec-' + self.namespace + '-dat-' + str(self.dat_id_base)
        
    def generate_actc_id(self):
        self.actc_id_base += 1
        return 'maec-' + self.namespace + '-actc-' + str(self.actc_id_base)

    def generate_bhvc_id(self):
        self.bhvc_id_base += 1
        return 'maec-' + self.namespace + '-bhvc-' + str(self.bhvc_id_base)
        
    def generate_effc_id(self):
        self.effc_id_base += 1
        return 'maec-' + self.namespace + '-effc-' + str(self.effc_id_base)

    def generate_objc_id(self):
        self.objc_id_base += 1
        return 'maec-' + self.namespace + '-objc-' + str(self.objc_id_base)

    def generate_avclass_id(self):
        self.avclass_id_base += 1
        return 'mmdef-class-' + str(self.avclass_id_base)
    
    #Methods for getting current id bases
    def get_current_obj_id(self):
        return self.obj_id_base

class maec_package:
    def __init__(self, generator, schema_version):
        self.generator = generator
        #Create the MAEC Package object
        self.package = maecpackage.PackageType(id=self.generator.generate_pkg_id())
        #Set the schema version
        self.package.set_schema_version(schema_version)
        #Create the subject list
        self.subjects = maecpackage.MalwareSubjectListType()
        #Create the namespace and schemalocation declarations
        self.namespace_prefixes = {'xmlns:maecPackage' : '"http://maec.mitre.org/XMLSchema/maec-package-1"',
                                   'xmlns:maecBundle' : '"http://maec.mitre.org/XMLSchema/maec-bundle-3"',
                                   'xmlns:cybox' : '"http://cybox.mitre.org/cybox_v1"',
                                   'xmlns:Common' : '"http://cybox.mitre.org/Common_v1"',
                                   'xmlns:mmdef' : '"http://xml/metadataSharing.xsd"',
                                   'xmlns:xsi' : '"http://www.w3.org/2001/XMLSchema-instance"'}
        self.schemalocations = {'http://maec.mitre.org/XMLSchema/maec-package-1' : 'maec-package-schema.xsd',
                                'http://maec.mitre.org/XMLSchema/maec-bundle-3' :  'maec-bundle-schema.xsd',
                                'http://cybox.mitre.org/Common_v1' : 'http://cybox.mitre.org/XMLSchema/cybox_common_types_v1.0.xsd',
                                'http://cybox.mitre.org/cybox_v1' : 'http://cybox.mitre.org/XMLSchema/cybox_core_v1.0.xsd',
                                'http://xml/metadataSharing.xsd' : 'http://grouper.ieee.org/groups/malware/malwg/Schema1.2/metadataSharing.xsd'}

    #Public methods

    #Add a malware subject
    def add_malware_subject(self, malware_subject):
        self.subjects.add_Malware_Subject(malware_subject)
    
    #Set the grouping relationship based on an input dictionary
    def set_grouping_relationship(self, grouping_relationship_attributes):
        for key, value in grouping_relationship_attributes.items():
            pass

    #Add a namespace to the namespaces list
    def add_namespace(self, namespace_prefix, namespace):
        self.namespace_prefixes[namespace_prefix] = '"' + namespace + '"'

    #Add a schemalocation to the schemalocation list
    def add_schemalocation(self, namespace, schemalocation):
        self.schemalocations[namespace] = schemalocation

    #Get the package
    def get_object(self):
        self.__build__()
        return self.package

    #Export the package and its contents to an XML file
    def export_to_file(self, outfilename):
        self.__build__()
        outfile = open(outfilename, 'w')
        self.package.export(outfile, 0, namespacedef_=self.__build_samespaces_schemalocations())


    #Private methods

    #Build the package, adding any list or other items
    def __build__(self):
        if self.subjects.hasContent_():
            self.package.set_Malware_Subjects(self.subjects)

    #Build the namespace/schemalocation declaration string
    def __build_samespaces_schemalocations(self):
        output_string = '\n '
        schemalocs = []
        first_string = True
        for namespace_prefix, namespace in self.namespace_prefixes.items():
            output_string += (namespace_prefix + '=' + namespace + ' \n ')
        output_string += 'xsi:schemaLocation="'
        for namespace, schemalocation in self.schemalocations.items():
            if first_string:
                schemalocs.append(namespace + ' ' + schemalocation)
                first_string = False
            else:
                schemalocs.append(' ' + namespace + ' ' + schemalocation)
        for schemalocation_string in schemalocs:
            if schemalocs.index(schemalocation_string) == (len(schemalocs) - 1):
                output_string += (schemalocation_string + '"\n')
            else:
                output_string += (schemalocation_string + '\n')
        return output_string

class maec_subject:
    def __init__(self, generator, schema_version):
        self.generator = generator
        #Create the MAEC Subject object
        self.subject = maecpackage.MalwareSubjectType(id=self.generator.generate_sub_id())
        #Instantiate the lists
        self.analyses = maecpackage.AnalysisListType()
        self.findings_bundles = maecpackage.FindingsBundleListType()
        #Create the namespace and schemalocation declarations
        self.namespace_prefixes = {'xmlns:maecPackage' : '"http://maec.mitre.org/XMLSchema/maec-package-1"',
                                   'xmlns:maecBundle' : '"http://maec.mitre.org/XMLSchema/maec-bundle-3"',
                                   'xmlns:cybox' : '"http://cybox.mitre.org/cybox_v1"',
                                   'xmlns:Common' : '"http://cybox.mitre.org/Common_v1"',
                                   'xmlns:mmdef' : '"http://xml/metadataSharing.xsd"',
                                   'xmlns:xsi' : '"http://www.w3.org/2001/XMLSchema-instance"'}
        self.schemalocations = {'http://maec.mitre.org/XMLSchema/maec-package-1' : 'maec-package-schema.xsd',
                                'http://maec.mitre.org/XMLSchema/maec-bundle-3' :  'maec-bundle-schema.xsd',
                                'http://cybox.mitre.org/Common_v1' : 'http://cybox.mitre.org/XMLSchema/cybox_common_types_v1.0.xsd',
                                'http://cybox.mitre.org/cybox_v1' : 'http://cybox.mitre.org/XMLSchema/cybox_core_v1.0.xsd',
                                'http://xml/metadataSharing.xsd' : 'http://grouper.ieee.org/groups/malware/malwg/Schema1.2/metadataSharing.xsd'}


    #Public methods
    #Set the subject_attributes with a CybOX object
    def set_subject_attributes(self, subject_object):
        self.subject.set_Subject_Attributes(subject_object)

    #Add an Analysis to the Analyses
    def add_analysis(self, analysis):
        self.analyses.add_Analysis(analysis)

    #Add a MAEC Bundle to the Findings Bundles
    def add_findings_bundle(self, findings_bundle):
        self.findings_bundles.add_Bundle(findings_bundle)

    #Add a namespace to the namespaces list
    def add_namespace(self, namespace_prefix, namespace):
        self.namespace_prefixes[namespace_prefix] = '"' + namespace + '"'

    #Add a schemalocation to the schemalocation list
    def add_schemalocation(self, namespace, schemalocation):
        self.schemalocations[namespace] = schemalocation

    #Get the Malware Subject
    def get_object(self):
        self.__build__()
        return self.subject

    #Export the Malware Subject and its contents to an XML file
    def export_to_file(self, outfilename):
        self.__build__()
        outfile = open(outfilename, 'w')
        self.subject.export(outfile, 0, namespacedef_=self.__build_samespaces_schemalocations())
    
    #Private methods

    #Build the Subject, adding any list or other items
    def __build__(self):
        if self.analyses.hasContent_():
            self.subject.set_Analyses(self.analyses)
        if self.findings_bundles.hasContent_():
            self.subject.set_Findings_Bundles(self.findings_bundles)

    #Build the namespace/schemalocation declaration string
    def __build_samespaces_schemalocations(self):
        output_string = '\n '
        schemalocs = []
        first_string = True
        for namespace_prefix, namespace in self.namespace_prefixes.items():
            output_string += (namespace_prefix + '=' + namespace + ' \n ')
        output_string += 'xsi:schemaLocation="'
        for namespace, schemalocation in self.schemalocations.items():
            if first_string:
                schemalocs.append(namespace + ' ' + schemalocation)
                first_string = False
            else:
                schemalocs.append(' ' + namespace + ' ' + schemalocation)
        for schemalocation_string in schemalocs:
            if schemalocs.index(schemalocation_string) == (len(schemalocs) - 1):
                output_string += (schemalocation_string + '"\n')
            else:
                output_string += (schemalocation_string + '\n')
        return output_string

class maec_bundle:
    def __init__(self, generator, schema_version, defined_subject, content_type = None, subject_attributes = None):
        self.generator = generator
        #Create the MAEC Bundle object
        self.bundle = maecbundle.BundleType(id=self.generator.generate_bnd_id())
        #Set the bundle schema version
        self.bundle.set_schema_version(schema_version)
        #Set the bundle timestamp
        self.bundle.set_timestamp(datetime.datetime.now().isoformat())
        #Set whether this Bundle has a defined_subject
        self.bundle.set_defined_subject(defined_subject)
        #Set the content_type if it is not none
        if content_type is not None:
            self.bundle.set_content_type(content_type)
        #Set the subject attributes (a CybOX object) if they are not none
        if subject_attributes is not None:
            self.bundle.set_Subject_Attributes(subject_attributes)
        #Create the top-level objects
        self.objects = maecbundle.ObjectListType()
        #Create the MAEC collections object
        self.collections = maecbundle.CollectionsType()
        #Create the object collections
        self.object_collections = maecbundle.ObjectCollectionListType()
        #Create the action collections
        self.action_collections = maecbundle.ActionCollectionListType()
        #Create the analyses
        self.analyses = maecpackage.AnalysisListType()
        #Create the object collections
        self.process_object_collection = maecbundle.ObjectCollectionType(name='Process Objects', id=self.generator.generate_objc_id())
        self.process_object_collection.set_Description('This collection encompasses the chain of processes spawned by the subject binary.')

        #Create the action collections
        self.filesystem_action_collection = maecbundle.ActionCollectionType(id=self.generator.generate_actc_id(), name="File System Actions")
        self.ipc_action_collection = maecbundle.ActionCollectionType(id=self.generator.generate_actc_id(), name="IPC Actions")
        self.service_action_collection = maecbundle.ActionCollectionType(id=self.generator.generate_actc_id(), name="Service Actions")
        self.process_action_collection = maecbundle.ActionCollectionType(id=self.generator.generate_actc_id(), name="Process Actions")
        self.registry_action_collection = maecbundle.ActionCollectionType(id=self.generator.generate_actc_id(), name="Registry Actions")
        self.network_action_collection = maecbundle.ActionCollectionType(id=self.generator.generate_actc_id(), name="Network Actions")
        self.memory_action_collection = maecbundle.ActionCollectionType(id=self.generator.generate_actc_id(), name="Memory Actions")
        self.module_action_collection = maecbundle.ActionCollectionType(id=self.generator.generate_actc_id(), name="Module Actions")
        self.system_action_collection = maecbundle.ActionCollectionType(id=self.generator.generate_actc_id(), name="System Actions")
        self.internet_action_collection = maecbundle.ActionCollectionType(id=self.generator.generate_actc_id(), name="Internet Actions")
        self.filemapping_action_collection = maecbundle.ActionCollectionType(id=self.generator.generate_actc_id(), name="Filemapping Actions")
        self.thread_action_collection = maecbundle.ActionCollectionType(id=self.generator.generate_actc_id(), name="Thread Actions")
        self.sysobject_action_collection = maecbundle.ActionCollectionType(id=self.generator.generate_actc_id(), name="System Object Actions")
        self.driver_action_collection = maecbundle.ActionCollectionType(id=self.generator.generate_actc_id(), name="Driver Actions")
        self.user_action_collection = maecbundle.ActionCollectionType(id=self.generator.generate_actc_id(), name="User Actions")
        self.networkshare_action_collection = maecbundle.ActionCollectionType(id=self.generator.generate_actc_id(), name="Network Share Actions")

    #"Public" methods
    def add_process_object(self, object):
        self.process_object_collection.add_Object(object)
        
    def add_action(self, action, action_group):
        if action_group == 'file_system':
            if self.filesystem_action_collection.get_Action_List() is not None:
                self.filesystem_action_collection.get_Action_List().add_Action(action)
            else:
                action_list = maecbundle.ActionListType()
                action_list.add_Action(action)
                self.filesystem_action_collection.set_Action_List(action_list)
        elif action_group == 'ipc':
            if self.ipc_action_collection.get_Action_List() is not None:
                self.ipc_action_collection.get_Action_List().add_Action(action)
            else:
                action_list = maecbundle.ActionListType()
                action_list.add_Action(action)
                self.ipc_action_collection.set_Action_List(action_list)
        elif action_group == 'service':
            if self.service_action_collection.get_Action_List() is not None:
                self.service_action_collection.get_Action_List().add_Action(action)
            else:
                action_list = maecbundle.ActionListType()
                action_list.add_Action(action)
                self.service_action_collection.set_Action_List(action_list)
        elif action_group == 'registry':
            if self.registry_action_collection.get_Action_List() is not None:
                self.registry_action_collection.get_Action_List().add_Action(action)
            else:
                action_list = maecbundle.ActionListType()
                action_list.add_Action(action)
                self.registry_action_collection.set_Action_List(action_list)
        elif action_group == 'network':
            if self.network_action_collection.get_Action_List() is not None:
                self.network_action_collection.get_Action_List().add_Action(action)
            else:
                action_list = maecbundle.ActionListType()
                action_list.add_Action(action)
                self.network_action_collection.set_Action_List(action_list)
        elif action_group == 'memory':
            if self.memory_action_collection.get_Action_List() is not None:
                self.memory_action_collection.get_Action_List().add_Action(action)
            else:
                action_list = maecbundle.ActionListType()
                action_list.add_Action(action)
                self.memory_action_collection.set_Action_List(action_list)        
        elif action_group == 'process':
            if self.process_action_collection.get_Action_List() is not None:
                self.process_action_collection.get_Action_List().add_Action(action)
            else:
                action_list = maecbundle.ActionListType()
                action_list.add_Action(action)
                self.process_action_collection.set_Action_List(action_list)        
        elif action_group == 'module':
            if self.module_action_collection.get_Action_List() is not None:
                self.module_action_collection.get_Action_List().add_Action(action)
            else:
                action_list = maecbundle.ActionListType()
                action_list.add_Action(action)
                self.module_action_collection.set_Action_List(action_list)            
        elif action_group == 'system':
            if self.system_action_collection.get_Action_List() is not None:
                self.system_action_collection.get_Action_List().add_Action(action)
            else:
                action_list = maecbundle.ActionListType()
                action_list.add_Action(action)
                self.system_action_collection.set_Action_List(action_list)     
        elif action_group == 'internet':
            if self.internet_action_collection.get_Action_List() is not None:
                self.internet_action_collection.get_Action_List().add_Action(action)
            else:
                action_list = maecbundle.ActionListType()
                action_list.add_Action(action)
                self.internet_action_collection.set_Action_List(action_list)
        elif action_group == 'filemapping':
            if self.filemapping_action_collection.get_Action_List() is not None:
                self.filemapping_action_collection.get_Action_List().add_Action(action)
            else:
                action_list = maecbundle.ActionListType()
                action_list.add_Action(action)
                self.filemapping_action_collection.set_Action_List(action_list)
        elif action_group == 'thread':
            if self.thread_action_collection.get_Action_List() is not None:
                self.thread_action_collection.get_Action_List().add_Action(action)
            else:
                action_list = maecbundle.ActionListType()
                action_list.add_Action(action)
                self.thread_action_collection.set_Action_List(action_list)
        elif action_group == 'sysobject':
            if self.sysobject_action_collection.get_Action_List() is not None:
                self.sysobject_action_collection.get_Action_List().add_Action(action)
            else:
                action_list = maecbundle.ActionListType()
                action_list.add_Action(action)
                self.sysobject_action_collection.set_Action_List(action_list)
        elif action_group == 'driver':
            if self.driver_action_collection.get_Action_List() is not None:
                self.driver_action_collection.get_Action_List().add_Action(action)
            else:
                action_list = maecbundle.ActionListType()
                action_list.add_Action(action)
                self.driver_action_collection.set_Action_List(action_list) 
        elif action_group == 'user':
            if self.user_action_collection.get_Action_List() is not None:
                self.user_action_collection.get_Action_List().add_Action(action)
            else:
                action_list = maecbundle.ActionListType()
                action_list.add_Action(action)
                self.user_action_collection.set_Action_List(action_list)
        elif action_group == 'share':
            if self.networkshare_action_collection.get_Action_List() is not None:
                self.networkshare_action_collection.get_Action_List().add_Action(action)
            else:
                action_list = maecbundle.ActionListType()
                action_list.add_Action(action)
                self.networkshare_action_collection.set_Action_List(action_list)
        elif action_group == 'module':
            if self.module_action_collection.get_Action_List() is not None:
                self.module_action_collection.get_Action_List().add_Action(action)
            else:
                action_list = maecbundle.ActionListType()
                action_list.add_Action(action)
                self.module_action_collection.set_Action_List(action_list)                             
    
    def add_actions(self, actions, action_group):
        if action_group == 'file_system':
            for action in actions:
                self.filesystem_action_collection.get_Action_List().add_Action(action)
        elif action_group == 'ipc':
            for action in actions:
                self.ipc_action_collection.get_Action_List().add_Action(action)
        elif action_group == 'service':
            for action in actions:
                self.service_action_collection.get_Action_List().add_Action(action)
        elif action_group == 'registry':
            for action in actions:
                self.registry_action_collection.get_Action_List().add_Action(action)
        elif action_group == 'network':
            for action in actions:
                self.network_action_collection.get_Action_List().add_Action(action)
        elif action_group == 'memory':
            for action in actions:
                self.memory_action_collection.get_Action_List().add_Action(action)           
        elif action_group == 'process':
            for action in actions:
                self.process_action_collection.get_Action_List().add_Action(action)            
        elif action_group == 'module':
            for action in actions:
                self.module_action_collection.get_Action_List().add_Action(action)            
        elif action_group == 'system':
            for action in actions:
                self.system_action_collection.get_Action_List().add_Action(action) 
        elif action_group == 'internet':
            for action in actions:
                self.internet_action_collection.get_Action_List().add_Action(action)
        elif action_group == 'filemapping':
            for action in actions:
                self.filemapping_action_collection.get_Action_List().add_Action(action)
            
    def add_object(self, object, action_group = None):
        if action_group == 'process':
            if self.process_object_collection.get_Object_List() is not None:
                self.process_object_collection.get_Object_List().add_Object(object)
            else:
                object_list = maecbundle.ObjectListType()
                object_list.add_Object(object)
                self.process_object_collection.set_Object_List(object_list)
        elif action_group == None:
            self.objects.add_Object(object)
            
    def add_objects(self, objects, action_group):        
        if action_group == 'process':
            for object in objects:
                self.process_object_collection.get_Object_List().add_Object(object)            
                                   
    #Build the MAEC bundle by adding all applicable elements
    def build_maecbundle(self):
        #Add the collections to their respective pools
        #Add the action collections
        if self.filesystem_action_collection.hasContent_(): self.action_collections.add_Action_Collection(self.filesystem_action_collection)
        if self.ipc_action_collection.hasContent_(): self.action_collections.add_Action_Collection(self.ipc_action_collection)
        if self.service_action_collection.hasContent_(): self.action_collections.add_Action_Collection(self.service_action_collection)
        if self.registry_action_collection.hasContent_(): self.action_collections.add_Action_Collection(self.registry_action_collection)
        if self.network_action_collection.hasContent_(): self.action_collections.add_Action_Collection(self.network_action_collection)
        if self.memory_action_collection.hasContent_(): self.action_collections.add_Action_Collection(self.memory_action_collection)
        if self.process_action_collection.hasContent_(): self.action_collections.add_Action_Collection(self.process_action_collection)
        if self.module_action_collection.hasContent_(): self.action_collections.add_Action_Collection(self.module_action_collection)
        if self.system_action_collection.hasContent_(): self.action_collections.add_Action_Collection(self.system_action_collection)
        if self.internet_action_collection.hasContent_(): self.action_collections.add_Action_Collection(self.internet_action_collection)
        if self.filemapping_action_collection.hasContent_(): self.action_collections.add_Action_Collection(self.filemapping_action_collection)
        if self.thread_action_collection.hasContent_(): self.action_collections.add_Action_Collection(self.thread_action_collection)
        if self.sysobject_action_collection.hasContent_(): self.action_collections.add_Action_Collection(self.sysobject_action_collection)
        if self.driver_action_collection.hasContent_(): self.action_collections.add_Action_Collection(self.driver_action_collection)
        if self.user_action_collection.hasContent_(): self.action_collections.add_Action_Collection(self.user_action_collection)
        if self.networkshare_action_collection.hasContent_(): self.action_collections.add_Action_Collection(self.networkshare_action_collection)
        #Add the objects
        if self.objects.hasContent_() : self.bundle.set_Objects(self.objects)
        #Add the object collections
        if self.process_object_collection.get_Object_List(): self.object_collections.add_Object_Collection(self.process_object_collection)
        #Add everything to the collections
        if self.object_collections.hasContent_() : self.collections.set_Object_Collections(self.object_collections)
        if self.action_collections.hasContent_() : self.collections.set_Action_Collections(self.action_collections)
        #Add the collections
        if self.collections.hasContent_():
            self.bundle.set_Collections(self.collections)
    
    #Export the MAEC bundle and its contents to an XML file
    def export(self, outfilename):
        filename = outfilename
        outfile = open(filename, 'w')
        print ("Exporting MAEC Bundle to: " + filename)
        self.bundle.export(outfile, 0, namespacedef_='xmlns:mmdef="http://xml/metadataSharing.xsd"\
        xmlns:maecBundle="http://maec.mitre.org/XMLSchema/maec-bundle-3"\
        xmlns:cybox="http://cybox.mitre.org/cybox_v1"\
        xmlns:Common="http://cybox.mitre.org/Common_v1"\
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"\
        xmlns:SystemObj="http://cybox.mitre.org/objects#SystemObject"\
        xmlns:FileObj="http://cybox.mitre.org/objects#FileObject"\
        xmlns:ProcessObj="http://cybox.mitre.org/objects#ProcessObject"\
        xmlns:PipeObj="http://cybox.mitre.org/objects#PipeObject"\
        xmlns:PortObj="http://cybox.mitre.org/objects#PortObject"\
        xmlns:AddressObj="http://cybox.mitre.org/objects#AddressObject"\
        xmlns:SocketObj="http://cybox.mitre.org/objects#SocketObject"\
        xmlns:MutexObj="http://cybox.mitre.org/objects#MutexObject"\
        xmlns:MemoryObj="http://cybox.mitre.org/objects#MemoryObject"\
        xmlns:LibraryObj="http://cybox.mitre.org/objects#LibraryObject"\
        xmlns:UserAccountObj="http://cybox.mitre.org/objects#UserAccountObject"\
        xmlns:URIObj="http://cybox.mitre.org/objects#URIObject"\
        xmlns:WinMutexObj="http://cybox.mitre.org/objects#WinMutexObject"\
        xmlns:WinServiceObj="http://cybox.mitre.org/objects#WinServiceObject"\
        xmlns:WinRegistryKeyObj="http://cybox.mitre.org/objects#WinRegistryKeyObject"\
        xmlns:WinPipeObj="http://cybox.mitre.org/objects#WinPipeObject"\
        xmlns:WinDriverObj="http://cybox.mitre.org/objects#WinDriverObject"\
        xmlns:WinFileObj="http://cybox.mitre.org/objects#WinFileObject"\
        xmlns:WinExecutableFileObj="http://cybox.mitre.org/objects#WinExecutableFileObject"\
        xmlns:WinMailslotObj="http://cybox.mitre.org/objects#WinMailslotObject"\
        xmlns:WinProcessObj="http://cybox.mitre.org/objects#WinProcessObject"\
        xmlns:WinHandleObj="http://cybox.mitre.org/objects#WinHandleObject"\
        xmlns:WinThreadObj="http://cybox.mitre.org/objects#WinThreadObject"\
        xmlns:WinTaskObj="http://cybox.mitre.org/objects#WinThreadObject"\
        xmlns:WinSystemObj="http://cybox.mitre.org/objects#WinSystemObject"\
        xmlns:WinNetworkShareObj="http://cybox.mitre.org/objects#WinNetworkShareObject"\
        xmlns:WinUserAccountObj="http://cybox.mitre.org/objects#WinUserAccountObject"\
        xsi:schemaLocation="http://cybox.mitre.org/Common_v1 http://cybox.mitre.org/XMLSchema/cybox_common_types_v1.0.xsd\
        http://cybox.mitre.org/objects#SystemObject http://cybox.mitre.org/XMLSchema/objects/System/System_Object_1.3.xsd\
        http://cybox.mitre.org/cybox_v1 http://cybox.mitre.org/XMLSchema/cybox_core_v1.0.xsd\
        http://maec.mitre.org/XMLSchema/maec-bundle-3 http://maec.mitre.org/language/version3.0/maec-bundle-schema.xsd\
        http://cybox.mitre.org/objects#FileObject http://cybox.mitre.org/XMLSchema/objects/File/File_Object_1.3.xsd\
        http://cybox.mitre.org/objects#ProcessObject http://cybox.mitre.org/XMLSchema/objects/Process/Process_Object_1.3.xsd\
        http://cybox.mitre.org/objects#SocketObject http://cybox.mitre.org/XMLSchema/objects/Socket/Socket_Object_1.4.xsd\
        http://cybox.mitre.org/objects#MemoryObject http://cybox.mitre.org/XMLSchema/objects/Memory/Memory_Object_1.2.xsd\
        http://cybox.mitre.org/objects#LibraryObject http://cybox.mitre.org/XMLSchema/objects/Library/Library_Object_1.3.xsd\
        http://cybox.mitre.org/objects#WinMutexObject http://cybox.mitre.org/XMLSchema/objects/Win_Mutex/Win_Mutex_Object_1.2.xsd\
        http://cybox.mitre.org/objects#WinServiceObject http://cybox.mitre.org/XMLSchema/objects/Win_Service/Win_Service_Object_1.3.xsd\
        http://cybox.mitre.org/objects#WinRegistryKeyObject http://cybox.mitre.org/XMLSchema/objects/Win_Registry_Key/Win_Registry_Key_Object_1.3.xsd\
        http://cybox.mitre.org/objects#WinPipeObject http://cybox.mitre.org/XMLSchema/objects/Win_Pipe/Win_Pipe_Object_1.2.xsd\
        http://cybox.mitre.org/objects#WinDriverObject http://cybox.mitre.org/XMLSchema/objects/Win_Driver/Win_Driver_Object_1.2.xsd\
        http://cybox.mitre.org/objects#WinFileObject http://cybox.mitre.org/XMLSchema/objects/Win_File/Win_File_Object_1.3.xsd\
        http://cybox.mitre.org/objects#WinExecutableFileObject http://cybox.mitre.org/XMLSchema/objects/Win_Executable_File/Win_Executable_File_Object_1.3.xsd\
        http://cybox.mitre.org/objects#WinMailslotObject http://cybox.mitre.org/XMLSchema/objects/Win_Mailslot/Win_Mailslot_Object_1.2.xsd\
        http://cybox.mitre.org/objects#WinProcessObject http://cybox.mitre.org/XMLSchema/objects/Win_Process/Win_Process_Object_1.3.xsd\
        http://cybox.mitre.org/objects#WinHandleObject http://cybox.mitre.org/XMLSchema/objects/Win_Handle/Win_Handle_Object_1.3.xsd\
        http://cybox.mitre.org/objects#WinThreadObject http://cybox.mitre.org/XMLSchema/objects/Win_Thread/Win_Thread_Object_1.3.xsd\
        http://cybox.mitre.org/objects#WinTaskObject http://cybox.mitre.org/XMLSchema/objects/Win_Task/Win_Task_Object_1.3.xsd\
        http://cybox.mitre.org/objects#WinSystemObject http://cybox.mitre.org/XMLSchema/objects/Win_System/Win_System_Object_1.2.xsd\
        http://cybox.mitre.org/objects#WinNetworkShareObject http://cybox.mitre.org/XMLSchema/objects/Win_Network_Share/Win_Network_Share_Object_1.3.xsd\
        http://cybox.mitre.org/objects#WinUserAccountObject http://cybox.mitre.org/XMLSchema/objects/Win_User_Account/Win_User_Account_Object_1.3.xsd"')
        
    #accessor methods
    def get_object(self):
        return self.bundle

class maec_analysis:
    def __init__(self, generator, method = None, type = None):
        self.generator = generator
        self.analysis = maecpackage.AnalysisType(id=self.generator.generate_ana_id())
        if method is not None:
            self.analysis.set_method(method)
        if type is not None:
            self.analysis.set_type(type)
        self.tool_list = maecpackage.ToolListType()

    #"Public" methods
    def set_findings_bundle_reference(self, bundle_idref):
        bundle_reference = maecbundle.BundleReferenceType(bundle_idref = bundle_idref)
        self.analysis.set_Findings_Bundle_Reference(bundle_reference)

    def set_summary(self, summary):
        self.analysis.set_Summary(summary)
   
    def add_tool(self, tool_dictionary):
        self.__create_tool(tool_dictionary)

    def get_object(self):
        if self.tool_list.hasContent_():
            self.analysis.set_Tools(self.tool_list)
        return self.analysis
    
    #"Private" methods

    #Create the MAEC tool type
    def __create_tool(self, tool_dictionary):
        #Create the Tool and set its ID
        tool = maecpackage.cybox_common_types_1_0.ToolInformationType(id=self.generator.generate_tol_id())
        for key, value in tool_dictionary.items():
            if key.lower() == 'description':
                if value is not None and len(value) > 0:
                    tool.set_Description(value)
            elif key.lower() == 'vendor':
                if value is not None and len(value) > 0:
                    tool.set_Vendor(value)
            elif key.lower() == 'name':
                if value is not None and len(value) > 0:
                    tool.set_Name(value)  
            elif key.lower() == 'version':
                if value is not None and len(value) > 0:
                    tool.set_Version(value)
        if tool.hasContent_():
            self.tool_list.add_Tool(tool)
    
    def __build__(self):
        if self.tool_list.hasContent_():
            self.analysis.set_Tools(tool_list)      


class maec_action:
    def __init__(self, generator, action_attributes):
        self.generator = generator
        #Create the action type and add basic attributes
        self.action = maecbundle.MalwareActionType()
        self.action.set_id(self.generator.generate_act_id())
        self.associated_objects = maecbundle.cybox_core_1_0.AssociatedObjectsType()
        for key, value in action_attributes.items():
            if key == 'undefined_name':
                self.action.set_undefined_name(value)
            elif key == 'name':
                self.action.set_name(value)
            elif key == 'action_status':
                self.action.set_action_status(value)
            elif key == 'action_type':
                if value.count('/') > 0:
                    self.action.set_type(value)
                else:
                    self.action.set_type(value.capitalize())
            elif key == 'object':
                if value is not None and value.hasContent_():
                    self.associated_objects.add_Associated_Object(value)
            elif key == 'secondary_object':
                if value is not None and value.hasContent_():
                    self.associated_objects.add_Associated_Object(value)
            elif key == 'object_old':
                if value is not None and value.hasContent_():
                    self.associated_objects.add_Associated_Object(value)
            elif key == 'object_new':
                if value is not None and value.hasContent_():
                    self.associated_objects.add_Associated_Object(value)
            elif key == 'context':
                self.action.set_context(value)
            elif key == 'network_protocol':
                self.action.set_network_protocol(value)
            #elif key == 'tool_id':
            #    discovery_method = maec.common.MeasureSourceType()
            #    tools = maec.common.ToolsInformationType()
            #    tool=maec.common.ToolInformationType(idref=value)
            #    tools.add_Tool(tool)
            #    discovery_method.set_Tools(tools)
            #    action.set_Discovery_Method(discovery_method)
            elif key == 'action_arguments':
                action_arguments = maecbundle.cybox_core_1_0.ActionArgumentsType()
                for argument in value:
                    action_argument = maecbundle.cybox_core_1_0.ActionArgumentType()
                    for key, value in argument.items():
                        if key == 'defined_argument_name':
                            action_argument.set_defined_argument_name(value)
                        elif key == 'undefined_argument_name':
                            action_argument.set_undefined_argument_name(value)
                        elif key == 'argument_value':
                            action_argument.set_argument_value(value)
                    action_arguments.add_Action_Argument(action_argument)
                if action_arguments.hasContent_():
                    self.action.set_Action_Arguments(action_arguments)

        if associated_objects.hasContent_():
            self.action.set_Associated_Objects(associated_objects)
    
    #Getter methods
    def get_object(self):
        return self.action
            
class maec_object:
    def __init__(self, generator):
        self.generator = generator
            
    def create_socket_object(self, network_attributes):
        cybox_object = maecbundle.cybox_core_1_0.AssociatedObjectType(id=self.generator.generate_obj_id(), type_='Socket')
        socketobj = socket_object.SocketObjectType()
        socketobj.set_anyAttributes_({'xsi:type' : 'SocketObj:SocketObjectType'})
        remote_address = socket_object.SocketAddressType()
        local_address = socket_object.SocketAddressType()
        
        for key, value in network_attributes.items():
            if key == 'socket_type':
                if value == 'tcp':
                    socketobj.set_Type(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_='SOCK_STREAM'))
            elif key == 'remote_port':
                if self.__value_test(value) and value != '0':
                    port = socket_object.port_object.PortObjectType()
                    port.set_Port_Value(maecbundle.cybox_common_types_1_0.PositiveIntegerObjectAttributeType(datatype='PositiveInteger', valueOf_=maecbundle.quote_xml(value)))
                    remote_address.set_Port(port)
            elif key == 'remote_address':
                if self.__value_test(value) :
                    ip_address = socket_object.address_object.AddressObjectType(category='ipv4-addr')
                    ip_address.set_Address_Value(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_=maecbundle.quote_xml(value)))
                    remote_address.set_IP_Address(ip_address)
            elif key == 'local_port':
                if self.__value_test(value) and value != '0':
                    port = socket_object.port_object.PortObjectType()
                    port.set_Port_Value(maecbundle.cybox_common_types_1_0.PositiveIntegerObjectAttributeType(datatype='PositiveInteger', valueOf_=maecbundle.quote_xml(value)))
                    local_address.set_Port(port)
            elif key == 'local_address':
                if self.__value_test(value):
                    ip_address = socket_object.address_object.AddressObjectType(category='ipv4-addr')
                    ip_address.set_Address_Value(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_=maecbundle.quote_xml(value)))
                    local_address.set_IP_Address(ip_address)
            elif key == 'islistening':
                socketobj.set_is_listening(value)
            elif key == 'association':
                cybox_object.set_association_type(value)
        if remote_address.hasContent_():
            socketobj.set_Remote_Address(remote_address)
        if local_address.hasContent_():
            socketobj.set_Local_Address(local_address)
            
        if socketobj.hasContent_():
            cybox_object.set_Defined_Object(socketobj)
        
        return cybox_object

    def create_port_object(self, port_attributes):
        cybox_object = maecbundle.cybox_core_1_0.AssociatedObjectType(id=self.generator.generate_obj_id(), type_="Port")
        portobj = port_object.PortObjectType()
        portobj.set_anyAttributes_({'xsi:type' : 'PortObj:PortObjectType'})
        for key, value in port_attributes.items():
            if key == 'value':
                portobj.set_Port_Value(maecbundle.cybox_common_types_1_0.PositiveIntegerObjectAttributeType(datatype='PositiveInteger', valueOf_=maecbundle.quote_xml(value)))
            elif key == 'association':
                cybox_object.set_association_type(value)
                
        if portobj.hasContent_():
            cybox_object.set_Defined_Object(portobj)
        
        return cybox_object
            
    def create_library_object(self, library_attributes):
        cybox_object = maecbundle.cybox_core_1_0.AssociatedObjectType(id=self.generator.generate_obj_id(), type_="Module")
        libobject = library_object.LibraryObjectType()
        libobject.set_anyAttributes_({'xsi:type' : 'LibraryObj:LibraryObjectType'})
        
        for key, value in library_attributes.items():
            if key == 'name':
                if self.__value_test(value):
                    libobject.set_Name(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_=maecbundle.quote_xml(value)))
            elif key == 'path':
                if self.__value_test(value):
                    libobject.set_Path(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_=maecbundle.quote_xml(value)))
            elif key == 'association':
                cybox_object.set_association_type(value)
        
        if libobject.hasContent_():
            cybox_object.set_Defined_Object(libobject)
        
        return cybox_object

    def create_win_kernel_hook_object(selfself, hook_attributes):
        cybox_object = maecbundle.cybox_core_1_0.AssociatedObjectType(id=self.generator.generate_obj_id()) # type_="Hook"
        hookobject = win_kernel_hook_object.WindowsKernelHookObjectType()
        hookobject.set_anyAttributes_({'xsi:type' : 'WinKernelHookObj:WindowsKernelHookObjectType'})
        
        for key, value in hook_attributes.items():
            if key == 'function_name':
                if self.__value_test(value):
                    hookobject.set_Name(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_=maecbundle.quote_xml(value)))
            elif key == 'association':
                cybox_object.set_association_type(value)
        
        if hookobject.hasContent_():
            cybox_object.set_Defined_Object(hookobject)
        
        return cybox_object

    def create_address_object(self, address_attributes):
        cybox_object = maecbundle.cybox_core_1_0.AssociatedObjectType(id=self.generator.generate_obj_id(), type_="IP Address")
        addrobject = address_object.AddressObjectType()
        addrobject.set_anyAttributes_({'xsi:type' : 'AddressObj:AddressObjectType'})
        
        for key, value in address_attributes.items():
            if key == 'category':
                if self.__value_test(value):
                    addrobject.set_category(value)
            elif key == 'address_value':
                if self.__value_test(value):
                    addrobject.set_Address_Value(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_=maecbundle.quote_xml(value)))
            elif key == 'related_objects':
                related_objects = maecbundle.cybox_core_1_0.RelatedObjectsType()
                for related_object in value:
                    related_objects.add_Related_Object(related_object)
                if related_objects.hasContent_():
                    cybox_object.set_Related_Objects(related_objects)
            elif key == 'association':
                cybox_object.set_association_type(value)
        
        if addrobject.hasContent_():
            cybox_object.set_Defined_Object(addrobject)
        
        return cybox_object

    def create_uri_object(self, uri_attributes):
        cybox_object = maecbundle.cybox_core_1_0.AssociatedObjectType(id=self.generator.generate_obj_id(), type_="URI")
        uriobject = uri_object.URIObjectType()
        uriobject.set_anyAttributes_({'xsi:type' : 'URIObj:URIObjectType'})
        
        for key, value in uri_attributes.items():
            if key == 'type':
                if self.__value_test(value):
                    uriobject.set_type(value)
            elif key == 'value':
                if self.__value_test(value):
                    uriobject.set_Value(maecbundle.cybox_common_types_1_0.AnyURIObjectAttributeType(datatype='AnyURI', valueOf_=maecbundle.quote_xml(value)))
            elif key == 'related_objects':
                related_objects = maecbundle.cybox_core_1_0.RelatedObjectsType()
                for related_object in value:
                    related_objects.add_Related_Object(related_object)
                if related_objects.hasContent_():
                    cybox_object.set_Related_Objects(related_objects)
            elif key == 'association':
                cybox_object.set_association_type(value)
        
        if uriobject.hasContent_():
            cybox_object.set_Defined_Object(uriobject)
        
        return cybox_object

    def create_registry_object(self, registry_attributes):
        cybox_object = maecbundle.cybox_core_1_0.AssociatedObjectType(id=self.generator.generate_obj_id(), type_='Key/Key Group')
        reg_object = win_registry_object.WindowsRegistryKeyObjectType()
        reg_object.set_anyAttributes_({'xsi:type' : 'WinRegistryKeyObj:WindowsRegistryKeyObjectType'})
        registry_value = win_registry_object.RegistryValueType()
        #set object attributes
        for key, value in registry_attributes.items():
            if key == 'hive':
                if self.__value_test(value):
                    reg_object.set_Hive(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_=maecbundle.quote_xml(value)))
            elif key == 'key':
                if self.__value_test(value):
                    reg_object.set_Key(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String',valueOf_=maecbundle.quote_xml(value)))
            elif key == 'value':
                if self.__value_test(value):
                    registry_value.set_Name(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String',valueOf_=maecbundle.quote_xml(value)))
            elif key == 'valuedata':
                if self.__value_test(value):
                    registry_value.set_Data(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String',valueOf_=maecbundle.quote_xml(value)))
            elif key == 'valuedatatype':
                if self.__value_test(value):
                    registry_value.set_Datatype(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String',valueOf_=maecbundle.quote_xml(value)))
            elif key == 'association':
                cybox_object.set_association_type(value)
                
        if registry_value.hasContent_():
            reg_values = win_registry_object.RegistryValuesType()
            reg_values.add_Value(registry_value)
            reg_object.set_Values(reg_values)
        
        if reg_object.hasContent_():    
            cybox_object.set_Defined_Object(reg_object)
        
        return cybox_object
  
    def create_file_system_object(self, file_system_attributes):
        cybox_object = maecbundle.cybox_core_1_0.AssociatedObjectType(id=self.generator.generate_obj_id())
        fileobj = win_file_object.WindowsFileObjectType()
        fileobj.set_anyAttributes_({'xsi:type' : 'WinFileObj:WindowsFileObjectType'})
        cybox_object.set_type('File')
        fs_hashes = maecbundle.cybox_common_types_1_0.HashListType()
        for key, value in file_system_attributes.items():
            if key == 'md5':
                if self.__value_test(value):
                    hash_value = maecbundle.cybox_common_types_1_0.HexBinaryObjectAttributeType(datatype='hexBinary', valueOf_=maecbundle.quote_xml(value))
                    hash_type = maecbundle.cybox_common_types_1_0.HashNameType(datatype='String', valueOf_='MD5')
                    hash = maecbundle.cybox_common_types_1_0.HashType(Simple_Hash_Value=hash_value, Type=hash_type)
                    fs_hashes.add_Hash(hash)
            elif key == 'sha1':
                if self.__value_test(value):
                    hash_value = maecbundle.cybox_common_types_1_0.HexBinaryObjectAttributeType(datatype='hexBinary', valueOf_=maecbundle.quote_xml(value))
                    hash_type = maecbundle.cybox_common_types_1_0.HashNameType(datatype='String', valueOf_='SHA1')
                    hash = maecbundle.cybox_common_types_1_0.HashType(Simple_Hash_Value=hash_value, Type=hash_type)
                    fs_hashes.add_Hash(hash)
            elif key == 'packer':
                if self.__value_test(value):
                    packer_list = file_object.PackerListType()
                    packer = file_object.PackerAttributesType(Name=maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_=maecbundle.quote_xml(value)))
                    packer_list.add_Packer(packer)
                    fileobj.set_Packer_List(packer_list)
            elif key == 'av_aliases':
                cybox_object.set_Domain_specific_Object_Attributes(value)
            elif key == 'filename':
                if self.__value_test(value):
                    fileobj.set_File_Name(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_=maecbundle.quote_xml(value)))
            elif key == 'filepath':
                if self.__value_test(value):
                    filepath = maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_=maecbundle.quote_xml(value))
                    fileobj.set_File_Path(filepath)
            elif key == 'origin':
                if self.__value_test(value):
                    uriobj = uri_object.URIObjectType()
                    uriobj.set_anyAttributes_({'xsi:type' : 'URIObj:URIObjectType'})
                    uriobj.set_Value(maecbundle.cybox_common_types_1_0.AnyURIObjectAttributeType(datatype='AnyURI', valueOf_=maecbundle.quote_xml(value)))
                    related_objects = maecbundle.cybox_core_1_0.RelatedObjectsType()
                    related_object = maecbundle.cybox_core_1_0.RelatedObjectType(id=self.generator.generate_obj_id(), type_='URI')
                    related_object.set_Defined_Object(uriobj)
                    related_objects.add_Related_Object(related_object)
                    cybox_object.set_Related_Objects(related_objects)
            elif key == 'linkname':
                if self.__value_test(value):
                    sym_links = file_object.SymLinksListType()
                    sym_link = maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_=maecbundle.quote_xml(value))
                    sym_links.add_Sym_Link(sym_link)
                    fileobj.set_Sym_Links(sym_links)
            elif key == 'controlcode':
                if self.__value_test(value):
                    send_control_effect = maecbundle.cybox_core_1_0.SendControlCodeEffectType(effect_type='ControlCode_Sent', Control_Code=value)
                    send_control_effect.set_extensiontype_('cybox:SendControlCodeEffectType')
                    cybox_object.set_Defined_Effect(send_control_effect)
            elif key == 'related_object':
                if value is not None:
                    related_objects = maecbundle.cybox_core_1_0.RelatedObjectsType()
                    related_objects.add_Related_Object(value)
                    cybox_object.set_Related_Objects(related_objects)
            #elif key == 'file_attributes':
            #    file_attributes = win_file_object.WindowsFileAttributesType()
            #    for file_attribute in value:
            #        attribute = win_file_object.WindowsFileAttributeType(datatype='String', valueOf_=file_attribute)
            #        file_attributes.add_Attribute(attribute)
            #    if file_attributes.hasContent_():
            #        fileobj.set_File_Attributes_List(file_attributes)
            elif key == 'effect':
                effect = self.__create_data_effect(value, value.get('type'))
                if effect != None and effect.hasContent_():
                    cybox_object.set_Defined_Effect(effect)
            elif key == 'association':
                cybox_object.set_association_type(value)
                
        if fs_hashes.hasContent_():
            fileobj.set_Hashes(fs_hashes)
        
        if fileobj.hasContent_():
            cybox_object.set_Defined_Object(fileobj)

        return cybox_object
    
    def create_pipe_object(self, pipe_attributes):
        cybox_object = maecbundle.cybox_core_1_0.AssociatedObjectType(id=self.generator.generate_obj_id())
        pipeobj = win_pipe_object.WindowsPipeObjectType(named='True')
        pipeobj.set_anyAttributes_({'xsi:type' : 'WinPipeObj:WindowsPipeObjectType'})
        cybox_object.set_type('Pipe')
        
        for key, value in pipe_attributes.items():
            if key == 'name' or key == 'filename':
                if self.__value_test(value):
                    pipeobj.set_Name(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_=maecbundle.quote_xml(value)))
            elif key == 'controlcode':
                if self.__value_test(value):
                    send_control_effect = maecbundle.cybox_core_1_0.SendControlCodeEffectType(effect_type='ControlCode_Sent', Control_Code=value)
                    send_control_effect.set_extensiontype_('cybox:SendControlCodeEffectType')
                    cybox_object.set_Defined_Effect(send_control_effect)
            elif key == 'effect':
                effect = self.__create_data_effect(value, value.get('type'))
                if effect != None and effect.hasContent_():
                    cybox_object.set_Defined_Effect(effect)
            elif key == 'association':
                cybox_object.set_association_type(value)

        if pipeobj.hasContent_():
            cybox_object.set_Defined_Object(pipeobj)

        return cybox_object
    
    def create_process_object(self, process_attributes):
        cybox_object = maecbundle.cybox_core_1_0.AssociatedObjectType(id=self.generator.generate_obj_id(), type_='Process')
        proc_object = process_object.ProcessObjectType()
        proc_object.set_anyAttributes_({'xsi:type' : 'ProcessObj:ProcessObjectType'})
        
        image_info = process_object.ImageInfoType()
        for key, value in process_attributes.items():
            if key == 'name':
                continue
            elif key == 'filename':
                if self.__value_test(value):
                    proc_object.set_Path(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String',valueOf_=maecbundle.quote_xml(value)))
            elif key == 'command_line':
                if self.__value_test(value):
                    image_info.set_Command_Line(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String',valueOf_=maecbundle.quote_xml(value)))
            elif key == 'pid':
                if self.__value_test(value):
                    proc_object.set_PID(maecbundle.cybox_common_types_1_0.UnsignedIntegerObjectAttributeType(datatype='UnsignedInt', valueOf_=value))
            elif key == 'parentpid':
                if self.__value_test(value):
                    proc_object.set_Parent_PID(maecbundle.cybox_common_types_1_0.UnsignedIntegerObjectAttributeType(datatype='UnsignedInt', valueOf_=value))
            elif key == 'username':
                if self.__value_test(value):
                    proc_object.set_Username(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String',valueOf_=maecbundle.quote_xml(value)))
            elif key == 'start_time':
                if self.__value_test(value):
                    proc_object.set_Start_Time(maecbundle.cybox_common_types_1_0.DateTimeObjectAttributeType(datatype='DateTime',valueOf_=maecbundle.quote_xml(value)))
            elif key == 'association':
                cybox_object.set_association_type(value)
            elif key == 'av_classifications':
                cybox_object.set_Domain_specific_Object_Attributes(value)
                
        if image_info.hasContent_():
            proc_object.set_Image_Info(image_info)
        
        if proc_object.hasContent_():                                                                    
            cybox_object.set_Defined_Object(proc_object)
        
        return cybox_object
        
    def create_win_process_object(self, process_attributes):
        cybox_object = maecbundle.cybox_core_1_0.AssociatedObjectType(id=self.generator.generate_obj_id(), type_='Process')
        proc_object = win_process_object.WindowsProcessObjectType()
        proc_object.set_anyAttributes_({'xsi:type' : 'WinProcessObj:WindowsProcessObjectType'})
        section_list = win_process_object.MemorySectionListType()
        image_info = win_process_object.process_object.ImageInfoType()
        for key, value in process_attributes.items():
            if key == 'name':
                continue
            elif key == 'filename':
                if self.__value_test(value):
                    proc_object.set_Path(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String',valueOf_=maecbundle.quote_xml(value)))
            elif key == 'command_line':
                if self.__value_test(value):
                    image_info.set_Command_Line(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String',valueOf_=maecbundle.quote_xml(value)))
            elif key == 'pid':
                if self.__value_test(value):
                    proc_object.set_PID(maecbundle.cybox_common_types_1_0.UnsignedIntegerObjectAttributeType(datatype='UnsignedInt', valueOf_=value))
            elif key == 'parentpid':
                if self.__value_test(value):
                    proc_object.set_Parent_PID(maecbundle.cybox_common_types_1_0.UnsignedIntegerObjectAttributeType(datatype='UnsignedInt', valueOf_=value))
            elif key == 'username':
                if self.__value_test(value):
                    proc_object.set_Username(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String',valueOf_=maecbundle.quote_xml(value)))
            elif key == 'start_time':
                if self.__value_test(value):
                    proc_object.set_Start_Time(maecbundle.cybox_common_types_1_0.DateTimeObjectAttributeType(datatype='DateTime',valueOf_=maecbundle.quote_xml(value)))
            elif key == 'sid':
                if self.__value_test(value):
                    proc_object.set_Security_ID(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String',valueOf_=maecbundle.quote_xml(value)))
            elif key == 'sections':
                if self.__value_test(value):
                    for memory_section in value:
                        section_list.add_Memory_Section(memory_section)
                if section_list.hasContent_():
                    proc_object.set_Section_List(section_list)
            elif key == 'association':
                cybox_object.set_association_type(value)
                
        if image_info.hasContent_():
            proc_object.set_Image_Info(image_info)
        
        if proc_object.hasContent_():                                                                    
            cybox_object.set_Defined_Object(proc_object)

        return cybox_object

    def create_memory_object(self, memory_attributes):
        cybox_object = maecbundle.cybox_core_1_0.AssociatedObjectType(id=self.generator.generate_obj_id(), type_='Memory Page')
        mem_object = memory_object.MemoryObjectType()
        mem_object.set_anyAttributes_({'xsi:type' : 'MemoryObj:MemoryObjectType'})
        #set object attributes
        for key,value in memory_attributes.items():
            if key == 'address':
                if self.__value_test(value):
                    mem_object.set_Region_Start_Address(maecbundle.cybox_common_types_1_0.HexBinaryObjectAttributeType(datatype='hexBinary', valueOf_=maecbundle.quote_xml(value)))
            if key == 'size':
                if self.__value_test(value):
                    mem_object.set_Region_Size(maecbundle.cybox_common_types_1_0.UnsignedLongObjectAttributeType(datatype='UnsignedLong', valueOf_=value))
            elif key == 'association':
                cybox_object.set_association_type(value)
                
        if mem_object.hasContent_():
            cybox_object.set_Defined_Object(mem_object)
        
        return cybox_object
            
    def create_internet_object(self, internet_attributes):
        cybox_object = maecbundle.cybox_core_1_0.AssociatedObjectType(id=self.generator.generate_obj_id(), type_='URI')
        uriobj = uri_object.URIObjectType()
        uriobj.set_anyAttributes_({'xsi:type' : 'URIObj:URIObjectType'})
        #set object attributes
        for key, value in internet_attributes.items():
            if key == 'uri':
                if self.__value_test(value):
                    uriobj.set_Value(maecbundle.cybox_common_types_1_0.AnyURIObjectAttributeType(datatype='AnyURI', valueOf_=maecbundle.quote_xml(value)))
            elif key == 'association':
                cybox_object.set_association_type(value)
                
        if uriobj.hasContent_():
            cybox_object.set_Defined_Object(uriobj)
        
        return cybox_object
    
    def create_win_service_object(self, service_attributes):
        cybox_object = maecbundle.cybox_core_1_0.AssociatedObjectType(id=self.generator.generate_obj_id(), type_='Service/Daemon')
        serv_object = win_service_object.WindowsServiceObjectType()
        serv_object.set_anyAttributes_({'xsi:type' : 'WinServiceObj:WindowsServiceObjectType'})
        
        for key, value in service_attributes.items():
            if key == 'name' or key == 'service_name':
                if self.__value_test(value):
                    serv_object.set_Service_Name(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String',valueOf_=maecbundle.quote_xml(value)))
            elif key == 'display_name':
                if self.__value_test(value):
                    serv_object.set_Display_Name(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String',valueOf_=maecbundle.quote_xml(value)))
            elif key == 'startup_type':
                if self.__value_test(value):
                    serv_object.set_Startup_Type(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String',valueOf_=maecbundle.quote_xml(value)))
            elif key == 'service_type':
                if self.__value_test(value):
                    serv_object.set_Service_Type(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String',valueOf_=maecbundle.quote_xml(value)))
            elif key == 'started_as':
                if self.__value_test(value):
                    serv_object.set_Started_As(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String',valueOf_=maecbundle.quote_xml(value)))
            elif key == 'service_status':
                if self.__value_test(value):
                    serv_object.set_Service_Status(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String',valueOf_=maecbundle.quote_xml(value)))
            elif key == 'filename':
                continue #revisit
            elif key == 'controlcode':
                if self.__value_test(value):
                    send_control_effect = maecbundle.cybox_core_1_0.SendControlCodeEffectType(effect_type='ControlCode_Sent', Control_Code=value)
                    send_control_effect.set_extensiontype_('cybox:SendControlCodeEffectType')
                    cybox_object.set_Defined_Effect(send_control_effect)
            elif key == 'effect':
                effect_type = value.get('type')
                if effect_type == 'state change':
                    state_change_effect = self.__create_state_change_effect(value.get('new_defined_object'))
                    cybox_object.set_Defined_Effect(send_control_effect)
            elif key == 'association':
                cybox_object.set_association_type(value)
        
        if serv_object.hasContent_():        
            cybox_object.set_Defined_Object(serv_object)
        
        return cybox_object       

    def create_mutex_object(self, mutex_attributes):
        cybox_object = maecbundle.cybox_core_1_0.AssociatedObjectType(id=self.generator.generate_obj_id(), type_='Mutex')
        mutex_obj = win_mutex_object.WindowsMutexObjectType()
        mutex_obj.set_anyAttributes_({'xsi:type' : 'WinMutexObj:WindowsMutexObjectType'})
        
        for key, value in mutex_attributes.items():
            if key == 'name':
                if self.__value_test(value):
                    mutex_obj.set_Name(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String',valueOf_=maecbundle.quote_xml(value)))
                    mutex_obj.set_named(True)
            elif key == 'association':
                cybox_object.set_association_type(value)
        
        if mutex_obj.hasContent_():
            cybox_object.set_Defined_Object(mutex_obj)
        
        return cybox_object
    

    def create_win_driver_object(self, driver_attributes):
        cybox_object = maecbundle.cybox_core_1_0.AssociatedObjectType(id=self.generator.generate_obj_id(), type_='Other') #change type to driver once CybOX type enum is updated
        driver_obj = win_driver_object.WindowsDriverObjectType()
        driver_obj.set_anyAttributes_({'xsi:type' : 'WinDriverObj:WindowsDriverObjectType'})
        
        for key, value in driver_attributes.items():
            if key == 'name' or key == 'filename':
                if self.__value_test(value):
                    driver_obj.set_Driver_Name(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String',valueOf_=maecbundle.quote_xml(value)))
            elif key == 'association':
                cybox_object.set_association_type(value)
        
        if driver_obj.hasContent_():
            cybox_object.set_Defined_Object(driver_obj)
        
        return cybox_object
    
    def create_mailslot_object(self, mailslot_attributes):
        cybox_object = maecbundle.cybox_core_1_0.AssociatedObjectType(id=self.generator.generate_obj_id(), type_='Mailslot')
        mailslot_obj = win_mailslot_object.WindowsMailslotObjectType()
        mailslot_obj.set_anyAttributes_({'xsi:type' : 'WinMailslotObj:WindowsMailslotObjectType'})
        
        for key, value in mailslot_attributes.items():
            if key == 'name' or key == 'filename':
                if self.__value_test(value):
                    mailslot_obj.set_Name(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String',valueOf_=maecbundle.quote_xml(value)))
            elif key == 'association':
                cybox_object.set_association_type(value)
        
        if mailslot_obj.hasContent_():
            cybox_object.set_Defined_Object(mailslot_obj)
        
        return cybox_object

    def create_win_executable_file_object(self, win_executable_file_attributes):
        cybox_object = maecbundle.cybox_core_1_0.AssociatedObjectType(id=self.generator.generate_obj_id(), type_='File')
        win_executable_file_obj = win_executable_file_object.WindowsExecutableFileObjectType()
        win_executable_file_obj.set_anyAttributes_({'xsi:type' : 'WinExecutableFileObj:WindowsExecutableFileObjectType'})
        pe_attributes = win_executable_file_object.PEAttributesType()

        for key, value in win_executable_file_attributes.items():
            if key.lower() == 'peak_code_entropy' and self.__value_test(value):
                entropytype = win_executable_file_object.EntropyType()
                for entropy_key, entropy_value in value.items():
                    if entropy_key.lower() == 'value' and self.__value_test(entropy_value):
                        entropytype.set_Value(maecbundle.cybox_common_types_1_0.FloatObjectAttributeType(datatype='Float',valueOf_=entropy_value))
                    elif entropy_key.lower() == 'min' and self.__value_test(entropy_value):
                        entropytype.set_Min(maecbundle.cybox_common_types_1_0.FloatObjectAttributeType(datatype='Float',valueOf_=entropy_value))
                    elif entropy_key.lower() == 'max' and self.__value_test(entropy_value):
                        entropytype.set_Max(maecbundle.cybox_common_types_1_0.FloatObjectAttributeType(datatype='Float',valueOf_=entropy_value))
                if entropytype.hasContent_():
                    win_executable_file_obj.set_Peak_Code_Entropy(entropytype)
            elif key.lower() == 'pe_attributes' and self.__value_test(value):
                pe_attributes = win_executable_file_object.PEAttributesType()
                for pe_attributes_key, pe_attributes_value in value.items():
                    if pe_attributes_key.lower() == 'base_address' and self.__value_test(pe_attributes_value):
                        pe_attributes.set_Base_Address(maecbundle.cybox_common_types_1_0.HexBinaryObjectAttributeType(datatype='hexBinary',valueOf_=pe_attributes_value))
                    elif pe_attributes_key.lower() == 'exports' and self.__value_test(pe_attributes_value):
                        exports = win_executable_file_object.PEExportsType()
                        for export_key, export_value in pe_attributes_value.items():
                            if export_key.lower() == 'exported_functions' and self.__value_test(export_value):
                                exported_functions = win_executable_file_object.PEExportedFunctionsType()
                                for exported_function in export_value:
                                    xported_function = win_executable_file_object.PEExportedFunctionType()
                                    for exported_function_key, exported_function_value in exported_function.items():
                                        if exported_function_key.lower() == 'function_name' and self.__value_test(exported_function_value):
                                            xported_function.set_Function_Name(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String',valueOf_=maecbundle.quote_xml(exported_function_value)))
                                        elif exported_function_key.lower() == 'entry_point' and self.__value_test(exported_function_value):
                                            xported_function.set_Entry_Point(maecbundle.cybox_common_types_1_0.HexBinaryObjectAttributeType(datatype='hexBinary',valueOf_=exported_function_value))
                                        elif exported_function_key.lower() == 'ordinal' and self.__value_test(exported_function_value):
                                            xported_function.set_Ordinal(maecbundle.cybox_common_types_1_0.NonNegativeIntegerObjectAttributeType(datatype='NonNegativeInteger',valueOf_=exported_function_value))
                                    if xported_function.hasContent_():
                                        exported_functions.add_Exported_Function(xported_function)
                                if exported_functions.hasContent_():
                                    exports.set_Exported_Functions(exported_functions)
                            elif export_key.lower() == 'exports_time_stamp' and self.__value_test(export_value):
                                exports.set_Exports_Time_stamp(maecbundle.cybox_common_types_1_0.DateTimeObjectAttributeType(datatype='DateTime',valueOf_=exported_function_value))
                            elif export_key.lower() == 'number_of_addresses' and self.__value_test(export_value):
                                exports.set_Number_Of_Addresses(maecbundle.cybox_common_types_1_0.LongObjectAttributeType(datatype='Long',valueOf_=exported_function_value))
                            elif export_key.lower() == 'number_of_names' and self.__value_test(export_value):
                                exports.set_Number_Of_Names(maecbundle.cybox_common_types_1_0.LongObjectAttributeType(datatype='Long',valueOf_=exported_function_value))
                        if exports.hasContent_():
                            pe_attributes.set_Exports(exports)
            elif key == 'association':
                cybox_object.set_association_type(value)
        
        if pe_attributes.hasContent_():
            win_executable_file_obj.set_PE_Attributes(pe_attributes)
        if win_executable_file_obj.hasContent_():
            cybox_object.set_Defined_Object(win_executable_file_obj)
        
        return cybox_object

    def create_win_handle_object(self, handle_attributes):
        cybox_object = maecbundle.cybox_core_1_0.AssociatedObjectType(id=self.generator.generate_obj_id(), type_='Handle')
        handle_obj = win_handle_object.WindowsHandleObjectType()
        handle_obj.set_anyAttributes_({'xsi:type' : 'WinHandleObj:WindowsHandleObjectType'})
        
        for key, value in handle_attributes.items():
            if key == 'id':
                if self.__value_test(value):
                    handle_obj.set_ID(maecbundle.cybox_common_types_1_0.UnsignedIntegerObjectAttributeType(datatype='UnsignedInt', valueOf_=value))
            if key == 'type':
                 if self.__value_test(value):
                    handle_obj.set_Type(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String',valueOf_=maecbundle.quote_xml(value)))
            elif key == 'association':
                cybox_object.set_association_type(value)
        
        if handle_obj.hasContent_():
            cybox_object.set_Defined_Object(handle_obj)
        
        return cybox_object

    def create_win_thread_object(self, thread_attributes):
        cybox_object = maecbundle.cybox_core_1_0.AssociatedObjectType(id=self.generator.generate_obj_id(), type_='Thread')
        thread_obj = win_thread_object.WindowsThreadObjectType()
        thread_obj.set_anyAttributes_({'xsi:type' : 'WinThreadObj:WindowsThreadObjectType'})
        
        for key, value in thread_attributes.items():
            if key == 'tid':
                if self.__value_test(value):
                    thread_obj.set_Thread_ID(maecbundle.cybox_common_types_1_0.NonNegativeIntegerObjectAttributeType(datatype='NonNegativeInteger', valueOf_=value))
            elif key == 'association':
                cybox_object.set_association_type(value)
        
        if thread_obj.hasContent_():
            cybox_object.set_Defined_Object(thread_obj)
        
        return cybox_object

    def create_win_task_object(self, task_attributes):
        cybox_object = maecbundle.cybox_core_1_0.AssociatedObjectType(id=self.generator.generate_obj_id(), type_='Task')
        task_obj = win_task_object.WindowsTaskObjectType()
        task_obj.set_anyAttributes_({'xsi:type' : 'WinTaskObj:WindowsTaskObjectType'})
        
        for key, value in task_attributes.items():
            if key == 'command':
                if self.__value_test(value):
                    task_obj.set_Parameters(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String',valueOf_=maecbundle.quote_xml(value)))
                elif key == '':
                    pass
            elif key == 'association':
                cybox_object.set_association_type(value)
        
        if thread_obj.hasContent_():
            cybox_object.set_Defined_Object(thread_obj)
        
        return cybox_object

    def create_win_user_object(self, user_attributes):
        cybox_object = maecbundle.cybox_core_1_0.AssociatedObjectType(id=self.generator.generate_obj_id(), type_='Other') #change type to User once added to CybOX object type enum
        user_obj = win_user_object.WindowsUserAccountObjectType()
        user_obj.set_anyAttributes_({'xsi:type' : 'WinUserAccountObj:WindowsUserAccountObjectType'})
        
        for key, value in user_attributes.items():
            if key == 'username':
                if self.__value_test(value):
                    user_obj.set_Username(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String',valueOf_=maecbundle.quote_xml(value)))
            elif key == 'association':
                cybox_object.set_association_type(value)
        
        if user_obj.hasContent_():
            cybox_object.set_Defined_Object(user_obj)
        
        return cybox_object

    def create_win_network_share_object(self, share_attributes):
        cybox_object = maecbundle.cybox_core_1_0.AssociatedObjectType(id=self.generator.generate_obj_id(), type_='Other') #change type to Network Share once added to CybOX object type enum
        share_obj = win_network_share_object.WindowsNetworkShareObjectType()
        share_obj.set_anyAttributes_({'xsi:type' : 'WinNetworkShareObj:WindowsNetworkShareObjectType'})
        
        for key, value in user_attributes.items():
            if key == 'netname':
                if self.__value_test(value):
                    share_obj.set_Netname(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String',valueOf_=maecbundle.quote_xml(value)))
            elif key == 'local_path':
                if self.__value_test(value):
                    share_obj.set_Local_Path(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String',valueOf_=maecbundle.quote_xml(value)))
            elif key == 'type':
                if self.__value_test(value):
                    share_obj.set_Type(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String',valueOf_=maecbundle.quote_xml(value)))
            elif key == 'association':
                cybox_object.set_association_type(value)
      
        if share_obj.hasContent_():
            cybox_object.set_Defined_Object(share_obj)
        
        return cybox_object

    def create_win_system_object(self, system_attributes):
        cybox_object = maecbundle.cybox_core_1_0.AssociatedObjectType(id=self.generator.generate_obj_id(), type_='System')
        sys_obj = win_system_object.WindowsSystemObjectType()
        sys_obj.set_anyAttributes_({'xsi:type' : 'WinSystemObj:WindowsSystemObjectType'})
        
        for key, value in system_attributes.items():
            if key == 'local_time':
                if self.__value_test(value):
                    sys_obj.set_Local_Time(maecbundle.cybox_common_types_1_0.TimeObjectAttributeType(datatype='Time',valueOf_=value))
            elif key == 'system_time':
                if self.__value_test(value):
                    sys_obj.set_System_Time(maecbundle.cybox_common_types_1_0.TimeObjectAttributeType(datatype='Time',valueOf_=value))
            elif key == 'global_flags':
                if self.__value_test(value):
                    global_flag_list = win_system_object.GlobalFlagListType()
                    for flag in value:
                        global_flag = win_system_object.GlobalFlagType()
                        global_flag.set_Symbolic_Name(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='string', valueOf_=flag))
                        global_flag_list.add_Global_Flag(global_flag)
                    if global_flag_list.hasContent_():
                        sys_obj.set_Global_Flag_List(global_flag_list)
            elif key == 'association':
                cybox_object.set_association_type(value)
        
        if sys_obj.hasContent_():
            cybox_object.set_Defined_Object(sys_obj)
        
        return cybox_object

    def create_port_object(self, port_attributes): #stub
        pass
    
    #Create a related object based on a cybox object and relationhip
    def create_related_object(self, cybox_object, relationship):
        defined_object = cybox_object.get_Defined_Object()
        related_object = maecbundle.cybox_core_1_0.RelatedObjectType(id=self.generator.generate_obj_id(), type_=cybox_object.get_type(), Defined_Object = defined_object, relationship = relationship)
        return related_object

    def create_av_classifications(self, classifications):
        av_classifications = maec.AVClassificationsType(type_='maec:AVClassificationsType')
        for classification in classifications:
            av_classification = maec.mmdef.classificationObject(type_='dirty', id=self.generator.generate_avclass_id())
            classificationdetails = maec.mmdef.classificationDetails()
            for key, value in classification.items():
                if key == 'company':
                    if self.__value_test(value):
                        av_classification.set_companyName(value)
                elif key == 'application_version':
                    if self.__value_test(value):
                        classificationdetails.set_productVersion(value)
                elif key == 'signature_version':
                    if self.__value_test(value):
                        classificationdetails.set_definitionVersion(value)
                elif key == 'classification':
                    if self.__value_test(value):
                        av_classification.set_classificationName(value)
            if classificationdetails.hasContent_():
                av_classification.set_classificationDetails(classificationdetails)
            if av_classification.hasContent_():
                av_classifications.add_AV_Classification(av_classification)
        return av_classifications

    #Create a state change effect for an action
    def __create_state_change_effect(self, new_defined_object):
        state_change_effect = maecbundle.cybox_core_1_0.StateChangeEffectType(effect_type = 'State_Changed')
        new_state = maecbundle.cybox_core_1_0.StateType(Defined_Object = new_defined_object)
        state_change_effect.set_New_State(new_state)
        return state_change_effect

    #Create a data read/write effect for an action
    def __create_data_effect(self, effect_attributes, type):
        data_effect = None
        if 'read' in type.lower():
            data_effect = maecbundle.cybox_core_1_0.DataReadEffectType(effect_type='Data_Read')
            data_effect.set_extensiontype_('cybox:DataReadEffectType')
        elif 'write' in type.lower():
            data_effect = maecbundle.cybox_core_1_0.DataWrittenEffectType(effect_type='Data_Written')
            data_effect.set_extensiontype_('cybox:DataWrittenEffectType')
        data_segment = maecbundle.cybox_common_types_1_0.DataSegmentType()
        for key, value in effect_attributes.items():
            if key == 'data_format':
                if self.__value_test(value):
                    data_segment.set_Data_Format(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_=value))
            elif key == 'data_size':
                if self.__value_test(value):
                    data_segment.set_Data_Size(maecbundle.cybox_common_types_1_0.DataSizeType(units='Bytes', datatype='String', valueOf_=value))
            elif key == 'data_segment':
                if self.__value_test(value):
                    data_segment.set_Data_Segment(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_=value))
            elif key == 'offset':
                if self.__value_test(value):
                    data_segment.set_Offset(maecbundle.cybox_common_types_1_0.IntegerObjectAttributeType(datatype='Int', valueOf_=value))
        if data_segment.hasContent_():
            data_effect.set_Data(data_segment)
        return data_effect
    
    #Test if a value is not None and has a length greater than 0
    def __value_test(self, value):
        if value is not None and len(str(value)) > 0:
            return True
        else:
            return False
