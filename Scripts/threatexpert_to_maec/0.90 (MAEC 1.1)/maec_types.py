#Copyright (c) 2011, The MITRE Corporation
#All rights reserved.

#ThreatExpert Converter Script
#Ivan Kirillov//ikirillov@mitre.org

#MAEC Class definitions and methods
import maecv11 as maec

#Class for mapping to and from various terms
class mapper:
    def __init__(self):
        return
    
    def map_action_name_to_object_effect(self, action_name):
        if action_name.count('create') > 0:
            return "Object_Created"
        elif action_name.count('delete') > 0:
            return 'Object_Deleted'
        elif action_name.count('get') > 0:
            return 'Object_Read_From'
        elif action_name.count('copy') > 0:
            return 'Object_Copied'
        elif action_name.count('move') > 0:
            return 'Object_Moved'
        elif action_name.count('query') > 0:
            return 'Object_Queried'
        elif action_name.count('map') > 0:
            return 'Object_Mapped'
        elif action_name.count('find') > 0:
            return 'Object_Searched_For'
        elif action_name.count('set') > 0:
            return 'Object_Properties_Modified'
        elif action_name.count('load') > 0:
            return 'Object_Loaded_Into_Memory'
        elif action_name.count('enum') > 0:
            return 'Object_Values_Enumerated'
        elif action_name.count('open') > 0:
            return 'Object_Opened'
        elif action_name.count('bind') > 0:
            return 'Object_Bound'
        elif action_name.count('listen') > 0:
            return 'Object_Listened_On'
        elif action_name.count('write') > 0:
            return 'Object_Written_To'
        elif action_name.count('allocate') > 0:
            return 'Object_Allocated'
        elif action_name.count('kill') > 0:
            return 'Object_Killed'
        elif action_name.count('modify') > 0:
            return 'Object_Properties_Modified'                
        elif action_name.count('rename') > 0:
            return 'Object_Properties_Modified'
        elif action_name.count('read') > 0:
            return 'Object_Read_From'
        else:
            return 'Other'            

class generator:
    def __init__(self, namespace):
        self.namespace = namespace
        self.general_id_base = 0
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
        
    #Methods for generating unique ids
    def generate_id(self):
        self.general_id_base += 1
        return self.general_id_base
    
    def generate_bnd_id(self):
        self.bnd_id_base += 1
        return 'maec:' + self.namespace + ':bnd:' + str(self.bnd_id_base)
    
    def generate_act_id(self):
        self.act_id_base += 1
        return 'maec:' + self.namespace + ':act:' + str(self.act_id_base)
    
    def generate_bhv_id(self):
        self.bhv_id_base += 1
        return 'maec:' + self.namespace + ':bhv:' + str(self.bhv_id_base)
    
    def generate_obj_id(self):
        self.obj_id_base += 1
        return 'maec:' + self.namespace + ':obj:' + str(self.obj_id_base)
    
    def generate_ana_id(self):
        self.ana_id_base += 1
        return 'maec:' + self.namespace + ':ana:' + str(self.ana_id_base)
    
    def generate_tol_id(self):
        self.tol_id_base += 1
        return 'maec:' + self.namespace + ':tol:' + str(self.tol_id_base)
        
    def generate_eff_id(self):
        self.eff_id_base += 1
        return 'maec:' + self.namespace + ':eff:' + str(self.eff_id_base)
        
    def generate_api_id(self):
        self.api_id_base += 1
        return 'maec:' + self.namespace + ':api:' + str(self.api_id_base)
        
    def generate_cde_id(self):
        self.cde_id_base += 1
        return 'maec:' + self.namespace + ':cde:' + str(self.cde_id_base)
        
    def generate_imp_id(self):
        self.imp_id_base += 1
        return 'maec:' + self.namespace + ':imp:' + str(self.imp_id_base)
        
    def generate_dat_id(self):
        self.dat_id_base += 1
        return 'maec:' + self.namespace + ':dat:' + str(self.dat_id_base)
        
    def generate_actc_id(self):
        self.actc_id_base += 1
        return 'maec:' + self.namespace + ':actc:' + str(self.actc_id_base)

    def generate_bhvc_id(self):
        self.bhvc_id_base += 1
        return 'maec:' + self.namespace + ':bhvc:' + str(self.bhvc_id_base)
        
    def generate_effc_id(self):
        self.effc_id_base += 1
        return 'maec:' + self.namespace + ':effc:' + str(self.effc_id_base)

    def generate_objc_id(self):
        self.objc_id_base += 1
        return 'maec:' + self.namespace + ':objc:' + str(self.objc_id_base)
    
    #Methods for getting current id bases
    def get_current_obj_id(self):
        return self.obj_id_base

class maec_bundle:
    def __init__(self, generator, schema_version):
        self.generator = generator
        #Create the MAEC Bundle object
        self.bundle = maec.MAEC_Bundle(id=self.generator.generate_bnd_id())
        #Set the bundle schema version
        self.bundle.set_schema_version(schema_version)
        #Create the MAEC pools object
        self.pools = maec.Pools()
        #Create the object collection pool
        self.object_collection_pool = maec.Object_Collection_Pool()
        #Create the action collection pool
        self.action_collection_pool = maec.Action_Collection_Pool()
        #Create the object pool
        self.object_pool = maec.Object_Pool()
        #Create the action pool
        self.action_pool = maec.Action_Pool()
        #Create the analyses
        self.analyses = maec.Analyses()
        #Create the object collections
        self.process_object_collection = maec.ObjectCollectionType(name='Process Objects', id=self.generator.generate_objc_id())
        self.network_object_collection = maec.ObjectCollectionType(name='Network Objects', id=self.generator.generate_objc_id())
        self.ipc_object_collection = maec.ObjectCollectionType(name='IPC Objects', id=self.generator.generate_objc_id())
        self.filesystem_object_collection = maec.ObjectCollectionType(name='File System Objects', id=self.generator.generate_objc_id())
        self.service_object_collection = maec.ObjectCollectionType(name='Service Objects', id=self.generator.generate_objc_id())
        self.registry_object_collection = maec.ObjectCollectionType(name='Registry Objects', id=self.generator.generate_objc_id())
        self.gui_object_collection = maec.ObjectCollectionType(name='Gui Objects', id=self.generator.generate_objc_id())
        self.memory_object_collection = maec.ObjectCollectionType(name='Memory Objects', id=self.generator.generate_objc_id())
        self.module_object_collection = maec.ObjectCollectionType(name='Module Objects', id=self.generator.generate_objc_id())
        self.internet_object_collection = maec.ObjectCollectionType(name='Internet Objects', id=self.generator.generate_objc_id())
        self.system_object_collection = maec.ObjectCollectionType(name='System Objects', id=self.generator.generate_objc_id())
        #Create the action collections
        self.filesystem_action_collection = maec.ActionCollectionType(id=self.generator.generate_actc_id(), name="File System Actions")
        self.ipc_action_collection = maec.ActionCollectionType(id=self.generator.generate_actc_id(), name="IPC Actions")
        self.service_action_collection = maec.ActionCollectionType(id=self.generator.generate_actc_id(), name="Service Actions")
        self.process_action_collection = maec.ActionCollectionType(id=self.generator.generate_actc_id(), name="Process Actions")
        self.registry_action_collection = maec.ActionCollectionType(id=self.generator.generate_actc_id(), name="Registry Actions")
        self.gui_action_collection = maec.ActionCollectionType(id=self.generator.generate_actc_id(), name="GUI Actions")
        self.network_action_collection = maec.ActionCollectionType(id=self.generator.generate_actc_id(), name="Network Actions")
        self.memory_action_collection = maec.ActionCollectionType(id=self.generator.generate_actc_id(), name="Memory Actions")
        self.module_action_collection = maec.ActionCollectionType(id=self.generator.generate_actc_id(), name="Module Actions")
        self.system_action_collection = maec.ActionCollectionType(id=self.generator.generate_actc_id(), name="System Actions")
        self.internet_action_collection = maec.ActionCollectionType(id=self.generator.generate_actc_id(), name="Internet Actions")
        #Create the behaviors
        self.behaviors = maec.Behaviors()
    #"Public" methods
   
    def add_analysis(self, analysis):
        self.analyses.add_Analysis(analysis)
        
    def add_behavior(self, behavior):
        self.behaviors.add_Behavior(behavior)
        
    def add_process_object(self, object):
        self.process_object_collection.add_Object(object)
        
    def add_action(self, action, action_group):
        if action_group == 'file_system':
            self.filesystem_action_collection.add_Action(action)
        elif action_group == 'ipc':
            self.ipc_action_collection.add_Action(action)
        elif action_group == 'service':
            self.service_action_collection.add_Action(action)
        elif action_group == 'registry':
            self.registry_action_collection.add_Action(action)
        elif action_group == 'gui':
            self.gui_action_collection.add_Action(action)
        elif action_group == 'network':
            self.network_action_collection.add_Action(action)
        elif action_group == 'memory':
            self.memory_action_collection.add_Action(action)           
        elif action_group == 'process':
            self.process_action_collection.add_Action(action)            
        elif action_group == 'module':
            self.module_action_collection.add_Action(action)            
        elif action_group == 'system':
            self.system_action_collection.add_Action(action) 
        elif action_group == 'internet':
            self.internet_action_collection.add_Action(action)
    
    def add_actions(self, actions, action_group):
        if action_group == 'file_system':
            for action in actions:
                self.filesystem_action_collection.add_Action(action)
        elif action_group == 'ipc':
            for action in actions:
                self.ipc_action_collection.add_Action(action)
        elif action_group == 'service':
            for action in actions:
                self.service_action_collection.add_Action(action)
        elif action_group == 'registry':
            for action in actions:
                self.registry_action_collection.add_Action(action)
        elif action_group == 'gui':
            for action in actions:
                self.gui_action_collection.add_Action(action)
        elif action_group == 'network':
            for action in actions:
                self.network_action_collection.add_Action(action)
        elif action_group == 'memory':
            for action in actions:
                self.memory_action_collection.add_Action(action)           
        elif action_group == 'process':
            for action in actions:
                self.process_action_collection.add_Action(action)            
        elif action_group == 'module':
            for action in actions:
                self.module_action_collection.add_Action(action)            
        elif action_group == 'system':
            for action in actions:
                self.system_action_collection.add_Action(action) 
        elif action_group == 'internet':
            for action in actions:
                self.internet_action_collection.add_Action(action)
            
    def add_object(self, object, action_group):
        if action_group == 'network':
            self.network_object_collection.add_Object(object)
        elif action_group == 'ipc':
            self.ipc_object_collection.add_Object(object)
        elif action_group == 'service':
            self.service_object_collection.add_Object(object)
        elif action_group == 'registry':
            self.registry_object_collection.add_Object(object)
        elif action_group == 'file_system':
            self.filesystem_object_collection.add_Object(object)
        elif action_group == 'gui':
            self.gui_object_collection.add_Object(object)
        elif action_group == 'memory':
            self.memory_object_collection.add_Object(object)           
        elif action_group == 'process':
            self.process_object_collection.add_Object(object)            
        elif action_group == 'module':
            self.module_object_collection.add_Object(object)            
        elif action_group == 'internet':
            self.internet_object_collection.add_Object(object)
            
    def add_objects(self, objects, action_group):
        if action_group == 'network':
            for object in objects:
                self.network_object_collection.add_Object(object)
        elif action_group == 'ipc':
            for object in objects:
                self.ipc_object_collection.add_Object(object)
        elif action_group == 'service':
            for object in objects:
                self.service_object_collection.add_Object(object)
        elif action_group == 'registry':
            for object in objects:
                self.registry_object_collection.add_Object(object)
        elif action_group == 'file_system':
            for object in objects:
                self.filesystem_object_collection.add_Object(object)
        elif action_group == 'gui':
            for object in objects:
                self.gui_object_collection.add_Object(object)
        elif action_group == 'memory':
            for object in objects:
                self.memory_object_collection.add_Object(object)           
        elif action_group == 'process':
            for object in objects:
                self.process_object_collection.add_Object(object)            
        elif action_group == 'module':
            for object in objects:
                self.module_object_collection.add_Object(object)            
        elif action_group == 'internet':
            for object in objects:
                self.internet_object_collection.add_Object(object)
                                   
    #Build the MAEC bundle by adding all applicable elements
    def build_maec_bundle(self):
        #Add the analyses to the MAEC bundle object
        self.bundle.set_Analyses(self.analyses)
        #Add the collections to their respective pools
        #Add the action collections
        if self.filesystem_action_collection.hasActions(): self.action_collection_pool.add_Action_Collection(self.filesystem_action_collection)
        if self.ipc_action_collection.hasActions(): self.action_collection_pool.add_Action_Collection(self.ipc_action_collection)
        if self.service_action_collection.hasActions(): self.action_collection_pool.add_Action_Collection(self.service_action_collection)
        if self.registry_action_collection.hasActions(): self.action_collection_pool.add_Action_Collection(self.registry_action_collection)
        if self.gui_action_collection.hasActions(): self.action_collection_pool.add_Action_Collection(self.gui_action_collection)
        if self.network_action_collection.hasActions(): self.action_collection_pool.add_Action_Collection(self.network_action_collection)
        if self.memory_action_collection.hasActions(): self.action_collection_pool.add_Action_Collection(self.memory_action_collection)
        if self.process_action_collection.hasActions(): self.action_collection_pool.add_Action_Collection(self.process_action_collection)
        if self.module_action_collection.hasActions(): self.action_collection_pool.add_Action_Collection(self.module_action_collection)
        if self.system_action_collection.hasActions(): self.action_collection_pool.add_Action_Collection(self.system_action_collection)
        if self.internet_action_collection.hasActions(): self.action_collection_pool.add_Action_Collection(self.internet_action_collection)
        #Add the object collections
        if self.filesystem_object_collection.hasObjects(): self.object_collection_pool.add_Object_Collection(self.filesystem_object_collection)
        if self.ipc_object_collection.hasObjects(): self.object_collection_pool.add_Object_Collection(self.ipc_object_collection)
        if self.service_object_collection.hasObjects(): self.object_collection_pool.add_Object_Collection(self.service_object_collection)
        if self.registry_object_collection.hasObjects(): self.object_collection_pool.add_Object_Collection(self.registry_object_collection)
        if self.gui_object_collection.hasObjects(): self.object_collection_pool.add_Object_Collection(self.gui_object_collection)
        if self.network_object_collection.hasObjects(): self.object_collection_pool.add_Object_Collection(self.network_object_collection)
        if self.memory_object_collection.hasObjects(): self.object_collection_pool.add_Object_Collection(self.memory_object_collection)
        if self.process_object_collection.hasObjects(): self.object_collection_pool.add_Object_Collection(self.process_object_collection)
        if self.module_object_collection.hasObjects(): self.object_collection_pool.add_Object_Collection(self.module_object_collection)
        if self.system_object_collection.hasObjects(): self.object_collection_pool.add_Object_Collection(self.system_object_collection)
        if self.internet_object_collection.hasObjects(): self.object_collection_pool.add_Object_Collection(self.internet_object_collection)
        #Add the behaviors
        if self.behaviors.hasBehaviors() : self.bundle.set_Behaviors(self.behaviors)
        #Add everything to the pools
        if self.object_collection_pool.hasContent_() : self.pools.set_Object_Collection_Pool(self.object_collection_pool)
        if self.action_collection_pool.hasContent_() : self.pools.set_Action_Collection_Pool(self.action_collection_pool)
        self.bundle.set_Pools(self.pools)
    
    #Export the MAEC bundle and its contents to an XML file
    def export(self, outfilename):
        filename = outfilename
        outfile = open(filename, 'w')
        print ("Exporting MAEC Bundle to: " + filename)
        self.bundle.export(outfile, 0, namespacedef_='xmlns:metadata="http://xml/metadataSharing.xsd" xmlns:maec="http://maec.mitre.org/XMLSchema/maec-core-1" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://maec.mitre.org/XMLSchema/maec-core-1 file:MAEC_v1.1.xsd"')        
    
    #accessor methods
    def get_bundle(self):
        return self.bundle


class maec_analysis:
    def __init__(self, generator, subject_md5, subject_sha1, subject_size, packer, av_aliases, tool_name, tool_vendor):
        self.generator = generator
        self.tool_name = tool_name
        self.tool_vendor = tool_vendor
        self.analysis_object = None
        self.file_object = None
        self.subject_md5 = subject_md5
        self.subject_sha1 = subject_sha1
        self.subject_size = subject_size
        self.packer = packer
        self.av_aliases = av_aliases
        self.tool_id = 0
    #"Public" methods
    
    #Create the analysis object
    def create_analysis(self):
        analysis = maec.AnalysisType(id=self.generator.generate_ana_id(), analysis_method='Dynamic')
        subject = maec.Subject()
        #Create the object for the analysis subject
        subject_object = self._create_analysis_object()
        object_reference = maec.ObjectReferenceType(type_='Object', object_id=subject_object.get_id())
        subject.set_Object_Reference(object_reference)
        analysis.add_Subject(subject)
        #Create the tooltype using the cwsandbox string
        tool = self._create_tool(self.tool_name, self.tool_vendor)
        tools_used = maec.Tools_Used()
        tools_used.add_Tool(tool)
        analysis.set_Tools_Used(tools_used)
        self.analysis_object = analysis
    
    def get_analysis_object(self):
        return self.analysis_object
    
    def get_analysis_file_object(self):
        return self.file_object
    
    def get_tool_id(self):
        return self.tool_id
    
    #"Private" methods
    
    #Create and return the MAEC object representing the analysis subject
    #In this case this is a file object
    def _create_analysis_object(self):
        #Create the MAEC object
        file_object = maec.ObjectType(id=self.generator.generate_obj_id(), type_='File')
        file_object_attributes = maec.File_System_Object_Attributes()
        #Set the hashes
        file_hashes = maec.Hashes()
        md5_hash = maec.HashType(type_='MD5', Hash_Value=self.subject_md5)
        sha1_hash = maec.HashType(type_='SHA1', Hash_Value=self.subject_sha1)
        file_hashes.add_Hash(md5_hash)
        file_hashes.add_Hash(sha1_hash)
        file_object_attributes.set_Hashes(file_hashes)
        #Set the file size
        size = maec.Object_Size(units='Bytes', valueOf_=self.subject_size)
        file_object.set_Object_Size(size)
        #Set the packer and av aliases, if they exist
        if self.packer != None:
            packing = maec.Packing(is_packed='True')
            packer = maec.Packer_Type(Name=self.packer, Version='Unknown')
            packing.add_Packer_Type(packer)
            file_object_attributes.set_Packing(packing)
        if self.av_aliases != None:
            file_object.set_Classifications(self.av_aliases)
        file_object.set_File_System_Object_Attributes(file_object_attributes)
        #Return the created object
        self.file_object = file_object
        return file_object
    
    #Create the MAEC tool type
    def _create_tool(self, tool_name, tool_vendor):
        #Set the tool id
        tool_id = self.generator.generate_tol_id()
        self.tool_id = tool_id
        tool = maec.ToolType(id=tool_id, Name=tool_name, Version='Unknown', Vendor=tool_vendor)
        #Return the created tool
        return tool

class maec_action:
    def __init__(self, generator):
        self.generator = generator
        self.mapper = mapper()
        
    #Create a MAEC Action
    def create_action(self, action_attributes):
        #Create the action type and add basic attributes
        action = maec.ActionType()
        action.set_id(self.generator.generate_act_id())
        action.set_successful("true")
        for key, value in action_attributes.items():
            if key == 'action_name':
                action.set_action_name(value)
            elif key == 'action_type':
                if value.count('/') > 0:
                    action.set_type(value)
                else:
                    action.set_type(value.capitalize())
            elif key == 'object_id':
                effects = maec.Effects()
                effect = maec_effect(self.generator, self.mapper, action_attributes).create_effect()
                effects.add_Effect(effect)
                action.set_Effects(effects)
            elif key == 'tool_id':
                action_disc_method = maec.DiscoveryMethod()
                action_disc_method.set_tool_id(value)
                action_disc_method.set_method('Dynamic/Runtime Analysis')
                action.set_Discovery_Method(action_disc_method)
            elif key == 'initiator_id':
                action_initiator = maec.Action_Initiator(type_='Process')
                init_object = maec.ObjectReferenceType(type_='Object', object_id=value)
                action_initiator.set_Initiator_Object(init_object)
                action.set_Action_Initiator(action_initiator)
        return action

    #Getter methods
    def get_action_object(self):
        return self.action_object
            
class maec_object:
    def __init__(self, generator):
        self.generator = generator
            
    def create_network_object(self, network_attributes):
        network_object = maec.ObjectType(id=self.generator.generate_obj_id())
        network_object_attributes = maec.Network_Object_Attributes()
        
        for key, value in network_attributes.items():
            if key == 'type':
                network_object.set_type(value)
            elif key == 'port':
                network_object_attributes.set_External_Port(int(value,10))
            elif key == 'protocol':
                network_object_attributes.set_IP_Protocol('ipv4')
            elif key == 'address':
                bound_address = maec.IPAddress(type_='ipv4', valueOf_=value)
                network_object_attributes.set_External_IP_Address(bound_address)
        
        if network_object_attributes.hasContent_():
            network_object.set_Network_Object_Attributes(network_object_attributes)
        
        return network_object
            
    def create_ipc_object(self, ipc_attributes):
        ipc_object = maec.ObjectType(id=self.generator.generate_obj_id())
        ipc_object_attributes = maec.IPC_Object_Attributes()
        
        for key, value in ipc_attributes.items():
            if key == 'type':
                ipc_object.set_type(value)
            elif key == 'name':
                ipc_object.set_object_name(value)
            elif key == 'start_address':
                ipc_object_attributes.set_Start_Address(value)
            elif key == 'tid':
                ipc_object_attributes.set_Thread_ID(value)
        
        if ipc_object_attributes.hasContent_():
            ipc_object.set_IPC_Object_Attributes(ipc_object_attributes)
            
        return ipc_object


    def create_module_object(self, module_attributes):
        module_object = maec.ObjectType(id=self.generator.generate_obj_id(), type_="Module")
        module_object_attributes = maec.Module_Object_Attributes()
        
        for key, value in module_attributes.items():
            if key == 'name':
                module_object.set_object_name(value)
            elif key == 'filename':
                module_object_attributes.set_Library_File_Name(value)
        
        if module_object_attributes.hasContent_():
            module_object.set_Module_Object_Attributes(module_object_attributes)
        
        return module_object


    def create_registry_object(self, registry_attributes):
        registry_object = maec.ObjectType(id=self.generator.generate_obj_id())
        registry_object_attributes = maec.Registry_Object_Attributes()
        registry_value = maec.Value()
        #set object attributes
        for key, value in registry_attributes.items():
            if key == 'hive':
                registry_object_attributes.set_Hive(value)
            elif key == 'key':
                registry_object_attributes.set_Key(value)
            elif key == 'type':
                registry_object.set_type(value)
            elif key == 'value':
                if value != '':
                    registry_value.set_Value_Name(value)
                elif registry_attributes.get('valuedata') != '':
                    registry_value.set_Value_Name(value)
            elif key == 'valuedata':
                if value != '':
                    registry_value.set_Value_Data(value)
                
        if registry_value.hasContent_():
            registry_object_attributes.set_Value(registry_value)
            
        if registry_object_attributes.hasContent_():
            registry_object.set_Registry_Object_Attributes(registry_object_attributes)
        
        return registry_object
  
    def create_file_system_object(self, file_system_attributes):
        fs_object = maec.ObjectType(id=self.generator.generate_obj_id())
        fs_object_attributes = maec.File_System_Object_Attributes()
        fs_hashes = maec.Hashes()
        for key, value in file_system_attributes.items():
            if key == 'md5':
                md5_hash = maec.HashType(type_='MD5', Hash_Value=value)
                fs_hashes.add_Hash(md5_hash)
            elif key == 'sha1':
                sha1_hash = maec.HashType(type_='SHA1', Hash_Value=value)
                fs_hashes.add_Hash(sha1_hash)
            elif key == 'packer':
                packing = maec.Packing(is_packed='True')
                packer = maec.Packer_Type(Name=value, Version='Unknown')
                packing.add_Packer_Type(packer)
                fs_object_attributes.set_Packing(packing)
            elif key == 'av_aliases':
                fs_object.set_Classifications(value)
            elif key == 'filename':
                fs_object.set_object_name(value)
            elif key == 'filepath':
                path_obj = maec.Path(type_='Relative', valueOf_=value)
                fs_object_attributes.set_Path(path_obj)
            elif key == 'type':
                fs_object.set_type(value)
            elif key == 'origin':
                uriobj = maec.uriObject(id=self.generator.generate_id())
                uriobj.set_uriString(value)
                fs_object_attributes.set_Origin(uriobj)
        if fs_hashes.hasContent_():
            fs_object_attributes.set_Hashes(fs_hashes)
        if fs_object_attributes.hasContent_():
            fs_object.set_File_System_Object_Attributes(fs_object_attributes)
        return fs_object
    
    def create_process_object(self, process_attributes):
        process_object = maec.ObjectType(id=self.generator.generate_obj_id(), type_='Process')
        process_object_attributes = maec.Process_Object_Attributes()
        process_object_attributes.set_Image_Name
        for key, value in process_attributes.items():
            if key == 'name':
                process_object.set_object_name(value)
            elif key == 'filename':
                process_object_attributes.set_Image_Name(value)
        if process_object_attributes.hasContent_():
            process_object.set_Process_Object_Attributes(process_object_attributes)
        return process_object
        
    def create_gui_object(self, gui_attributes):
        gui_object = maec.ObjectType(id=self.generator.generate_obj_id(), type_='Window')
        gui_object_attributes = maec.GUI_Object_Attributes()
        #set object attributes
        for key,value in gui_attributes.items():
            if key == 'windowname':
                gui_object_attributes.set_Window_Display_Name(value)
            elif key == 'height':
                gui_object_attributes.set_Height(value)
            elif key == 'width':
                gui_object_attributes.set_Width(value)

        gui_object.set_GUI_Object_Attributes(gui_object_attributes)
        if gui_object_attributes.hasContent_():
            self.object = gui_object
  
    def create_memory_object(self, memory_attributes):
        memory_object = maec.ObjectType(id=self.generator.generate_obj_id(), type_='MemoryPage')
        memory_object_attributes = maec.Memory_Object_Attributes()
        #set object attributes
        for key,value in memory_attributes.items():
            if key == 'address':
                memory_object_attributes.set_Start_Address(value.replace('$',''))
                
        memory_object.set_Memory_Object_Attributes(memory_object_attributes)
        if memory_object_attributes.hasContent_():
            self.object = memory_object
            
    def create_internet_object(self, internet_attributes):
        internet_object = maec.ObjectType(id=self.generator.generate_obj_id(), type_='URI')
        internet_object_attributes = maec.Internet_Object_Attributes()
        #set object attributes
        for key, value in internet_attributes.items():
            if key == 'type':
                internet_object.set_type(value)
            elif key == 'uri':
                uriobj = maec.uriObject(id=self.generator.generate_id())
                uriobj.set_uriString(value)
                internet_object_attributes.set_URI(uriobj)
        
        if internet_object_attributes.hasContent_():
            internet_object.set_Internet_Object_Attributes(internet_object_attributes)
        
        return internet_object
    
    def create_service_object(self, service_attributes):
        service_object = maec.ObjectType(id=self.generator.generate_obj_id(), type_='Service/Daemon')
        service_object_attributes = maec.Daemon_Object_Attributes()
        
        for key, value in service_attributes.items():
            if key == 'name':
                service_object.set_object_name(value)
            elif key == 'displayname':
                service_object_attributes.set_Display_Name(value)
            elif key == 'filename':
                service_file_object = maec.ObjectType(id=self.generator.generate_obj_id(), type_='File')
                service_file_object_attributes = maec.File_System_Object_Attributes()
                split_filename = value.split('\\')
                actual_filename = split_filename[len(split_filename)-1]
                filepath = value.rstrip(actual_filename)
                path_obj = maec.Path(type_='Relative', valueOf_=filepath)
                service_file_object_attributes.set_Path(path_obj)
                service_file_object.set_object_name(actual_filename)
                service_file_object.set_File_System_Object_Attributes(service_file_object_attributes)
                service_object_attributes.set_Daemon_Binary_Object(service_file_object)
        
        if service_object_attributes.hasContent_():
            service_object.set_Daemon_Object_Attributes(service_object_attributes)
        
        return service_object       

            
class maec_effect:
        def __init__(self, generator, mapper, effect_attributes):
            self.generator = generator
            self.mapper = mapper
            self.effect_attributes = effect_attributes
            
        def create_effect(self):
            action_name = self.effect_attributes.get('action_name')
            effecttype = maec.EffectType(id=self.generator.generate_eff_id())
            affected_objects = maec.Affected_Objects()
            affected_object = maec.Affected_Object()
            for key, value in self.effect_attributes.items():
                if key == 'object_id':
                     object_reference = maec.ObjectReferenceType(object_id=value, type_='Object')
                     affected_object.set_Object_Reference(object_reference)
                     affected_object.set_effect_type(self.mapper.map_action_name_to_object_effect(action_name))
                     affected_objects.add_Affected_Object(affected_object)
                     effecttype.set_Affected_Objects(affected_objects)
            return effecttype

#Basic implementation of MAEC Behaviors
#Currently supports hidden file creation/setting and debugger checking 
class maec_behavior:
        def __init__(self, generator, mapper, action):
            self.generator = generator
            self.mapper = mapper
            self.action = action
            self.behavior_object = None
        
        def create_behavior(self):
            action_name = self.action.get_action_name()
            action_id = self.action.get_id()
            #First, extract the API call data
            action_implementation = self.action.get_Action_Implementation()
            if action_implementation != None:
                api_call = action_implementation.get_API_Call()
                if api_call != None:
                    #Parse the parameters of the API call and create the behavior as appropriate
                    for parameter in api_call.get_APICall_Parameter():
                        if parameter.get_Parameter_Name() == 'flags':
                            if parameter.get_Parameter_Value().count('FILE_ATTRIBUTE_HIDDEN') > 0:
                                self._create_hidden_file_behavior(action_id, action_name)
            if action_name == 'check_for_debugger':
                self._create_debugger_check_behavior(action_id)
        
        def behavior_set(self):
            if self.behavior_object != None:
                return True
            else:
                return False
        
        def get_behavior_object(self):
            return self.behavior_object
            
        def _create_hidden_file_behavior(self, action_id, action_name):
            behavior = maec.BehaviorType(id=self.generator.generate_bhv_id())
            behavioral_actions = maec.Behavioral_Actions()
            action_ref = maec.ActionReferenceType(action_reference_type='Action', action_id=action_id)
            behavioral_actions.add_Action_Reference(action_ref)
            behavior.set_Actions(behavioral_actions)
            #Create the description
            description = maec.StructuredTextType()
            if action_name.count('create') > 0:
                description.add_Text('Hidden File Created')
            elif action_name.count('attributes') > 0 or action_name.count('open') > 0:
                description.add_Text('File Attributes Set to Hidden')
            behavior.set_Description(description)
            self.behavior_object = behavior
        
        def _create_debugger_check_behavior(self, action_id):
            behavior = maec.BehaviorType(id=self.generator.generate_bhv_id())
            behavioral_actions = maec.Behavioral_Actions()
            action_ref = maec.ActionReferenceType(action_reference_type='Action', action_id=action_id)
            behavioral_actions.add_Action_Reference(action_ref)
            behavior.set_Actions(behavioral_actions)
            #Create the description
            description = maec.StructuredTextType()
            description.add_Text('Debugger Checked For')
            behavior.set_Description(description)
            self.behavior_object = behavior  

