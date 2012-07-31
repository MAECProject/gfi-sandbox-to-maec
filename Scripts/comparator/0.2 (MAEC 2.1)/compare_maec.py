#!/usr/bin/python
#blake -@- jeek.org @ iDefense May 2011
#updated for MAEC v2.1 July 2012 by Ivan Kirillov
#use command line arguments file for:
# - ThreatExpert *add &xml=1* to ThreatExpert report URL
# - Anubis XML output
#Thanks Ivan Kirillov/MITRE for writing:
# - anubis_to_maec.py
# - threatexpert_to_maec.py

import sys
import lxml.etree as etree
import os

#Define the objects and elements to match on
match_on = {
    'FileObj:FileObjectType': 
        ['FileObj:File_Path', 'FileObj:File_Name'],
    'WinRegistryKeyObj:WindowsRegistryKeyObjectType': 
        ['WinRegistryKeyObj:Hive','WinRegistryKeyObj:Key'],
    'WinMutexObj:WindowsMutexObjectType':
        ['MutexObj:Name'], #'@object_name'
    'SocketObj:SocketObjectType':
        ['AddressObj:Address_Value', 'PortObj:Port_Value'],
    'WinPipeObj:WindowsPipeObjectType':
        ['PipeObj:Name'],
    'ProcessObj:ProcessObjectType':
        ['ProcessObj:Command_Line']
}
#the optional_matches array specifies which fields can be different
# but still be grouped together. For instance, if you have a registry
# key that uses HKEY_USERS and HKEY_CURRENT_USER as a hive for the same key
optional_matches = ['WinRegistryKeyObj:Hive']

globalvars = {
        '%AppData%': 'C:\\Documents and Settings\\Administrator\\Application Data\\Application Data',
        '%System%': 'C:\\Windows\\System32',
        '%Windir%': 'C:\\Windows'
    }
join_chars = {
        'Internet_Object_Attributes':'://', #for http://
        'SocketObj:SocketObjectType':':',    #for 1.2.3.4:80
    }
ns={
    'maec':'http://maec.mitre.org/XMLSchema/maec-core-2',
    'cybox':'http://cybox.mitre.org/cybox_v1',
    'metadata':'http://xml/metadataSharing.xsd',
    'common':'http://cybox.mitre.org/Common_v1',
    'FileObj':'http://cybox.mitre.org/objects#FileObject',
    'URIObj':'http://cybox.mitre.org/objects#URIObject',
	'SystemObj':'http://cybox.mitre.org/objects#SystemObject',
	'WinSystemObj':'http://cybox.mitre.org/XMLSchema/objects#WinSystemObject',
	'CodeObj':'http://cybox.mitre.org/objects#CodeObject',
    'ProcessObj':'http://cybox.mitre.org/objects#ProcessObject',
    'PipeObj':'http://cybox.mitre.org/objects#PipeObject',
    'PortObj':'http://cybox.mitre.org/objects#PortObject',
    'AddressObj':'http://cybox.mitre.org/objects#AddressObject',
    'SocketObj':'http://cybox.mitre.org/objects#SocketObject',
    'MutexObj':'http://cybox.mitre.org/objects#MutexObject',
    'MemoryObj':'http://cybox.mitre.org/objects#MemoryObject',
    'LibraryObj':'http://cybox.mitre.org/objects#LibraryObject',
    'UserAccountObj':'http://cybox.mitre.org/objects#UserAccountObject',
    'WinMutexObj':'http://cybox.mitre.org/objects#WinMutexObject',
    'WinServiceObj':'http://cybox.mitre.org/objects#WinServiceObject',
    'WinRegistryKeyObj':'http://cybox.mitre.org/objects#WinRegistryKeyObject',
    'WinPipeObj':'http://cybox.mitre.org/objects#WinPipeObject',
    'WinDriverObj':'http://cybox.mitre.org/objects#WinDriverObject',
    'WinFileObj':'http://cybox.mitre.org/objects#WinFileObject',
    'WinExecutableFileObj':'http://cybox.mitre.org/objects#WinExecutableFileObject',
    'WinMailslotObj':'http://cybox.mitre.org/objects#WinMailslotObject',
    'WinProcessObj':'http://cybox.mitre.org/objects#WinProcessObject',
    'WinHandleObj':'http://cybox.mitre.org/objects#WinHandleObject',
    'WinThreadObj':'http://cybox.mitre.org/objects#WinThreadObject',
    'WinTaskObj':'http://cybox.mitre.org/objects#WinThreadObject',
    'WinSystemObj':'http://cybox.mitre.org/objects#WinSystemObject',
    'WinNetworkShareObj':'http://cybox.mitre.org/objects#WinNetworkShareObject',
    'WinUserAccountObj':'http://cybox.mitre.org/objects#WinUserAccountObject',
    'xsl':'http://www.w3.org/1999/XSL/Transform',
    'xsi':'http://www.w3.org/2001/XMLSchema-instance'
    }

class compare_maec:
    def __init__(self, root):
        self.root = root
        self.lookup_table = dict()
        self.process_matches()

    def process_matches(self):
        root_objects = ['//cybox:Associated_Object', '//maec:Object']
        for source in self.root:
            tree = self.root[source]
            for root_object in root_objects:
                r = tree.xpath(root_object, namespaces=ns)
                for item in r:
                    type = 'Other'
                    if 'type' in item.attrib:
                        type = item.attrib['type']
                
                    objs = item.getchildren()
                    for obj in objs:
                        xsitype = obj.get('{http://www.w3.org/2001/XMLSchema-instance}type') 
                        unique_value = ''
                        for tag_to_match in match_on:
                            if xsitype == tag_to_match:
                                fields = []
                                collected_values = []
                                for subitem in match_on[tag_to_match]:
                                    val = ''
                                    try:
                                        xpath_result = obj.xpath('..//%s' % (subitem),namespaces=ns)
                                
                                        if len(xpath_result) >= 1:
                                            if hasattr(xpath_result[0], 'text'):
                                                val = xpath_result[0].text
                                            else:
                                                val = xpath_result[0]

                                            if val:
                                                for to_replace_var in globalvars:
                                                    if val.find(to_replace_var) >= 0:
                                                        val = val.replace(to_replace_var, globalvars[to_replace_var])
                                            else:
                                                val = ''
                                    except:
                                        pass
                                    if subitem in optional_matches:
                                        if val and val not in collected_values:
                                            collected_values.append(val)
                                    else:
                                        if val:
                                            fields.append(val)

                                if fields:
                                    unique_value = self.get_unique_value(fields,tag_to_match)

                                    if unique_value in self.lookup_table:
                                        self.lookup_table[unique_value].append([source,item,type,collected_values]) 
                                    else:
                                        self.lookup_table[unique_value] = [(source,item,type,collected_values)]

    def get_unique_value(self,fields, type = None):
        #performs partial matching on existing keys first, then if none match, make a new key
        if len(fields) <= 0:
            return 'ERROR'
            
        join_char = ''

        if type and type in join_chars:
            join_char = join_chars[type]
            
        new_key = join_char.join(fields)
        for existing_key in self.lookup_table:
            # make sure they aren't subkeys of another, but if they have a different root path
            if existing_key.find(new_key) >= 1:
                return existing_key
            if new_key.find(existing_key) >= 1:
                return existing_key
        return new_key

    def print_confirmed(self):
        for unique_value in self.lookup_table:
            sources = self.get_sources(unique_value)
            if len(sources) > 1:
                print self.get_text(unique_value, 'confirmed')
        
    def print_unique(self):
        for unique_value in self.lookup_table:
            sources = self.get_sources(unique_value)
            if len(sources) <= 1:
                print self.get_text(unique_value, 'unique')

    def get_sources(self,unique_value):
        val = []
        for source,item,type,collected_values in self.lookup_table[unique_value]:
            if not source in val: 
                val.append(source)
        return val

    def get_collected_values(self,unique_value):
        val = []
        for source,item,type,collected_values in self.lookup_table[unique_value]:
            for item in collected_values:
                if not item in val: 
                    val.append(item)
        return val
        
    def get_text(self, unique_value, msg):
        source,item,type,collected_values = self.lookup_table[unique_value][0]
        optional_values = ''

        if self.get_collected_values(unique_value):
            optional_values = '\n   optional_match_values: %s' % (','.join(self.get_collected_values(unique_value)))

        return '%s %s\n   [by %s]\n   values: %s %s' % (
            type,
            msg,
            ' and '.join(self.get_sources(unique_value)),
            unique_value,
            optional_values,
        )
            
if __name__ == '__main__':
    if len(sys.argv) <= 1:
        print '''
        Use %s [XML files list] OR -d [directory]
        Purpose: extracts and compares MAEC standardized data
        blake -@- jeek.org @ iDefense May 2011
        updated by Ivan Kirillov July 2012''' % sys.argv[0]
    root = dict()

    if sys.argv[1] == '-d':
        directoryname = sys.argv[2]
        for filename in os.listdir(directoryname):
            if '.xml' not in filename:
                pass
            else:
                fin = open(os.path.join(directoryname, filename),'rb')
                root[filename] = etree.parse(fin)
    else:
        for arg in sys.argv[1:]:
            fin = open(arg,'rb')
            root[arg] = etree.parse(fin)

    c = compare_maec(root)
    print '-'*5, 'Print All Objects Unique to a Single Report', '-'*5
    c.print_unique()
    print '-'*5, 'Print All Objects Confirmed in Multiple Reports', '-'*5
    c.print_confirmed()
