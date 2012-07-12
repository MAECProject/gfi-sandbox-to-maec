#!/usr/bin/python
#blake -@- jeek.org @ iDefense May 2011
#use command line arguments file for:
# - ThreatExpert *add &xml=1* to ThreatExpert report URL
# - Anubis XML output
#Thanks Ivan Kirillov/MITRE for writing:
# - anubis_to_maec.py
# - threatexpert_to_maec.py

import sys
import lxml.etree as etree

match_on = {
    'Registry_Object_Attributes': 
        ['maec:Hive','maec:Key'],
    'File_System_Object_Attributes':
        ['maec:Path', '@object_name'], #'@object_name'
    'Network_Object_Attributes':
        ['maec:External_IP_Address', 'maec:External_Port'],
    'Internet_Object_Attributes':
        ['metadata:protocol', 'metadata:hostname', 'metadata:path'],
    'Process_Object_Attributes':
        ['maec:Command_Line'],
}
#the optional_matches array specifies which fields can be different
# but still be grouped together. For instance, if you have a registry
# key that uses HKEY_USERS and HKEY_CURRENT_USER as a hive for the same key
optional_matches = ['maec:Hive','metadata:path']

globalvars = {
        '%AppData%': 'C:\\Documents and Settings\\LocalService\\Application Data',
    }
join_chars = {
        'Internet_Object_Attributes':'://', #for http://
        'Network_Object_Attributes':':',    #for 1.2.3.4:80
    }
ns={
    'maec':'http://maec.mitre.org/XMLSchema/maec-core-1',
    'metadata':'http://xml/metadataSharing.xsd',
    'xsl':'http://www.w3.org/1999/XSL/Transform',
    }


class compare_maec:
    def __init__(self, root):
        self.root = root
        self.lookup_table = dict()
        self.process_matches()

    def process_matches(self):
        for source in self.root:
            tree = self.root[source]
            r = tree.xpath('//maec:Object', namespaces=ns)
            for item in r:
                type = 'Other'
                if 'type' in item.attrib:
                    type = item.attrib['type']
                
                objs = item.getchildren()
                for obj in objs: 
                    unique_value = ''

                    for tag_to_match in match_on:
                        if obj.tag.endswith(tag_to_match):
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
        Use %s [XML files list]
        Purpose: extracts and compares MAEC standardized data
        blake -@- jeek.org @ iDefense May 2011''' % sys.argv[0]
    root = dict()
    for arg in sys.argv[1:]:
        fin = open(arg,'rb')
        root[arg] = etree.parse(fin)

    c = compare_maec(root)
    print '-'*5, 'Print All Objects Unique to a Single Report', '-'*5
    c.print_unique()
    print '-'*5, 'Print All Objects Confirmed in Multiple Reports', '-'*5
    c.print_confirmed()
