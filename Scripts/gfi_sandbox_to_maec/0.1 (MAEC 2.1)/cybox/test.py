import cybox_1_0 as cybox

observables = cybox.parse('msbgt_cybox.xml')
#for observable in observables.get_Observable():
#    statefulmeasure = observable.get_Stateful_Measure()
#    cyboxobject = statefulmeasure.get_Object()
#    definedobject = cyboxobject.get_Defined_Object()
#    print definedobject.get_File_Name()
#    hashes = definedobject.get_Hashes()
#    for filehash in hashes.get_Hash():
#        print filehash.get_Type()
#    #print definedobject