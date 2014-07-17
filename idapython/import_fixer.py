"""Wrote this script because I was getting errors with IDA when trying to grab additional
   information from modules that were imported by the target exe, error was:
        "blah blah can't be accepted as a module 'blah'. Probably it contains only
        entry point numbers"
    So what it does is uses pefile library to parse the export table of the 
    target module, creates a mapping of ordinal to name and then use idapython api
    to rename the import functions, including checking the xrefs so we can name the actual
    function (jmp table). End result is you can get the actual imported names. Wrote this
    quickly so just hardcoded the modules I am interested for now, need to make it take in
    the module path somehow later."""


import pefile

import idaapi
from idc import *
from idautils import *

import sys
import os


global export_table
export_table = {}

def get_exports(mod):
    """This just parses the export table and creates a dict with ordinal to name mapping"""
    
    #Couldn't think of a better way than using a global var :/
    pe = pefile.PE(mod)
    for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        export_table[e.ordinal] = e.name

	
    
def imports_names_cb(ea, name, ord):
    """This is the callback function for iterating over a imports of a specific module"""
    new_name = export_table[ord]
    
    #lets rename the import table entry
    MakeName(ea, '__imp_' + new_name)
    
    #checking to see if the xref type is Data_Read (3), this could use more checking....
    for xref in XrefsTo(ea, 0):
        if xref.type == 3:
            print "Changing 0x%016x : %s to %s" % (xref.frm,name,new_name)
            MakeName(xref.frm, new_name)
            #Lets also set the color so it is easier to spot in our func window
            SetColor(xref.frm, idc.CIC_FUNC, 0xc7c7ff)
    
    #return true so we keep cycling through imports
    return True            

#lazy for now, hardcoded path    
path = r'F:\bin\libeay32.dll'
#strip out the name and make it upper so we can match output from ida (plus strip .dll)
modname =  os.path.basename(path.split('.')[0].upper())
    
#set our global var    
get_exports(path)

#get the number of imported modules
n_mods = idaapi.get_import_module_qty()

#iterate over and see if it matches our module we are interested in
for i in xrange(0, n_mods):
    name = idaapi.get_import_module_name(i)
    print name
    if modname in name:
        #enum and rename the imports
        idaapi.enum_import_names(i, imports_names_cb)



