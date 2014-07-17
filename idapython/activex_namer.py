#https://pythonhosted.org/comtypes/
import comtypes
import comtypes.client

#https://www.hex-rays.com/products/ida/support/idapython_docs/
import idaapi
from idc import *
from idautils import *

#http://docs.python.org/2/library/ctypes.html
import ctypes



def get_guid(path):
    """Hacky way to get the ClassID using the typelib information and some python introspection..."""

    #Type we are looking for
    coclass = comtypes._meta._coclass_meta

    #Get the typelib infos
    typelib = comtypes.client.GetModule(path)

    #For every attribute of the typelib stuffs, see if the attr matches the coclass
    for i in dir(typelib):
        tmp = getattr(typelib, i)
        #If is it a coclass type and not named CoClass...
        if type(tmp) == coclass and i != "CoClass":
            #Instantiate it so the clsid will get populated
            tmp = tmp()
            #Get clsid
            guid = tmp.IPersist_GetClassID()
            #Only handles checking one interface, so lets just return now that we have one
            return guid
			
			
if __name__ == "__main__":
    """This creates a COM object, gets the pointer to the objects vtable, and then using the methods dispid
        determines the offset into the vtable for that method and appropriately names it in IDA"""

    #Get ctypes access to kernel32 exported functions
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    #Get the path for the current binary opened in IDA
    binary_path = GetInputFilePath()
    #Create the object from its GUID/ClassID
    newobj = comtypes.client.CreateObject(get_guid(binary_path))
    #Gross way to parse out the actual interface name
    interface_name = newobj.__class__.__name__.split('(')[1].strip(')')
    
    #Lets cast it to a real ctypes pointer so we can get the pointer to interface vtbl
    #This feels like a dirty hack, but seems to be easiest way to get the actual pointer
    #http://blogs.msdn.com/b/oldnewthing/archive/2004/02/05/68017.aspx
    vtbl_ptr = ctypes.cast(newobj, ctypes.POINTER(ctypes.c_void_p)).contents.value
	
    #Lets get our module base address using ctypes/win32 api
    mod_base = kernel32.GetModuleHandleA(binary_path)
    
    #Get the base address of the binary loaded in IDA
    base = idaapi.get_imagebase()
	
    #Get the delta of the actual module load address vs what the binary is currently loaded at in IDA
    delta = mod_base - base
    
    #Now rebase, we do this so our vtable ptr is accurate in the IDA display
    rebase_program(delta,  0x0008)
	
    #Bring focus to the vtable
    idaapi.jumpto(vtbl_ptr)
    
    #Name it after the interface name
    MakeName(vtbl_ptr, interface_name + '_vtable')
    
    #Now skip down the vtable past the stuff inherited from IDispatch etc.
    #Not 100% sure this will always be the same....
    first_method = vtbl_ptr + (4 * 6)
    
    #Now lets iterate through the methods, _methods_ returns a tuple of tuples
    #which ultimately contain a dispid (http://msdn.microsoft.com/en-us/library/windows/desktop/ms221242(v=vs.85).aspx) 
    #to function name mapping, as far as I have been able to tell dispid matches up directly to the offset within the vtable
    for method in newobj._methods_:
        #Walk down the vtable, which is basically first_method + method_dispid * 4 (bytes)
        #Dword() method derefs the pointer, to get our actual method address
        cur_meth = int(Dword(first_method + int(method[4][0]) * 4))
        #Get the actual method name
        meth_name = method[4][1].split('method')[1].strip()
        #Name the function, note we have to encode it to ascii as comtypes gives us the name in unicode, which IDA dislikes
        MakeName(cur_meth, meth_name.encode('ascii'))
    
    
	
	
	