idapython
========


Idapython is the python API to the IDA dissassembler/debugger/decompiler.

[IDA Homepage] (https://www.hex-rays.com/products/ida/)

[Idapython API Doc Page] (https://www.hex-rays.com/products/ida/support/idapython_docs/)

###activex namer###
Using comraider/view-source/oleview I knew the name of activex methods but IDA does not. So this gets the pointer to the objects vtable, and then using the methods dispid determines the offset into the vtable for that method and appropriately names it in IDA. Not sure if it can be guarenteed that the dispid is the offset of the method in the vtable, but worked for me. This is dependent on [Comtypes library] (https://pythonhosted.org/comtypes/).


###import fixer###
Came across an issue where IDA couldn't resolve some imports, this script can parse the export table of a dll and name the imports on a target exe. Dependent on [pefile library] (https://code.google.com/p/pefile/)


