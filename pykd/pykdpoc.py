
"""
1)	Script takes in the name of a module
2)	Reads the IAT and looks for any networking related symbols (i.e. WININET, WSOCK32, WS2_32).
3)	Set a breakpoint on every related symbol and log to the screen
4)	Check if we broke on InternetReadFileExA,  if we did examine the stack and pull out the pointer to the INTERNET_BUFFERS struct (see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385105(v=vs.85).aspx)
5)	Having access to the buffer structure, pull out the pointer to the actual data and compare it to the data we sent
6)	If it matches (i.e. it is our data that was read in by the func) then create a memory access breakpoint (rw) on that buffer to see how it is used
7)	When the memory access breakpoint is hit then check to see if it is being accessed within the module we are interested in, if so log to screen
"""



from pykd import *
import sys


mymod = module(sys.argv[1])

mydata = 'AAAA'


modules = ['WININET', 'WSOCK32', 'WS2_32']

def bufdump(id):
    '''make sure EIP is within our module'''

    eip = reg('eip')

    if eip >= mymod.begin() and eip <= mymod.end(): 
        dprintln('our data was accessed at 0x%08x' % reg('eip'))

    return False #False apparently tells it to keep debugging
    

def recorder(id):
    '''this checks which symbol we broke on and if it is the symbol we want it looks to see if
        if our data is in the buffer, just looks at InternetReadFileExA for now'''

    cursymbol = findSymbol(reg('eip'))
    esp = reg('esp')
    dprintln('hit %s(%x,%x,%x,%x)' % (cursymbol, ptrDWord(esp+0x4), ptrDWord(esp+0x8), ptrDWord(esp+0xc), ptrDWord(esp+0x10)))

    if 'InternetReadFileExA' in cursymbol:
        thebuf = ptrDWord(ptrDWord(esp+0x8)+0x14)
        data = loadCStr(thebuf)

        if mydata in data:
            dprintln('setting bp at interesting buf: 0x%08x' % thebuf)
            setBp(thebuf, 1, 3, bufdump)
            
    else:
        return False

    return False

def imports(target):
    """pass module object, will parse the IAT and return a list of symbols"""

    for line in dbgCommand('!dh -f ' + target.name()).split('\n'):
        if 'Import Address Table Directory' in line:
            iat,len = line.split(']')[0].split('[')
            iat = iat.strip()
            len = len.strip()

            return dbgCommand('dps %x+%s %x+%s+%s' % (target.begin(), iat, target.begin(), iat, len)).split('\n')

def getmodules(symbol):   

    for modname in modules:
        for symbol in symbols:
            if modname in symbol:
                
                try:
                    symaddr = module(modname).__getattr__(symbol.split('!')[1])

                except:
                    dprintln('Think there was a symbol error, just continuing')

                dprintln('setting bp for sym %s at %x' % ( modname + '!' + symbol.split('!')[1], symaddr))
                setBp(symaddr, recorder) 
                
symbols = imports(mymod)
dprintln(str(symbols))
getmodules(symbols)
    
dbgCommand('.symfix')
dbgCommand('.reload')

go()



