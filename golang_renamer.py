# Restore func names in stripped Golang binary
#@author Egor Zaytsev & QwErTy
#@category Ghidra Ninja.Golang
#@keybinding 
#@menupath 
#@toolbar 

"""
Initial script for IDA by Egor Zaytsev
https://gitlab.com/zaytsevgu/goutils
ported to GHIDRA by QwErTy (QwErTyReverse on Telegram)
"""

from ghidra.program.model.symbol.SourceType import *
from ghidra.program.model.data import *
import string
import random

addressFactory = currentProgram.getAddressFactory()
functionManager = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()

DWORD = DWordDataType()
QWORD = QWordDataType()
CSTRING = TerminatedStringDataType()

class bitZ(object):
    def __init__(self, ptr, size, maker):
        self.ptr = ptr
        self.size = size
        self.maker = maker

def addressToInt(ghidra_addr):
    return int(ghidra_addr.toString(), 16)

def intToAddress(addr):
    return addressFactory.getAddress(hex(addr))

def MakeDword(addr):
    addr = intToAddress(addr)
    listing.clearCodeUnits(addr, addr, False)
    listing.createData(addr, DWORD)

    return int(listing.getDataAt(addr).value.toString(), 16)

def MakeQword(addr):
    addr = intToAddress(addr)
    listing.clearCodeUnits(addr, addr, False)
    listing.createData(addr, QWORD)

    return int(listing.getDataAt(addr).value.toString(), 16)

def MakeString(addr):
    addr = intToAddress(addr)
    listing.clearCodeUnits(addr, addr, False)
    listing.createData(addr, CSTRING)
    return listing.getDataAt(addr).value

bits32 = bitZ(MakeDword, 4, MakeDword)
bits64 = bitZ(MakeDword, 8, MakeQword)

def get_bitness():
    ptr = bits32
    if currentProgram.defaultPointerSize == 8:
        ptr = bits64
    return ptr

def process_segment(handler, name=".gopclntab"):
    segments = memory.getBlocks() 
    position = 0

    for i in segments:
        if i.getName() == name:
            position = i
            break
    if position == 0:
        GoRenameSectionless()
        # raise Exception("Couldn't find segment")
    else:
        h = handler(addressToInt(position.getStart()), get_bitness())

def go_renamer(beg, ptr):
    base = beg
    pos = beg + 8 #skip header
    size = ptr.ptr(pos)
    pos += ptr.size
    end = pos + (size * ptr.size * 2)
    print "%x" % end
    while pos < end:
        offset = ptr.ptr(pos + ptr.size)
        ptr.maker(pos)
        ptr.maker(pos+ptr.size)
        pos += ptr.size * 2
        ptr.maker(base+offset)
        func_addr = ptr.ptr(base+offset)

        name_offset = MakeDword(base+offset+ptr.size)

        name = MakeString(base + name_offset)
        name += "_" + hex(func_addr)[2:].upper()

        name = name.replace('.','_').replace("<-",'_chan_left_').replace('*','_ptr_').replace('-','_').replace(';','').replace('"','').replace('\\','')
        name = name.replace('(','').replace(')','').replace('/','_').replace(' ','_').replace(',','comma').replace('{','').replace('}','')
        
        func = functionManager.getFunctionAt(intToAddress(func_addr))

        if func != None:
            old_name = func.getName()
            func.setName(name, USER_DEFINED)
            print "%s renamed as %s" % (old_name, name)
        else:
            func = createFunction(intToAddress(func_addr), name)
            print "Created function %s" % name

def tryLocateGopcltab():
    addr = getFirstFunction().getBody().getMinAddress() # Get some valid address in .text segment. Returns ghidra address
    while True:
        possible_loc = memory.findBytes(addr, b"\xFB\xFF\xFF\xFF\x00\x00", b"\xFF\xFF\xFF\xFF\xFF\xFF", True, monitor) #header of gopclntab

        if possible_loc == None:
            return None

        if check_is_gopclntab(addressToInt(possible_loc)):
            return possible_loc

        addr = possible_loc+1
    return None

def check_is_gopclntab(addr):
    ptr = get_bitness()
    first_entry = ptr.ptr(addr+8+ptr.size)
    first_entry_off = ptr.ptr(addr+8+ptr.size*2)
    addr_func = addr+first_entry_off
    func_loc = ptr.ptr(addr_func)
    if func_loc == first_entry:
        return True
    return False

def GoRename():
    process_segment(go_renamer)

def GoRenameSectionless():
    addr = tryLocateGopcltab()
    if addr is not None:
        addr = addressToInt(addr)
        print "Possible Gopclnab found at: %x" % addr
        go_renamer(addr, get_bitness())
    else:
        print "Coulnd't find gopclntab. Is this a Go binary?"

GoRename()
