# Run Yara with crypto patterns on the current file and create bookmarks and EOL comments for findings.
#@author Thomas Roth code@stacksmashing.net
#@category Ghidra Ninja
#@keybinding
#@menupath
#@toolbar

import ghidra_ninja_helpers as gn
import subprocess
import tempfile
import os
from ghidra.program.model.listing import CodeUnit


def convert_phys_addr(addr):
    # Convert physical address to logical address
    for section in currentProgram.getMemory().getBlocks():
        pointer_to_rawdata = section.getSourceInfos()[0].fileBytesOffset
        rawdata_size = section.getSourceInfos()[0].length
        if (addr >= pointer_to_rawdata) and (addr <= pointer_to_rawdata + rawdata_size):
            # This is it
            return section.start.offset + addr - pointer_to_rawdata
    return None


def add_bookmark_comment(addr, text):
    gaddr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(addr)
    createBookmark(gaddr, "yara", text)
    cu = currentProgram.getListing().getCodeUnitAt(gaddr)
    cu.setComment(CodeUnit.EOL_COMMENT, text)


# Start
file_location = currentProgram.getExecutablePath()
rule_location = os.path.join(gn.PATH, "yara-crypto.yar")

if not os.path.isfile(file_location):
    print("File not found at {}".format(file_location))
    sys.exit(-1)
if not os.path.isfile(rule_location):
    print("yara rules not found at {}".format(rule_location))
    sys.exit(-1)

current_rule = None
output = subprocess.check_output(["yara", "--print-string-length", rule_location, file_location], stderr=None)
for line in output.splitlines():
    if line.startswith("0x"):
        if current_rule:
            addr_int = int(line.split(":")[0][2:], 16)
            vaddr = convert_phys_addr(addr_int)
            if vaddr:
                print("Found : {} - {} - {}".format(current_rule, hex(addr_int), hex(vaddr)))
                add_bookmark_comment(vaddr, current_rule)
            else:
                print("Physical address {} cannot be converted".format(hex(addr_int)))
    else:
        current_rule = line.split(" ")[0]
