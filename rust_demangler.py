# Demangle Rust function names
# A script can be easily created in the Script Manager window
# Make sure https://github.com/luser/rustfilt is installed on your system

#@author Thomas Roth
#@category Ghidra Ninja.Rust
#@keybinding 
#@menupath 
#@toolbar 

from subprocess import Popen, PIPE
import re

from ghidra.program.model.symbol import *
from ghidra.program.model.listing import CodeUnit

functionManager = currentProgram.getFunctionManager()

fns = functionManager.getFunctions(True)
for f in fns:
    f_name = f.getName()

    # Is it a hash?
    if not re.match(r"\bh[0-9a-f]{16}\b", f_name):
        continue

    signature = f.getComment()
    signature = signature.replace("$LT$", "<")
    signature = signature.replace("$GT$", ">")
    signature = signature.replace("$u20$", " ")
    signature = signature.replace("$C$", ",")
    signature = signature.replace(".", ":")

    try:
        f.setName(signature, SourceType.ANALYSIS)
    except:
        pass

# Get symbols
st = currentProgram.getSymbolTable();
symbols = st.getDefinedSymbols();
for f in symbols:
    f_name = f.getName()

    # Is it a mangled name?
    if not (f_name.startswith("_ZN") or f_name.startswith("_R")):
        continue

    rustfilt = Popen(['rustfilt'], stdin=PIPE, stdout=PIPE)
    signature = rustfilt.communicate(input=f_name)[0]

    # Replace characters we can't have in our name
    signature = signature.split("(")[0]
    signature = signature.replace(" ", "_")

    try:
        f.setName(signature, SourceType.ANALYSIS)
    except:
        pass
