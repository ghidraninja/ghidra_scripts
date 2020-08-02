# Demangle swift function names
# A script can be easily created in the Script Manager window
# Make sure https://github.com/luser/rustfilt is installed on your system

#@author Thomas Roth
#@category Ghidra Ninja.Rust
#@keybinding 
#@menupath 
#@toolbar 

from subprocess import Popen, PIPE

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import CodeUnit

functionManager = currentProgram.getFunctionManager()

# Get functions in ascending order
fns = functionManager.getFunctions(True)
for f in fns:
    f_name = f.getName()
    # Is it a mangled name?
    if not (f_name.startswith("_ZN") or f_name.startswith("_R")):
        continue

    previous_comment = f.getComment()
    if not previous_comment:
        previous_comment = ""

    rustfilt = Popen(['rustfilt'], stdin=PIPE, stdout=PIPE)
    signature = rustfilt.communicate(input=f_name)[0]

    # Replace characters we can't have in our name
    signature = signature.split("(")[0]
    signature = signature.replace(" ", "_")

    f.setName(signature, SourceType.ANALYSIS)
