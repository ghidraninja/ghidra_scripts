# Demangle swift function names
#@author Thomas Roth
#@category Ghidra Ninja.Swift
#@keybinding 
#@menupath 
#@toolbar 

import subprocess

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import CodeUnit

functionManager = currentProgram.getFunctionManager()

# Get functions in ascending order
fns = functionManager.getFunctions(True)
for f in fns:
    f_name = f.getName()
    # Is it a mangled name?
    if not f_name.startswith("_$"):
        continue


    previous_comment = f.getComment()
    if not previous_comment:
        previous_comment = ""

    signature_full = subprocess.check_output(["swift", "demangle", "-compact", f_name])[:-1]
    signature = signature_full


    # Check if it's one of those strange verbose names like:
    # generic specialization <Any> of Swift._allocateUninitializedArray<A>(Builtin.Word) -> ([A], Builtin.RawPointer)
    # If yes, we use the simplified version.
    #
    # This is a workaround and not really nice :)
    # We basically just check whether there is more than 1 space in the function name
    func_description = signature.split("(")[0]
    if func_description.count(" ") > 1:
        signature = subprocess.check_output(["swift", "demangle", "-compact", "-simplified", f_name])[:-1]

    # Replace characters we can't have in our name
    signature = signature.split("(")[0]
    signature = signature.replace(" ", "_")

    # Add newlines into full comment (maximum comment len = 58, afterwards truncated)
    lines = len(signature_full) / 58
    for l in range(1, lines+1):
        signature_full = signature_full[:(l*58)+(l-1)] + "\n" + signature_full[(l*58)+(l-1):]

    f.setComment(previous_comment + "\n" + signature_full)
    f.setName(signature, SourceType.ANALYSIS)
