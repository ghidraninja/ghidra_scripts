# Demangle swift function names
#@author Thomas Roth & Or Dagmi
#@category Ghidra Ninja.Swift
#@keybinding 
#@menupath 
#@toolbar 

import subprocess
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import CodeUnit
import java.lang


OS = java.lang.System.getProperty("os.name").lower()
IS_WINDOWS = OS.startswith("windows")


def execute_swift(params):
    exec_parameters = ["swift"] + params
    if IS_WINDOWS:
        cmd_line = ' '.join(exec_parameters)
        # Since the $ symbol is reserved for accessing environment variables, we need to escape it. 
        # To make it work we actually need to escape it with 3 backsapces, and since we need to also
        # escape the '\' in python, we need 6 escapes in total.
        cmd_line = cmd_line.replace('$', '\\\\\\$')  
        exec_parameters = ["bash", "-c", cmd_line]
    return subprocess.check_output(exec_parameters)


def demangle(name):
    signature_full = execute_swift(["demangle", "-compact", name])[:-1]
    signature = signature_full

    # Check if it's one of those strange verbose names like:
    # generic specialization <Any> of Swift._allocateUninitializedArray<A>(Builtin.Word) -> ([A], Builtin.RawPointer)
    # If yes, we use the simplified version.
    #
    # This is a workaround and not really nice :)
    # We basically just check whether there is more than 1 space in the function name
    func_description = signature.split("(")[0]
    if func_description.count(" ") > 1:
        signature = execute_swift(["demangle", "-compact", "-simplified", name])[:-1]

    # Replace characters we can't have in our name
    signature = signature.split("(")[0]
    signature = signature.replace(" ", "_")

    # Add newlines into full comment (maximum comment len = 58, afterwards truncated)
    lines = len(signature_full) / 58
    for l in range(1, lines+1):
        signature_full = signature_full[:(l*58)+(l-1)] + "\n" + signature_full[(l*58)+(l-1):]
    
    return (signature_full, signature)


def is_mangled_name(name):
    if name.startswith('_$'):
        return True
    
    if name.startswith('_T'):
        return True

    return False

def demangle_functions():
    functionManager = currentProgram.getFunctionManager()

    # Get functions in ascending order
    fns = functionManager.getFunctions(True)
    for f in fns:
        try: 
            f_name = f.getName()
            # Is it a mangled name?
            if not is_mangled_name(f_name):
                continue

            previous_comment = f.getComment()
            if not previous_comment:
                previous_comment = ""

            signature_full, signature = demangle(f_name)

            f.setComment(previous_comment + "\n" + signature_full)
            f.setName(signature, SourceType.ANALYSIS)
        except:
            print("WARNING: could not change function name for: %s" % f_name)


def demangle_symbols():
    symbolTable = currentProgram.getSymbolTable()
    for s in symbolTable.getAllSymbols(True):
        try: 
            s_name = s.getName()

            if not is_mangled_name(s_name):
                continue

            demangled_name = demangle(s_name)[1] 
            if demangled_name != '':
                s.setName(demangled_name, SourceType.ANALYSIS)
        except:
            print("WARNING: could not change symbol name for: %s" % s_name)


demangle_functions()
demangle_symbols()