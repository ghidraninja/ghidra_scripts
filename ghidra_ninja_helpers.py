# Tools and workarounds for the Ghidra Ninja scripts.
#@author Thomas Roth code@stacksmashing.net
#@category Ghidra Ninja
#@keybinding 
#@menupath 
#@toolbar 

import os

# Workaround for __file__ not being available in the script
# (We need to get the path of the script to find the Yara rules)
PATH = os.path.dirname(__file__)
