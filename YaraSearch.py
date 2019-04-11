#Searches the program via YARA.
#@author 
#@category Search
#@keybinding 
#@menupath Search.YARA
#@toolbar 

import os, tempfile

from subprocess import Popen, PIPE
from ghidra.program.model.listing import CodeUnit
from ghidra.program.util import ProgramSelection
from ghidra.util.exception import CancelledException
from ghidra.program.model.mem import MemoryAccessException

PIPE_BUFFER_SIZE=10*1024*1024
SCRIPT_NAME="YaraSearch.py"
COMMENT_STYLE = CodeUnit.PRE_COMMENT

try:
	rule_file = askFile(SCRIPT_NAME, "Search with YARA rule").getPath()
except CancelledException as e:
	print "[!] CANCELLED: " + str(e)
	exit()

# get all memory ranges
ranges = currentProgram.getMemory().getAddressRanges()

for r in ranges:
	begin = r.getMinAddress()
	end = r.getMaxAddress()
	length = r.getLength()
	
	status = "Searching: " + r.toString()
	print "[+] " + status

	try:
		bytes = getBytes(begin,length)
	except MemoryAccessException as e:
		print "[!] FAILED: " + str(e)
		continue

	try:
		tmp = tempfile.NamedTemporaryFile(delete=False)
		print "[+] using temporary file " + tmp.name
		tmp.write(bytes)
		tmp.close()

		command = "yara " + rule_file + " -gs " + tmp.name
		p = Popen(command, stdout=PIPE, stderr=PIPE, shell=True, bufsize=PIPE_BUFFER_SIZE)
		stdout, stderr = p.communicate()
	finally:
		os.unlink(tmp.name)

 	#print stderr

	# fail on non successful execution
	if p.returncode != 0:
		print "[!] FAILED: subprocess did not return with 0 (=success)"
		continue

	lines = stdout.splitlines()
	rule = ""
	tag = ""
	for line in lines:
		if line.startswith("0x"):
			l = line.split(":")
			addr = int(l[0],16)
			string = l[1]
			match = l[2]
			createBookmark(begin.add(addr), SCRIPT_NAME, rule + " " + tag)
			cu = currentProgram.getListing().getCodeUnitAt(begin.add(addr))
			if cu == None:
				print "ERROR: CodeUnitAt " + begin.add(addr).toString() + " does not exist! Can't set comment."
				continue
			comment = cu.getComment(COMMENT_STYLE)
			if comment == None or comment == "":
				comment = ""
			else:
				comment += "\n"
			comment += SCRIPT_NAME + "\n"
			comment += rule + " " + tag + "\n"
			comment += string + ": " + match
			cu.setComment(COMMENT_STYLE, comment)
			print line
		else:
			rule = line.split()[0]
			tag = line.split()[1]
			print rule + " " + tag
	print "[$] SUCCESS"
