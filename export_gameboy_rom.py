# Export a working Game Boy ROM imported with Gekkio's GhidraBoy
#@author Thomas Roth thomas.roth@leveldown.de
#@category Ghidra Ninja.Game Boy

def dump_block(file, name):
	block = currentProgram.memory.getBlock(name)
	file.write(block.getData().readAllBytes())

def rom_sorter(e):
	return int(e[3:])

blocks = currentProgram.memory.getBlocks()
names = []
for block in blocks:
	if(block.getName().startswith("rom")):
		names.append(block.getName())

names = sorted(names, key=rom_sorter)
rom_file = str(askFile("Select target file", "Save ROM"))

with open(rom_file, "wb") as f:
	for n in names:
		dump_block(f, n)
