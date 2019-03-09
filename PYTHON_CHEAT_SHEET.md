# Ghidra Python Scripting Cheat-sheet

## Pre-imported globals

These are available in the shell and in scripts, no need to import anything:

| Name | Type | Description |
| --- | --- | --- |
| `currentAddress` | `ghidra.program.model.address.GenericAddress` | The currently selected address. |
| `currentHighlight` | | TODO |
| `currentProgram` | `ghidra.program.database.ProgramDB` | The current program. |
| `currentSelection` | `ghidra.program.util.ProgramSelection` | The currently selected instructions. |

## Adding comments

> A code unit is an interface to access both data & instructions


Comment types:

- `EOL_COMMENT`
- `PLATE_COMMENT`
- `PRE_COMMENT`
- `POST_COMMENT`
- `REPEATABLE_COMMENT`

```
cu = currentProgram.getListing().getCodeUnitAt(addr)
cu.setComment(CodeUnit.EOL_COMMENT, "Comment text")
```

## Adding bookmarks

```
createBookmark(addr, "Category", "Description")
```

## Working with functions

```
from ghidra.program.model.symbol import SourceType

# Get the FunctionManager
fm = currentProgram.getFunctionManager()

# Get a function at a certain address
f = fm.getFunctionAt(currentAddress)

# Get a function which contains the currentAddress
f = fm.getFunctionContaining(currentAddress)

# Change the function name
f.setName("test", SourceType.USER_DEFINED)
```

## Working with addresses

```
# Get address from String
address = currentProgram.getAddressFactory().getAddress("0x123")

# Create new address from earlier one
new_address = address.add(5)

# Example: Get an address relative to the program base
currentProgram.minAddress.add(10)
```
