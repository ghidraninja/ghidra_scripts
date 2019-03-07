# ghidra_scripts
Scripts for the Ghidra software reverse engineering suite.

## Installation

In the Ghidra Script Manager click the "Script Directories" icon in the toolbar and add the checked out repository as a path. Scripts from this collection will appear in the "Ghidra Ninja" category.

## binwalk.py

Runs binwalk on the current program and bookmarks the findings. Requires binwalk to be in `$PATH`.

![Example result: SHA256 constants found by binwalk.](images/binwalk.png)

## yara.py

Automatically find crypto constants in the loaded program - allows to very quickly identify crypto code.

![Example result: ]

Runs yara with the patterns found in yara-crypto.yar on the current program. The Yara rules are licensed under GPLv2. In addition @phoul's SHA256 rule was added.

Requires `yara` to be in `$PATH`.
