# Peekaboo
Peekaboo is an attempt to provide an easily extensible and usable dynamic trace
format. Peekaboo provides definitions for typical properties expected for
dynamic traces like instruction addresses, memory operand info, register info,
etc. The trace is structured as a collection of files each corresponding to some
piece of information which the trace support. Currently, peekaboo has a
execution tracer that is built on top of DynamoRIO. There are future plans for a
PIN execution tracer and different conversion tools to convert traces obtained
from other tools to peekaboo format.

## Architectures
### Currently Support
AMD64, AARCH64, X86
### Planned Support
AARCH32

## C/C++ library: libpeekaboo
### How to build
```
cd libpeekaboo
make
```
### How to install
This is for your easy deployment, not required for the tracer or the trace reader.
```
sudo make install
```
### How to uninstall
```
sudo make uninstall
```

## Tracer (DynamoRIO)
### Dependency
- [DynamoRIO](https://github.com/DynamoRIO/dynamorio)>= 7.90.17998

### How to build
Before building the tracer, you need to build `libpeekaboo` in libpeekaboo directory.
```
cd peekaboo_dr
mkdir build
cd build
DynamoRIO_DIR=($DynamoRIO_PATH) cmake ..
make
```
Then you will have a file named 'libpeekaboo_dr.so' under the build folder.
### How to start tracing
Say, you want to run with command ls in 64-bit mode:
```
($DynamoRIO_PATH)/bin64/drrun -c ($Peekaboo_PATH)/peekaboo_dr/build/libpeekaboo_dr.so -- ls
```
### What you can get
You should get a folder in the current directory like this:
```
ls-31401
|----insn.bytemap
|----process_tree.txt
|----31401
      |----insn.trace
      |----memfile
      |----memrefs
      |----metafile
      |----proc_map
      |----regfile
```
If the application forked during tracing, there will be other sub folders. The structure will be like this (child PID is `32109`):
```
fork-32105
|----insn.bytemap
|----process_tree.txt
|----32105
|     |----insn.trace
|     |----memfile
|     |----memrefs
|     |----metafile
|     |----proc_map
|     |----regfile
|----32109
      |----insn.trace
      |----memfile
      |----memrefs
      |----metafile
      |----proc_map
      |----regfile
```
## Trace Reader (C/C++)
### Dependency
(Optional) For disassembly function
- (Recommended) `libcapstone-dev`
- `binutils-dev`>=2.29

### How to build
In the project home directory:
```
make
```
### How to use
```
Usage: ./read_trace [Options] path_to_trace_dir
Options:
  -r               	Print register values.
  -m               	Print memory values.
  -s <instr id>    	Print trace starting from the given id.
  -e <instr id>    	Print trace till the given id.
  -a <memory addr> 	Search for all instructions accessing given memory address.
  -p <pattern file>	Search for instruction patterns in trace.
  -h               	Print this help.
```
#### Example 1: Print all instructions inside the trace
```
./read_trace ./ls-31401/31401
```
#### Example 2: Print those instructions from the 100th to the 200th
```
./read_trace -s 100 -e 200 ./ls-31401/31401
```
#### Example 3: Print instructions with their memory access address and register values
```
./read_trace -mr ./ls-31401/31401
```
#### Example 4: Search for instruction patterns in the trace
Let's say you want to search for a code snippet with following instructions:
- ...
- `push rbp` 
- `mov rbp,rsp`
- ...

You can create a `pattern.txt` with their rawbytes:
```
55       # push  rbp
48 89 e5 # mov   rbp,rsp
```
Then use `pattern.txt` to search:
```
./read_trace -p pattern.txt ./ls-31401/31401
```
#### Example 5: Search for instructions which accessed certain address
If you want to get all instructions that read/write `0x7fbfc3c3ccde`:
```
./read_trace -a 0x7fbfc3c3ccde ./ls-31401/31401
```
