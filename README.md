# Peekaboo
peekaboo is an attempt to provide an easily extensible and usable dynamic trace
format. peekaboo provides definitions for typical properties expected for
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

## Dependency
read_trace: binutils-dev>=2.29
```
sudo apt install binutils-dev
```
peekaboo_dr: [DynamoRIO](https://github.com/DynamoRIO/dynamorio)

## libpeekaboo API
Build a static library:
```
cd libpeekaboo
make
```
APIs:
TODO

## For DynamoRIO
### How to build
DynamoRIO version must be higher than 7.90.17998
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
Then you should get a folder in the current directory (e.g. ./ls-31401)
### How to read your trace with C/C++
A example reader `read_trace.c` has been provided. You will need binutils-dev to compile it.
```
cd ($Peekaboo_root)
make
./read_trace ($trace_folder)/ls-31401/31401
```
If the application forked during tracing, there will be other sub folders. The structure will be like this:
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
You may use `./read_trace ($trace_folder)/fork-32105/32105` to read the trace of the parent thread and use `./read_trace ($trace_folder)/fork-32105/32109` for the child thread.