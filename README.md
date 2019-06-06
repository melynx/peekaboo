# Peekaboo
A tracer for DynamoRIO and Pin (not supported yet).

## How to build Peekaboo for DynamoRIO
```
cd peekaboo_dr
mkdir build
cd build
DynamoRIO_DIR=($DynamoRIO_PATH) cmake ..
```
Then you will have a file named 'libpeekaboo_dr.so' under the build folder.
