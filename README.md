# Peekaboo
A tracer for DynamoRIO and Pin (not supported yet).

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
### How to run
Say, you want to run with command ls in 64-bit mode:
```
($DynamoRIO_PATH)/bin64/drrun -c ($Peekaboo_PATH)/peekaboo_dr/build/libpeekaboo_dr.so -- ls
```
