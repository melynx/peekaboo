TARGET = libpeekaboo.a
CC = gcc
OPT = -O2
WARNINGS =
ARCH_DIR = ./arch
IDIR = .
LDIR = .
CFLAGS  = $(WARNINGS) $(OPT) -I$(IDIR) -L$(LDIR)

all: $(TARGET)

libpeekaboo.a: libpeekaboo.o aarch64.o amd64.o
	ar rcs $(TARGET) libpeekaboo.o aarch64.o amd64.o
	ranlib libpeekaboo.a

libpeekaboo.o: libpeekaboo.c libpeekaboo.h
	$(CC) -c libpeekaboo.c libpeekaboo.h $(CFLAGS)

aarch64.o: $(ARCH_DIR)/aarch64.c $(ARCH_DIR)/aarch64.h
	$(CC) -c $(ARCH_DIR)/aarch64.c $(ARCH_DIR)/aarch64.h $(CFLAGS)

amd64.o: $(ARCH_DIR)/amd64.c $(ARCH_DIR)/amd64.h
	$(CC) -c $(ARCH_DIR)/amd64.c $(ARCH_DIR)/amd64.h $(CFLAGS)

.PHONY: clean

clean:
	rm -f *.o *.a *.gch