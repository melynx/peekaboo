PROG = read_trace
PROJ_HOME = .
IDIR_PEEKABOO = $(PROJ_HOME)/libpeekaboo
LDIR_PEEKABOO = $(PROJ_HOME)/libpeekaboo
LIBS = -lpeekaboo
CC = gcc
OPT = -O2
WARNINGS =
CFLAGS  = $(WARNINGS) $(OPT) -I$(IDIR_PEEKABOO) -L$(LDIR_PEEKABOO)

all: $(PROG)

debug: CFLAGS += -DDEBUG -g
debug: $(PROG)

read_trace: read_trace.o $(LDIR_PEEKABOO)/libpeekaboo.a
	$(CC) read_trace.o $(LDIR_PEEKABOO)/libpeekaboo.a -o read_trace $(CFLAGS) $(LIBS)

$(LDIR_PEEKABOO)/libpeekaboo.a:
	(cd $(LDIR_PEEKABOO) && $(MAKE))

.PHONY: clean

clean:
	rm -f *.o *.a *.gch $(PROG)
	(cd $(LDIR_PEEKABOO) && $(MAKE) clean)
