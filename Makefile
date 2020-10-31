PROG = read_trace
PROJ_HOME = .
IDIR_PEEKABOO = $(PROJ_HOME)/libpeekaboo
LDIR_PEEKABOO = $(PROJ_HOME)/libpeekaboo
LIBS = -lpeekaboo -lm 
CC = gcc
OPT = -O2
WARNINGS =
CFLAGS  = $(WARNINGS) $(OPT) -I$(IDIR_PEEKABOO) -L$(LDIR_PEEKABOO)

# Solaris provides a non-Posix shell at /usr/bin
ifneq ($(wildcard /usr/xpg4/bin),)
  GREP ?= /usr/xpg4/bin/grep
else
  GREP ?= grep
endif

# We only support binutils 2.29 or later for disasm with libopcodes.
HAVE_GAS := $(shell $(CXX) -xc -c /dev/null -Wa,-v -o/dev/null 2>&1 | $(GREP) -c "GNU assembler")
ifneq ($(HAVE_GAS),0)
	GAS229_OR_LATER := $(shell $(CXX) -xc -c /dev/null -Wa,-v -o/dev/null 2>&1 | $(GREP) -c -E "GNU assembler version (2\.29|2\.[3-9]|[3-9])")
	ifneq ($(GAS229_OR_LATER),0)
		CFLAGS += -DASM
		LIBS += -lopcodes
	else
		$(info WARNING: Binutils library is too old. Disassembling in the trace reader is disabled.)
		$(info )
	endif # -DASM
else
	$(info WARNING: Binutils-dev not found. Disassembling in the trace reader is disabled.)
	$(info )
endif # HAVE_GAS

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