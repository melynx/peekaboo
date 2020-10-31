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
	endif # -DASM
endif # HAVE_GAS

all: $(PROG)

debug: CFLAGS += -DDEBUG -g
debug: $(PROG)

read_trace: read_trace.o $(LDIR_PEEKABOO)/libpeekaboo.a 
	$(binutils_warning)
	$(CC) read_trace.o $(LDIR_PEEKABOO)/libpeekaboo.a -o read_trace $(CFLAGS) $(LIBS)

$(LDIR_PEEKABOO)/libpeekaboo.a:
	(cd $(LDIR_PEEKABOO) && $(MAKE))

.PHONY: clean
clean:
	rm -f *.o *.a *.gch $(PROG)
	(cd $(LDIR_PEEKABOO) && $(MAKE) clean)

# Print warning if disassembling is disabled due to incompatible binutils 
.PHONY: binutils_warning
binutils_warning:
ifeq ($(HAVE_GAS),1)
	ifeq ($(GAS229_OR_LATER),0)
		$(info WARNING: Binutils library is too old. Disassembling in the trace reader is disabled.)
		$(info )
	endif # Warning for old binutils
else
	$(info WARNING: Binutils-dev not found. Disassembling in the trace reader is disabled.)
	$(info )
endif # Warning for no binutils-dev
