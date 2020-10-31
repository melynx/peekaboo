PROG := read_trace
PROJ_HOME := .
IDIR_PEEKABOO := $(addprefix $(PROJ_HOME)/,libpeekaboo)
LDIR_PEEKABOO := $(addprefix $(PROJ_HOME)/,libpeekaboo)
STATIC_LIB_TARGET := $(addprefix $(LDIR_PEEKABOO)/,libpeekaboo.a)

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
else
	$(info WARNING: Binutils-dev not found. Disassembling in the trace reader is disabled.)
	$(info )
endif # HAVE_GAS

all: $(PROG)

debug: CFLAGS += -DDEBUG -g
debug: $(PROG)

read_trace: binutils_warning | read_trace.o $(STATIC_LIB_TARGET) 
	$(CC) read_trace.o $(STATIC_LIB_TARGET) -o read_trace $(CFLAGS) $(LIBS)

$(STATIC_LIB_TARGET):
	(cd $(LDIR_PEEKABOO) && $(MAKE))

.PHONY: clean
clean:
	rm -f *.o *.a *.gch $(PROG)
	(cd $(LDIR_PEEKABOO) && $(MAKE) clean)

.PHONY: binutils_warning
binutils_warning:
ifeq ($(HAVE_GAS),0)
	$(info WARNING: Binutils-dev not found. Disassembling in the trace reader is disabled.)
	$(info )
endif
ifeq ($(HAVE_GAS)$(GAS229_OR_LATER),10)
	$(info WARNING: Binutils-dev>=2.29 required. Disassembling in the trace reader is disabled.)
	$(info )
endif