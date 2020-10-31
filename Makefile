PROG := read_trace

PROJ_HOME := .
IDIR_PEEKABOO := $(addprefix $(PROJ_HOME)/,libpeekaboo)
LDIR_PEEKABOO := $(addprefix $(PROJ_HOME)/,libpeekaboo)
LIBOBJ := $(addprefix $(LDIR_PEEKABOO)/,libpeekaboo.a)

RM ?= rm -f

LDLIBS = -lpeekaboo -lm 
OPT = -O3
WARNINGS = #-Wall -Wextra
CFLAGS = $(OPT) $(WARNINGS) -I$(IDIR_PEEKABOO) -L$(LDIR_PEEKABOO)

# Solaris provides a non-Posix shell at /usr/bin
ifneq ($(wildcard /usr/xpg4/bin),)
  GREP ?= /usr/xpg4/bin/grep
else
  GREP ?= grep
endif

# We only support binutils 2.29 or later for disasm with libopcodes.
HAVE_GAS := $(shell $(CC) -xc -c /dev/null -Wa,-v -o/dev/null 2>&1 | $(GREP) -c "GNU assembler")
ifneq ($(HAVE_GAS),0)
	GAS229_OR_LATER := $(shell $(CC) -xc -c /dev/null -Wa,-v -o/dev/null 2>&1 | $(GREP) -c -E "GNU assembler version (2\.29|2\.[3-9]|[3-9])")
	ifneq ($(GAS229_OR_LATER),0)
		CFLAGS += -DASM
		LDLIBS += -lopcodes
	endif # -DASM
endif # HAVE_GAS

all: $(PROG) | binutils_warning 

debug: CFLAGS += -DDEBUG -g 
debug: is_debug = debug
debug: all

read_trace: read_trace.o $(LIBOBJ) 
	$(CC) -o $@ $(strip $(CFLAGS) $^ $(LDLIBS))

%.o: %.c
	$(CC) $(strip $(CFLAGS) -c) $<

$(LIBOBJ):
	(cd $(LDIR_PEEKABOO) && $(strip $(MAKE) $(findstring debug,$(is_debug))))

.PHONY: clean
clean:
	$(RM) *.o *.a *.gch $(PROG)
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