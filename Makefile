# Command ard arguments
RM ?= rm -f
GREP ?= grep

PROG := read_trace

PROJ_HOME := .
DIR_PEEKABOO := $(addprefix $(PROJ_HOME)/,libpeekaboo)
LDIR := $(DIR_PEEKABOO)

LDLIB_PEEKABOO := -lpeekaboo
LDLIBS = -lm $(LDLIB_PEEKABOO) 
OPT = -O3
WARNINGS = #-Wall -Wextra
CFLAGS = $(OPT) $(WARNINGS)

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
debug: all

read_trace: read_trace.o $(LDLIBS) 
	$(CC) -o $@ $(strip $(CFLAGS) -L$(LDIR) $^)

%.o: %.c
	$(CC) $(strip $(CFLAGS) -c) $<

$(LDLIB_PEEKABOO): 
	(cd $(DIR_PEEKABOO) && $(strip $(MAKE) $(patsubst DEBUG,debug,$(findstring DEBUG,$(CFLAGS)))))

.PHONY: clean
clean:
	$(RM) *.o *.a *.gch $(PROG)
	(cd $(DIR_PEEKABOO) && $(MAKE) clean)

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