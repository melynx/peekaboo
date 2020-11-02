# Command ard arguments
RM ?= rm -f
GREP ?= grep
LDCONF ?= /sbin/ldconfig
FILE ?= file

# Support MacOS and Linux
MACHINE := $(shell $(CC) -dumpmachine 2>/dev/null)
IS_DARWIN := $(shell echo "$(MACHINE)" | $(GREP) -i -c "Darwin")
IS_LINUX := $(shell echo "$(MACHINE)" | $(GREP) -i -c "Linux")

# General variables
OPT ?= -O3
WARNINGS = #-Wall -Wextra
LDLIB_PEEKABOO ?= -lpeekaboo
LDLIBS := $(LDLIB_PEEKABOO) 
ifneq ($(IS_DARWIN), 1)
	LDLIBS += -lm # MacOS doesn't need link math library
endif
CFLAGS ?= $(OPT) $(WARNINGS)

# Path
PROJ_HOME := .
DIR_PEEKABOO := $(addprefix $(PROJ_HOME)/,libpeekaboo)

# We only support binutils-dev 2.29 or later for disasm with libopcodes. 
# KH: Note that MacOS doesn't use binutils.
HAVE_GAS := $(shell $(CC) -xc -c /dev/null -Wa,-v -o/dev/null 2>&1 | $(GREP) -c "GNU assembler")
ifneq ($(HAVE_GAS),0)
	GAS229_OR_LATER := $(shell $(CC) -xc -c /dev/null -Wa,-v -o/dev/null 2>&1 | $(GREP) -c -E "GNU assembler version (2\.29|2\.[3-9]|[3-9])")
	ifneq ($(GAS229_OR_LATER),0)
		ifneq (, $(shell which dpkg))
			Binutils_dev_229_OR_LATER := $(shell dpkg -s binutils-dev | $(GREP) -c -E "Version: (2\.29|2\.[3-9]|[3-9])")
		endif
		ifneq (, $(Binutils_dev_229_OR_LATER))
			ifeq ($(Binutils_dev_229_OR_LATER), 1)
				# We are sure it has right version of binutils-dev
				CFLAGS += -DASM
				LDLIBS += -lopcodes
			else 
				HAVE_GAS_BUT_NO_DEV := 1
			endif
		else
			# Fixup: It has right version of binutils, but not sure if it has binutils-dev correctly.
			CFLAGS += -DASM
			LDLIBS += -lopcodes
		endif
	endif # -DASM
endif # HAVE_GAS

# Search for libpeekaboo dynamic library on system
ifeq ($(IS_LINUX),1)
	# Use ldconf to search for peekaboo in dynamic lib caceh
	HAVE_LIBPEEKABOO_SO := $(shell $(LDCONF) -p | $(GREP) -c "peekaboo")
endif
ifeq ($(IS_DARWIN), 1)
	# MacOS doesn't have ldconf
	HAVE_LIBPEEKABOO_SO ?= $(shell $(FILE) /usr/local/lib/libpeekaboo.dylib | $(GREP) -c -i "dynamically linked shared library")
endif

# Targets and Recipes
PROG := read_trace

all: $(PROG) | binutils_warning 

debug: CFLAGS += -DDEBUG -g 
debug: all

read_trace: read_trace.o $(LDLIBS) 
ifeq ($(HAVE_LIBPEEKABOO_SO), 0)
	@# Cannot find peekaboo installed. Static link!
	$(CC) -o $@ $(strip $(CFLAGS) $< $(patsubst -lpeekaboo,$(DIR_PEEKABOO)/libpeekaboo.a,$(LDLIBS)))
else
	@# Dynamic link if libpeekaboo has been installed
	$(CC) -o $@ $(strip $(CFLAGS) $^)
endif

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
	$(info WARNING: Binutils not found. Disassembling in the trace reader is disabled.)
	$(info )
endif
ifeq ($(HAVE_GAS)$(GAS229_OR_LATER),10)
	$(info WARNING: Binutils-dev>=2.29 required. Disassembling in the trace reader is disabled.)
	$(info )
endif
ifeq ($(HAVE_GAS_BUT_NO_DEV),1)
	$(info WARNING: Binutils-dev>=2.29 required. Disassembling in the trace reader is disabled.)
	$(info Upgrade your binutils-dev to enable disassembling.)
	$(info)
endif