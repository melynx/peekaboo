# Command ard arguments
AR ?= ar
ARFLAGS ?= -rcs # ar needs the dash on OpenBSD
RANLIB ?= ranlib
GREP ?= grep
CHMOD ?= chmod
MKDIR ?= mkdir
CP ?= cp
MV ?= mv
RM ?= rm -f
LN ?= ln -sf
LDCONF ?= /sbin/ldconfig


# Support MacOS and Linux
MACHINE := $(shell $(CC) -dumpmachine 2>/dev/null)
IS_DARWIN := $(shell echo "$(MACHINE)" | $(GREP) -i -c "Darwin")
IS_LINUX := $(shell echo "$(MACHINE)" | $(GREP) -i -c "Linux")

# Version config
LIB_VER := $(shell $(GREP) "define LIBPEEKABOO_VER" libpeekaboo.h | cut -d" " -f 3)
LIB_MAJOR := $(shell echo $(LIB_VER) | cut -c 1)
LIB_MINOR := $(shell echo $(LIB_VER) | cut -c 2)
LIB_PATCH := $(shell echo $(LIB_VER) | cut -c 3)
SOLIB_VERSION_SUFFIX=.$(LIB_MAJOR).$(LIB_MINOR).$(LIB_PATCH)
SOLIB_COMPAT_SUFFIX=.$(LIB_MAJOR).$(LIB_MINOR)
HAS_SOLIB_VERSION := $(IS_LINUX)

# General variables
# OPT ?= -O3
OPT ?= -DDEBUG -g -O0
PIC_FLAG ?= -fPIC
LDLIBS ?=
LDFLAGS ?=
SOLIB_FLAGS ?= -Wl,-soname,libpeekaboo.so$(SOLIB_COMPAT_SUFFIX)
CFLAGS ?= $(WARNINGS) $(OPT) -I$(IDIR) -L$(LDIR)
ifneq ($(IS_DARWIN),0)
  AR = libtool
  ARFLAGS = -static -o
  CC ?= gcc
endif

# Default prefix for make install
ifeq ($(PREFIX),)
PREFIX := /usr/local
endif

# Follow http://www.gnu.org/prep/standards/html_node/Directory-Variables.html
ifeq ($(DATADIR),)
DATADIR := $(PREFIX)/share
endif
ifeq ($(LIBDIR),)
LIBDIR := $(PREFIX)/lib
endif
ifeq ($(BINDIR),)
BINDIR := $(PREFIX)/bin
endif
ifeq ($(INCLUDEDIR),)
INCLUDEDIR := $(PREFIX)/include
endif

# Common 
WARNINGS ?=
ARCH_DIR = ./arch
IDIR ?= .
LDIR ?= .

# Source and object files
ARCH_SRC = $(wildcard $(ARCH_DIR)/*.c)
ARCH_OBJ = $(patsubst %.c,%.o,$(ARCH_SRC))
ARCH_AMD64_CONF = $(ARCH_DIR)/amd64_conf.h
OBJ = $(patsubst %.c,%.o,$(wildcard *.c))
LIBOBJ = $(ARCH_OBJ) $(OBJ)

# Configure
ifeq ($(DISABLE_SIMD),)
endif
ifeq ($(DISABLE_FXSAVE),)
endif


# Targets and Recipes
.PHONY: all
all: static dynamic | installation_hint
ifneq ($(IS_DARWIN),0)
static: libpeekaboo.a
dynamic: libpeekaboo.dylib
else
static: libpeekaboo.a
dynamic: libpeekaboo.so$(SOLIB_VERSION_SUFFIX)
endif

# Debug
debug: CFLAGS += -DDEBUG -g 
debug: all

libpeekaboo.a: $(LIBOBJ)
ifneq ($(IS_DARWIN),0)
	-$(CP) *.o $(ARCH_DIR)/
endif
	$(AR) $(ARFLAGS) $@ $^
	$(RANLIB) $@

libpeekaboo.dylib: $(LIBOBJ)
	$(CC) -dynamiclib -o $@ $(strip $(CFLAGS)) -install_name "$@" -current_version "$(LIB_MAJOR).$(LIB_MINOR).$(LIB_PATCH)" -compatibility_version "$(LIB_MAJOR).$(LIB_MINOR)" -headerpad_max_install_names $(LDFLAGS) $^

libpeekaboo.so$(SOLIB_VERSION_SUFFIX): $(LIBOBJ)
	$(CC) -shared $(SOLIB_FLAGS) -o $@ $(strip $(CFLAGS) $(PIC_FLAG) $(LDFLAGS) $(LDLIBS) $^)
ifeq ($(HAS_SOLIB_VERSION),1)
	-$(LN) libpeekaboo.so$(SOLIB_VERSION_SUFFIX) libpeekaboo.so
	-$(LN) libpeekaboo.so$(SOLIB_VERSION_SUFFIX) libpeekaboo.so$(SOLIB_COMPAT_SUFFIX)
endif

%.o: %.c
	$(CC) $(strip $(CFLAGS) $(PIC_FLAG) -c) $<

$(ARCH_DIR)/%.o : $(ARCH_DIR)/%.c | config
	$(CC) $(strip $(CFLAGS) $(PIC_FLAG) -c) -o $(patsubst %.c,%.o,$@) $<

# Configuration for what to store
.PHONY: config
config:
ifeq ($(ONLY_GPR), 1)
	$(info Only stores GPRs.)
	$(shell echo > $(ARCH_AMD64_CONF))
else
ifneq ($(DISABLE_SIMD), 1)
	$(info Enable SIMD storage.)
	$(shell echo "#define _STORE_SIMD" > $(ARCH_AMD64_CONF))
endif
ifneq ($(DISABLE_FXSAVE), 1)
	$(info Enable FXSAVE storage.)
	$(shell echo "#define _STORE_FXSAVE" >> $(ARCH_AMD64_CONF))
endif
endif

.PHONY: install
install:
	@# Copy header files and set permission
	@-$(MKDIR) -p $(INCLUDEDIR)/libpeekaboo
	$(CP) *.h $(INCLUDEDIR)/libpeekaboo
	-$(CHMOD) 0755 $(INCLUDEDIR)/libpeekaboo
	-$(CHMOD) 0644 $(INCLUDEDIR)/libpeekaboo/*.h
	@-$(MKDIR) -p $(INCLUDEDIR)/libpeekaboo/arch
	$(CP) $(ARCH_DIR)/*.h $(INCLUDEDIR)/libpeekaboo/arch
	-$(CHMOD) 0755 $(INCLUDEDIR)/libpeekaboo/arch
	-$(CHMOD) 0644 $(INCLUDEDIR)/libpeekaboo/arch/*.h
	
	@# Copy static library and set permission
ifneq ($(wildcard libpeekaboo.a),)
	@-$(MKDIR) -p $(LIBDIR)
	$(CP) libpeekaboo.a $(LIBDIR)
	-$(CHMOD) 0644 $(LIBDIR)/libpeekaboo.a
endif
	
	@# Copy dynamic library for MacOS and set permission
ifneq ($(wildcard libpeekaboo.dylib),)
	@-$(MKDIR) -p $(LIBDIR)
	$(CP) libpeekaboo.dylib $(LIBDIR)
	-install_name_tool -id $(LIBDIR)/libpeekaboo.dylib $(LIBDIR)/libpeekaboo.dylib
	-$(CHMOD) 0755 $(LIBDIR)/libpeekaboo.dylib
endif

	@# Copy dynamic library for non-Mac OS and set permission
ifneq ($(wildcard libpeekaboo.so$(SOLIB_VERSION_SUFFIX)),)
	@-$(MKDIR) -p $(LIBDIR)
	$(CP) libpeekaboo.so$(SOLIB_VERSION_SUFFIX) $(LIBDIR)
	@-$(CHMOD) 0755 $(LIBDIR)/libpeekaboo.so$(SOLIB_VERSION_SUFFIX)
ifeq ($(HAS_SOLIB_VERSION),1)
	@# Create soft link for Linux
	-$(LN) libpeekaboo.so$(SOLIB_VERSION_SUFFIX) $(LIBDIR)/libpeekaboo.so
	-$(LN) libpeekaboo.so$(SOLIB_VERSION_SUFFIX) $(LIBDIR)/libpeekaboo.so$(SOLIB_COMPAT_SUFFIX)
	$(LDCONF) $(LIBDIR)
endif
endif


.PHONY: remove uninstall
remove uninstall:
	-$(RM) -r $(INCLUDEDIR)/libpeekaboo
	-$(RM) $(LIBDIR)/libpeekaboo.a
	@-$(RM) $(LIBDIR)/libpeekaboo.dylib
	@-$(RM) $(LIBDIR)/libpeekaboo.so$(SOLIB_VERSION_SUFFIX)
	@-$(RM) $(LIBDIR)/libpeekaboo.so$(SOLIB_COMPAT_SUFFIX)
	@-$(RM) $(LIBDIR)/libpeekaboo.so
	@-$(RM) -r $(DATADIR)/libpeekaboo


.PHONY: clean
clean:
	-$(RM) *.o *.gch $(ARCH_DIR)/*.o $(ARCH_DIR)*.gch
	-$(RM) libpeekaboo.a libpeekaboo.so libpeekaboo.so$(SOLIB_VERSION_SUFFIX) libpeekaboo.so$(SOLIB_COMPAT_SUFFIX) libpeekaboo.dylib


.PHONY: installation_hint
installation_hint:
	$(info To install peekaboo library to your system, run "sudo make install")
	$(info )
