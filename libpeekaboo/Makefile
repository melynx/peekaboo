OBJLIB = libpeekaboo.a
OPT = -O3
WARNINGS =
ARCH_DIR = ./arch
IDIR = .
LDIR = .
CFLAGS  = $(WARNINGS) $(OPT) -I$(IDIR) -L$(LDIR)

RM ?= rm -f

ARCH_SRC = $(wildcard $(ARCH_DIR)/*.c)
ARCH_OBJ = $(patsubst %.c,%.o,$(ARCH_SRC))
OBJ = $(patsubst %.c,%.o,$(wildcard *.c))

all: $(OBJLIB)

debug: CFLAGS += -DDEBUG -g 
debug: all

$(OBJLIB): $(OBJ) $(ARCH_OBJ)
	ar rcs $(OBJLIB) $^
	ranlib libpeekaboo.a

%.o: %.c
	$(CC) $(strip $(CFLAGS) -c) $<

$(ARCH_DIR)/%.o : $(ARCH_DIR)/%.c
	$(CC) $(strip $(CFLAGS) -c) -o $(patsubst %.c,%.o,$@) $<

.PHONY: clean
clean:
	$(RM) *.o *.a *.gch $(ARCH_DIR)/*.o $(ARCH_DIR)/*.gch