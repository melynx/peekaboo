#include <stdint.h>
#include <stdio.h>
#include <dirent.h>

#define MAX_PATH (256)

typedef struct {
	FILE *insn_trace;
	FILE *bytes_map;
	FILE *regfile;
	FILE *memfile;
	FILE *metafile;
} peekaboo_trace_t;

int create_folder(char *name, char *output, uint32_t max_size);
int create_trace(char *name, peekaboo_trace_t *trace);
int close_trace(peekaboo_trace_t *trace);
