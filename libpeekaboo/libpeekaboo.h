#ifndef __LIBPEEKABOO_H__
#define __LIBPEEKABOO_H__

#include <stdint.h>
#include <stdio.h>
#include <dirent.h>

#define MAX_PATH (256)
#define LIBPEEKABOO_VER 1

typedef struct {
	FILE *insn_trace;
	FILE *bytes_map;
	FILE *regfile;
	FILE *memfile;
	FILE *memrefs;
	FILE *metafile;
} peekaboo_trace_t;

typedef struct {
	uint32_t arch;
	uint32_t version;
} metadata_hdr_t;

enum ARCH {
	ARCH_AARCH32,
	ARCH_AARCH64,
	ARCH_X86,
	ARCH_AMD64
};

int create_folder(char *name, char *output, uint32_t max_size);
int create_trace(char *name, peekaboo_trace_t *trace);
int close_trace(peekaboo_trace_t *trace);

#endif
