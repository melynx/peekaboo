#ifndef __LIBPEEKABOO_H__
#define __LIBPEEKABOO_H__

#include <stdint.h>
#include <stdio.h>
#include <dirent.h>

#define MAX_PATH (256)
#define LIBPEEKABOO_VER 1

// Bunch of type definitions for register sizes
typedef union {
	uint64_t r;
	uint32_t w[2];
	uint16_t hw[4];
	uint8_t b[8];
} uint64_reg_t;

typedef union {
	uint8_t b[10];
} uint80_t;

typedef union {
	uint64_t r[4];
} uint256_t;

typedef union {
	uint64_t r[2];
} uint128_t;

enum ARCH {
	ARCH_AARCH32,
	ARCH_AARCH64,
	ARCH_X86,
	ARCH_AMD64
};
// end of type definitions

// Misc functions
int create_folder(char *name, char *output, uint32_t max_size);
// end

//-----common structure declaration-----------------------
typedef struct {
	uint32_t arch;
	uint32_t version;
} metadata_hdr_t;

typedef struct insn_ref {
	uint64_t pc;
} insn_ref_t;

typedef struct bytes_map {
	uint64_t pc;
	uint32_t size;
	uint8_t rawbytes[16];
} bytes_map_t ;

typedef struct {
	uint32_t length;	/* how many refs are there*/
} memref_t;

typedef struct {
	uint64_t addr;		/* memory address */
	uint64_t value;		/* memory value */
	uint32_t size;		/* how many bits are vaild in value */
	uint32_t status; 	/* 0 for Read, 1 for write */
} memfile_t;
//---------------------------------------------------------


//------Supported archs declarations-----------------------
#include "arch/amd64.h"
#include "arch/aarch64.h"
//---------------------------------------------------------

// peekaboo trace definition
typedef struct {
	FILE *insn_trace;
	FILE *bytes_map;
	FILE *regfile;
	FILE *memrefs;
	FILE *memfile;
	FILE *metafile;
	void *internal;
} peekaboo_trace_t;

typedef struct {
	insn_ref_t *insn_ref_buf;
	bytes_map_t *bytes_map_buf;
	void *regfile_buf;
	memfile_t *memfile_buf;
	memref_t *memref_buf;
} peekaboo_internal_t;
// end

peekaboo_trace_t *create_trace(char *name);
void close_trace(peekaboo_trace_t *trace);
peekaboo_trace_t *load_trace(char *);

void write_metadata(peekaboo_trace_t, enum ARCH, uint32_t version);
//size_t num_insn(peekaboo_trace_t);
//size_t num_regfile(peekaboo_trace_t);
//int load_bytes_map(peekaboo_trace_t, bytes_map_t *);

#endif
