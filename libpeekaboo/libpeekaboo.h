/* 
 * Copyright 2019 Chua Zheng Leong
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     https://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __LIBPEEKABOO_H__
#define __LIBPEEKABOO_H__

#include <stdint.h>
#include <stdio.h>
#include <dirent.h>

#define MAX_PATH (256)
#define LIBPEEKABOO_VER 004

#define PEEKABOO_DIE(...) {fprintf(stderr, __VA_ARGS__); exit(1);}

//------Supported archs declarations-----------------------
#include "common.h"
#include "arch/amd64.h"
#include "arch/aarch64.h"
#include "arch/x86.h"
#include "arch/amd64_syscall.h"
//---------------------------------------------------------

// Misc functions
int create_folder(char *name, char *output, uint32_t max_size);
int create_trace_file(char *dir_path, char *filename, int size, FILE **output);
// end

//-----common structure declaration-----------------------
typedef union {
	storage_option_amd64_t amd64; 
	uint64_t size;
}storage_options_t;

typedef struct {
	uint32_t arch;
	uint32_t version;
	storage_options_t storage_options;
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
	uint64_t pc;		/* Ad-hoc fix for alignment to support legacy version traces.*/
} memfile_t;
//---------------------------------------------------------


// peekaboo trace definition
typedef struct {
	uint64_t addr;
	size_t size;
	uint8_t rawbytes[16];
	size_t num_mem;
	memfile_t mem[8];
	uint32_t arch;
	void *regfile;
} peekaboo_insn_t;

typedef struct {
	uint32_t arch;
	size_t ptr_size;
	size_t regfile_size;
	bytes_map_t *bytes_map_buf;
	size_t bytes_map_size;
	size_t num_insns;

	size_t current_id;
	insn_ref_t *insn_ref_buf;
	void *regfile_buf;
	memfile_t *memfile_buf;
	memref_t *memref_buf;
	uint32_t version;

	storage_options_t storage_options;
} peekaboo_internal_t;

typedef struct {
	FILE *insn_trace;
	FILE *bytes_map;
	FILE *regfile;
	FILE *memrefs;
	FILE *memfile;
	FILE *metafile;
	FILE *memrefs_offsets;
	peekaboo_internal_t *internal;
} peekaboo_trace_t;
// end

/*** Tracer Utility ***/
peekaboo_trace_t *create_trace(char *name);
void write_metadata(peekaboo_trace_t *, enum ARCH, uint32_t version);
void close_trace(peekaboo_trace_t *trace);

/*** Trace Reader Utility ***/
void load_trace(char *, peekaboo_trace_t *trace);
void free_peekaboo_trace(peekaboo_trace_t *trace_ptr); // Must be called to free trace pointer loaded by load_trace
peekaboo_insn_t *get_peekaboo_insn(const size_t id, peekaboo_trace_t *trace);
void free_peekaboo_insn(peekaboo_insn_t *insn_ptr); // Must be called to free instruction pointed returned by get_peekaboo_insn
uint64_t get_addr(size_t id, peekaboo_trace_t *trace);
size_t get_num_insn(peekaboo_trace_t *);
void regfile_pp(peekaboo_insn_t *insn);

#endif
