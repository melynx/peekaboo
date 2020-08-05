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

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

#include "libpeekaboo.h"

int create_folder(char *name, char *output, uint32_t max_size)
{
	DIR *dir = opendir(name);
	realpath(name, output);
	if (errno == ENOENT)
		mkdir(name, S_IRWXU|S_IRWXG|S_IROTH);
	else
		return -1;
	return 0;
}

int term_dir(char *path, int size)
{
	int path_len = strlen(path);
	// check if directory terminates with '/'
	if (path[path_len-1] != '/')
	{
		if (path_len > MAX_PATH-1) return -1;

		path[path_len] = '/';
		path[path_len+1] = 0;
	}
	return 0;
}

int join_path(char *dir_path, char *filename, int size)
{
	if (!term_dir(dir_path, size))
	{
		int dir_len;
		int file_len;

		dir_len = strlen(dir_path);
		file_len = strlen(filename);

		if (dir_len + file_len >= size) return -1;
		strncat(dir_path, filename, size);
	}
	return 0;
}

int create_trace_file(char *dir_path, char *filename, int size, FILE **output)
{
	char path[MAX_PATH];

	strncpy(path, dir_path, MAX_PATH);
	if (join_path(path, filename, size)) return -1;
	*output = fopen(path, "wb");
	return 0;
}

void close_trace(peekaboo_trace_t *trace_ptr)
{
	fflush(trace_ptr->insn_trace);
	fflush(trace_ptr->bytes_map);
	fflush(trace_ptr->regfile);
	fflush(trace_ptr->memfile);
	fflush(trace_ptr->memrefs);
	fflush(trace_ptr->metafile);

	fclose(trace_ptr->insn_trace);
	fclose(trace_ptr->bytes_map);
	fclose(trace_ptr->regfile);
	fclose(trace_ptr->memfile);
	fclose(trace_ptr->memrefs);
	fclose(trace_ptr->metafile);
}

peekaboo_trace_t *create_trace(char *name)
{
	char dir_path[MAX_PATH];
	peekaboo_trace_t *trace_ptr;

	if (create_folder(name, dir_path, MAX_PATH))
	{
		fprintf(stderr, "Unable to create directory %s.\n", name);
		return NULL;
	}

	trace_ptr = (peekaboo_trace_t *)malloc(sizeof(peekaboo_trace_t));

	create_trace_file(dir_path, "insn.trace", MAX_PATH, &trace_ptr->insn_trace);
	create_trace_file(dir_path, "insn.bytemap", MAX_PATH, &trace_ptr->bytes_map);
	create_trace_file(dir_path, "regfile", MAX_PATH, &trace_ptr->regfile);
	create_trace_file(dir_path, "memfile", MAX_PATH, &trace_ptr->memfile);
	create_trace_file(dir_path, "memrefs", MAX_PATH, &trace_ptr->memrefs);
	create_trace_file(dir_path, "metafile", MAX_PATH, &trace_ptr->metafile);

	return trace_ptr;
}

void load_bytes_map(peekaboo_trace_t *trace)
{
	fseek(trace->bytes_map, 0, SEEK_END);
	size_t bytesmap_size = ftell(trace->bytes_map);
	size_t num_maps = bytesmap_size / sizeof(bytes_map_t);

	trace->internal->bytes_map_buf = malloc(bytesmap_size);
	trace->internal->bytes_map_size = bytesmap_size;

	rewind(trace->bytes_map);
	printf("Found %lu instructions in bytemap...\n", num_maps);
	if (fread(trace->internal->bytes_map_buf, sizeof(bytes_map_t), num_maps, trace->bytes_map) != num_maps)
	{
		printf("BYTES MAP READ ERROR!\n");
		exit(1);
	}
	printf("\n");
	return ;
}

bytes_map_t *find_bytes_map(uint64_t pc, peekaboo_trace_t *trace)
{
	bytes_map_t *bytes_map_buf = trace->internal->bytes_map_buf;
	size_t map_size = trace->internal->bytes_map_size;
	size_t num_maps = map_size / sizeof(bytes_map_t);
	int x;
	for (x=0; x<num_maps; x++)
	{
		if ((bytes_map_buf+x)->pc == pc)
			return bytes_map_buf+x;
	}

	return NULL;
}

void load_memrefs_offsets(char *dir_path, peekaboo_trace_t *trace)
{
	char path[MAX_PATH];
	snprintf(path, MAX_PATH, "%s/%s", dir_path, "memrefs_offsets");
	if (access(path, F_OK) == -1)
	{
		FILE *memrefs_offsets = fopen(path, "wb");

		memref_t buffer[1024];
		size_t write_buffer[1024];

		size_t read_size = 0;
		size_t offset = 0;

		rewind(trace->memrefs);
		do {
			read_size = fread(buffer, sizeof(memref_t), 1024, trace->memrefs);
      int x;
			for (x=0; x<read_size; x++)
			{
				if (buffer[x].length)
				{
					write_buffer[x] = offset;
					offset += buffer[x].length * sizeof(memref_t);
				}
				else
				{
					write_buffer[x] = -1;
				}
			}
			fwrite(write_buffer, sizeof(size_t), read_size, memrefs_offsets);
		} while (feof(trace->memrefs));
		rewind(trace->memrefs);
		fclose(memrefs_offsets);
	}
	trace->memrefs_offsets = fopen(path, "rb");
}

size_t get_num_insn(peekaboo_trace_t *trace)
{
	return trace->internal->num_insns;
}

void load_trace(char *dir_path, peekaboo_trace_t *trace_ptr)
{
	char path[MAX_PATH];

	snprintf(path, MAX_PATH, "%s/%s", dir_path, "insn.trace");
	trace_ptr->insn_trace = fopen(path, "rb");
	snprintf(path, MAX_PATH, "%s/%s", dir_path, "insn.bytemap");
	trace_ptr->bytes_map = fopen(path, "rb");
	snprintf(path, MAX_PATH, "%s/%s", dir_path, "regfile");
	trace_ptr->regfile = fopen(path, "rb");
	snprintf(path, MAX_PATH, "%s/%s", dir_path, "memfile");
	trace_ptr->memfile = fopen(path, "rb");
	snprintf(path, MAX_PATH, "%s/%s", dir_path, "memrefs");
	trace_ptr->memrefs = fopen(path, "rb");
	snprintf(path, MAX_PATH, "%s/%s", dir_path, "metafile");
	trace_ptr->metafile = fopen(path, "rb");

	load_memrefs_offsets(dir_path, trace_ptr);

	// creates the internal data-structure to store the
	// meta-information about the loaded trace
	trace_ptr->internal = malloc(sizeof(peekaboo_internal_t));
	memset(trace_ptr->internal, 0, sizeof(peekaboo_internal_t));

	// setup the information
	metadata_hdr_t meta;
	fread(&meta, sizeof(metadata_hdr_t), 1, trace_ptr->metafile);
	trace_ptr->internal->arch = meta.arch;
	switch (meta.arch)
	{
		case ARCH_AMD64:
			trace_ptr->internal->ptr_size = 8;
			trace_ptr->internal->regfile_size = sizeof(regfile_amd64_t);
			break;
		case ARCH_AARCH64:
			trace_ptr->internal->ptr_size = 8;
			trace_ptr->internal->regfile_size = sizeof(regfile_aarch64_t);
			break;
		case ARCH_X86:
			trace_ptr->internal->ptr_size = 4;
			trace_ptr->internal->regfile_size = sizeof(regfile_x86_t);
			break;
		default:
			trace_ptr->internal->ptr_size = 0;
			trace_ptr->internal->regfile_size = 0;
			break;
	}

	size_t trace_size = 0;
	size_t ptr_size = trace_ptr->internal->ptr_size;
	fseek(trace_ptr->insn_trace, 0, SEEK_END);
	trace_size = ftell(trace_ptr->insn_trace);
	rewind(trace_ptr->insn_trace);
	trace_ptr->internal->num_insns = trace_size/ptr_size;

	// loads the rawbytes map for the trace
	load_bytes_map(trace_ptr);

	return ;
}

void write_metadata(peekaboo_trace_t *trace_ptr, enum ARCH arch, uint32_t version)
{
	metadata_hdr_t metadata;
	metadata.arch = arch;
	metadata.version = version;
	fwrite(&metadata, sizeof(metadata_hdr_t), 1, trace_ptr->metafile);
}

size_t get_ptr_size(peekaboo_trace_t *trace)
{
	return trace->internal->ptr_size;
}

size_t get_regfile_size(peekaboo_trace_t *trace)
{
	return trace->internal->regfile_size;
}

uint64_t get_addr(size_t id, peekaboo_trace_t *trace)
{
	if (!id) exit(1);

	uint64_t addr = 0;
	size_t ptr_size = get_ptr_size(trace);

	fseek(trace->insn_trace, (id-1) * ptr_size, SEEK_SET);
	fread(&addr, ptr_size, 1, trace->insn_trace);
	return addr;
}

size_t get_num_mem(size_t id, peekaboo_trace_t *trace)
{
	if (!id) exit(1);

	size_t num_mem = 0;
	fseek(trace->memrefs, (id-1) * sizeof(memref_t), SEEK_SET);
	fread(&num_mem, sizeof(memref_t), 1, trace->memrefs);
	return num_mem;
}

peekaboo_insn_t *get_peekaboo_insn(size_t id, peekaboo_trace_t *trace)
{
	peekaboo_insn_t *insn = malloc(sizeof(peekaboo_insn_t));
	size_t regfile_size = get_regfile_size(trace);
	insn->regfile = malloc(regfile_size);
	insn->arch = trace->internal->arch;

	// insn is the peekaboo instruction record
	
	// populate the address for the instruction
	insn->addr = get_addr(id, trace);

	// get the rawbytes for the instruction
	bytes_map_t *bytes_map = find_bytes_map(insn->addr, trace);

	if (!bytes_map)
	{
	    printf("libpeekaboo: Error. Cannot find instruction (ID:%ld) at 0x%"PRIx64" in bytes_map. Terminated!\n", id, insn->addr);
	    exit(1);
	}

	insn->size = bytes_map->size;
	memcpy(insn->rawbytes, bytes_map->rawbytes, 16);

	// get the number of mem operands
	insn->num_mem = get_num_mem(id, trace);
	if (insn->num_mem > 8) exit(1);
	fseek(trace->memrefs_offsets, (id-1) * sizeof(size_t), SEEK_SET);
	size_t memfile_offset;
	fread(&memfile_offset, sizeof(size_t), 1, trace->memrefs_offsets);
	fseek(trace->memfile, memfile_offset, SEEK_SET);
	fread(insn->mem, sizeof(memfile_t), insn->num_mem, trace->memfile);

	// read the regfile...
	fseek(trace->regfile, (id-1) * regfile_size, SEEK_SET);
	fread(insn->regfile, regfile_size, 1, trace->regfile);

	// done! return
	return insn;
}

void regfile_pp(peekaboo_insn_t *insn)
{
	switch (insn->arch)
	{
		case ARCH_AMD64:
			amd64_regfile_pp(insn->regfile);
			break;
		case ARCH_AARCH64:
			aarch64_regfile_pp(insn->regfile);
			break;
		case ARCH_X86:
			x86_regfile_pp(insn->regfile);
			break;
		default:
			printf("Unsupported Architecture!\n");
			break;
	}
}
