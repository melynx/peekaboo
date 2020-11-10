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
	char *resolved_name = realpath(name, output);
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
	//fflush(trace_ptr->metafile);

	fclose(trace_ptr->insn_trace);
	fclose(trace_ptr->bytes_map);
	fclose(trace_ptr->regfile);
	fclose(trace_ptr->memfile);
	fclose(trace_ptr->memrefs);
	//fclose(trace_ptr->metafile);
}

peekaboo_trace_t *create_trace(char *name)
{
	char dir_path[MAX_PATH];
	peekaboo_trace_t *trace_ptr;

	if (create_folder(name, dir_path, MAX_PATH)) PEEKABOO_DIE("libpeekaboo: Unable to create directory %s.\n", name);

	trace_ptr = (peekaboo_trace_t *)malloc(sizeof(peekaboo_trace_t));
	if (!trace_ptr) PEEKABOO_DIE("libpeekaboo: Unable to malloc trace instance.\n");

	create_trace_file(dir_path, "insn.trace", MAX_PATH, &trace_ptr->insn_trace);
	create_trace_file(dir_path, "regfile", MAX_PATH, &trace_ptr->regfile);
	create_trace_file(dir_path, "memfile", MAX_PATH, &trace_ptr->memfile);
	create_trace_file(dir_path, "memrefs", MAX_PATH, &trace_ptr->memrefs);
	create_trace_file(dir_path, "metafile", MAX_PATH, &trace_ptr->metafile);

	/* Since version 2, insn.bytemap is shared by all threads. So we do not create
	 * here.
	 */
	//create_trace_file(dir_path, "insn.bytemap", MAX_PATH, &trace_ptr->bytes_map);


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
		PEEKABOO_DIE("libpeekaboo: BYTES MAP READ ERROR!\n");
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

size_t get_num_insn(peekaboo_trace_t *trace)
{
	return trace->internal->num_insns;
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
	if (!id) PEEKABOO_DIE("libpeekaboo: Error. Instruction index 0 is not accepted.\n");

	uint64_t addr = 0;
	size_t ptr_size = get_ptr_size(trace);

	fseek(trace->insn_trace, (id-1) * ptr_size, SEEK_SET);
	size_t fread_bytes = fread(&addr, ptr_size, 1, trace->insn_trace);
	return addr;
}

size_t get_num_mem(size_t id, peekaboo_trace_t *trace)
{
	if (!id) PEEKABOO_DIE("libpeekaboo: Error. Instruction index 0 is not accepted.\n");

	size_t num_mem = 0;
	fseek(trace->memrefs, (id-1) * sizeof(memref_t), SEEK_SET);
	size_t fread_bytes = fread(&num_mem, sizeof(memref_t), 1, trace->memrefs);
	return num_mem;
}


void load_memrefs_offsets(char *dir_path, peekaboo_trace_t *trace)
{
	char path[MAX_PATH];
	snprintf(path, MAX_PATH, "%s/%s", dir_path, "memrefs_offsets");

	if (access(path, F_OK) == -1)
	{
		uint64_t base_offset = 0;

		/* KH: This is a ad-hoc patch to fix the bug in peekaboo_dr.
		 * When the application process forks, there is some residue
		 * in memfile buffer that can't be cleaned up.
		 * Thus, When read those traces, we need to find the real starting
		 * point of the memfile. We use base_offset to store it.
		 */
		if (trace->internal->version >= 3)
		{
			// Find the first instruction that has memory access
			uint64_t first_pc = 0x0;
			size_t trace_len = trace->internal->num_insns;
			size_t id=1;
			for(; id<=trace_len; id++)
			{
				size_t num_mem = get_num_mem(id, trace);
				if (num_mem == 0) continue;
				first_pc = get_addr(id, trace);
				break;
			}
			if (id > trace_len)
			{
				// A weird trace. It doesn't have any memory access. 
				// Do nothing but gives a warning.
				fprintf(stderr, "libpeekaboo: [Warning] No memory ops found in this trace.\n");
			}
			else
			{
				if (first_pc==0) PEEKABOO_DIE("libpeekaboo: zero pc for id %lu", id);
				fseek(trace->memfile, 0, SEEK_END);
				memfile_t mem;
				mem.pc = 0;
				errno = 0;
				fseek(trace->memfile, base_offset, SEEK_SET);
				size_t read_size = fread(&mem, sizeof(memfile_t), 1, trace->memfile);
				while(mem.pc!=first_pc && errno==0)
				{
					base_offset += sizeof(memfile_t);
					fseek(trace->memfile, base_offset, SEEK_SET);
					read_size = fread(&mem, sizeof(memfile_t), 1, trace->memfile);
				}
			}
		}
		if (base_offset!=0) fprintf(stderr, "libpeekaboo: (Trace from a child thread/process?) Re-align the memory offset, starting from %ld.\n", base_offset/sizeof(memfile_t));

		FILE *memrefs_offsets = fopen(path, "wb");
		if (!memrefs_offsets) PEEKABOO_DIE("libpeekaboo: Fail to open memref file!\n");

		memref_t buffer[1024];
		size_t write_buffer[1024];

		size_t read_size = 0;
		size_t offset = base_offset;

		rewind(trace->memrefs);
		do {
			read_size = fread(buffer, sizeof(memref_t), 1024, trace->memrefs);
			int x;
			for (x=0; x<read_size; x++)
			{
				if (buffer[x].length)
				{
					write_buffer[x] = offset;
					offset += buffer[x].length * sizeof(memfile_t);
				}
				else
				{
					write_buffer[x] = -1;
				}
			}
			fwrite(write_buffer, sizeof(size_t), read_size, memrefs_offsets);
		} while (read_size == 1024);
		rewind(trace->memrefs);
		fclose(memrefs_offsets);
	}
	trace->memrefs_offsets = fopen(path, "rb");

}

void load_trace(char *dir_path, peekaboo_trace_t *trace_ptr)
{
	char path[MAX_PATH];

	// Load metadata first
	snprintf(path, MAX_PATH, "%s/%s", dir_path, "metafile");
	trace_ptr->metafile = fopen(path, "rb");
	if (trace_ptr->metafile == NULL) PEEKABOO_DIE("libpeekaboo: Unable to load %s\n", path);

	// Creates the internal data-structure to store the
	// meta-information about the loaded trace
	trace_ptr->internal = malloc(sizeof(peekaboo_internal_t));
	memset(trace_ptr->internal, 0, sizeof(peekaboo_internal_t));

	// Setup the information
	metadata_hdr_t meta;
	size_t fread_bytes = fread(&meta, sizeof(metadata_hdr_t), 1, trace_ptr->metafile);
	trace_ptr->internal->arch = meta.arch;
	trace_ptr->internal->version = meta.version;
	fprintf(stderr, "Trace's libpeekaboo version: %d\n", meta.version);
	fclose(trace_ptr->metafile);

	if (trace_ptr->internal->version >= 4)
	{
		// New trace format that can customize which registers to store
		if (trace_ptr->internal->arch == ARCH_AMD64)
		{
			trace_ptr->internal->storage_options.amd64.has_simd = meta.storage_options.amd64.has_simd;
			trace_ptr->internal->storage_options.amd64.has_fxsave = meta.storage_options.amd64.has_fxsave;
			fprintf(stderr, "Stored register: GPRs ");
			if (trace_ptr->internal->storage_options.amd64.has_simd) fprintf(stderr, "SIMD ");
			if (trace_ptr->internal->storage_options.amd64.has_fxsave) fprintf(stderr, "FXSAVE ");
			fprintf(stderr, "\n");
		}
	}
	else
	{
		// Trace version lower than 003, stores everything
		trace_ptr->internal->storage_options.amd64.has_simd = 1;
		trace_ptr->internal->storage_options.amd64.has_fxsave = 1;
	}

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

	// Load bytes_map based on the version
	if (meta.version > 1)
		snprintf(path, MAX_PATH, "%s/../%s", dir_path, "insn.bytemap");
	else
		// Legacy trace format in Verion 1 which does not have separate folders for different threads.
		snprintf(path, MAX_PATH, "%s/%s", dir_path, "insn.bytemap");
	trace_ptr->bytes_map = fopen(path, "rb");
	if (trace_ptr->bytes_map == NULL) PEEKABOO_DIE("libpeekaboo: Unable to load bytes_map\n");

	// Load insn.trace, regfile, memfile, memrefs.
	snprintf(path, MAX_PATH, "%s/%s", dir_path, "insn.trace");
	trace_ptr->insn_trace = fopen(path, "rb");
	if (trace_ptr->insn_trace == NULL) PEEKABOO_DIE("libpeekaboo: Unable to load %s\n", path);
	snprintf(path, MAX_PATH, "%s/%s", dir_path, "regfile");
	trace_ptr->regfile = fopen(path, "rb");
	if (trace_ptr->regfile == NULL) PEEKABOO_DIE("libpeekaboo: Unable to load %s\n", path);
	snprintf(path, MAX_PATH, "%s/%s", dir_path, "memfile");
	trace_ptr->memfile = fopen(path, "rb");
	if (trace_ptr->memfile == NULL) PEEKABOO_DIE("libpeekaboo: Unable to load %s\n", path);
	snprintf(path, MAX_PATH, "%s/%s", dir_path, "memrefs");
	trace_ptr->memrefs = fopen(path, "rb");
	if (trace_ptr->memrefs == NULL) PEEKABOO_DIE("libpeekaboo: Unable to load %s\n", path);

	// Init for internal structure
	size_t trace_size = 0;
	size_t ptr_size = trace_ptr->internal->ptr_size;
	fseek(trace_ptr->insn_trace, 0, SEEK_END);
	trace_size = ftell(trace_ptr->insn_trace);
	rewind(trace_ptr->insn_trace);
	trace_ptr->internal->num_insns = trace_size/ptr_size;

	// loads the rawbytes map for the trace
	load_bytes_map(trace_ptr);

	// load memrefs_offsets. Create if not exist 
	load_memrefs_offsets(dir_path, trace_ptr);

	// All good. Ready to go~!
	return ;
}

void free_peekaboo_trace(peekaboo_trace_t *trace_ptr)
{
	fclose(trace_ptr->bytes_map);
	fclose(trace_ptr->insn_trace);
	fclose(trace_ptr->regfile);
	fclose(trace_ptr->memfile);
	fclose(trace_ptr->memrefs);
	if (trace_ptr->memrefs_offsets)	fclose(trace_ptr->memrefs_offsets);
	free(trace_ptr->internal->bytes_map_buf);
	free(trace_ptr->internal);
	free(trace_ptr);
}

void write_metadata(peekaboo_trace_t *trace_ptr, enum ARCH arch, uint32_t version)
{
	metadata_hdr_t metadata;
	metadata.arch = arch;
	metadata.version = version;
	if (arch == ARCH_AMD64)
	{
		#ifdef _STORE_SIMD
			metadata.storage_options.amd64.has_simd = 1;
		#else
			metadata.storage_options.amd64.has_simd = 0;
		#endif
		#ifdef _STORE_FXSAVE
			metadata.storage_options.amd64.has_fxsave = 1;
		#else
			metadata.storage_options.amd64.has_fxsave = 0;
		#endif
	}
	fwrite(&metadata, sizeof(metadata_hdr_t), 1, trace_ptr->metafile);
	fflush(trace_ptr->metafile);
	fclose(trace_ptr->metafile);
}


// It is caller's duty to free peekaboo insn ptr. Call free_peekaboo_insn() to do so.
peekaboo_insn_t *get_peekaboo_insn(const size_t id, peekaboo_trace_t *trace)
{
	// insn is the peekaboo instruction record
	peekaboo_insn_t *insn = malloc(sizeof(peekaboo_insn_t));
	size_t regfile_size = get_regfile_size(trace);
	insn->regfile = malloc(regfile_size);
	insn->arch = trace->internal->arch;

	
	// populate the address for the instruction
	insn->addr = get_addr(id, trace);

	// get the rawbytes for the instruction
	bytes_map_t *bytes_map = find_bytes_map(insn->addr, trace);
	if (!bytes_map) PEEKABOO_DIE("libpeekaboo: Error. Cannot find instruction (ID:%ld) at 0x%"PRIx64" in bytes_map. Terminated!\n", id, insn->addr);
	insn->size = bytes_map->size;
	memcpy(insn->rawbytes, bytes_map->rawbytes, 16);

	// get the number of mem operands
	insn->num_mem = get_num_mem(id, trace);
	if (insn->num_mem > 8) PEEKABOO_DIE("libpeekaboo: Error. Instruction (ID:%ld) at 0x%"PRIx64" has more than 8 memory ops. Terminated!\n", id, insn->addr);
	int fseek_return = fseek(trace->memrefs_offsets, (id-1) * sizeof(size_t), SEEK_SET);
	size_t memfile_offset;
	size_t fread_bytes = fread(&memfile_offset, sizeof(size_t), 1, trace->memrefs_offsets);
	errno = 0;
	if (memfile_offset != (size_t) -1)
	{
		fseek(trace->memfile, memfile_offset, SEEK_SET);
		fread_bytes = fread(insn->mem, sizeof(memfile_t), insn->num_mem, trace->memfile);
	}

	// read the regfile...
	fseek(trace->regfile, (id-1) * regfile_size, SEEK_SET);
	fread_bytes = fread(insn->regfile, regfile_size, 1, trace->regfile);

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
			PEEKABOO_DIE("libpeekaboo: Unsupported Architecture!\n");
			break;
	}
}


// Free peekaboo insn ptr. Must be called after get_peekaboo_insn().
void free_peekaboo_insn(peekaboo_insn_t *insn_ptr)
{
	if (insn_ptr != NULL)
	{
		if (insn_ptr->regfile != NULL)
		{
			free(insn_ptr->regfile);
			insn_ptr->regfile = NULL;
		}
		free(insn_ptr);
		insn_ptr = NULL;
	}
}
