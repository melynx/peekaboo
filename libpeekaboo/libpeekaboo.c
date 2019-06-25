#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

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
		return -1;
	}

	trace_ptr = (peekaboo_trace_t *)malloc(sizeof(peekaboo_trace_t));

	create_trace_file(dir_path, "insn.trace", MAX_PATH, trace_ptr->insn_trace);
	create_trace_file(dir_path, "insn.bytemap", MAX_PATH, trace_ptr->bytes_map);
	create_trace_file(dir_path, "regfile", MAX_PATH, trace_ptr->regfile);
	create_trace_file(dir_path, "memfile", MAX_PATH, trace_ptr->memfile);
	create_trace_file(dir_path, "memrefs", MAX_PATH, trace_ptr->memrefs);
	create_trace_file(dir_path, "metafile", MAX_PATH, trace_ptr->metafile);

	return trace_ptr;
}

peekaboo_trace_t *load_trace(char *dir_path)
{
	peekaboo_trace_t *trace_ptr = (peekaboo_trace_t *)malloc(sizeof(peekaboo_trace_t));
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
	trace_ptr->memfile = fopen(path, "rb");
	snprintf(path, MAX_PATH, "%s/%s", dir_path, "metafile");
	trace_ptr->metafile = fopen(path, "rb");

	// check the metadata
	metadata_hdr_t metadata;
	fread(&metadata, sizeof(metadata_hdr_t), 1, trace_ptr->metafile);
	switch(metadata)
	{
		case AMD64:
			break;
		case AARCH64:
			break;
		default:
			break;
	}
	

	return trace_ptr;
}

void write_metadata(peekaboo_trace_t trace, enum ARCH arch, uint32_t version)
{
	metadata_hdr_t metadata;
	metadata.arch = arch;
	metadata.version = version;
	fwrite(&metadata, sizeof(metadata_hdr_t), 1, trace.metafile);
}

size_t get_insn_size(peekaboo_trace_t trace)
{
	size_t size = 0;
	metadata_hdr_t meta;
	fread(&meta, sizeof(metadata_hdr_t), 1, trace.metafile);
	switch (meta.arch)
	{
		case ARCH_AMD64:
			size = 8;
			break;
		case ARCH_AARCH64:
			size = 4;
			break;
		default:
			size = 0;
			break;
	}

	return size;
}

size_t num_insn(peekaboo_trace_t trace)
{
	size_t trace_size = 0;
	size_t insn_size = get_insn_size(trace);
	fseek(trace.insn_trace, 0, SEEK_END);
	trace_size = ftell(trace.insn_trace);
	rewind(trace.insn_trace);
	return trace_size / insn_size;
}

size_t num_regfile(peekaboo_trace_t *trace)
{
	size_t trace_size = 0;
	size_t insn_size = get_insn_size(trace);
	fseek(trace->insn_trace, 0, SEEK_END);
	trace_size = ftell(trace->insn_trace);
	rewind(trace->insn_trace);
	return trace_size / insn_size;
}

int load_bytes_map(peekaboo_trace_t trace, bytes_map_t *bytes_map_buf)
{
	size_t bytesmap_size = ftell(trace.bytes_map);
	size_t num_maps = bytesmap_size / sizeof(bytes_map_t);
	rewind(bytes_map);
	printf("Found %lu instructions in bytemap...\n", num_maps);
	bytes_map_buf = malloc(bytesmap_size);
	if (fread(bytes_map_buf, sizeof(bytes_map_t), num_maps, bytes_map) != num_maps)
	{
		printf("BYTES MAP READ ERROR!\n");
		exit(1);
	}
	printf("\n");
	return 0;
}
