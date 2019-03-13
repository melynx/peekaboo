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

int close_trace(peekaboo_trace_t *trace)
{
	fflush(trace->insn_trace);
	fflush(trace->bytes_map);
	fflush(trace->regfile);
	fflush(trace->memfile);
	fflush(trace->metafile);

	fclose(trace->insn_trace);
	fclose(trace->bytes_map);
	fclose(trace->regfile);
	fclose(trace->memfile);
	fclose(trace->metafile);
	return 0;
}

int create_trace(char *name, peekaboo_trace_t *trace)
{
	char dir_path[MAX_PATH];

	if (create_folder(name, dir_path, MAX_PATH))
	{
		fprintf(stderr, "Unable to create directory %s.\n", name);
		return -1;
	}

	create_trace_file(dir_path, "insn.trace", MAX_PATH, &trace->insn_trace);
	create_trace_file(dir_path, "insn.bytemap", MAX_PATH, &trace->bytes_map);
	create_trace_file(dir_path, "regfile", MAX_PATH, &trace->regfile);
	create_trace_file(dir_path, "memfile", MAX_PATH, &trace->memfile);
	create_trace_file(dir_path, "metafile", MAX_PATH, &trace->metafile);

	return 0;
}
