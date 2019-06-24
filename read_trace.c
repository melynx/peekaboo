#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>

#include "libpeekaboo.h"
#include "arch/amd64.h"

typedef regfile_amd64_t regfile_ref_t;

bytes_map_t *find_bytes_map(uint64_t pc, bytes_map_t *bytes_map_buf, size_t num_maps)
{
	for (int x=0; x<num_maps; x++)
	{
		if ((bytes_map_buf+x)->pc == pc)
			return bytes_map_buf+x;
	}
	return NULL;
}

int main(int argc, char *argv[])
{
	insn_ref_t *insn_ref_buf = malloc(MEM_BUF_SIZE);
	//regfile_ref_t *regfile_ref_buf = malloc(REG_BUF_SIZE);
	regfile_ref_t *regfile_ref_buf = malloc(sizeof(regfile_ref_t)*MAX_NUM_REG_REFS);
	bytes_map_t *bytes_map_buf;

	char *trace_path = argv[1];

	char insn_trace_path[256];
	char insn_bytemap_path[256];
	char regfile_path[256];

	snprintf(insn_trace_path, 256, "%s/insn.trace", trace_path);
	snprintf(insn_bytemap_path, 256, "%s/insn.bytemap", trace_path);
	snprintf(regfile_path, 256, "%s/regfile", trace_path);

	printf("Opening bytes_map file : %s\n", insn_bytemap_path);
	FILE *bytes_map = fopen(insn_bytemap_path, "r");
	fseek(bytes_map, 0, SEEK_END);
	size_t bytesmap_size = ftell(bytes_map);
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

	printf("Opening trace file : %s\n", insn_trace_path);
	FILE *insn_trace = fopen(insn_trace_path, "r");
	fseek(insn_trace, 0, SEEK_END);
	size_t trace_size = ftell(insn_trace);
	rewind(insn_trace);
	size_t num_insn = trace_size / sizeof(insn_ref_t);
	printf("Found %lu instructions in trace...\n", num_insn);

	printf("Opening regfile file : %s\n", regfile_path);
	FILE *regfile = fopen(regfile_path, "r");
	fseek(regfile, 0, SEEK_END);
	size_t regfile_size = ftell(regfile);
	rewind(regfile);
	size_t num_regfile = regfile_size/ sizeof(regfile_ref_t);
	printf("Found %lu instructions in regfile...\n", num_regfile);

	if (num_regfile != num_insn)
	{
		printf("num_regfile != num_insn!\n");
		exit(1);
	}

	int valid_reads = 0;
	int valid_reads2 = 0;
	bytes_map_t *cur_bytes_map = NULL;
	do {
		valid_reads = fread(insn_ref_buf, sizeof(insn_ref_t), MAX_NUM_INS_REFS, insn_trace);
		valid_reads2 = fread(regfile_ref_buf, sizeof(regfile_ref_t), MAX_NUM_REG_REFS, regfile);
		if (valid_reads != valid_reads2)
		{
			printf("insn_ref_read != regfile_ref_read!\n");
			exit(1);
		}
		for (int x=0; x<valid_reads; x++)
		{
			cur_bytes_map = find_bytes_map(insn_ref_buf[x].pc, bytes_map_buf, num_maps);
			printf("0x%" PRIx64 "", insn_ref_buf[x].pc);
			printf("\t size: %d", cur_bytes_map->size);
			printf("\t rawbytes: ");
			for (int y=0; y<cur_bytes_map->size; y++)
				printf("%" PRIx8 " ", cur_bytes_map->rawbytes[y]);
			regfile_pp(regfile_ref_buf[x]);
			printf("\n");
		}
	} while (!feof(insn_trace));

	return 0;
}
