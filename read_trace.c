#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>

#include "libpeekaboo.h"
#include "arch/amd64.h"

typedef regfile_amd64_t regfile_ref_t;

int main(int argc, char *argv[])
{

	insn_ref_t *insn_ref_buf = malloc(MEM_BUF_SIZE);
	//regfile_ref_t *regfile_ref_buf = malloc(REG_BUF_SIZE);
	regfile_ref_t *regfile_ref_buf = malloc(sizeof(regfile_ref_t)*MAX_NUM_REG_REFS);
	bytes_map_t *bytes_map_buf;

	char *trace_path = argv[1];

	peekaboo_trace_t mytrace;
	load_trace(sys.argv[1], &mytrace);
	load_bytes_map(mytrace, bytes_map_buf);

	size_t num_insn = num_insn(mytrace);
	printf("Found %lu instructions in trace...\n", num_insn);

	printf("Opening regfile file : %s\n", regfile_path);
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
