#include "x86.h"

void x86_regfile_pp(regfile_x86_t *regfile)
{
	char * regname[] = {"eax",
						"ecx",
						"edx",
						"ebx",
						"esp",
						"ebp",
						"esi",
						"edi"};

	for (int x=0; x < 8; x++)
		printf("%s:%" PRIx32 "\n", regname[x], ((uint32_t *)&(regfile->gpr))[x]);
}