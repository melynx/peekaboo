#include "amd64.h"

void amd64_regfile_pp(regfile_amd64_t *regfile)
{
	char *gpr_string[] = {"rdi",
	                     "rsi",
	                     "rsp",
	                     "rbp",
	                     "rbx",
	                     "rdx",
	                     "rcx",
	                     "rax",
	                     "r8",
	                     "r9",
	                     "r10",
	                     "r11",
	                     "r12",
	                     "r13",
	                     "r14",
	                     "r15",
	                     "rflags",
	                     "rip"};

	for (int x=0; x<18; x++)
	{
		printf("%s:%" PRIx64 "\n", gpr_string[x], ((uint64_t *)&(regfile->gpr))[x]);
	}
}
