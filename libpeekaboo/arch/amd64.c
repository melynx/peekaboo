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

#include "amd64.h"

void amd64_regfile_pp(regfile_amd64_t *regfile)
{
	printf("\tRegisters:\n");
	char *gpr_string[] = {"rdi",
	                     "rsi",
	                     "rsp",
	                     "rbp",
	                     "rbx",
	                     "rdx",
	                     "rcx",
	                     "rax",
	                     "r8 ",
	                     "r9 ",
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
		printf("\t  %s: %" PRIx64 "\n", gpr_string[x], ((uint64_t *)&(regfile->gpr))[x]);
	}
	printf("\n");
}

#ifdef _STORE_SEGMENT_REGISTER
void amd64_sr_pp(amd64_cpu_seg_t *regfile_sr)
{
	printf("\tSegment Registers:\n");
	char *sr_string[] = {"cs",
						"ss",
						"ds",
						"es",
						"fs",
						"gs"};

	for (int x=0; x<6; x++)
	{
		printf("\t  %s: %hx\n", sr_string[x], ((uint16_t *)&(regfile_sr))[x]);
	}
	printf("\n");
}
#endif 