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

#include "aarch64.h"

void aarch64_regfile_pp(regfile_aarch64_t *regfile)
{
	char *regname[] = {"r0", "r1", "r2", "r3", "r4", "r5",
		           "r6", "r7", "r8", "r9", "r10", "r11",
		           "r12", "r13", "r14", "r15", "r16", "r17",
		           "r18", "r19", "r20", "r21", "r22", "r23",
		           "r24", "r25", "r26", "r27", "r28", "r29",
		           "lr", "sp", "pc", "nzcv", "fpcr", "fpsr"};

	for (int x=0; x<31; x++)
	{
		printf("%s:%" PRIx64 "\n", regname[x], ((uint64_t *)&(regfile->gpr))[x]);
	}
}
