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

#include <stdio.h>
#include <stdlib.h>

#include "libpeekaboo.h"

int main(int argc, char *argv[])
{
	char *trace_path = argv[1];
	peekaboo_trace_t mytrace;
	load_trace(trace_path, &mytrace);
	
	size_t num_insn = get_num_insn(&mytrace);

	for (int x=1; x<=num_insn; x++)
	{
		peekaboo_insn_t *insn = get_peekaboo_insn(x, &mytrace);

		printf("0x%" PRIx64 "", insn->addr);
		printf("\t size: %d", insn->size);
		printf("\t rawbytes: ");
		for (int y=0; y<insn->size; y++)
			printf("%" PRIx8 " ", insn->rawbytes[y]);
		printf("\n");
		regfile_pp(insn);
		printf("\n");
	}

	return 0;
}
