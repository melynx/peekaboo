#ifndef __LIBPEEKABOO_AMD64_SYSCALL_H__
#define __LIBPEEKABOO_AMD64_SYSCALL_H__

#include "amd64.h"
#include <assert.h>
#include <stdbool.h>

int amd64_syscall_pp(regfile_amd64_t *regfile, uint64_t rvalue, bool print_details);

typedef struct sysent {
	unsigned int nargs;
	const char *sys_name;
} struct_syscall_info;

#endif // __LIBPEEKABOO_AMD64_SYSCALL_H__
