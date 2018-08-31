/*! @file
*  this file is the x86-64 memfile structure.
*/


#include <stdint.h>

typedef struct {
	uint64_t addr;		/* memory address */
	uint64_t value;		/* memory value */
	uint32_t size;		/* how many bits are vaild in value */
	uint32_t status; 	/* 0 for Read, 1 for write */
} mem_ref_t;

typedef struct {
	uint32_t length;	/* how many refs are there*/
	mem_ref_t *ref;
} memfile_amd64_t;
