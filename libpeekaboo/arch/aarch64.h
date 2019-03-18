/*! @file
 *  this file is the aarch64 regfile structure & memfile structure.
 */

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <inttypes.h>

#define NUM_SIMD_SLOTS 32

typedef uint64_t UINT64_T;

typedef union {
    uint64_t r;
    uint32_t w[2];
    uint16_t hw[4];
    uint8_t b[8];
} UINT64_REG_T;

typedef union {
    uint8_t b[10];
} UINT80_T;

typedef union {
    UINT64_T r[4];
} UINT256_T;

typedef union {
    UINT64_T r[2];
} UINT128_T;

/* Regfile */

typedef struct {
	uint64_t r0;   /**< The r0 register. */
	uint64_t r1;   /**< The r1 register. */
	uint64_t r2;   /**< The r2 register. */
	uint64_t r3;   /**< The r3 register. */
	uint64_t r4;   /**< The r4 register. */
	uint64_t r5;   /**< The r5 register. */
	uint64_t r6;   /**< The r6 register. */
	uint64_t r7;   /**< The r7 register. */
	uint64_t r8;   /**< The r8 register. */
	uint64_t r9;   /**< The r9 register. */
	uint64_t r10;  /**< The r10 register. */
	uint64_t r11;  /**< The r11 register. */
	uint64_t r12;  /**< The r12 register. */
	uint64_t r13;  /**< The r13 register. */
	uint64_t r14;  /**< The r14 register. */
	uint64_t r15;  /**< The r15 register. */
	uint64_t r16;  /**< The r16 register. \note For 64-bit DR builds only. */
	uint64_t r17;  /**< The r17 register. \note For 64-bit DR builds only. */
	uint64_t r18;  /**< The r18 register. \note For 64-bit DR builds only. */
	uint64_t r19;  /**< The r19 register. \note For 64-bit DR builds only. */
	uint64_t r20;  /**< The r20 register. \note For 64-bit DR builds only. */
	uint64_t r21;  /**< The r21 register. \note For 64-bit DR builds only. */
	uint64_t r22;  /**< The r22 register. \note For 64-bit DR builds only. */
	uint64_t r23;  /**< The r23 register. \note For 64-bit DR builds only. */
	uint64_t r24;  /**< The r24 register. \note For 64-bit DR builds only. */
	uint64_t r25;  /**< The r25 register. \note For 64-bit DR builds only. */
	uint64_t r26;  /**< The r26 register. \note For 64-bit DR builds only. */
	uint64_t r27;  /**< The r27 register. \note For 64-bit DR builds only. */
	uint64_t r28;  /**< The r28 register. \note For 64-bit DR builds only. */
	uint64_t r29;  /**< The r29 register. \note For 64-bit DR builds only. */
	uint64_t lr;  /**< The link register. */
	uint64_t sp;  /**< The stack pointer register. */
	/**
	 * The program counter.
	 * \note This field is not always set or read by all API routines.
	 */
	uint64_t pc;

	uint32_t nzcv; /**< Condition flags (status register). */
	uint32_t fpcr; /**< Floating-Point Control Register. */
	uint32_t fpsr; /**< Floating-Point Status Register. */
} CPU_GR_T;

typedef struct {
	CPU_GR_T 	gpr;
	UINT128_T v[NUM_SIMD_SLOTS];
} regfile_aarch64_t;

void regfile_pp(regfile_aarch64_t regfile)
{
	char *regname[] = {"r0", "r1", "r2", "r3", "r4", "r5",
		           "r6", "r7", "r8", "r9", "r10", "r11",
		           "r12", "r13", "r14", "r15", "r16", "r17",
		           "r18", "r19", "r20", "r21", "r22", "r23",
		           "r24", "r25", "r26", "r27", "r28", "r29",
		           "lr", "sp", "pc", "nzcv", "fpcr", "fpsr"};

	for (int x=0; x<31; x++)
	{
		printf("%s:%" PRIx64 "\n", regname[x], ((UINT64_T *)&(regfile.gpr))[x]);
	}
}
/* End of Regfile */


/* Memfile */

typedef struct {
	uint64_t addr;		/* memory address */
	uint64_t value;		/* memory value */
	uint32_t size;		/* how many bits are vaild in value */
	uint32_t status; 	/* 0 for Read, 1 for write */
} mem_ref_t;

typedef struct {
	uint32_t length;	/* how many refs are there*/
	mem_ref_t *ref;
} memfile_aarch64_t;
/* End of Memfile */

typedef struct insn_ref {
	uint64_t pc;
} insn_ref_t;

typedef struct {
	uint64_t pc;
	uint32_t size;
	uint8_t rawbytes[16];
} bytes_map_t ;

char *arch = "AARCH64";
typedef regfile_aarch64_t regfile_ref_t;

