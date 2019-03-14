/*! @file
 *  this file is the aarch64 regfile structure & memfile structure.
 */

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

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
    UINT64_T reg_cs;
    UINT64_T reg_ss;
    UINT64_T reg_ds;
    UINT64_T reg_es;
    UINT64_T reg_fs;
    UINT64_T reg_gs;
} CPU_SEG_T;

typedef struct {
    //  simd: avx2
    UINT256_T ymm0;
    UINT256_T ymm1;
    UINT256_T ymm2;
    UINT256_T ymm3;
    UINT256_T ymm4;
    UINT256_T ymm5;
    UINT256_T ymm6;
    UINT256_T ymm7;
    UINT256_T ymm8;
    UINT256_T ymm9;
    UINT256_T ymm10;
    UINT256_T ymm11;
    UINT256_T ymm12;
    UINT256_T ymm13;
    UINT256_T ymm14;
    UINT256_T ymm15;
} CPU_SIMD_T;

typedef struct {
    // fp registers
    UINT80_T reg_st0;
    UINT80_T reg_st1;
    UINT80_T reg_st2;
    UINT80_T reg_st3;
    UINT80_T reg_st4;
    UINT80_T reg_st5;
    UINT80_T reg_st6;
    UINT80_T reg_st7;
} CPU_ST_T;

typedef struct {
	CPU_GR_T 	gpr;
	CPU_SIMD_T 	simd;
	CPU_SEG_T 	seg;
	CPU_ST_T 	fpr;
} regfile_aarch64_t;

void regfile_pp(regfile_amd64_t regfile)
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
		printf("%s:%" PRIx64 "\n", gpr_string[x], ((UINT64_T *)&(regfile.gpr))[x]);
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

#define MAX_NUM_INS_REFS 8192
#define MEM_BUF_SIZE (sizeof(insn_ref_t) * MAX_NUM_INS_REFS)

#define MAX_NUM_REG_REFS 8192
#define REG_BUF_SIZE (sizeof(regfile_amd64_t) * MAX_NUM_REG_REFS)

#define MAX_NUM_BYTES_MAP 512
#define MAX_BYTES_MAP_SIZE (sizeof(insn_ref_t) * MAX_NUM_BYTES_MAP)

#define NUM_SIMD_SLOTS 16
