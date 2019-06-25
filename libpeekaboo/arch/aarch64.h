/*! @file
 *  this file is the aarch64 regfile structure & memfile structure.
 */
#ifndef __LIBPEEKABOO_AARCH64_H__
#define __LIBPEEKABOO_AARCH64_H__

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <inttypes.h>

#include "libpeekaboo.h"

#define AARCH64_NUM_SIMD_SLOTS 32

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
} aarch64_cpu_gr_t;

typedef struct regfile_aarch64 {
	aarch64_cpu_gr_t gpr;
	uint128_t v[AARCH64_NUM_SIMD_SLOTS];
} regfile_aarch64_t;

void aarch64_regfile_pp(regfile_aarch64_t regfile);

#endif
