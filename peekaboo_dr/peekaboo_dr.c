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
#include <string.h>
#include <stdint.h>
#include <stddef.h> /* for offsetof */
#include <assert.h>
#include <inttypes.h>
#include <signal.h>


#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "drutil.h"
#include "drx.h"
#include "dr_defines.h"
#include "drsyscall.h"

#include "libpeekaboo.h"
#include "syscalls.h"

#ifdef X86
	#ifdef X64
		char *arch_str = "AMD64";
		enum ARCH arch = ARCH_AMD64;
		typedef regfile_amd64_t regfile_t;
		void copy_regfile(regfile_t *regfile_ptr, dr_mcontext_t *mc)
		{
			regfile_ptr->gpr.reg_rdi = mc->rdi;
			regfile_ptr->gpr.reg_rsi = mc->rsi;
			regfile_ptr->gpr.reg_rsp = mc->rsp;
			regfile_ptr->gpr.reg_rbp = mc->rbp;
			regfile_ptr->gpr.reg_rbx = mc->rbx;
			regfile_ptr->gpr.reg_rdx = mc->rdx;
			regfile_ptr->gpr.reg_rcx = mc->rcx;
			regfile_ptr->gpr.reg_rax = mc->rax;
			regfile_ptr->gpr.reg_r8 = mc->r8;
			regfile_ptr->gpr.reg_r9 = mc->r9;
			regfile_ptr->gpr.reg_r10 = mc->r10;
			regfile_ptr->gpr.reg_r11 = mc->r11;
			regfile_ptr->gpr.reg_r12 = mc->r12;
			regfile_ptr->gpr.reg_r13 = mc->r13;
			regfile_ptr->gpr.reg_r14 = mc->r14;
			regfile_ptr->gpr.reg_r15 = mc->r15;
			regfile_ptr->gpr.reg_rflags = mc->rflags;
			regfile_ptr->gpr.reg_rip = (uint64_t) mc->rip;
			// printf("czl:%p\n", regfile_ptr->gpr.reg_rip);

			// here, we cast the simd structure into an array of uint256_t
			memcpy(&regfile_ptr->simd, mc->ymm, sizeof(regfile_ptr->simd.ymm0)*MCXT_NUM_SIMD_SLOTS);

			// here we'll call fxsave, that saves into the fxsave area.
			proc_save_fpstate((byte *)&regfile_ptr->fxsave);
		}
	#else
		char *arch_str = "X86";
		// TODO: Implement X86 stuff here
	#endif
#else
	#ifdef X64
		char *arch_str = "AArch64";
		enum ARCH arch = ARCH_AARCH64;
		typedef regfile_aarch64_t regfile_t;
		void copy_regfile(regfile_t *regfile_ptr, dr_mcontext_t *mc)
		{
			memcpy(&regfile_ptr->gpr, &mc->r0, 33*8 + 3*4);
			memcpy(&regfile_ptr->v, &mc->simd, MCXT_NUM_SIMD_SLOTS*sizeof(regfile_ptr->v[0]));
		}
	#else
		char *arch_str = "AArch32";
		// TODO: Implement ARM stuff here
	#endif
#endif

#define MAX_NUM_INS_REFS 8192
#define INSN_REF_SIZE (sizeof(insn_ref_t) * MAX_NUM_INS_REFS)

#define MAX_NUM_REG_REFS 8192
#define REG_BUF_SIZE (sizeof(regfile_t) * MAX_NUM_REG_REFS)

#define MAX_NUM_MEM_REFS 8192
#define MEM_REFS_SIZE (sizeof(memref_t) * MAX_NUM_MEM_REFS)

#define MAX_NUM_MEM_REFS 8192
#define MEMFILE_SIZE (sizeof(memfile_t) * MAX_NUM_MEM_REFS)

#define MAX_NUM_BYTES_MAP 128
#define MAX_BYTES_MAP_SIZE (sizeof(bytes_map_t) * MAX_NUM_BYTES_MAP)


typedef struct {
	peekaboo_trace_t *peek_trace;
	uint64_t num_refs;
} per_thread_t;

static client_id_t client_id;
static void *mutex;     /* for multithread support */
static uint64 num_refs; /* keep a global instruction reference count */

static int tls_idx;

static drx_buf_t *insn_ref_buf;
static drx_buf_t *bytes_map_buf;
static drx_buf_t *regfile_buf;
static drx_buf_t *memrefs_buf;
static drx_buf_t *memfile_buf;


static void flush_insnrefs(void *drcontext, void *buf_base, size_t size)
{
	per_thread_t *data = drmgr_get_tls_field(drcontext, tls_idx);
	size_t count = size / sizeof(insn_ref_t);
	DR_ASSERT(size % sizeof(insn_ref_t) == 0);
	fwrite(buf_base, sizeof(insn_ref_t), count, data->peek_trace->insn_trace);
	data->num_refs += count;
}

static void flush_regfile(void *drcontext, void *buf_base, size_t size)
{
	per_thread_t *data = drmgr_get_tls_field(drcontext, tls_idx);
	size_t count = size / sizeof(regfile_t);
	DR_ASSERT(size % sizeof(regfile_t) == 0);
	fwrite(buf_base, sizeof(regfile_t), count, data->peek_trace->regfile);
}

static void flush_memrefs(void *drcontext, void *buf_base, size_t size)
{
	per_thread_t *data = drmgr_get_tls_field(drcontext, tls_idx);
	size_t count = size / sizeof(memref_t);
	DR_ASSERT(size % sizeof(memref_t) == 0);
	fwrite(buf_base, sizeof(memref_t), count, data->peek_trace->memrefs);
}

static void flush_memfile(void *drcontext, void *buf_base, size_t size)
{
	per_thread_t *data = drmgr_get_tls_field(drcontext, tls_idx);
	size_t count = size / sizeof(memfile_t);
	DR_ASSERT(size % sizeof(memfile_t) == 0);
	fwrite(buf_base, sizeof(memfile_t), count, data->peek_trace->memfile);
}

/*

static void flush_map(void *drcontext, void *buf_base, size_t size)
{
	per_thread_t *data = drmgr_get_tls_field(drcontext, tls_idx);
	size_t count = size / sizeof(bytes_map_t);
	DR_ASSERT(size % sizeof(bytes_map_t) == 0);
	fwrite(buf_base, sizeof(bytes_map_t), count, data->peek_trace->bytes_map);
}

*/

static dr_signal_action_t event_signal(void *drcontext, dr_siginfo_t *info)
{
    /* Flush data in buffers when receiving SIGINT(2), SIGABRT(6), SIGSEGV(11) */
    if ((info->sig == SIGINT) || (info->sig == SIGABRT) || (info->sig ==  SIGSEGV))
    {
        printf("Peekaboo: Signal %d caught.\n", info->sig);
        per_thread_t *data;
        data = drmgr_get_tls_field(drcontext, tls_idx);
        dr_mutex_lock(mutex);

        flush_insnrefs(drcontext, insn_ref_buf, INSN_REF_SIZE);
        flush_memfile(drcontext, memfile_buf, MEMFILE_SIZE);
        flush_memrefs(drcontext, memrefs_buf, MEM_REFS_SIZE);
        flush_regfile(drcontext, regfile_buf, REG_BUF_SIZE);

        fflush(data->peek_trace->insn_trace);
        fflush(data->peek_trace->bytes_map);
        fflush(data->peek_trace->regfile);
        fflush(data->peek_trace->memfile);
        fflush(data->peek_trace->memrefs);
        fflush(data->peek_trace->metafile);
        
        dr_mutex_unlock(mutex);
    }

    /* Deliver the signal to app */
    return DR_SIGNAL_DELIVER;
}


static void save_regfile(void)
{
	void *drcontext = dr_get_current_drcontext();
	regfile_t *regfile_ptr;
	regfile_ptr = (regfile_t *) drx_buf_get_buffer_ptr(drcontext, regfile_buf);

	dr_mcontext_t mc = {sizeof(mc), DR_MC_ALL};
	dr_get_mcontext(drcontext, &mc);
	copy_regfile(regfile_ptr, &mc);

	//void *base = drx_buf_get_buffer_base(drcontext, regfile_buf);
	//uint64_t size = ((uint64_t)(regfile_ptr+1) - (uint64_t)base);
	//uint64_t count = size/sizeof(regfile_ref_t);
	//uint64_t buf_size = drx_buf_get_buffer_size(drcontext, regfile_buf);
	//mem_ref_t *mem_ref_ptr = (mem_ref_t *)drx_buf_get_buffer_ptr(drcontext, memrefs_buf);
	//mem_ref_t *mem_ref_base = (mem_ref_t *)drx_buf_get_buffer_base(drcontext, memrefs_buf);
	//size = (uint64_t)mem_ref_ptr - (uint64_t)mem_ref_base;
	//printf("memref_ptr:%p\n", mem_ref_ptr);
	//printf("memref_size:%d\n", size);
	//printf("memref_count:%llu\n", size/sizeof(mem_ref_t));
}

static void instrument_mem(void *drcontext, instrlist_t *ilist, instr_t *where, opnd_t ref, bool write)
{
	/* We need two scratch registers */
	reg_id_t reg_ptr, reg_tmp;
	if (drreg_reserve_register(drcontext, ilist, where, NULL, &reg_ptr) !=
			DRREG_SUCCESS ||
			drreg_reserve_register(drcontext, ilist, where, NULL, &reg_tmp) !=
			DRREG_SUCCESS) {
		DR_ASSERT(false); /* cannot recover */
		return;
	}

	uint32_t size = drutil_opnd_mem_size_in_bytes(ref, where);
	drutil_insert_get_mem_addr(drcontext, ilist, where, ref, reg_tmp, reg_ptr);

	drx_buf_insert_load_buf_ptr(drcontext, memfile_buf, ilist, where, reg_ptr);
	drx_buf_insert_buf_store(drcontext, memfile_buf, ilist, where, reg_ptr, DR_REG_NULL, opnd_create_reg(reg_tmp), OPSZ_PTR, offsetof(memfile_t, addr)); 
	drx_buf_insert_buf_store(drcontext, memfile_buf, ilist, where, reg_ptr, reg_tmp, OPND_CREATE_INT32(0), OPSZ_4, offsetof(memfile_t, value));
	drx_buf_insert_buf_store(drcontext, memfile_buf, ilist, where, reg_ptr, reg_tmp, OPND_CREATE_INT32(size), OPSZ_4, offsetof(memfile_t, size));
	drx_buf_insert_buf_store(drcontext, memfile_buf, ilist, where, reg_ptr, reg_tmp, OPND_CREATE_INT32(write?1:0), OPSZ_4, offsetof(memfile_t, status));
	drx_buf_insert_update_buf_ptr(drcontext, memfile_buf, ilist, where, reg_ptr, reg_tmp, sizeof(memfile_t));

	//printf("sizesize:%d\n", size);
	//disassemble_with_info(drcontext, instr_get_app_pc(where), 0, true, true);

	if (drreg_unreserve_register(drcontext, ilist, where, reg_ptr) != DRREG_SUCCESS ||
	    drreg_unreserve_register(drcontext, ilist, where, reg_tmp) != DRREG_SUCCESS)
		DR_ASSERT(false);
}

static void instrument_insn(void *drcontext, instrlist_t *ilist, instr_t *where, int mem_count)
{
	reg_id_t reg_ptr, reg_tmp;
	if (drreg_reserve_register(drcontext, ilist, where, NULL, &reg_ptr) != DRREG_SUCCESS ||
	    drreg_reserve_register(drcontext, ilist, where, NULL, &reg_tmp) != DRREG_SUCCESS)
	{
		DR_ASSERT(false);
		return;
	}

	int insn_len = instr_length(drcontext, where);
	app_pc pc = instr_get_app_pc(where);

	// instrument update to insn_ref, pushes a 64bit pc into the buffer
	drx_buf_insert_load_buf_ptr(drcontext, insn_ref_buf, ilist, where, reg_ptr);
	drx_buf_insert_buf_store(drcontext, insn_ref_buf, ilist, where, reg_ptr, reg_tmp, OPND_CREATE_INT64(pc), OPSZ_8, 0);
	drx_buf_insert_update_buf_ptr(drcontext, insn_ref_buf, ilist, where, reg_ptr, DR_REG_NULL, sizeof(insn_ref_t));

	// ZL: insert a write 0 into the stream using dynamorio sanctioned instruction to trigger the flushing of file from trace buffer.
	drx_buf_insert_load_buf_ptr(drcontext, regfile_buf, ilist, where, reg_ptr);
	drx_buf_insert_buf_store(drcontext, regfile_buf, ilist, where, reg_ptr, reg_tmp, OPND_CREATE_INT32(0), OPSZ_4, offsetof(regfile_t, gpr));


	// ZL: insert write to store mem_count into memrefs
	drx_buf_insert_load_buf_ptr(drcontext, memrefs_buf, ilist, where, reg_ptr);
	drx_buf_insert_buf_store(drcontext, memrefs_buf, ilist, where, reg_ptr, reg_tmp, OPND_CREATE_INT32(mem_count), OPSZ_4, offsetof(memref_t, length));
	drx_buf_insert_update_buf_ptr(drcontext, memrefs_buf, ilist, where, reg_ptr, DR_REG_NULL, sizeof(memref_t));

	// instruments a clean call to save the register info
	dr_insert_clean_call(drcontext, ilist, where, (void *)save_regfile, false, 0);
	drx_buf_insert_load_buf_ptr(drcontext, regfile_buf, ilist, where, reg_ptr);
	drx_buf_insert_update_buf_ptr(drcontext, regfile_buf, ilist, where, reg_ptr, DR_REG_NULL, sizeof(regfile_t));


	if (drreg_unreserve_register(drcontext, ilist, where, reg_ptr) != DRREG_SUCCESS ||
	    drreg_unreserve_register(drcontext, ilist, where, reg_tmp) != DRREG_SUCCESS)
		DR_ASSERT(false);
}


static dr_emit_flags_t save_bb_rawbytes(void *drcontext, void *tag, instrlist_t *bb, bool for_trace, bool translating, void **user_data)
{
	per_thread_t *data = drmgr_get_tls_field(drcontext, tls_idx);
	bytes_map_t bytes_map[MAX_NUM_BYTES_MAP];
	uint idx=0;
	instr_t *insn;

	for (insn = instrlist_first_app(bb), idx=0; insn && idx < MAX_NUM_BYTES_MAP; insn=instr_get_next_app(insn), idx++)
	{
		uint32_t length = instr_length(drcontext, insn);
		DR_ASSERT(length <= 16);
		bytes_map[idx].pc = (uint64_t)instr_get_app_pc(insn);
		bytes_map[idx].size = length;
    int x;
		for (x=0; x<length; x++)
		{
			bytes_map[idx].rawbytes[x] = instr_get_raw_byte(insn, x);
		}
	}

	fwrite(bytes_map, sizeof(bytes_map_t), idx, data->peek_trace->bytes_map);
	return DR_EMIT_DEFAULT;
}

static dr_emit_flags_t per_insn_instrument(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr, 
		                             bool for_trace, bool translating, void *user_data)
{
	drmgr_disable_auto_predication(drcontext, bb);
	if (!instr_is_app(instr)) return DR_EMIT_DEFAULT;

	/* insert code to add an entry for each memory reference opnd */
	uint32_t mem_count = 0;
	int i;
	for (i = 0; i < instr_num_srcs(instr); i++) {
		if (opnd_is_memory_reference(instr_get_src(instr, i)))
		{
			instrument_mem(drcontext, bb, instr, instr_get_src(instr, i), false);
			mem_count++;
		}
	}

	for (i = 0; i < instr_num_dsts(instr); i++) {
		if (opnd_is_memory_reference(instr_get_dst(instr, i)))
		{
			instrument_mem(drcontext, bb, instr, instr_get_dst(instr, i), true);
			mem_count++;
		}
	}

	// ZL: would instrument the memref count (memfile) inside
	instrument_insn(drcontext, bb, instr, mem_count);


	//if (drmgr_is_first_instr(drcontext, instr) IF_AARCHXX(&& !instr_is_exclusive_store(instr)))
	//	dr_insert_clean_call(drcontext, bb, instr, (void *)save_insn, false, 0);
	return DR_EMIT_DEFAULT;
}

static bool event_filter_syscall(void *drcontext, int sysnum)
{
    return true; /* intercept everything */
}

static bool event_pre_syscall(void *drcontext, int sysnum)
{
    drsys_syscall_t *syscall;
    const char *name = "<unknown>";
    if (drsys_cur_syscall(drcontext, &syscall) == DRMF_SUCCESS)
        drsys_syscall_name(syscall, &name);
    dr_printf("Peekaboo: get syscall id %d: %s ", name, sysnum);
    /* We can also get the # of args and the type of each arg.
     * See the drstrace tool for an example of how to do that.
     */
    return true; /* execute normally */
}
static void event_post_syscall(void *drcontext, int sysnum)
{
    return;
}

static void event_thread_init(void *drcontext)
{
	char buf[256];
	per_thread_t *data = dr_thread_alloc(drcontext, sizeof(per_thread_t));
	DR_ASSERT(data != NULL);
	drmgr_set_tls_field(drcontext, tls_idx, data);

	int pid = dr_get_process_id();
	int tid = dr_get_thread_id(drcontext);
	snprintf(buf, 256, "%s-%d-%d", dr_get_application_name(), pid, tid);

	data->num_refs = 0;
	data->peek_trace = create_trace(buf);
	write_metadata(data->peek_trace, arch, LIBPEEKABOO_VER);
	dr_printf("Peekaboo: Created trace : %s\n", buf);
    //dr_printf("Peekaboo: Arch: %d\n", arch);
    //dr_printf("Peekaboo: libpeekaboo Version: %d\n", LIBPEEKABOO_VER);
	char path[256];
	sprintf(path, "cp /proc/%d/maps %s/proc_map", pid, buf);
	system(path);
}

static void event_thread_exit(void *drcontext)
{
	per_thread_t *data;
	data = drmgr_get_tls_field(drcontext, tls_idx);
	dr_mutex_lock(mutex);
	num_refs += data->num_refs;
	close_trace(data->peek_trace);
	dr_mutex_unlock(mutex);
	dr_thread_free(drcontext, data, sizeof(per_thread_t));
}

static void event_exit(void)
{
	//dr_log(NULL, DR_LOG_ALL, 1, "'peekaboo': Total number of instructions seen: " SZFMT "\n", num_refs);
    dr_printf("Peekaboo: Total number of instructions seen: " SZFMT "\n", num_refs);


	if (!drmgr_unregister_tls_field(tls_idx) ||
	    !drmgr_unregister_thread_init_event(event_thread_init) ||
	    !drmgr_unregister_thread_exit_event(event_thread_exit) ||
	    !drmgr_unregister_bb_insertion_event(per_insn_instrument) ||
	    !drmgr_unregister_pre_syscall_event(event_pre_syscall) ||
	    !drmgr_unregister_post_syscall_event(event_post_syscall) ||
	    drreg_exit() != DRREG_SUCCESS)
	    DR_ASSERT(false && "failed to unregister");

	dr_mutex_destroy(mutex);
	drmgr_exit();
	drutil_exit();

	drx_buf_free(regfile_buf);
	drx_buf_free(memrefs_buf);
	drx_buf_free(memfile_buf);
	drx_buf_free(insn_ref_buf);

	drx_exit();
}


DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[])
{

    drreg_options_t ops = {sizeof(ops), 4, false};
    drsys_options_t ops_sys = { sizeof(ops), 0, };
    dr_set_client_name("peekaboo DynamoRIO tracer", "https://github.com/melynx/peekaboo");

	drreg_init(&ops);
	drmgr_init();
	drutil_init();
	drx_init();
    if (drsys_init(id, &ops_sys) != DRMF_SUCCESS)
        DR_ASSERT(false);

	drmgr_register_signal_event(event_signal);
	dr_register_filter_syscall_event(event_filter_syscall);
	drmgr_register_pre_syscall_event(event_pre_syscall);
	drmgr_register_post_syscall_event(event_post_syscall);
	dr_register_exit_event(event_exit);
	drmgr_register_thread_init_event(event_thread_init);
	drmgr_register_thread_exit_event(event_thread_exit);
	drmgr_register_bb_instrumentation_event(save_bb_rawbytes, per_insn_instrument, NULL);

	client_id = id;
	mutex = dr_mutex_create();

	tls_idx = drmgr_register_tls_field();
	DR_ASSERT(tls_idx != -1);

	insn_ref_buf = drx_buf_create_trace_buffer(INSN_REF_SIZE, flush_insnrefs);
	memfile_buf = drx_buf_create_trace_buffer(MEMFILE_SIZE, flush_memfile);
	memrefs_buf = drx_buf_create_trace_buffer(MEM_REFS_SIZE, flush_memrefs);
	regfile_buf = drx_buf_create_trace_buffer(REG_BUF_SIZE, flush_regfile);

	//dr_log(NULL, DR_LOG_ALL, 11, "%s - Client 'peekaboo' initializing\n", arch);
    dr_printf("Peekaboo: %s - Client 'peekaboo' initializing\n", arch_str);

    dr_printf("Peekaboo: Binary being traced: %s\n", dr_get_application_name());
    dr_printf("Peekaboo: Number of SIMD slots: %d\n", MCXT_NUM_SIMD_SLOTS);

}
