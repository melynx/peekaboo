#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h> /* for offsetof */
#include <assert.h>
#include <inttypes.h>

#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "drutil.h"
#include "drx.h"
#include "dr_defines.h"

#include "libpeekaboo.h"

#ifdef X86
	#ifdef X64
		#include "arch/amd64.h"
		void copy_regfile(regfile_ref_t *regfile_ptr, dr_mcontext_t *mc)
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

			// here, we cast the simd structure into an array of uint256_t
			// TODO: Convert this to a single memcpy for performance
			UINT256_T *dst_ptr = (UINT256_T *)&regfile_ptr->simd;
			for (int x=0; x<15; x++)
				memcpy(&dst_ptr[x], &mc->ymm[x], sizeof(UINT256_T));
		}
	#else
		#include "arch/x86.h"
		char *arch = "X86";
	#endif
#else
	#ifdef X64
		#include "arch/aarch64.h"
		void copy_regfile(regfile_ref_t *regfile_ref, dr_mcontext_t *mc)
		{
		}
	#else
		#include "arch/arm.h"
		char *arch = "ARM";
	#endif
#endif

#define MAX_NUM_INS_REFS 8192
#define MEM_BUF_SIZE (sizeof(insn_ref_t) * MAX_NUM_INS_REFS)

#define MAX_NUM_REG_REFS 8192
#define REG_BUF_SIZE (sizeof(regfile_ref_t) * MAX_NUM_REG_REFS)

#define MAX_NUM_MEM_REFS 8192
#define MEM_REFS_SIZE (sizeof(mem_ref_t) * MAX_NUM_MEM_REFS)

#define MAX_NUM_BYTES_MAP 128
#define MAX_BYTES_MAP_SIZE (sizeof(insn_ref_t) * MAX_NUM_BYTES_MAP)


typedef struct {
	byte *seg_base;
	insn_ref_t *buf_base;
	peekaboo_trace_t peek_trace;
	uint64_t num_refs;
} per_thread_t;

static client_id_t client_id;
static void *mutex;     /* for multithread support */
static uint64 num_refs; /* keep a global instruction reference count */

enum {
    INSTRACE_TLS_OFFS_BUF_PTR,
    INSTRACE_TLS_COUNT, /* total number of TLS slots allocated */
};

static reg_id_t tls_seg;
static uint tls_offs;
static int tls_idx;
#define TLS_SLOT(tls_base, enum_val) (void **)((byte *)(tls_base) + tls_offs + (enum_val))
#define CUR_BUF_PTR(tls_base) *(insn_ref_t **)TLS_SLOT(tls_base, INSTRACE_TLS_OFFS_BUF_PTR)

static drx_buf_t *bytes_map_buf;
static drx_buf_t *regfile_buf;
static drx_buf_t *memrefs_buf;

static void flush_trace(void *drcontext)
{
	per_thread_t *data;
	insn_ref_t *buf_ptr;
	data = drmgr_get_tls_field(drcontext, tls_idx);
	buf_ptr = CUR_BUF_PTR(data->seg_base);
	int num_insn = (buf_ptr - data->buf_base);
	fwrite(data->buf_base, sizeof(insn_ref_t), num_insn, data->peek_trace.insn_trace);
	data->num_refs += num_insn;
	CUR_BUF_PTR(data->seg_base) = data->buf_base;
}

static void flush_regfile(void *drcontext, void *buf_base, size_t size)
{
	//printf("flush_regfile\n");
	per_thread_t *data = drmgr_get_tls_field(drcontext, tls_idx);
	size_t count = size / sizeof(regfile_ref_t);
	DR_ASSERT(size % sizeof(regfile_ref_t) == 0);
	fwrite(buf_base, sizeof(regfile_ref_t), count, data->peek_trace.regfile);
	//drx_buf_set_buffer_ptr(drcontext, regfile_buf, buf_base);
}

static void flush_memrefs(void *drcontext, void *buf_base, size_t size)
{
	//printf("flush:%llu:%p\n", size / sizeof(mem_ref_t), buf_base);
	//printf("size:%d\n", sizeof(mem_ref_t));
	per_thread_t *data = drmgr_get_tls_field(drcontext, tls_idx);
	size_t count = size / sizeof(mem_ref_t);
	DR_ASSERT(size % sizeof(mem_ref_t) == 0);
	fwrite(buf_base, sizeof(mem_ref_t), count, data->peek_trace.memfile);
	//drx_buf_set_buffer_ptr(drcontext, memrefs_buf, buf_base);
}

static void flush_map(void *drcontext, void *buf_base, size_t size)
{
	per_thread_t *data = drmgr_get_tls_field(drcontext, tls_idx);
	size_t count = size / sizeof(bytes_map_t);
	DR_ASSERT(size % sizeof(bytes_map_t) == 0);
	fwrite(buf_base, sizeof(bytes_map_t), count, data->peek_trace.bytes_map);
}

static void save_insn(void)
{
	void *drcontext = dr_get_current_drcontext();
	flush_trace(drcontext);
}

static void insert_load_buf_ptr(void *drcontext, instrlist_t *ilist, instr_t *where, reg_id_t reg_ptr)
{
	dr_insert_read_raw_tls(drcontext, ilist, where, tls_seg, tls_offs + INSTRACE_TLS_OFFS_BUF_PTR, reg_ptr);
}

static void insert_update_buf_ptr(void *drcontext, instrlist_t *ilist, instr_t *where, reg_id_t reg_ptr, int adjust)
{
	instr_t *add_offset = XINST_CREATE_add(drcontext, opnd_create_reg(reg_ptr), OPND_CREATE_INT16(adjust));
	instrlist_meta_preinsert(ilist, where, add_offset);
	dr_insert_write_raw_tls(drcontext, ilist, where, tls_seg, tls_offs + INSTRACE_TLS_OFFS_BUF_PTR, reg_ptr);
}

static void insert_save_pc(void *drcontext, instrlist_t *ilist, instr_t *where, reg_id_t base, reg_id_t scratch, app_pc pc)
{
	instrlist_insert_mov_immed_ptrsz(drcontext, (ptr_int_t)pc, opnd_create_reg(scratch), ilist, where, NULL, NULL);
	instr_t *store_pc = XINST_CREATE_store(drcontext, OPND_CREATE_MEMPTR(base, offsetof(insn_ref_t, pc)), opnd_create_reg(scratch));
	instrlist_meta_preinsert(ilist, where, store_pc);
}

static void save_regfile(void)
{
	void *drcontext = dr_get_current_drcontext();
	regfile_ref_t *regfile_ptr;
	regfile_ptr = (regfile_ref_t *) drx_buf_get_buffer_ptr(drcontext, regfile_buf);

	dr_mcontext_t mc = {sizeof(mc), DR_MC_ALL};
	dr_get_mcontext(drcontext, &mc);

	copy_regfile(regfile_ptr, &mc);

	void *base = drx_buf_get_buffer_base(drcontext, regfile_buf);
	uint64_t size = ((uint64_t)(regfile_ptr+1) - (uint64_t)base);
	uint64_t count = size/sizeof(regfile_ref_t);
	uint64_t buf_size = drx_buf_get_buffer_size(drcontext, regfile_buf);
	//printf("bufsize:%d\n", buf_size);
	//printf("size:%d\n", size);
	//printf("base_ptr:%p\n", base);
	//printf("buf_ptr:%p\n", regfile_ptr);
	//printf("count:%d\n", count);
	mem_ref_t *mem_ref_ptr = (mem_ref_t *)drx_buf_get_buffer_ptr(drcontext, memrefs_buf);
	mem_ref_t *mem_ref_base = (mem_ref_t *)drx_buf_get_buffer_base(drcontext, memrefs_buf);
	size = (uint64_t)mem_ref_ptr - (uint64_t)mem_ref_base;
	//printf("memref_ptr:%p\n", mem_ref_ptr);
	//printf("memref_size:%d\n", size);
	//printf("memref_count:%llu\n", size/sizeof(mem_ref_t));
}

static void insert_save_regfile(void *drcontext, instrlist_t *ilist, instr_t *where)
{
	dr_insert_clean_call(drcontext, ilist, where, (void *)save_regfile, false, 0);
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
	/* save_addr should be called first as reg_ptr or reg_tmp maybe used in ref */
	// app_pc pc = instr_get_app_pc(where);
	uint32_t size = drutil_opnd_mem_size_in_bytes(ref, where);
	drutil_insert_get_mem_addr(drcontext, ilist, where, ref, reg_tmp, reg_ptr);

	drx_buf_insert_load_buf_ptr(drcontext, memrefs_buf, ilist, where, reg_ptr);
	drx_buf_insert_buf_store(drcontext, memrefs_buf, ilist, where, reg_ptr, DR_REG_NULL, opnd_create_reg(reg_tmp), OPSZ_PTR, offsetof(mem_ref_t, addr)); 
    	///* inserts size */
	drx_buf_insert_buf_store(drcontext, memrefs_buf, ilist, where, reg_ptr, reg_tmp, OPND_CREATE_INT32(0), OPSZ_4, offsetof(mem_ref_t, size));
	drx_buf_insert_buf_store(drcontext, memrefs_buf, ilist, where, reg_ptr, reg_tmp, OPND_CREATE_INT32(size), OPSZ_4, offsetof(mem_ref_t, size));
	drx_buf_insert_buf_store(drcontext, memrefs_buf, ilist, where, reg_ptr, reg_tmp, OPND_CREATE_INT32(write?1:0), OPSZ_4, offsetof(mem_ref_t, status));

	drx_buf_insert_update_buf_ptr(drcontext, memrefs_buf, ilist, where, reg_ptr, reg_tmp, sizeof(mem_ref_t));

	//printf("sizesize:%d\n", size);
	//disassemble_with_info(drcontext, instr_get_app_pc(where), 0, true, true);

	if (drreg_unreserve_register(drcontext, ilist, where, reg_ptr) != DRREG_SUCCESS ||
	    drreg_unreserve_register(drcontext, ilist, where, reg_tmp) != DRREG_SUCCESS)
		DR_ASSERT(false);
}

static void instrument_insn(void *drcontext, instrlist_t *ilist, instr_t *where)
{
	reg_id_t reg_ptr, reg_tmp;
	if (drreg_reserve_register(drcontext, ilist, where, NULL, &reg_ptr) != DRREG_SUCCESS ||
	    drreg_reserve_register(drcontext, ilist, where, NULL, &reg_tmp) != DRREG_SUCCESS)
	{
		DR_ASSERT(false);
		return;
	}

	int insn_len = instr_length(drcontext, where);


	insert_load_buf_ptr(drcontext, ilist, where, reg_ptr);
	insert_save_pc(drcontext, ilist, where, reg_ptr, reg_tmp, instr_get_app_pc(where));
	insert_update_buf_ptr(drcontext, ilist, where, reg_ptr, sizeof(insn_ref_t));
	// ZL: insert a write 0 into the stream using dynamorio sanctioned instruction to trigger the flushing of file from trace buffer.
	drx_buf_insert_load_buf_ptr(drcontext, regfile_buf, ilist, where, reg_ptr);
	drx_buf_insert_buf_store(drcontext, regfile_buf, ilist, where, reg_ptr, reg_tmp, OPND_CREATE_INT32(0), OPSZ_4, offsetof(regfile_ref_t, gpr));
	insert_save_regfile(drcontext, ilist, where);
	drx_buf_insert_load_buf_ptr(drcontext, regfile_buf, ilist, where, reg_ptr);
	drx_buf_insert_update_buf_ptr(drcontext, regfile_buf, ilist, where, reg_ptr, DR_REG_NULL, sizeof(regfile_ref_t));

	if (drreg_unreserve_register(drcontext, ilist, where, reg_ptr) != DRREG_SUCCESS ||
	    drreg_unreserve_register(drcontext, ilist, where, reg_tmp) != DRREG_SUCCESS)
		DR_ASSERT(false);
}


static dr_emit_flags_t bb_rawbytes(void *drcontext, void *tag, instrlist_t *bb, bool for_trace, bool translating, void **user_data)
{
	//printf("bb!\n");
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
		for (int x=0; x<length; x++)
		{
			bytes_map[idx].rawbytes[x] = instr_get_raw_byte(insn, x);
		}
	}

	fwrite(bytes_map, sizeof(bytes_map_t), idx, data->peek_trace.bytes_map);
	//printf("write\n");
	return DR_EMIT_DEFAULT;
}

static dr_emit_flags_t event_app_instruction(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr, 
		                             bool for_trace, bool translating, void *user_data)
{
	//printf("instr!\n");
	drmgr_disable_auto_predication(drcontext, bb);
	if (!instr_is_app(instr)) return DR_EMIT_DEFAULT;

	instrument_insn(drcontext, bb, instr);

	/* insert code to add an entry for each memory reference opnd */
	int i;
	for (i = 0; i < instr_num_srcs(instr); i++) {
		if (opnd_is_memory_reference(instr_get_src(instr, i)))
			instrument_mem(drcontext, bb, instr, instr_get_src(instr, i), false);
	}

	for (i = 0; i < instr_num_dsts(instr); i++) {
		if (opnd_is_memory_reference(instr_get_dst(instr, i)))
			instrument_mem(drcontext, bb, instr, instr_get_dst(instr, i), true);
	}

	if (drmgr_is_first_instr(drcontext, instr) IF_AARCHXX(&& !instr_is_exclusive_store(instr)))
		dr_insert_clean_call(drcontext, bb, instr, (void *)save_insn, false, 0);
	
	return DR_EMIT_DEFAULT;
}

static void event_thread_init(void *drcontext)
{
	char buf[256];
	per_thread_t *data = dr_thread_alloc(drcontext, sizeof(per_thread_t));
	DR_ASSERT(data != NULL);
	drmgr_set_tls_field(drcontext, tls_idx, data);

	data->seg_base = dr_get_dr_segment_base(tls_seg);
	data->buf_base = dr_raw_mem_alloc(MEM_BUF_SIZE, DR_MEMPROT_READ | DR_MEMPROT_WRITE, NULL);
	DR_ASSERT(data->seg_base != NULL && data->buf_base != NULL);

	CUR_BUF_PTR(data->seg_base) = data->buf_base;

	int pid = dr_get_process_id();
	int tid = dr_get_thread_id(drcontext);
	snprintf(buf, 256, "%s-%d-%d", dr_get_application_name(), pid, tid);

	data->num_refs = 0;
	create_trace(buf, &data->peek_trace);
	printf("Created trace : %s\n", buf);
}

static void event_thread_exit(void *drcontext)
{
	per_thread_t *data;
	flush_trace(drcontext);
	//flush_regfile_manual(drcontext);
	data = drmgr_get_tls_field(drcontext, tls_idx);
	dr_mutex_lock(mutex);
	num_refs += data->num_refs;
	close_trace(&data->peek_trace);
	dr_mutex_unlock(mutex);
	dr_raw_mem_free(data->buf_base, MEM_BUF_SIZE);
	dr_thread_free(drcontext, data, sizeof(per_thread_t));
}

static void event_exit(void)
{
	//dr_log(NULL, DR_LOG_ALL, 1, "'peekaboo': Total number of instructions seen: " SZFMT "\n", num_refs);
	printf("'peekaboo': Total number of instructions seen: " SZFMT "\n", num_refs);

	if (!dr_raw_tls_cfree(tls_offs, INSTRACE_TLS_COUNT)) DR_ASSERT(false);

	if (!drmgr_unregister_tls_field(tls_idx) ||
	    !drmgr_unregister_thread_init_event(event_thread_init) ||
	    !drmgr_unregister_thread_exit_event(event_thread_exit) ||
	    !drmgr_unregister_bb_insertion_event(event_app_instruction) ||
	    drreg_exit() != DRREG_SUCCESS)
	    DR_ASSERT(false);

	dr_mutex_destroy(mutex);
	drmgr_exit();
	drutil_exit();

	drx_buf_free(regfile_buf);
	drx_buf_free(memrefs_buf);

	drx_exit();
}


DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[])
{
	drreg_options_t ops = {sizeof(ops), 4, false};
	dr_set_client_name("peekaboo DynamoRIO tracer", "https://github.com/melynx/peekaboo");

	drreg_init(&ops);
	drmgr_init();
	drutil_init();
	drx_init();

	dr_register_exit_event(event_exit);
	drmgr_register_thread_init_event(event_thread_init);
	drmgr_register_thread_exit_event(event_thread_exit);
	drmgr_register_bb_instrumentation_event(bb_rawbytes, event_app_instruction, NULL);

	client_id = id;
	mutex = dr_mutex_create();

	tls_idx = drmgr_register_tls_field();
	DR_ASSERT(tls_idx != -1);

	if (!dr_raw_tls_calloc(&tls_seg, &tls_offs, INSTRACE_TLS_COUNT, 0)) DR_ASSERT(false);

	memrefs_buf = drx_buf_create_trace_buffer(MEM_REFS_SIZE, flush_memrefs);
	regfile_buf = drx_buf_create_trace_buffer(REG_BUF_SIZE, flush_regfile);

	//dr_log(NULL, DR_LOG_ALL, 11, "%s - Client 'peekaboo' initializing\n", arch);
	printf("%s - Client 'peekaboo' initializing\n", arch);

	printf("Binary being traced: %s\n", dr_get_application_name());
	printf("REGFILE_BUF = %p\n", regfile_buf);
	printf("Sizeof bytes map: %lu\n", sizeof(bytes_map_t));
	printf("Sizeof regfile: %lu\n", sizeof(regfile_ref_t));
	printf("sizeof reg_t:%lu\n", sizeof(reg_t));
	printf("sizeof dr_mcontext_t:%lu\n", sizeof(dr_mcontext_t));
	printf("Number of SIMD slots: %d\n", MCXT_NUM_SIMD_SLOTS);

}
