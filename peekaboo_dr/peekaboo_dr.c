#include <stdio.h>
#include <stddef.h> /* for offsetof */
#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"

#include "peekaboo_utils.h"

typedef struct insn_ref {
	uint64_t pc;
	int opcode;
} insn_ref_t;

#define MAX_NUM_INS_REFS 8192
#define MEM_BUF_SIZE (sizeof(insn_ref_t) * MAX_NUM_INS_REFS)

typedef struct {
    byte *seg_base;
    insn_ref_t *buf_base;
    file_t log;
    FILE *logf;
    uint64 num_refs;
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

static void flush_data(void *drcontext)
{
	per_thread_t *data;
	insn_ref_t *insn_ref, *buf_ptr;
	data = drmgr_get_tls_field(drcontext, tls_idx);
	buf_ptr = CUR_BUF_PTR(data->seg_base);
	for (insn_ref = (insn_ref_t *)data->buf_base; insn_ref < buf_ptr; insn_ref++)
	{
		fprintf(data->logf, PIFX ",%s\n", (ptr_uint_t)insn_ref->pc, decode_opcode_name(insn_ref->opcode));
		data->num_refs++;
	}
	CUR_BUF_PTR(data->seg_base) = data->buf_base;
}

static void insert_save_pc(void *drcontext, instrlist_t *ilist, instr_t *where, reg_id_t base, reg_id_t scratch, app_pc pc)
{
	instrlist_insert_mov_immed_ptrsz(drcontext, (ptr_int_t)pc, opnd_create_reg(scratch), ilist, where, NULL, NULL);
	instr_t *store_pc = XINST_CREATE_store(drcontext, OPND_CREATE_MEMPTR(base, offsetof(insn_ref_t, pc)), opnd_create_reg(scratch));
	instrlist_meta_preinsert(ilist, where, store_pc);
}

static void instrument_insn(void *drcontext, instrlist_t *ilist, instr_t *where)
{
	reg_id_t reg_ptr, reg_tmp;
	if (drreg_reserve_register(drcontext, ilist, where, NULL, &reg_ptr) != DRREG_SUCCESS ||
	    drreg_reserve_register(drcontext, ilist, where, NULL, ^reg_tmp) != DRREG_SUCCESS)
	{
		DR_ASSERT(false);
		return;
	}

	insert_load_buf_ptr(drcontext, ilist, where, reg_ptr);
	insert_save_pc(drcontext, ilist, where, reg_ptr, reg_tmp, instr_get_app_pc(where));
	insert_save_opcode(drcontext, ilist, where, reg_ptr, reg_tmp, instr_get_opcode(where));
	insert_update_buf_ptr(drcontext, ilist, where, reg_ptr, sizeof(insn_ref_t));

	if (drreg_unreserve_register(drcontext, ilist, where, reg_ptr) != DRREG_SUCCESS ||
	    drreg_unreserve_register(drcontext, ilist, where, reg_tmp) != DRREG_SUCCESS)
		DR_ASSERT(false);
}

static dr_emit_flags_t event_app_instruction(void *drcontext, void *tag, instrlist_t *bb, instr_t *insn, 
		                             bool for_trace, bool translating, void *user_data)
{
	drmgr_disable_auto_predication(drcontext, bb);
	if (!instr_is_app(instr)) return DR_EMIT_DEFAULT;

	instrument_insn(drcontext, bb, insn);

	if (drmgr_is_first_instr(drcontext, insn) IF_AARCHXX(&& !instr_is_exclusive_store(insn)))
		dr_insert_clean_call(drcontext, bb, insn, (void *)clean_call, false, 0);
	
	return DR_EMIT_DEFAULT;
}

static void event_thread_init(void *drcontext)
{
	per_thread_t *data = dr_thread_alloc(drcontext, sizeof(per_thread_t));
	DR_ASSERT(data != NULL);
	drmgr_set_tls_field(drcontext, tls_idx, data);

	data->seg_base = dr_get_dr_segment_base(tls_seg);
	data->buf_base = dr_raw_mem_alloc(MEM_BUF_SIZE, DR_MEMPROT_READ | DR_MEMPROT_WRITE, NULL);
	DR_ASSERT(data->seg_base != NULL && data->buf_base != NULL);

	CUR_BUF_PTR(data->seg_base) = data->buf_base;	

	data->num_refs = 0;
	data->log = file_open(client_id, drcontext, NULL, "peekaboo", DR_FILE_ALLOW_LARGE);
	data->logf = fdopen(data->log, "w");
	fprintf(data->logf, "Format: <instr address>,<opcode>\n");
}

static void event_thread_exit(void *drcontext)
{
	per_thread_t *data;
	flush_data(drcontext);
	data = drmgr_get_tls_field(drcontext, tls_idx);
	dr_mutex_lock(mutex);
	num_refs += data->num_refs;
	dr_mutex_unlock(mutex);
	fclose(data->logf);
	close_file(data->log);
	dr_raw_mem_free(data->buf_base, MEM_BUF_SIZE);
	dr_thread_free(drcontext, data, sizeof(per_thread_t));
}

static void event_exit(void)
{
	dr_log(NULL, DR_LOG_ALL, 1, "'peekaboo': Total number of instructions seen: " SZFMT "\n", num_refs);
	if (!dr_raw_tls_cfree(tls_offs, INSTRACE_TLS_COUNT)) DR_ASSERT(false);

	if (!drmgr_unregister_tls_field(tls_idx) ||
	    !drmgr_unregister_thread_init_event(event_thread_init) ||
	    !drmgr_unregister_thread_exit_event(event_thread_exit) ||
	    !drmgr_unregister_bb_insertion_event(event_app_instruction) ||
	    drreg_exit() != DRREG_SUCCESS)
	    DR_ASSERT(false);

	dr_mutex_destroy(mutex);
	drmgr_exit();
}


DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[])
{
	drreg_options_t ops = {sizeof(ops), 3, false};
	dr_set_client_name("peekaboo DynamoRIO tracer");

	drmgr_init();
	drreg_init(&ops);

	dr_register_exit_event(event_exit);
	dr_register_thread_init_event(event_thread_init);
	dr_register_thread_exit_event(event_thread_exit);
	drmgr_register_bb_instrumentation_event(NULL, event_app_instruction, NULL);

	client_id = id;
	mutex = dr_mutex_create();

	tls_idx = drmgr_register_tls_field();
	if (!dr_raw_tls_calloc(&tls_seg, &tls_offs, INSTRACE_TLS_COUNT, 0)) DR_ASSERT(false);
	dr_log(NULL, DR_LOG_ALL, 11, "Client 'peekaboo' initializing\n");
}
