#include "pin.H"
#include <iostream>
#include <fstream>
#include <vector>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include "peekaboo.h"

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<string> KnobOutputDir(KNOB_MODE_WRITEONCE,  "pintool", "outdir", "", "specify dir name for peekaboo output");

KNOB<BOOL> KnobCount(KNOB_MODE_WRITEONCE,  "pintool", "count", "1", "count instructions, basic blocks and threads in the application");


/* ===================================================================== */
// Utilities
/* ===================================================================== */

INT32 Usage()
{
	cerr << "This tool logs the execution trace of the application. " << endl <<
		"Trace contains both register values and memory values. " << endl << endl;

	cerr << KNOB_BASE::StringKnobSummary() << endl;

	return -1;
}

string Val2Str(const void* value, unsigned int size)
{
	stringstream sstr;
	sstr << hex;
	const unsigned char* cval = (const unsigned char*)value;
	// Traverse cval from end to beginning since the MSB is in the last block of cval.
	while (size)
	{
		--size;
		sstr << (unsigned int)cval[size];
	}
	return string("0x")+sstr.str();
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */

/*!
 * Increase counter of the executed basic blocks and instructions.
 * This function is called for every basic block when it is about to be executed.
 * @param[in]	numInstInBbl	number of instructions in the basic block
 * @note use atomic operations for multi-threaded applications
 */
VOID CountBbl(UINT32 numInstInBbl)
{
	bblCount++;
	insCount += numInstInBbl;
}

VOID PrintRegVals(const CONTEXT *ctxt)
{
	PIN_REGISTER val;
	static const UINT stRegSize = REG_Size(REG_ST_BASE);
	for (int reg = (int)REG_GR_BASE; reg <= (int)REG_GR_LAST; ++reg)
	{
		// For the integer registers, it is safe to use ADDRINT. But make sure to pass a pointer to it.
		PIN_GetContextRegval(ctxt, (REG)reg, reinterpret_cast<UINT8*>(&val));
		cerr << REG_StringShort((REG)reg) << ": " << Val2Str(&val, stRegSize) << endl;
	}
	for (int reg = (int)REG_ST_BASE; reg <= (int)REG_ST_LAST; ++reg)
	{
		// For the x87 FPU stack registers, using PIN_REGISTER ensures a large enough buffer.
		PIN_GetContextRegval(ctxt, (REG)reg, reinterpret_cast<UINT8*>(&val));
		cerr << REG_StringShort((REG)reg) << ": " << Val2Str(&val, stRegSize) << endl;
	}

}

VOID PrepRegVals(const CONTEXT *ctxt, ADDRINT pc, UINT32 insn_size)
{
	for (unsigned int count=0; count < trace_regs.size(); count++)
		PIN_GetContextRegval(ctxt, trace_regs[count], reinterpret_cast<UINT8*>(&reg_struct[count]));

	insn_record.pc = pc;
	insn_record.insn_size = insn_size;
	PIN_SafeCopy(insn_record.rawbytes, reinterpret_cast<const VOID *>(pc), insn_size);
	insn_record.mem_id = 0;
}

VOID PrepMemVals(const CONTEXT *ctxt)
{
	memCount++;
	insn_record.mem_id = memCount;
}

VOID DumpRecord()
{
	reg_entries->write(reinterpret_cast<const char *>(reg_struct), trace_regs.size());
	insn_trace->write(reinterpret_cast<const char *>(&insn_record), sizeof(insn_record));
}

/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

/*!
 * Insert call to the CountBbl() analysis routine before every basic block 
 * of the trace.
 * This function is called every time a new trace is encountered.
 * @param[in]	trace	 trace to be instrumented
 * @param[in]	v		 value specified by the tool in the TRACE_AddInstrumentFunction
 *						 function call
 */

VOID Trace(TRACE trace, VOID *v)
{
	// Visit every basic block in the trace
	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
	{
		// Insert a call to CountBbl() before every basic bloc, passing the number of instructions
		BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)CountBbl, IARG_UINT32, BBL_NumIns(bbl), IARG_END);
	}
}

VOID Instruction(INS ins, VOID *v)
{
	USIZE insn_size = INS_Size(ins);
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)PrepRegVals, IARG_CONST_CONTEXT, IARG_INST_PTR, IARG_UINT32, insn_size, IARG_END);
	if (INS_IsMemoryRead(ins))
	{
	}
	if (INS_IsMemoryWrite(ins))
	{
	}
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)DumpRecord, IARG_CONST_CONTEXT, IARG_INST_PTR, IARG_UINT32, insn_size, IARG_END);
}


/*!
 * Increase counter of threads in the application.
 * This function is called for every thread created by the application when it is
 * about to start running (including the root thread).
 * @param[in]	threadIndex		ID assigned by PIN to the new thread
 * @param[in]	ctxt			initial register state for the new thread
 * @param[in]	flags			thread creation flags (OS specific)
 * @param[in]	v				value specified by the tool in the 
 *								PIN_AddThreadStartFunction function call
 */
VOID ThreadStart(THREADID threadIndex, CONTEXT *ctxt, INT32 flags, VOID *v)
{
	threadCount++;
}

/*!
 * Print out analysis results.
 * This function is called when the application exits.
 * @param[in]	code			exit code of the application
 * @param[in]	v				value specified by the tool in the 
 *								PIN_AddFiniFunction function call
 */
VOID Fini(INT32 code, VOID *v)
{
	*logfile <<  "===============================================" << endl;
	*logfile <<  "peekaboo analysis results: " << endl;
	*logfile <<  "Number of instructions: " << insCount  << endl;
	*logfile <<  "Number of basic blocks: " << bblCount  << endl;
	*logfile <<  "Number of threads: " << threadCount  << endl;
	*logfile <<  "===============================================" << endl;
}

/*!
 * The main procedure of the tool.
 * This function is called when the application image is loaded but not yet started.
 * @param[in]	argc			total number of elements in the argv array
 * @param[in]	argv			array of command line arguments, 
 *								including pin -t <toolname> -- ...
 */
int main(int argc, char *argv[])
{
	// Initialize PIN library. Print help message if -h(elp) is specified
	// in the command line or the command line is invalid 
	if( PIN_Init(argc,argv) )
	{
		return Usage();
	}
	
	// initialize the registers we will be dumping for our trace
	for (int reg = (int)REG_GR_BASE; reg <= (int)REG_GR_LAST; ++reg) trace_regs.push_back((REG)reg);
	for (int reg = (int)REG_ST_BASE; reg <= (int)REG_ST_LAST; ++reg) trace_regs.push_back((REG)reg);
	for (int reg = (int)REG_XMM_BASE; reg <= (int)REG_LastSupportedXmm(); ++reg) trace_regs.push_back((REG)reg);
	// for eflags and eip, we'll upcast it to the full name, so for x64, it'll be rip and x32, eip.
	trace_regs.push_back(REG_FullRegName(REG_EFLAGS));
	trace_regs.push_back(REG_FullRegName(REG_EIP));
	trace_regs.push_back(REG_FullRegName(REG_FPSW));

	for (REG reg : trace_regs)
	{
		REGSET_Insert(trace_regset, reg);
	}

	string dirName = KnobOutputDir.Value();

	if (dirName.empty())
	{
		cerr << "No output directory provided!" << endl;
		return 0;
	}

	DIR *dir;
	const char *dir_name = dirName.c_str();
	if ((dir = opendir(dir_name)))
		closedir(dir);
	else
		mkdir(dir_name, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);

	// out = new std::ofstream(fileName.c_str());
	insn_trace = new std::ofstream((dirName + "/trace.insn").c_str());
	reg_entries = new std::ofstream((dirName + "/trace.reg").c_str());
	mem_entries = new std::ofstream((dirName + "/trace.mem").c_str());
	reg_struct_file = new std::ofstream((dirName + "/trace.struct").c_str());
	logfile = new std::ofstream((dirName + "/trace.log").c_str());

	// Register function to be called to instrument traces
	TRACE_AddInstrumentFunction(Trace, 0);
	
	// Register function to be called for every thread before it starts running
	PIN_AddThreadStartFunction(ThreadStart, 0);
	
	// Register function to be called when the application exits
	PIN_AddFiniFunction(Fini, 0);

	INS_AddInstrumentFunction(Instruction, 0);

	cerr <<  "===============================================" << endl;
	cerr <<  "This application is instrumented by peekaboo" << endl;
	cerr << "Results are stored in directory " << KnobOutputDir.Value() << endl;
	cerr <<  "===============================================" << endl;
	cerr << "Recording " << REGSET_PopCount(trace_regset) << " registers..." << endl;
	cerr << REGSET_StringList(trace_regset) << endl;
	cerr <<  "===============================================" << endl;

	// create the register structure file and allocate enough memory for a single entry
	*reg_struct_file << trace_regs.size() << "," << sizeof(PIN_REGISTER) << endl;
	for (REG reg : trace_regs)
	{
		*reg_struct_file << (int)reg << endl;
	}
	
	reg_struct = new PIN_REGISTER[trace_regs.size()];

	// Start the program, never returns
	PIN_StartProgram();
	
	return 0;
}
