#include "pin.H"
#include <iostream>
#include <fstream>
#include <vector>

/* ================================================================== */
// Global variables 
/* ================================================================== */

UINT64 insCount = 0;        //number of dynamically executed instructions
UINT64 bblCount = 0;        //number of dynamically executed basic blocks
UINT64 threadCount = 0;     //total number of threads, including main thread


std::ostream * out = &cerr;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,  "pintool",
    "o", "", "specify file name for peekaboo output");

KNOB<BOOL>   KnobCount(KNOB_MODE_WRITEONCE,  "pintool",
    "count", "1", "count instructions, basic blocks and threads in the application");

/* ===================================================================== */
// Data Structures
/* ===================================================================== */

REGSET fullRegSet;
REGSET traceRegSet;

vector<REG> traceRegs;

struct InsnRecord
{
    ADDRINT pc;

};

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
 * @param[in]   numInstInBbl    number of instructions in the basic block
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

/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

/*!
 * Insert call to the CountBbl() analysis routine before every basic block 
 * of the trace.
 * This function is called every time a new trace is encountered.
 * @param[in]   trace    trace to be instrumented
 * @param[in]   v        value specified by the tool in the TRACE_AddInstrumentFunction
 *                       function call
 */

VOID Instruction(INS ins, VOID *v)
{
    REGSET regset;
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)PrintRegVals, IARG_CONST_CONTEXT, IARG_END);
}

VOID Trace(TRACE trace, VOID *v)
{
    // Visit every basic block in the trace
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        // Insert a call to CountBbl() before every basic bloc, passing the number of instructions
        BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)CountBbl, IARG_UINT32, BBL_NumIns(bbl), IARG_END);
    }
}

/*!
 * Increase counter of threads in the application.
 * This function is called for every thread created by the application when it is
 * about to start running (including the root thread).
 * @param[in]   threadIndex     ID assigned by PIN to the new thread
 * @param[in]   ctxt            initial register state for the new thread
 * @param[in]   flags           thread creation flags (OS specific)
 * @param[in]   v               value specified by the tool in the 
 *                              PIN_AddThreadStartFunction function call
 */
VOID ThreadStart(THREADID threadIndex, CONTEXT *ctxt, INT32 flags, VOID *v)
{
    threadCount++;
}

/*!
 * Print out analysis results.
 * This function is called when the application exits.
 * @param[in]   code            exit code of the application
 * @param[in]   v               value specified by the tool in the 
 *                              PIN_AddFiniFunction function call
 */
VOID Fini(INT32 code, VOID *v)
{
    *out <<  "===============================================" << endl;
    *out <<  "peekaboo analysis results: " << endl;
    *out <<  "Number of instructions: " << insCount  << endl;
    *out <<  "Number of basic blocks: " << bblCount  << endl;
    *out <<  "Number of threads: " << threadCount  << endl;
    *out <<  "===============================================" << endl;
}

/*!
 * The main procedure of the tool.
 * This function is called when the application image is loaded but not yet started.
 * @param[in]   argc            total number of elements in the argv array
 * @param[in]   argv            array of command line arguments, 
 *                              including pin -t <toolname> -- ...
 */
int main(int argc, char *argv[])
{
    // Initialize PIN library. Print help message if -h(elp) is specified
    // in the command line or the command line is invalid 
    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }
    
    // Get the full reg set for our architecture...
    REGSET_AddAll(fullRegSet);
    // initialize the registers we will be dumping for our trace
    for (int reg = (int)REG_GR_BASE; reg <= (int)REG_GR_LAST; ++reg) traceRegs.push_back((REG)reg);
    for (int reg = (int)REG_ST_BASE; reg <= (int)REG_ST_LAST; ++reg) traceRegs.push_back((REG)reg);
    for (int reg = (int)REG_XMM_BASE; reg <= (int)REG_LastSupportedXmm(); ++reg) traceRegs.push_back((REG)reg);
    // for eflags and eip, we'll upcast it to the full name, so for x64, it'll be rip and x32, eip.
    traceRegs.push_back(REG_FullRegName(REG_EFLAGS));
    traceRegs.push_back(REG_FullRegName(REG_EIP));
    traceRegs.push_back(REG_FullRegName(REG_FPSW));

    for (REG reg : traceRegs)
    {
	    REGSET_Insert(traceRegSet, reg);
    }

    string fileName = KnobOutputFile.Value();

    if (!fileName.empty()) { out = new std::ofstream(fileName.c_str());}

    // INS_AddInstrumentFunction(Instruction, 0);

    if (KnobCount)
    {
        // Register function to be called to instrument traces
        TRACE_AddInstrumentFunction(Trace, 0);

        // Register function to be called for every thread before it starts running
        PIN_AddThreadStartFunction(ThreadStart, 0);

        // Register function to be called when the application exits
        PIN_AddFiniFunction(Fini, 0);
    }
    
    cerr <<  "===============================================" << endl;
    cerr <<  "This application is instrumented by peekaboo" << endl;
    if (!KnobOutputFile.Value().empty()) 
    {
        cerr << "See file " << KnobOutputFile.Value() << " for analysis results" << endl;
    }
    cerr <<  "===============================================" << endl;
    cerr << "Recording " << REGSET_PopCount(traceRegSet) << " registers..." << endl;
    cerr << REGSET_StringList(traceRegSet) << endl;
    cerr <<  "===============================================" << endl;
    REG reg;
    REGSET myregset;
    REGSET_AddAll(myregset);
    while ((reg = REGSET_PopNext(myregset)))
    {
        cerr << reg << ":" << REG_StringShort(reg) << endl;
    }
    cerr << REG_EIP << ":" << REG_FullRegName(REG_EIP) << endl;

    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}
