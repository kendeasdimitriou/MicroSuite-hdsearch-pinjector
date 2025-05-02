#include <unordered_map>
#include "pin.H"
#include <iostream>
#include <fstream>
#include "xed-interface.h"  // Include XED for opcode definitions
#include "xed-extension-enum.h"
#include <iomanip>
using namespace std;
std::ofstream traceFile;
std::unordered_map<ADDRINT, ADDRINT> loopStarts; // Maps loop start address to loop end address
int c=0,loop=0;
ADDRINT lastCmpAddr = 0;  // Address of the last executed comparison instruction
ADDRINT mainStartAddr = 0x401187;  // Start address of 'main' function
ADDRINT mainEndAddr = 0x4012cc;    // End address of 'main' function
// Track comparison instructions within 'main'              INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)BranchInstruction, IARG_INST_PTR, IARG_BOOL, TRUE, IARG_END);

//VOID TrackCmpInstruction(ADDRINT ip) {
//    if (ip >= mainStartAddr && ip <= mainEndAddr) {
//        lastCmpAddr = ip;  // Store the address of the last comparison instruction
//    }
//}
// Log branch information if it follows a comparison instruction and is within 'mainVOID BranchInstruction(ADDRINT ip,ADDRINT target, BOOL taken) {           // Check if the branch instruction is within 'main' and follows a>    if (ip >= mainStartAddr && ip <= mainEndAddr ) {  // Increased of>        if (taken) {                                                              // Start of a loop                                                    loop=1;                                                               traceFile << "Loop start at address: 0x" << std::hex << t>                          << ", looping back from: 0x" << std::hex <<>            loopStarts[ip] = target; // Record the start of the loop          } else if (loopStarts.find(target) != loopStarts.end()) {                 loop=0;                                                               // Loop exit condition met (not taken branch)                         traceFile << "Loop end at address: 0x" << std::hex << ip                            << ", exiting loop started at: 0x" << std::>        }else if(loop==0){                                                        traceFile << "Branch at address: 0x" << std::hex << ip                  << " - " << (c ? "Conditional" : "Unconditional")                     << " - " << (taken ? "Taken" : "Not Taken") << std::end>        }                                                              }                                                                    }'
VOID BranchInstruction(ADDRINT ip,ADDRINT target, BOOL taken) {
    // Check if the branch instruction is within 'main' and follows a comparison instruction
    if (ip >= mainStartAddr && ip <= mainEndAddr ) {  // Increased offset range to 50 bytes
       if (target < ip && loop ==0 ) { 
        if (taken) {
           loop++;
            // Start of a loop
            traceFile << "Loop start at address: 0x" << std::hex << target
                          << ", looping back from: 0x" << std::hex << ip << std::endl;
            loopStarts[ip] = target; // Record the start of the loop
        }
    
    }else if(target < ip){loop++;} 
     else if (target > ip && loop >= 1) {
           
         // Loop exit condition met (not taken branch)
            traceFile << "Loop end at address: 0x" << std::hex << ip
                          << ", exiting loop started at: 0x" << std::hex<< target << " and made "<<loop<<" iterations"<< std::endl;
            loop=0;
       }else if(loop == 0){
            traceFile << "Branch at address: 0x" << std::hex << ip 
              << " - " << (c ? "Conditional" : "Unconditional") 
              << " - " << (taken ? "Taken" : "Not Taken") << std::endl;
        }   
} 
}

// Track function calls within 'main'
VOID TrackFunctionCall(ADDRINT ip, ADDRINT target) {
    PIN_LockClient(); // Lock before using RTN_FindByAddress
    if (ip >= mainStartAddr && ip <= mainEndAddr) {
       // std::string funcName = RTN_FindNameByAddress(target);
        RTN rtn = RTN_FindByAddress(target);
        if (RTN_Valid(rtn)) {
       // if (!funcName.empty()) {
            traceFile << "Function call at 0x" << std::hex << ip
                      <<" to target address 0x" << std::hex << target << " -> " << RTN_Name(rtn) << std::endl;
       // }
        }else {
        traceFile << "Unknown function at address: 0x" << std::hex << target << std::endl;
    }
    }
    PIN_UnlockClient(); // Unlock after using RTN_FindByAddress
}

VOID TrackIndirectCall(ADDRINT ip, ADDRINT target) {
    PIN_LockClient(); // Lock before using RTN_FindByAddress
    if (ip >= mainStartAddr && ip <= mainEndAddr) {
        RTN rtn = RTN_FindByAddress(target);
        if (RTN_Valid(rtn)) {
       traceFile << "Indirect call at address: 0x" << std::hex << ip
                 << " to target address 0x" << std::hex << target << " -> " << RTN_Name(rtn) << std::endl;
   }
    }
    PIN_UnlockClient(); // Unlock after using RTN_FindByAddress
}

VOID TrackIndirectJump(ADDRINT ip, ADDRINT target) {
    PIN_LockClient(); // Κλείδωμα πριν τη χρήση του RTN_FindByAddress

    if (ip >= mainStartAddr && ip <= mainEndAddr) {
        RTN rtn = RTN_FindByAddress(target);
            if (RTN_Valid(rtn)) {
            traceFile << "Indirect jump at address: 0x" << std::hex << ip
                      << " to target address: 0x" << std::hex << target
                      << " ->  " << RTN_Name(rtn) << std::endl;
        }
    }

    PIN_UnlockClient(); // Ξεκλείδωμα μετά τη χρήση του RTN_FindByAddress
}


// Instrument instructions
VOID Instruction(INS ins, VOID *v) {
    // Check if the instruction is a comparison
    //if (INS_Opcode(ins) == XED_ICLASS_CMP) {
     //   INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)TrackCmpInstruction, IARG_INST_PTR, IARG_END);
   // }
    xed_iclass_enum_t opcode = (xed_iclass_enum_t)INS_Opcode(ins);
    // Check if the instruction is a conditional branch and has a fall-through path
    if (INS_IsBranch(ins) &&INS_IsDirectControlFlow(ins)) {
        if (opcode == XED_ICLASS_JZ   || opcode == XED_ICLASS_JNZ ||
    opcode == XED_ICLASS_JL   || opcode == XED_ICLASS_JLE ||
    opcode == XED_ICLASS_JS   || opcode == XED_ICLASS_JNS) {
        c=1;
        ADDRINT target = INS_DirectControlFlowTargetAddress(ins);
        INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)BranchInstruction, IARG_INST_PTR, IARG_ADDRINT, target, IARG_BOOL, TRUE, IARG_END);
        INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)BranchInstruction, IARG_INST_PTR, IARG_ADDRINT, target, IARG_BOOL, FALSE, IARG_END);
    } else {
         ADDRINT target = INS_DirectControlFlowTargetAddress(ins);
         c=0;
         INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)BranchInstruction, IARG_INST_PTR, IARG_ADDRINT, target,IARG_BOOL, TRUE, IARG_END);
    }
    }           

    // Check if the instruction is a call instruction
    if (INS_IsCall(ins) && INS_IsDirectControlFlow(ins)){
        ADDRINT target = INS_DirectControlFlowTargetAddress(ins);
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)TrackFunctionCall, IARG_INST_PTR, IARG_ADDRINT, target, IARG_END);
    }

    if (INS_IsCall(ins) && INS_IsIndirectControlFlow(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)TrackIndirectCall,
                       IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, IARG_END);
    }
    if (INS_IsBranch(ins) && INS_IsIndirectControlFlow(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)TrackIndirectJump,
                       IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, IARG_END);
    }
}
// Finalize the trace file when the program finishes execution
VOID Fini(INT32 code, VOID *v) {
    traceFile.close();
}
// Main function for the Pin tool
int main(int argc, char *argv[]) {
    PIN_InitSymbols();
    // Initialize Pin
    PIN_Init(argc, argv);
    // Open the output file
    traceFile.open("branch_trace.out");
    // Register the function to be called for every instruction
    INS_AddInstrumentFunction(Instruction, 0);
    
    // Register the function to be called when the program exits
    PIN_AddFiniFunction(Fini, 0);
    // Start the program execution
    PIN_StartProgram();
    return 0;
}
