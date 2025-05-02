#include "pin.H"
#include <iostream>
#include <unordered_set>
#include <fstream>

// Output file for logging instructions
std::ofstream logFile("mem_instructions.txt");
// Store routines that contain memory pointer registers
std::unordered_set<std::string> routinesWithMemPointerRegs;
REG bReg;
REG iReg;


// Function to check if an instruction uses base or index registers in memory operands
bool HasMemoryPointerRegs(INS ins) {
//    if (!INS_IsMemoryRead(ins) && !INS_IsMemoryWrite(ins)) {
 //       return false; // Skip instructions that don't involve memory access
  //  }
 //   UINT32 memOperands = INS_MemoryOperandCount(ins);
            //logFile << "mem operands: " << memOperands << " | ";
  //  for (UINT32 i = 0; i < memOperands; i++) {
  //      REG baseReg = INS_OperandMemoryBaseReg(ins, i);
  //      REG indexReg = INS_OperandMemoryIndexReg(ins, i);
  //          //logFile << "mem operands: " << REG_StringShort(baseReg) << ","<<REG_StringShort(indexReg);
  //      if ((baseReg != REG_INVALID() || indexReg != REG_INVALID())&&(baseReg != REG_RIP && baseReg != REG_RBP&& indexReg != REG_RIP && indexReg != REG_RBP)) {
  //         bReg=baseReg;iReg=indexReg;
  //         return true; // Found a memory instruction using base or index register
  //      }
  //  }

// Check ALL operands, including input registers
    UINT32 numOperands = INS_OperandCount(ins);
    for (UINT32 i = 0; i < numOperands; i++) {
        if (INS_OperandIsMemory(ins, i)) {
            REG baseReg = INS_OperandMemoryBaseReg(ins, i);
            REG indexReg = INS_OperandMemoryIndexReg(ins, i);

            if ((baseReg != REG_INVALID() || indexReg != REG_INVALID())&&(baseReg != REG_RIP && baseReg != REG_RBP && baseReg != REG_EBP 
            && baseReg != REG_RSP && indexReg != REG_RIP && indexReg != REG_RBP && indexReg != REG_RSP && indexReg != REG_EBP)) {
                bReg = baseReg;
                iReg = indexReg;
                return true;
            }
        }
    }
    // **SPECIAL CHECK FOR LEA (Load Effective Address)**
    if (INS_Opcode(ins) == XED_ICLASS_LEA) {
      UINT32 numOperands = INS_OperandCount(ins);
      for (UINT32 i = 0; i < numOperands; i++) {
        if (INS_OperandIsMemory(ins, i)) {
            REG baseReg = INS_OperandMemoryBaseReg(ins, i);
            REG indexReg = INS_OperandMemoryIndexReg(ins, i);
            if ((baseReg != REG_INVALID() || indexReg != REG_INVALID())&&(baseReg != REG_RIP && baseReg != REG_RBP &&  baseReg != REG_EBP
            && baseReg != REG_RSP && indexReg != REG_RIP && indexReg != REG_RBP && indexReg != REG_RSP && indexReg != REG_EBP)) {
              bReg = baseReg;
              iReg = indexReg;  
              return true;
            }
       }
     }
   }
    return false;
}

// Callback function to analyze instructions inside routines
VOID InstructionInstrumentation(INS ins, VOID* v) {
    if (HasMemoryPointerRegs(ins)) {
        RTN rtn = INS_Rtn(ins);
        if (RTN_Valid(rtn)) {
            std::string functionName = RTN_Name(rtn);
            routinesWithMemPointerRegs.insert(functionName);
        }
   }else{
    bReg = REG_INVALID();
    iReg = REG_INVALID();
   }
        logFile << "Instruction: " << INS_Disassemble(ins) << "\n";

        if (bReg != REG_INVALID()) {
            logFile << "  Base Register: " << REG_StringShort(bReg)<<"\n";
        }
        if (iReg != REG_INVALID()) {
            logFile << "  Index Register: " << REG_StringShort(iReg) << "\n";
        }
}

// Callback function to print routines at the end
VOID Fini(INT32 code, VOID* v) {
    std::cerr << "\nRoutines that use base/index registers for memory access:\n";
    for (const auto& routine : routinesWithMemPointerRegs) {
        std::cerr << routine << std::endl;
    }
    logFile.close();  // Close the log file
}

// PinTool main function
int main(int argc, char* argv[]) {
    PIN_InitSymbols();

    if (PIN_Init(argc, argv)) {
        std::cerr << "Pin initialization failed!" << std::endl;
        return 1;
    }
    // Hook instruction analysis
    INS_AddInstrumentFunction(InstructionInstrumentation, nullptr);
    
    // Register finalization function
    PIN_AddFiniFunction(Fini, nullptr);

    // Start execution under Pin
    PIN_StartProgram();
    
    return 0;
}
