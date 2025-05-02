#include "pin.H"
#include <iostream>
#include <string>


// Function to check if an instruction belongs to arithmetic or logic operations
bool IsArithmeticLogicInstruction(INS ins) {
    xed_category_enum_t category = static_cast<xed_category_enum_t>(INS_Category(ins));
    return category == XED_CATEGORY_LOGICAL ||
    category == XED_CATEGORY_BITBYTE ||
    category == XED_CATEGORY_ROTATE ||
    category == XED_CATEGORY_SHIFT ||
    category == XED_CATEGORY_BMI1 ||
    category == XED_CATEGORY_BMI2 ||
    category == XED_CATEGORY_X87_ALU ||
    category == XED_CATEGORY_FMA4 ||
    category == XED_CATEGORY_FP16 ||
    category == XED_CATEGORY_VFMA||
    category ==XED_CATEGORY_BINARY||
    category ==XED_CATEGORY_SSE||
    category ==XED_CATEGORY_LOGICAL_FP||
    category ==XED_CATEGORY_CONVERT||
    category ==XED_CATEGORY_SETCC;
//CONVERT,SETCC
}


bool isValidInst(INS ins) {
/**
 * IMPORTANT: This is to make sure fault injections are done at the .text
 * of the compiled code, instead of at libraries or .init/.fini sections
 */
  if (!RTN_Valid(INS_Rtn(ins))) { // some library instructions do not have rtn !?
    LOG("Invalid RTN " + INS_Disassemble(ins) + "\n");
    return false;
  }

  if (!IMG_IsMainExecutable(SEC_Img(RTN_Sec(INS_Rtn(ins))))) {
//    LOG("Libraries " + IMG_Name(SEC_Img(RTN_Sec(INS_Rtn(ins)))) + "\n");
    return false;
  }
  if (SEC_Name(RTN_Sec(INS_Rtn(ins))) != ".text") {
  // LOG("Section: " + SEC_Name(RTN_Sec(INS_Rtn(ins))) + "\n");
   return false;
  }
  std::string rtnname = RTN_Name(INS_Rtn(ins));
  if (rtnname.find("__libc") == 0 || rtnname.find("_start") == 0 ||
      rtnname.find("call_gmon_start") == 0 || rtnname.find("frame_dummy") == 0 ||
      rtnname.find("__do_global") == 0 || rtnname.find("__stat") == 0) {
    return false;
  }
  LOG("Exe " + RTN_Name(INS_Rtn(ins)) + "\n");

//        REG reg = INS_RegW(ins, 0);
 //       if(!REG_valid(reg))
 //              return false;

  return true;
}
// Analysis routine: called for every instruction
VOID InstructionAnalysis(ADDRINT ip,INS ins,UINT32 numW, CONTEXT *ctxt) {
    // Disassemble the instruction
//    if(!REG_valid(reg))return;
    std::string disassembled = INS_Disassemble(ins);
//    reg = REG_FullRegName(reg);
//    ADDRINT regValue = PIN_GetContextReg(ctxt, reg); // Get the curre>
    // Get the instruction category
    //xed_category_enum_t category = static_cast<xed_category_enum_t>(INS_Category(ins));
    UINT32 i=0;
    std::string categoryName = CATEGORY_StringShort(INS_Category(ins));
    //REG reg = INS_RegW(ins, randW); // Get the corresponding reg
    for(i =0;i<numW;i++){
         REG reg = INS_RegW(ins, i); // Get the corresponding reg
         if (!REG_valid(reg)){continue;}
         std::cout <<"Register: " << REG_StringShort(reg) << ", ";
    }
    std::cout << std::endl;
    // Print the instruction and its category
    std::cout << "IP: 0x" << std::hex << ip <<  " | Instruction: " << disassembled << " | Category: " << categoryName << std::endl;
}

// Entry point: Initialize and add the instrumentation routine
VOID InstructionInstrumentation(INS ins, VOID *v) { 
    // Add a call to InstructionAnalysis for each instruction
    if(!isValidInst(ins))return;

    if (!(IsArithmeticLogicInstruction(ins)))return; // Select a r>) {               return; // Skip non-arithmetic/logic instructions
    srand(time(0)); // Initialize random number generator
    int numW = INS_MaxNumWRegs(ins); // Get the number of write registers for the instruction
//    if (numW == 0) return; // Skip if no write registers are available

  //  int randW = rand() % numW; // Select a random write register
//    int i=0;
//    REG reg = INS_RegW(ins, randW); // Get the corresponding register
    //  while(numW>=i && numW > 1 && (REG_is_any_app_flags(reg)||(reg == REG_RFLAGS || reg == REG_FLAGS || reg == REG_EFLAGS||reg == REG_STACK_PTR))){
  //         randW = (randW + 1) % numW;
   //        i++;
    //       if(numW > 1 && REG_valid(INS_RegW(ins, randW)))
     //          reg = INS_RegW(ins, randW);
    //  }
       // else
           // reg = INS_RegW(ins, 0);
   // if (!REG_valid(reg)){//|| (REG_is_any_app_flags(reg)||(reg == REG_RFLAGS || reg == REG_FLAGS || reg == REG_EFLAGS || reg == REG_STACK_PTR))){
    //        LOG("!!!!!!!!!REGNOTVALID: inst " + INS_Disassemble(ins) + "!!!!!!!!!!!!!\n");
     //       return;
     // }
    INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)InstructionAnalysis,
        IARG_INST_PTR, 
        IARG_PTR, ins,
        IARG_UINT32, numW, // Pass the register index
      //  IARG_UINT32, randW, // Pass the register index
       // IARG_UINT32, reg, // Pass the register identifier
        IARG_CONTEXT, // Pass the full execution context
        IARG_END);

  
}

// Finalization routine
VOID Fini(INT32 code, VOID *v) {
    std::cout << "Done!" << std::endl;
}

// Main function
int main(int argc, char *argv[]) {
    // Initialize PIN
    if (PIN_Init(argc, argv)) {
        std::cerr << "PIN Initialization failed!" << std::endl;
        return -1;
    }

    // Add instrumentation function
    INS_AddInstrumentFunction(InstructionInstrumentation, 0);

    // Register the finalization routine
    PIN_AddFiniFunction(Fini, 0);

    // Start the program
    PIN_StartProgram();

    return 0;
}
