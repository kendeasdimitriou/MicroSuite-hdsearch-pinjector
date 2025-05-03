#include "pin.H"
#include <iostream>
#include <cstdlib>
#include <ctime>
#include "xed-category-enum.h"
#include <fstream> // For file operations
#include <unordered_set>
#include <random>//
#include <chrono>//

using namespace std;
using namespace std::chrono;
#define LOGOUT std::cout
std::ofstream injection_commands;

KNOB<BOOL> KnobInjectMem(KNOB_MODE_WRITEONCE, "pintool", "inject_only_mem", "0", "Enable memory injection (1=yes, 0=no)");


/*
int generateRandomNumber() {
    // Seed with a combination of steady clock and current time for better randomness
    static std::mt19937 generator(
        std::chrono::steady_clock::now().time_since_epoch().count()
    );

    // Define the range of random numbers (e.g., 1 to 100)
    std::uniform_int_distribution<int> distribution(1, 100);

    return distribution(generator);
}
*/

int seed=15;
int generateRandomNumber(int seed1) {
    // Παράμετροι του LCG (Numerical Recipes)
    seed = (1664525 * seed1 + 1013904223) % 0xFFFFFFFF;

    // Περιορισμός στο διάστημα [1, 100]
    return 1 + (seed % 100);
}


/**
*Function from  https://github.com/DependableSystemsLab/pinfi/blob/master/utils.cpp#L4
*System routines injections guide program execution to segmentation faults
*SDC are undetectable and make program work like nothing happened
*/
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
    //LOG("Libraries " + IMG_Name(SEC_Img(RTN_Sec(INS_Rtn(ins)))) + "\n");
    return false;
  }
  if (SEC_Name(RTN_Sec(INS_Rtn(ins))) != ".text") {
    //LOG("Section: " + SEC_Name(RTN_Sec(INS_Rtn(ins))) + "\n");
    return false;
  }
  std::string rtnname = RTN_Name(INS_Rtn(ins));
  if (rtnname.find("__libc") == 0 || rtnname.find("_start") == 0 ||
      rtnname.find("call_gmon_start") == 0 || rtnname.find("frame_dummy") == 0 ||
      rtnname.find("__do_global") == 0 || rtnname.find("__stat") == 0) {
    return false;
  }
  LOG("Exe " + RTN_Name(INS_Rtn(ins)) + "\n");

return true;
}


// Function to check if an instruction belongs to arithmetic or logic operations(ALU)
// https://github.com/jingpu/pintools/blob/master/extras/xed2-ia32/include/xed-category-enum.h
bool IsArithmeticLogicInstruction(INS ins) {
    xed_category_enum_t category = static_cast<xed_category_enum_t>(INS_Category(ins));
    return category == XED_CATEGORY_LOGICAL || //and,or,xor
    category == XED_CATEGORY_BITBYTE || //byte oriented instr
    category == XED_CATEGORY_ROTATE ||
    category == XED_CATEGORY_SHIFT || //shl,shr
//    category == XED_CATEGORY_BMI1 || //Bit Manipulation Instruction
//    category == XED_CATEGORY_BMI2 ||
  //  category == XED_CATEGORY_X87_ALU || //ALU εντολές του x87 FPU
    //category == XED_CATEGORY_FMA4 || 
   // category == XED_CATEGORY_FP16 ||
   // category == XED_CATEGORY_VFMA||
    category ==XED_CATEGORY_BINARY|| //ADD,SYB,MUL
    category ==XED_CATEGORY_LZCNT;//ALU-based counting instructions (POPCNT, LZCNT)
   // category ==XED_CATEGORY_SSE||
 //   category ==XED_CATEGORY_LOGICAL_FP||
 //   category ==XED_CATEGORY_CONVERT||
  //  category ==XED_CATEGORY_SETCC;
//CONVERT,SETCC
}


VOID FI_InjectFault_Mem(VOID * ip, VOID *memp, UINT32 size)
{
        injection_commands << "Injection at MEMORY instruction: 0x" << std::hex << ip
        << ", Memory: " << std::hex << memp
        << ", Original Value: 0x" << std::hex << (*((int*)memp));// << std::endl;
        UINT8* temp_p = (UINT8*) memp;
        srand((unsigned)time(0));
        UINT32 inject_bit = generateRandomNumber(seed) % (size * 8/* bits in one byte*/);

        UINT32 byte_num = inject_bit / 8;
        UINT32 offset_num = inject_bit % 8;

        *(temp_p + byte_num) = *(temp_p + byte_num) ^ (1U << offset_num);


        injection_commands
           << ", Mask: 0x" << std::hex << (1U << offset_num)
           << ", Injected Value: 0x" << std::hex << (*((int*)memp))
           << std::endl;

}

// Injects a single bit flip into the specified register
VOID InjectBitFlip(ADDRINT ip, UINT32 regIndex, REG reg, CONTEXT *ctxt) {
    if(REG_valid(reg)){
    reg = REG_FullRegName(reg);
    ADDRINT regValue = PIN_GetContextReg(ctxt, reg); // Get the current value of the register
    UINT32 injectBit = generateRandomNumber(seed) % (sizeof(UINT32) * 8); // MOST SDCs FOUND ON LEAST SIGNIFICANT BITS(UINT32)
    ADDRINT mask = 1UL << injectBit; // Create a mask for the bit flip
    ADDRINT injectedValue = regValue ^ mask; // Apply the bit flip
    PIN_SetContextReg(ctxt, reg, injectedValue); // Update the register with the new value

    // Log the details of the injection// LOGOUT
    injection_commands << "Injection at instruction: 0x" << std::hex << ip
           << ", Register: " << REG_StringShort(reg)
           << ", Original Value: 0x" << std::hex << regValue
           << ", Mask: 0x" << std::hex << mask
           << ", Injected Value: 0x" << std::hex << injectedValue
           << std::endl;
    PIN_ExecuteAt(ctxt);
 }
}



// Instruments write registers of each instruction for fault injection
VOID InstructionInstrumentation(INS ins, VOID *v) {
// Check if the instruction belongs to arithmetic or logic
    if (!isValidInst(ins))
        return;
    if (!(IsArithmeticLogicInstruction(ins))) // Select a r>) {
        return; // Skip non-arithmetic/logic instructions
    if (INS_IsMemoryWrite(ins)) {
       INS_InsertCall(
      ins, IPOINT_BEFORE, (AFUNPTR)FI_InjectFault_Mem,
      IARG_ADDRINT, INS_Address(ins),
      IARG_MEMORYREAD_EA,
      IARG_MEMORYREAD_SIZE,
      IARG_END);
      return;
    }
    if (KnobInjectMem.Value()) { //if option is 1 inject only on memomry instructions
      return;
    }

    int numW = INS_MaxNumWRegs(ins); // Get the number of write registers for the instruction
    if (numW == 0) return; // Skip if no write registers are available

    int randW =generateRandomNumber(23) % numW; // Select a random write register
    int i=0;
    REG reg = INS_RegW(ins, randW); // Get the corresponding register
//There are Rflags,stack,flag write registers in some instructions that cant be injected or it will cause segmentation faults
      while(numW > i  && (REG_is_any_app_flags(reg)||(reg == REG_RFLAGS || reg == REG_FLAGS || reg == REG_EFLAGS
||reg == REG_STACK_PTR|| reg == REG_RBP || reg == REG_EBP))){
           randW = (randW + 1) % numW;
           i++;
           if (REG_valid(INS_RegW(ins, randW)))
               reg = INS_RegW(ins, randW);
      }

      if (!REG_valid(reg) || (REG_is_any_app_flags(reg)||(reg == REG_RFLAGS || reg == REG_FLAGS || reg == REG_EFLAGS || reg == REG_STACK_PTR))){
            LOG("!!!!!!!!!REGNOTVALID: inst " + INS_Disassemble(ins) + "!!!!!!!!!!!!!\n");
            return;
      }

    INS_InsertCall(
        ins, IPOINT_AFTER, (AFUNPTR)InjectBitFlip,
        IARG_INST_PTR, // Pass the instruction pointer
        IARG_UINT32, randW, // Pass the register index
        IARG_UINT32, reg, // Pass the register identifier
        IARG_CONTEXT, // Pass the full execution context
        IARG_END
    );
}



// Function to execute when the program ends
VOID Fini(INT32 code, VOID *v) {
    LOGOUT << "Finished injection tool!" << std::endl; // Indicate tool termination
}



int main(int argc, char *argv[]) { 
    PIN_InitSymbols(); // Initialize Pin's symbol manager

    if (PIN_Init(argc, argv)) { // Initialize Pin with the given arguments
        std::cerr << "This Pintool does fault injection!" << std::endl;
        return 1; // Exit if initialization fails
    }

    // Open the results file for writing
    injection_commands.open("injection_results.txt", std::ios::out | std::ios::trunc);
    if (!injection_commands.is_open()) {
        std::cerr << "Error opening results file!" << std::endl;
        return 1;
    }

    INS_AddInstrumentFunction(InstructionInstrumentation, 0); // Register the instrumentation function
    PIN_AddFiniFunction(Fini, 0); // Register the finalization function

    PIN_StartProgram(); // Start the target program execution
    return 0; // Should never reach here
}
