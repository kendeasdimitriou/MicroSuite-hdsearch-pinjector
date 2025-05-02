#include "pin.H"
#include <iostream>
#include <cstdlib>
#include <random>//
#include <chrono>//
#include <ctime>
#include <set>
#include <string>
#include "xed-category-enum.h"
#include <unordered_set>
#include <fstream> // For file operations
std::ofstream injection_commands;
std::ofstream OutFile;
std::ofstream instruction_log("instruction_log.txt"); // Create and open the file
#define LOGOUT std::cout


// Συνάρτηση για να ελέγξεις αν η τιμή είναι διεύθυνση μνήμης
bool IsMemoryAddress(ADDRINT value) {
    // Χρησιμοποιούμε την PIN_CheckReadAccess για να δούμε αν η διεύθυνση είναι προσβάσιμη
    if (PIN_CheckReadAccess((void *)value) ||	PIN_CheckWriteAccess((void *)value)|| value>0xffffffff) {
        return true; // Αν η διεύθυνση είναι προσβάσιμη, θεωρείται pointer
    }
    return false; // Αλλιώς δεν είναι pointer
}

std::set<std::string> blacklisted;
        
/**
 * Συνάρτηση που διαβάζει από το αρχείο "filename" (ένα όνομα routine ανά γραμμή)
 * και προσθέτει κάθε routine στο global set gDangerousRoutines.
 */
void loadBlacklistedRoutines(const std::string &filename) {
    std::ifstream infile(filename.c_str());
    if (!infile.is_open()) {
        std::cerr << "Error opening file: " << filename << std::endl;
        return;
    }
    
    std::string line;
    while (std::getline(infile, line)) {
        // Αφαιρούμε τυχόν περιττά whitespace (προαιρετικά)
        std::istringstream iss(line);
        std::string routine;
        if (!(iss >> routine)) {
            continue; // παραλείπουμε κενές γραμμές
        }
        blacklisted.insert(routine);
    }
    infile.close();
}

    int generateRandomNumber() {
    // Seed with a combination of steady clock and current time for better randomness
    static std::mt19937 generator(
        std::chrono::steady_clock::now().time_since_epoch().count()
    );

    // Define the range of random numbers (e.g., 1 to 100)
    std::uniform_int_distribution<int> distribution(1, 100);

    return distribution(generator);
}

enum PrecisionType {
    SinglePrecision,
    DoublePrecision
};

bool isValidInst(INS ins) {

 // IMPORTANT: This is to make sure fault injections are done at the .text
 // of the compiled code, instead of at libraries or .init/.fini sections
 
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
 // if (rtnname.find("__libc") == 0 || rtnname.find("_start") == 0 ||
 //     rtnname.find("call_gmon_start") == 0 || rtnname.find("frame_dummy") == 0 ||
 //     rtnname.find("__do_global") == 0 || rtnname.find("__stat") == 0) {
 //   return false;
 // }

    // Εάν το όνομα της routine βρίσκεται στη λίστα των αποκλεισμένων, επιστρέφουμε false.
    if (blacklisted.find(rtnname) != blacklisted.end() || rtnname == ".text") {
        return false;
 //   }
  LOG("Exe " + RTN_Name(INS_Rtn(ins)) + "\n");

return true;
}


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
bool isDoublePrecision(INS ins){
    std::string mnemonic = INS_Mnemonic(ins);
    return mnemonic == "ADDSD" ||
           mnemonic == "SUBSD" ||
           mnemonic == "MULSD" ||
           mnemonic == "DIVSD" ||
           mnemonic == "SQRTSD" ;
}
bool isSinglePrecision(INS ins) {
    std::string mnemonic = INS_Mnemonic(ins);
    return mnemonic == "ADDSS" ||
           mnemonic == "SUBSS" ||
           mnemonic == "MULSS" ||
           mnemonic == "DIVSS" ||
           mnemonic == "SQRTSS";
}
bool isVectorDoublePrecision(INS ins) {
    std::string mnemonic = INS_Mnemonic(ins);
    return mnemonic == "ADDPD" ||
           mnemonic == "SUBPD" ||
           mnemonic == "MULPD" ||
           mnemonic == "DIVPD" ||
           mnemonic == "SQRTPD";
}
bool isVectorSinglePrecision(INS ins) {
    std::string mnemonic = INS_Mnemonic(ins);
    return mnemonic == "ADDPS" ||
           mnemonic == "SUBPS" ||
           mnemonic == "MULPS" ||
           mnemonic == "DIVPS" ||
           mnemonic == "SQRTPS";
}
/*
bool isMixedPrecision(INS ins) {
    std::string mnemonic = INS_Mnemonic(ins);
    return mnemonic == "ADDSUBPD" ||
           mnemonic == "ADDSUBPS";
}
*/


VOID FI_InjectFault_Mem(VOID * ip, VOID *memp, UINT32 size)
{
//              if(size == 4) {
//                      PRINT_MESSAGE(4, ("Executing %p, memory %p, value %d, in hex %p\n",
//                      ip, memp, * ((int*)memp), (VOID*)(*((int*)memp))));
//              }
                injection_commands << "Injection at MEMORY instruction: 0x" << std::hex << ip
                  << ", Memory: " << std::hex << memp
                  << ", Original Value: 0x" << std::hex << (*((int*)memp));// << std::endl;
                UINT8* temp_p = (UINT8*) memp;
               // srand(seed1);
                UINT32 inject_bit = generateRandomNumber() % (size * 8);// bits in one byte);

                UINT32 byte_num = inject_bit / 8;
                UINT32 offset_num = inject_bit % 8;

                *(temp_p + byte_num) = *(temp_p + byte_num) ^ (1U << offset_num);
                //ADDRINT injectedValue = (*((int*)memp)));
//              if(size == 4) {
//                      PRINT_MESSAGE(4, ("Executing %p, memory %p, value %d, in hex %p\n", ip, memp, * ((int*)memp), (VOID*)(*((int*)memp))));
//              }

        injection_commands
           << ", Mask: 0x" << std::hex << (1U << offset_num)
           << ", Injected Value: 0x" << std::hex << (*((int*)memp))
           << std::endl;



}//

/*
// FI: set the XMM[0-7] context register
VOID FI_XmmFloatPointFraction (ADDRINT ip, UINT32 regIndex, REG reg, CONTEXT *ctxt,PrecisionType precision)
{
        srand(time(0)); // Initialize random number generator
        //choose XMM[i] to inject
//      string reg_name = REG_StringShort(reg);
        UINT32 i =  REG_StringShort(reg)[ REG_StringShort(reg).size() - 1] - '0';

        CHAR fpContextSpace[FPSTATE_SIZE];
        FPSTATE *fpContext = reinterpret_cast<FPSTATE *>(fpContextSpace);

        PIN_GetContextFPState(ctxt, fpContext);

        UINT32 bound_bit = (precision == DoublePrecision) ? 52 : 23;

        UINT32 inject_bit = (rand() % bound_bit);//want to inject fraction part

   // JIESHENG: this is not a right change from the hardware perspective, but it
  // is to improve the activated faults.
  // xmm is used for double, so only the lower 64 bits are used
                uint64_t xmmValue = fpContext->fxsave_legacy._xmms[i]._vec64[0];
        //      PRINT_MESSAGE(3, ("EXECUTING: Reg name %s Low value %p\n", REG_StringShort(reg).c_str(),
//                      (VOID*)fpContext->fxsave_legacy._xmms[i]._vec64[0]));
                ADDRINT mask = 1UL << inject_bit;
                fpContext->fxsave_legacy._xmms[i]._vec64[0] ^= mask;

        //      PRINT_MESSAGE(3, ("EXECUTING: Changed Reg name %s Low value %p\n", REG_StringShort(reg).c_str(),
        //              (VOID*)fpContext->fxsave_legacy._xmms[i]._vec64[0]));
                uint64_t injectedValue = fpContext->fxsave_legacy._xmms[i]._vec64[0];

        PIN_SetContextFPState(ctxt, fpContext);

        injection_commands << "Injection at instruction: 0x" << std::hex << ip
           << ", Register: " << REG_StringShort(reg)
           << ", Original Value: 0x" << std::hex << xmmValue
           << ", Mask: 0x" << std::hex << mask
           << ", Injected Value: 0x" << std::hex << injectedValue
           << std::endl;

        PIN_ExecuteAt(ctxt);
}
*/


// FI: set the XMM[0-7] context register
VOID FI_XmmFloatPointFraction (ADDRINT ip, UINT32 regIndex, REG reg, UINT32 isvector, CONTEXT *ctxt,PrecisionType precision)
{
   //     srand(time(0)); // Initialize random number generator
        //choose XMM[i] to inject
//      string reg_name = REG_StringShort(reg);
        UINT32 i =  REG_StringShort(reg)[ REG_StringShort(reg).size() - 1] - '0';
        //srand(seed1);
        CHAR fpContextSpace[FPSTATE_SIZE];
        FPSTATE *fpContext = reinterpret_cast<FPSTATE *>(fpContextSpace);

        PIN_GetContextFPState(ctxt, fpContext);

        UINT32 bound_bit = (precision == DoublePrecision) ? 52 : 23;

        UINT32 inject_bit = (generateRandomNumber() % bound_bit);//want to inject fraction part
        uint64_t xmmValue;
        uint64_t injectedValue;
        UINT32 j;
        ADDRINT mask;
   // JIESHENG: this is not a right change from the hardware perspective, but it
  // is to improve the activated faults.
  // xmm is used for double, so only the lower 64 bits are used
       if(precision ==  DoublePrecision){
                if(isvector == 1){j = rand()%2;}
                else{j=0;}

                xmmValue = fpContext->fxsave_legacy._xmms[i]._vec64[j];
        //      PRINT_MESSAGE(3, ("EXECUTING: Reg name %s Low value %p\n", REG_StringShort(reg).c_str(),
//                      (VOID*)fpContext->fxsave_legacy._xmms[i]._vec64[0]));
                mask = 1UL << inject_bit;
                fpContext->fxsave_legacy._xmms[i]._vec64[j] ^= mask;

        //      PRINT_MESSAGE(3, ("EXECUTING: Changed Reg name %s Low value %p\n", REG_StringShort(reg).c_str(),
        //              (VOID*)fpContext->fxsave_legacy._xmms[i]._vec64[0]));
                injectedValue = fpContext->fxsave_legacy._xmms[i]._vec64[0];
        } else{
                if(isvector == 1){j = generateRandomNumber()%5;}
                else{j=0;}
                xmmValue = fpContext->fxsave_legacy._xmms[i]._vec32[j];
        //      PRINT_MESSAGE(3, ("EXECUTING: Reg name %s Low value %p\n", REG_StringShort(reg).c_str(),
//                      (VOID*)fpContext->fxsave_legacy._xmms[i]._vec64[0]));
                mask = 1UL << inject_bit;
                fpContext->fxsave_legacy._xmms[i]._vec32[j] ^= mask;

        //      PRINT_MESSAGE(3, ("EXECUTING: Changed Reg name %s Low value %p\n", REG_StringShort(reg).c_str(),
        //              (VOID*)fpContext->fxsave_legacy._xmms[i]._vec64[0]));
                injectedValue = fpContext->fxsave_legacy._xmms[i]._vec32[0];


        }
        PIN_SetContextFPState(ctxt, fpContext);

        injection_commands << "Injection at instruction: 0x" << std::hex << ip
           << ", Register: " << REG_StringShort(reg) << ", Vector: " << j
           << ", Original Value: 0x" << std::hex << xmmValue
           << ", Mask: 0x" << std::hex << mask
           << ", Injected Value: 0x" << std::hex << injectedValue
           << std::endl;

        PIN_ExecuteAt(ctxt);
}

// Injects a single bit flip into the specified register
VOID InjectBitFlip(ADDRINT ip, UINT32 regIndex, REG reg, CONTEXT *ctxt, ADDRINT value) {
    if(REG_valid(reg)){
//    srand(seed1); // Initialize random number generator
    reg = REG_FullRegName(reg);
    ADDRINT regValue = PIN_GetContextReg(ctxt, reg); // Get the current value of the register
    if(IsMemoryAddress(regValue)){return;}
    UINT32 injectBit = rand() % (sizeof(UINT32) * 8); // MOST SDCs FOUND ON LEAST SIGNIFICANT BITS(UINT32)
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
 }//else if (IsMemoryAddress(value)) {
   //     std::cout << "reg is pointer : "
    //              << REG_StringShort(reg) << " (value: 0x" << std::hex << value << ")" << std::endl;
   //     return; // Αν είναι pointer, αποφεύγουμε το fault injection
   // }
}

// Instruments write registers of each instruction for fault injection
VOID InstructionInstrumentation(INS ins, VOID *v) {
    // Check if the instruction belongs to arithmetic or logic
   // srand(seed2);

/////    int randomValue = generateRandomNumber() % 100 + 1;
    std::string categoryName = CATEGORY_StringShort(INS_Category(ins));

       // injection_commands << randomValue << std::endl;

//    if (randomValue > 10) { // 10% chance (1-10 out of 100)
//        injection_commands << "90% case triggered!" << std::endl;
 //       return;
  //  }

    if (!isValidInst(ins))
        return;
    if (INS_Category(ins) == XED_CATEGORY_LOGICAL && INS_Mnemonic(ins) == "XOR") {
        return;
    }

    ADDRINT addr = INS_Address(ins);
    std::string disasm = INS_Disassemble(ins);
    RTN rtn = RTN_FindByAddress(addr);
    instruction_log << "Instruction at 0x" << std::hex << addr << ": " << disasm << " category: "<<categoryName<<",  routine: "<<  RTN_Name(rtn) <<  std::endl;
    //if (INS_IsCall(ins)) {///////////////////
    //ADDRINT targetAddress = INS_DirectControlFlowTargetAddress(ins);
   // RTN targetRtn = RTN_FindByAddress(targetAddress);
   // instruction_log <<"TARGET ROUTINE" <<RTN_Name(targetRtn)<<  std::endl;
   // }
    if (!(IsArithmeticLogicInstruction(ins))) // Select a r>) {
        return; // Skip non-arithmetic/logic instructions

    if (INS_IsMemoryWrite(ins)) {
        instruction_log <<"IP: 0x" << std::hex << INS_Address(ins)<<" |MEMORY Instrumented instruction: " << INS_Disassemble(ins)<< std::endl;
        INS_InsertCall(
      ins, IPOINT_BEFORE, (AFUNPTR)FI_InjectFault_Mem,
      IARG_ADDRINT, INS_Address(ins),
      IARG_MEMORYREAD_EA,
      IARG_MEMORYREAD_SIZE,
      IARG_END);
      return;
    }

  //  srand(seed3);
    int numW = INS_MaxNumWRegs(ins); // Get the number of write registers for the instruction
    if (numW == 0) return; // Skip if no write registers are available

    int randW = generateRandomNumber() % numW; // Select a random write register
    int i=0;
    REG reg = INS_RegW(ins, randW); // Get the corresponding register
      while(numW > i  && (REG_is_any_app_flags(reg)||(reg == REG_RFLAGS || reg == REG_FLAGS || reg == REG_EFLAGS
||reg == REG_STACK_PTR || reg == REG_RBP || reg == REG_EBP))){
           randW = (randW + 1) % numW;
           i++;
           if (REG_valid(INS_RegW(ins, randW)))
               reg = INS_RegW(ins, randW);
      }
/////////////////////////

//for (int i = 0; i < numW; ++i) {
 //   REG reg = INS_RegW(ins, i);
 //   instruction_log <<"IP: 0x" << std::hex << INS_Address(ins)<< " |Instrumented instruction: " << INS_Disassemble(ins) <<" |Register " << i << ": " << REG_StringShort(reg)
 //          << " | Valid: " << REG_valid(reg) << std::endl;
//}

////////////////////////

       // else
           // reg = INS_RegW(ins, 0);
    if (!REG_valid(reg) || (REG_is_any_app_flags(reg)||(reg == REG_RFLAGS || reg == REG_FLAGS || reg == REG_EFLAGS
|| reg == REG_STACK_PTR || reg == REG_RBP|| reg == REG_EBP))){
            LOG("!!!!!!!!!REGNOTVALID: inst " + INS_Disassemble(ins) + "!!!!!!!!!!!!!\n");
            return;
      }
    instruction_log<<REG_StringShort(reg)<<"\n";
    UINT32 isvector;
    // Insert a call to inject a fault into the selected write register
    if (REG_is_xmm(reg)) {
       if (isDoublePrecision(ins)) {
             isvector = 0;
             INS_InsertCall(
           ins, IPOINT_AFTER, (AFUNPTR)FI_XmmFloatPointFraction,
           IARG_INST_PTR, // Pass the instruction pointer
           IARG_UINT32, randW, // Pass the register index
           IARG_UINT32, reg, // Pass the register identifier
           IARG_UINT32, isvector, //is vector or not
           IARG_CONTEXT, // Pass the full execution context
           IARG_ADDRINT,DoublePrecision,
           IARG_END
           );
       }
       if (isSinglePrecision(ins)) {
             isvector = 0;
             INS_InsertCall(
           ins, IPOINT_AFTER, (AFUNPTR)FI_XmmFloatPointFraction,
           IARG_INST_PTR, // Pass the instruction pointer
           IARG_UINT32, randW, // Pass the register index
           IARG_UINT32, reg, // Pass the register identifier
           IARG_UINT32, isvector, //is vector or not
           IARG_CONTEXT, // Pass the full execution context
           IARG_ADDRINT,SinglePrecision,
           IARG_END
           );
       }
       if (isVectorDoublePrecision(ins)) {
             isvector = 1;
             INS_InsertCall(
           ins, IPOINT_AFTER, (AFUNPTR)FI_XmmFloatPointFraction,
           IARG_INST_PTR, // Pass the instruction pointer
           IARG_UINT32, randW, // Pass the register index
           IARG_UINT32, reg, // Pass the register identifier
           IARG_UINT32, isvector, //is vector or not
           IARG_CONTEXT, // Pass the full execution context
           IARG_ADDRINT,DoublePrecision,
           IARG_END
           );
       }
       if (isVectorSinglePrecision(ins)) {
             isvector = 1;
             INS_InsertCall(
           ins, IPOINT_AFTER, (AFUNPTR)FI_XmmFloatPointFraction,
           IARG_INST_PTR, // Pass the instruction pointer
           IARG_UINT32, randW, // Pass the register index
           IARG_UINT32, reg, // Pass the register identifier
           IARG_UINT32, isvector, //is vector or not
           IARG_CONTEXT, // Pass the full execution context
           IARG_ADDRINT,SinglePrecision,
           IARG_END
           );
       }
    }else{
    INS_InsertCall(
        ins, IPOINT_AFTER, (AFUNPTR)InjectBitFlip,
        IARG_INST_PTR, // Pass the instruction pointer
        IARG_UINT32, randW, // Pass the register index
        IARG_UINT32, reg, // Pass the register identifier
        IARG_CONTEXT, // Pass the full execution context
        IARG_REG_VALUE, reg,  // Τρέχουσα τιμή του καταχωρητή
        IARG_END
    );
   }
}

// Function to execute when the program ends
VOID Fini(INT32 code, VOID *v) {
    LOGOUT << "Finished injection tool!" << std::endl; // Indicate tool termination
}

int main(int argc, char *argv[]) {
//    srand(time(0));
    PIN_InitSymbols(); // Initialize Pin's symbol manager

    if (PIN_Init(argc, argv)) { // Initialize Pin with the given arguments
        std::cerr << "This Pintool does fault injection!" << std::endl;
        return 1; // Exit if initialization fails
    }
    loadBlacklistedRoutines("blacklisted_routines.txt");
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
