#include "pin.H"
#include <iostream>
#include <cstdlib>
#include <random>//
#include <chrono>//
#include <ctime>
#include <mutex>
#include <set>
#include <string>
#include "xed-category-enum.h"
#include <unordered_set>
#include <fstream> // For file operations
std::ofstream injection_commands;
std::ofstream OutFile;
std::ofstream instruction_log("instruction_log.txt"); // Create and open the file

#define LOGOUT std::cout
// Δηλώνουμε ένα PIN_LOCK για συγχρονισμό
PIN_LOCK fileLock;

// Global random generator και mutex για προστασία
std::mt19937 globalGenerator(std::chrono::steady_clock::now().time_since_epoch().count());
std::mutex generatorMutex;

int generateRandomNumber() {
    std::lock_guard<std::mutex> lock(generatorMutex);
    std::uniform_int_distribution<int> distribution(1, 100);
    return distribution(globalGenerator);
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
    category ==XED_CATEGORY_AVX||
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
           mnemonic == "SQRTPD"|| mnemonic == "VADDPD"  ||
           mnemonic == "VSUBPD"  ||
           mnemonic == "VMULPD"  ||
           mnemonic == "VDIVPD"  ||
           mnemonic == "VSQRTPD" ||
           mnemonic == "VADDSD" ||
           mnemonic == "VSUBSD" ||
           mnemonic == "VMULSD" ||
           mnemonic == "VDIVSD" ||
           mnemonic == "VSQRTSD"|| mnemonic == "SQRTPD" || mnemonic == "VSQRTPD" ||
           mnemonic == "MINPD"  || mnemonic == "VMINPD"  ||
           mnemonic == "MAXPD"  || mnemonic == "VMAXPD"  ||
        // Logical operations
           mnemonic == "ANDPD"  || mnemonic == "VANDPD"  ||
           mnemonic == "ORPD"   || mnemonic == "VORPD"   ||
           //mnemonic == "XORPD"  || mnemonic == "VXORPD"  ||
        // Comparison instructions (predicate-based cmppd variants)
           mnemonic == "CMPEQPD"  || mnemonic == "VCMPEQPD"  ||
           mnemonic == "CMPNEPD"  || mnemonic == "VCMPNEPD"  ||
           mnemonic == "CMPLTPD"  || mnemonic == "VCMPLTPD"  ||
           mnemonic == "CMPLEPD"  || mnemonic == "VCMPLEPD"  ||
           mnemonic == "CMPNLEPD" || mnemonic == "VCMPNLEPD" ||
           mnemonic == "CMPNLTPD" || mnemonic == "VCMPNLTPD" ||
        // Test operation: extract mask
           mnemonic == "MOVMSKPD" || mnemonic == "VMOVMSKPD";
}
bool isVectorSinglePrecision(INS ins) {
    std::string mnemonic = INS_Mnemonic(ins);
    return  mnemonic == "ADDPS"  || mnemonic == "VADDPS"  ||
           mnemonic == "SUBPS"  || mnemonic == "VSUBPS"  ||
           mnemonic == "MULPS"  || mnemonic == "VMULPS"  ||
           mnemonic == "DIVPS"  || mnemonic == "VDIVPS"  ||
           mnemonic == "SQRTPS" || mnemonic == "VSQRTPS" ||
           mnemonic == "MINPS"  || mnemonic == "VMINPS"  ||
           mnemonic == "MAXPS"  || mnemonic == "VMAXPS"  ||
        // Logical operations
           mnemonic == "ANDPS"  || mnemonic == "VANDPS"  ||
           mnemonic == "ORPS"   || mnemonic == "VORPS"   ||
           //mnemonic == "XORPS"  || mnemonic == "VXORPS"  ||
        // Comparison instructions (predicate-based cmpps variants)
           mnemonic == "CMPEQPS"  || mnemonic == "VCMPEQPS"  ||
           mnemonic == "CMPNEPS"  || mnemonic == "VCMPNEPS"  ||
           mnemonic == "CMPLTPS"  || mnemonic == "VCMPLTPS"  ||
           mnemonic == "CMPLEPS"  || mnemonic == "VCMPLEPS"  ||
           mnemonic == "CMPNLEPS" || mnemonic == "VCMPNLEPS" ||
           mnemonic == "CMPNLTPS" || mnemonic == "VCMPNLTPS" ||
        // Test operation: extract mask
           mnemonic == "MOVMSKPS" || mnemonic == "VMOVMSKPS"||mnemonic == "VADDSS" ||
           mnemonic == "VSUBSS" ||
           mnemonic == "VMULSS" ||
           mnemonic == "VDIVSS" ||
           mnemonic == "VSQRTSS";
}

//οταν χρησημοποιειθει βαλε pinlock
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
//std::atomic<int> counter(0);
//std::atomic<int> counter2(0);
int counter=0;
int counter2=0;
// FI: set the XMM[0-7] context register
VOID FI_XmmFloatPointFraction (ADDRINT ip, UINT32 regIndex, REG reg, UINT32 isvector, CONTEXT *ctxt,PrecisionType precision)
{
   //     srand(time(0)); // Initialize random number generator
        //choose XMM[i] to inject
//      string reg_name = REG_StringShort(reg);

        // Κάθε νήμα αποκτά το lock πριν από την εγγραφή στο αρχείο
        //PIN_GetLock(&fileLock, PIN_ThreadId());

        UINT32 i =  REG_StringShort(reg)[ REG_StringShort(reg).size() - 1] - '0';
        //srand(seed1);
        //if (i==6){return;}
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
        //counter++;
     PIN_GetLock(&fileLock, PIN_ThreadId());
        counter++;
        injection_commands << "Injection at instruction: 0x" << std::hex << ip
           << ", Register: " << REG_StringShort(reg) << ", Vector: " << j
           << ", Original Value: 0x" << std::hex << xmmValue
           << ", Mask: 0x" << std::hex << mask
           << ", Injected Value: 0x" << std::hex << injectedValue
           << " counter= "<< counter <<" counter2= "<< counter2 <<std::endl;

        // Απελευθερώνουμε το lock πριν συνεχίσουμε την εκτέλεση
     PIN_ReleaseLock(&fileLock);
        PIN_ExecuteAt(ctxt);
}

//std::atomic<bool> inject(false);
bool inject=false;
// Instruments write registers of each instruction for fault injection
VOID InstructionInstrumentation(INS ins, VOID *v) {
    // Check if the instruction belongs to arithmetic or logic
   // srand(seed2);

/////    int randomValue = generateRandomNumber() % 100 + 1;
    // Αποκτούμε το lock για την εγγραφή στο αρχείο
   // PIN_GetLock(&fileLock, PIN_ThreadId());

    std::string categoryName = CATEGORY_StringShort(INS_Category(ins));
   PIN_GetLock(&fileLock, PIN_ThreadId());
       // injection_commands << randomValue << std::endl;

    RTN rtn = RTN_FindByAddress(INS_Address(ins));
    if (RTN_Valid(rtn)) {
        std::string routineName = RTN_Name(rtn);
        // Check if the instruction is inside one of the fault injection marker routines.
        if (routineName == "FaultInjectionBegin") {
            // Option: skip instrumentation for these routines,
            // or handle them in a special way.
            // PROBLEM: PROGRAM JUMPS AND end_fault_injection NEVER ACCESED
            //inject.store(true, std::memory_order_relaxed);////////////
            //PIN_GetLock(&fileLock, PIN_ThreadId());            
            inject=true;
        }
        else if(routineName == "FaultInjectionEnd"){
            ADDRINT addr1 = INS_Address(ins);
      PIN_GetLock(&fileLock, PIN_ThreadId());
            instruction_log << "Instruction at 0x" << std::hex << addr1 <<"   injection finished "<<std::endl;
      //PIN_ReleaseLock(&fileLock);
        //      inject.store(false, std::memory_order_relaxed);
inject=false;
        }
    }
//            instruction_log <<"   inject = "<<inject <<std::endl;
   // PIN_ReleaseLock(&fileLock);
    if(inject == false){PIN_ReleaseLock(&fileLock);return;}
   PIN_ReleaseLock(&fileLock);


    if (!isValidInst(ins))
        return;
  //  if (INS_Category(ins) == XED_CATEGORY_LOGICAL && INS_Mnemonic(ins) == "XOR") {
    //    return;
    //}

    ADDRINT addr = INS_Address(ins);
    //if(addr == 0x56205ca16810){return;}
    std::string disasm = INS_Disassemble(ins);
    RTN rtn1 = RTN_FindByAddress(addr);

    // Ξανακλειδώνουμε για την εγγραφή του log
    PIN_GetLock(&fileLock, PIN_ThreadId());

    instruction_log << "Instruction at 0x" << std::hex << addr << ": " << disasm << " category: "<<categoryName<<",  routine: "<<  RTN_Name(rtn1) <<  std::endl;

    PIN_ReleaseLock(&fileLock);

    //if (INS_IsCall(ins)) {///////////////////
    //ADDRINT targetAddress = INS_DirectControlFlowTargetAddress(ins);
   // RTN targetRtn = RTN_FindByAddress(targetAddress);
   // instruction_log <<"TARGET ROUTINE" <<RTN_Name(targetRtn)<<  std::endl;
   // }
    if (!(IsArithmeticLogicInstruction(ins))) // Select a r>) {
        return; // Skip non-arithmetic/logic instructions

//    if (INS_IsMemoryWrite(ins)) {
 //       instruction_log <<"IP: 0x" << std::hex << INS_Address(ins)<<" |MEMORY Instrumented instruction: " << INS_Disassemble(ins)<< std::endl;
 //       INS_InsertCall(
 //     ins, IPOINT_BEFORE, (AFUNPTR)FI_InjectFault_Mem,
  //    IARG_ADDRINT, INS_Address(ins),
  //    IARG_MEMORYREAD_EA,
  //    IARG_MEMORYREAD_SIZE,
  //    IARG_END);
  //    return;
   // }

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

    // Κλείδωμα για την εγγραφή του register στο log
    PIN_GetLock(&fileLock, PIN_ThreadId());

    instruction_log<<REG_StringShort(reg)<<"\n";

    PIN_ReleaseLock(&fileLock);

    UINT32 isvector;
    // Insert a call to inject a fault into the selected write register
    if (REG_is_xmm(reg)) {
//counter2++;
       if (isDoublePrecision(ins)) {
    PIN_GetLock(&fileLock, PIN_ThreadId());
             counter2++;
    PIN_ReleaseLock(&fileLock);
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
    PIN_GetLock(&fileLock, PIN_ThreadId());
             counter2++;
    PIN_ReleaseLock(&fileLock);
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
    PIN_GetLock(&fileLock, PIN_ThreadId());
           counter2++;
    PIN_ReleaseLock(&fileLock);
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
    PIN_GetLock(&fileLock, PIN_ThreadId());
           counter2++;
    PIN_ReleaseLock(&fileLock);
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
    }//else{
    //INS_InsertCall(
     ///   ins, IPOINT_AFTER, (AFUNPTR)InjectBitFlip,
      //  IARG_INST_PTR, // Pass the instruction pointer
      //  IARG_UINT32, randW, // Pass the register index
      //  IARG_UINT32, reg, // Pass the register identifier
       // IARG_CONTEXT, // Pass the full execution context
     //   IARG_REG_VALUE, reg,  // Τρέχουσα τιμή του καταχωρητή
      //  IARG_END
   // );
   //}
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


    // Αρχικοποίηση του lock
    PIN_InitLock(&fileLock);

   // loadBlacklistedRoutines("blacklisted_routines.txt");
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
