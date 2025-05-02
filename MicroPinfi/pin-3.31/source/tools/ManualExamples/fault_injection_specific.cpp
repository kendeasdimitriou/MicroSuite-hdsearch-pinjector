#include "pin.H"
#include <iostream>
#include <cstdlib>
#include <random>//
#include <chrono>//
#include <ctime>
#include <set>
#include <string>
#include <mutex>
#include "xed-category-enum.h"
#include <unordered_set>
#include <fstream> // For file operations
std::ofstream injection_commands;
std::ofstream OutFile;
//std::ofstream instruction_log("instruction_log.txt"); // Create and open the file
#define LOGOUT std::cout
PIN_LOCK globalLock;

// Global random generator και mutex για προστασία
/*
std::mt19937 globalGenerator(std::chrono::steady_clock::now().time_since_epoch().count());
std::mutex generatorMutex;

int generateRandomNumber() {
    std::lock_guard<std::mutex> lock(generatorMutex);
    std::uniform_int_distribution<int> distribution(1, 100);
    return distribution(globalGenerator);
}
*/
// Θα κληθεί μετά την εκτέλεση της FaultInjectionBegin                         VOID SetInjectTrue(THREADID tid) {                                                 ThreadData* tdata = static_cast<ThreadData*>(PIN_GetThreadData(tls_key, ti>    tdata->inject = true;
//}
////////////////////////////////////////////////////////////
// Κάθε νήμα έχει το δικό του generator, χωρίς global mutex

////////////////////////////////////////////////////////////

std::mt19937 globalGenerator(std::chrono::steady_clock::now().time_since_epoch().count());

int generateRandomNumber() {
    std::uniform_int_distribution<int> distribution(1, 100);
    return distribution(globalGenerator);
}

//////////////////////////////////////////////////////////

struct ThreadData {
    bool inject;
};

static TLS_KEY tls_key;

VOID ThreadStart(THREADID tid, CONTEXT* ctxt, INT32 flags, VOID* v) {
    ThreadData* data = new ThreadData();
    data->inject = false;
    PIN_SetThreadData(tls_key, data, tid);
}

VOID ThreadFini(THREADID tid, const CONTEXT* ctxt, INT32 code, VOID* v) {
    ThreadData* data = static_cast<ThreadData*>(PIN_GetThreadData(tls_key, tid));
    delete data;
}




// Analysis function που θέτει το flag σε true (εισαγωγή στο window)
// Θα κληθεί μετά την εκτέλεση της FaultInjectionBegin
VOID SetInjectTrue(THREADID tid) {
    ThreadData* tdata = static_cast<ThreadData*>(PIN_GetThreadData(tls_key, tid));
    tdata->inject = true;
}

// Analysis function που θέτει το flag σε false (έξοδος από το window)
// Θα κληθεί πριν την εκτέλεση της FaultInjectionEnd
VOID SetInjectFalse(THREADID tid) {
    ThreadData* tdata = static_cast<ThreadData*>(PIN_GetThreadData(tls_key, tid));
    tdata->inject = false;
}


// Routine instrumentation: Εντοπίζει τις routines που ορίζουν το window
VOID RoutineInstrumentation(RTN rtn, VOID *v) {
    std::string name = RTN_Name(rtn);
   // std::cout << "ROUTINE :" << RTN_Name(rtn) << std::endl; // Debug output
    if(name == "FaultInjectionBegin") {
    //std::cout << "Found FaultInjectionBegin" << std::endl; // Debug output
        RTN_Open(rtn);
        // Μετά την FaultInjectionBegin θέτουμε το flag σε true
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)SetInjectTrue,
                       IARG_THREAD_ID, IARG_END);
        RTN_Close(rtn);
    }
    else if(name == "FaultInjectionEnd") {
   // std::cout << "Found FaultInjectionEnd" << std::endl; // Debug output
        RTN_Open(rtn);
        // Πριν την FaultInjectionEnd θέτουμε το flag σε false
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)SetInjectFalse,
                       IARG_THREAD_ID, IARG_END);
        RTN_Close(rtn);
    }
}



///////////////////////////////////////////////////////////////////////

/*    int generateRandomNumber() {
    // Seed with a combination of steady clock and current time for better randomness
    static std::mt19937 generator(
        std::chrono::steady_clock::now().time_since_epoch().count()
    );

    // Define the range of random numbers (e.g., 1 to 100)
    std::uniform_int_distribution<int> distribution(1, 100);

    return distribution(generator);
}
*/
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
    return mnemonic == "ADDPS" ||
           mnemonic == "SUBPS" ||
           mnemonic == "MULPS" ||
           mnemonic == "DIVPS" ||
           mnemonic == "SQRTPS"|| 
           mnemonic == "VADDPS"||
           mnemonic == "VSUBPS" ||
           mnemonic == "VMULPS"  ||
           mnemonic == "VDIVPS"  ||
           mnemonic == "VSQRTPS" ||mnemonic == "MINPS"  || mnemonic == "VMINPS"  ||
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
/*
bool isMixedPrecision(INS ins) {
    std::string mnemonic = INS_Mnemonic(ins);
    return mnemonic == "ADDSUBPD" ||
           mnemonic == "ADDSUBPS";
}
*/

/*
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
*/
///bool boolean=true;///
///int count=0;///
// FI: set the XMM[0-7] context register
VOID FI_XmmFloatPointFraction (ADDRINT ip, UINT32 regIndex, REG reg, UINT32 isvector, CONTEXT *ctxt,PrecisionType precision,THREADID tid)
{
  ///  PIN_GetLock(&globalLock, tid);///
   /// int randomValue = generateRandomNumber() % 100 + 1;///

    //injection_commands << randomValue << std::endl;
///    if (randomValue > 10) { //10% chance (1-10 out of 100)///
    //    injection_commands << "90% case triggered!" << std::endl;
///      PIN_ReleaseLock(&globalLock);///
///        return;///
///    }///
  // PIN_GetLock(&globalLock, tid);
///    count++;///
///    if(count>=6){boolean=false;PIN_ReleaseLock(&globalLock);return;}///
///   PIN_ReleaseLock(&globalLock);///
    ThreadData* tdata = static_cast<ThreadData*>(PIN_GetThreadData(tls_key, tid));
    if(tdata && tdata->inject) {//Ελεγχος εδω, γιατι το injection window (δηλαδή το flag tdata->inject) μπορεί να αλλάζει δυναμικά κατά την εκτέλεση
   //     srand(time(0)); // Initialize random number generator
        //choose XMM[i] to inject
//      string reg_name = REG_StringShort(reg);
        UINT32 i =  REG_StringShort(reg)[ REG_StringShort(reg).size() - 1] - '0';
        //srand(seed1);
        CHAR fpContextSpace[FPSTATE_SIZE];
        FPSTATE *fpContext = reinterpret_cast<FPSTATE *>(fpContextSpace);

        PIN_GetContextFPState(ctxt, fpContext);

        UINT32 bound_bit = (precision == DoublePrecision) ? 52 : 23;
    PIN_GetLock(&globalLock, tid);
        UINT32 inject_bit = (generateRandomNumber() % bound_bit);//want to inject fraction part
    PIN_ReleaseLock(&globalLock);
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
                if(isvector == 1){
                    PIN_GetLock(&globalLock, tid);
                     j = generateRandomNumber()%5;
                    PIN_ReleaseLock(&globalLock);
                }
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
//injection_commands <<"inside"<<std::endl;
   PIN_GetLock(&globalLock, tid);
        injection_commands << "Injection at instruction: 0x" << std::hex << ip
           << ", Register: " << REG_StringShort(reg) << ", Vector: " << j
           << ", Original Value: 0x" << std::hex << xmmValue
           << ", Mask: 0x" << std::hex << mask
           << ", Injected Value: 0x" << std::hex << injectedValue
           << std::endl;
   PIN_ReleaseLock(&globalLock);

        PIN_ExecuteAt(ctxt);
   }
}
///////////////////////////

/*

// Analysis function για καταγραφή των instructions
VOID LogInstructionInfo(THREADID tid,
                        ADDRINT ip,
                        const char* disasm,
                        const char* categoryName,
                        const char* rtnName)
{
    // Ανάκτηση των thread-local δεδομένων
    ThreadData* tdata = static_cast<ThreadData*>(PIN_GetThreadData(tls_key, tid));

    // Κλείδωμα για ασφαλή εγγραφή στο κοινό αρχείο
    PIN_GetLock(&globalLock, tid);

    instruction_log << "Instruction at 0x" << std::hex << ip << ": "
                    << disasm << " category: " << categoryName
                    << ", routine: " << rtnName;

    // Έλεγχος injection window: αν το thread είναι μέσα στο window, προσθέτει το μήνυμα
    if(tdata && tdata->inject) {
        instruction_log << "[ is in window ]";
    }
    instruction_log << std::endl;

    PIN_ReleaseLock(&globalLock);

    // Απελευθέρωση των strings που δεσμεύτηκαν με strdup
    free((void*)disasm);
    free((void*)categoryName);
    free((void*)rtnName);
}

*/

/*
// Analysis function για την εκτύπωση της εντολής (disassembled code)
// Αυτή η συνάρτηση καλείται για κάθε instruction και, εάν το flag inject είναι true, εκτυπώνει το disassembly.
VOID PrintInstruction(THREADID tid, const char* disasm,ADDRINT addr) {
    ThreadData* data = static_cast<ThreadData*>(PIN_GetThreadData(tls_key, tid));
    if(data->inject) {
    PIN_GetLock(&globalLock, tid);
     instruction_log   << "Thread " << tid << " executing at address: " << " 0x" << std::hex << addr << ": " << disasm << std::endl;
    PIN_ReleaseLock(&globalLock);
    }

}
*/
/////////////////////////////

// Instruments write registers of each instruction for fault injection
VOID InstructionInstrumentation(INS ins, VOID *v) {
    // Check if the instruction belongs to arithmetic or logic
   // srand(seed2);

//    int randomValue = generateRandomNumber() % 100 + 1;
//    std::string categoryName = CATEGORY_StringShort(INS_Category(ins));

//    injection_commands << randomValue << std::endl;

//    if (randomValue > 20) { // 10% chance (1-10 out of 100)
 //       injection_commands << "80% case triggered!" << std::endl;
 //       return;
  //  }
//    std::string disasmStr = INS_Disassemble(ins);
    //char* disasmCopy = new char[disasmStr.size() + 1];
    //std::strcpy(disasmCopy, disasmStr.c_str());
    //const char* disasm = disasmStr.c_str();
  //  const char* disasmC = strdup(disasmStr.c_str());
  //  ADDRINT addr = INS_Address(ins);
  //  INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)PrintInstruction,
  //                 IARG_THREAD_ID, IARG_PTR, disasmC,IARG_ADDRINT,addr, IARG_END);
   // PIN_GetLock(&globalLock, tid);
///    if(boolean==false){return;}///
   // PIN_ReleaseLock(&globalLock);
    if (!isValidInst(ins))
        return;
    if (INS_Mnemonic(ins) == "XOR") {
        return;
    }
//////////////////////////////////////////////////////////
/*
    std::string disasmStr = INS_Disassemble(ins);
    //char* disasmCopy = new char[disasmStr.size() + 1];
    //std::strcpy(disasmCopy, disasmStr.c_str());
    //const char* disasm = disasmStr.c_str();
    const char* disasmC = strdup(disasmStr.c_str());
    ADDRINT addr = INS_Address(ins);
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)PrintInstruction,
                   IARG_THREAD_ID, IARG_PTR, disasmC,IARG_ADDRINT,addr, IARG_END);
*/
///////////////////////////////////////////////////////
// ΠΡΙΝ
    //ADDRINT addr = INS_Address(ins);
    //std::string disasm = INS_Disassemble(ins);
    //RTN rtn = RTN_FindByAddress(addr);
//////////////////////////////////////////////////////
   //PIN_GetLock(&globalLock, IARG_THREAD_ID);
   // instruction_log << "Instruction at 0x" << std::hex << addr << ": " << disasm << " category: "<<categoryName<<",  routine: "<<  RTN_Name(rtn) <<  std::endl;
   //PIN_ReleaseLock(&globalLock);

///////////////////////////ΜΕΤΑ

/*
    // Λήψη βασικών πληροφοριών
    ADDRINT addr = INS_Address(ins);
    std::string disasmStr = INS_Disassemble(ins);
    std::string categoryNameStr = CATEGORY_StringShort(INS_Category(ins));
    RTN rtn = RTN_FindByAddress(addr);
    
    // Λήψη του ονόματος της routine, με έλεγχο εγκυρότητας
    const char* rtnName;
    if (RTN_Valid(rtn))
        rtnName = strdup(RTN_Name(rtn).c_str());
    else
        rtnName = strdup("unknown");
    
    // Δημιουργία αντιγράφων των strings για χρήση στο analysis function
    const char* disasmC = strdup(disasmStr.c_str());
    const char* categoryNameC = strdup(categoryNameStr.c_str());
    
    // Εισαγωγή κλήσης στην analysis function LogInstructionInfo
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)LogInstructionInfo,
                   IARG_THREAD_ID,
                   IARG_INST_PTR,
                   IARG_PTR, disasmC,
                   IARG_PTR, categoryNameC,
                   IARG_PTR, rtnName,
                   IARG_END);
*/

//////////////////////////////
    //if (INS_IsCall(ins)) {///////////////////
    //ADDRINT targetAddress = INS_DirectControlFlowTargetAddress(ins);
   // RTN targetRtn = RTN_FindByAddress(targetAddress);
   // instruction_log <<"TARGET ROUTINE" <<RTN_Name(targetRtn)<<  std::endl;
   // }
    if (!(IsArithmeticLogicInstruction(ins))) // Select a r>) {
        return; // Skip non-arithmetic/logic instructions

/*    if (INS_IsMemoryWrite(ins)) {
        instruction_log <<"IP: 0x" << std::hex << INS_Address(ins)<<" |MEMORY Instrumented instruction: " << INS_Disassemble(ins)<< std::endl;
        INS_InsertCall(
      ins, IPOINT_BEFORE, (AFUNPTR)FI_InjectFault_Mem,
      IARG_ADDRINT, INS_Address(ins),
      IARG_MEMORYREAD_EA,
      IARG_MEMORYREAD_SIZE,
      IARG_END);
      return;
    }
*/

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
  /////PIN_GetLock(&globalLock, IARG_THREAD_ID);////// INSTRUCTION REGISTERS /////////
  ////  instruction_log<<REG_StringShort(reg)<<"\n";///////
 ////  PIN_ReleaseLock(&globalLock);//////
    UINT32 isvector;
    // Insert a call to inject a fault into the selected write register
    if (REG_is_xmm(reg)) {
       if (isDoublePrecision(ins)) {
//injection_commands <<"inside1"<<std::endl;////////
             isvector = 0;
             INS_InsertCall(
           ins, IPOINT_AFTER, (AFUNPTR)FI_XmmFloatPointFraction,
           IARG_INST_PTR, // Pass the instruction pointer
           IARG_UINT32, randW, // Pass the register index
           IARG_UINT32, reg, // Pass the register identifier
           IARG_UINT32, isvector, //is vector or not
           IARG_CONTEXT, // Pass the full execution context
           IARG_ADDRINT,DoublePrecision,IARG_THREAD_ID,
           IARG_END
           );
       }
       if (isSinglePrecision(ins)) {
//injection_commands <<"inside2"<<std::endl;
             isvector = 0;
             INS_InsertCall(
           ins, IPOINT_AFTER, (AFUNPTR)FI_XmmFloatPointFraction,
           IARG_INST_PTR, // Pass the instruction pointer
           IARG_UINT32, randW, // Pass the register index
           IARG_UINT32, reg, // Pass the register identifier
           IARG_UINT32, isvector, //is vector or not
           IARG_CONTEXT, // Pass the full execution context
           IARG_ADDRINT,SinglePrecision,IARG_THREAD_ID,
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
           IARG_ADDRINT,DoublePrecision,IARG_THREAD_ID,
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
           IARG_ADDRINT,SinglePrecision,IARG_THREAD_ID,
           IARG_END
           );
       }
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
   // loadBlacklistedRoutines("blacklisted_routines.txt");
    // Open the results file for writing
    injection_commands.open("injection_results.txt", std::ios::out | std::ios::trunc);
    if (!injection_commands.is_open()) {
        std::cerr << "Error opening results file!" << std::endl;
        return 1;
    }

//////////////////////////
    // Αρχικοποίηση του global lock
    PIN_InitLock(&globalLock);

    // Δημιουργία TLS key
    tls_key = PIN_CreateThreadDataKey(NULL);

    // Εγγραφή callbacks για το ξεκίνημα και το τέλος νημάτων
    PIN_AddThreadStartFunction(ThreadStart, NULL);
    PIN_AddThreadFiniFunction(ThreadFini, NULL);


    // Εγγραφή instrumentation για routines (για την ανίχνευση των ορίων του w>    
    RTN_AddInstrumentFunction(RoutineInstrumentation, NULL);



    INS_AddInstrumentFunction(InstructionInstrumentation, 0); // Register the instrumentation function
    PIN_AddFiniFunction(Fini, 0); // Register the finalization function

    PIN_StartProgram(); // Start the target program execution
    return 0; // Should never reach here
}
