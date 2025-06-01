#include "pin.H"
#include <iostream>
#include <cstdlib>
#include <ctime>
#include "xed-category-enum.h"
#include <fstream> // For file operations
#include <unordered_set>
#include <random>//
#include <chrono>//
#include <sys/mman.h>
#include <thread>
#include <sys/types.h>
#include <unistd.h>

using namespace std;
using namespace std::chrono;
#define LOGOUT std::cout
std::ofstream injection_commands;

KNOB<BOOL> KnobInjectMem(KNOB_MODE_WRITEONCE, "pintool", "inject_only_mem", "0", "Enable memory injection (1=yes, 0=no)");
KNOB<UINT32> KnobNumInjections(
    KNOB_MODE_WRITEONCE, 
    "pintool",               // category
    "n",                     // switch name: -n
    "0",                     // default value
    "Number of bit‐flip injections to perform (086)");
PIN_LOCK globalLock;
PIN_LOCK pinLock;
static UINT64 globalInstCount = 0;
static UINT64 globalInstCountinject = 0;
UINT64 v=-1;
static UINT32 numInject = 0;
static std::vector<UINT64> injectionSpots;
static bool select_spots=false;
static INT *sharedValue = nullptr;
// Πιάσε το PID του parent πριν το fork
static ADDRINT parentPID = 0;
// Flag που λέει αν είμαστε στο child process
static bool isChildProcess = false;
static bool inject = false;
//uint64_t seed = 42; // Μπορείς να αλλάξεις το seed
static bool trace = false;
static int queryId=0;
static int seed = 45;




// Πριν το fork: αποθήκευσε το PID του parent
VOID BeforeFork(THREADID tid, const CONTEXT* ctxt, VOID* v) {
    PIN_GetLock(&pinLock, tid+1);
    parentPID = PIN_GetPid();
  //  ThreadData* tdata = static_cast<ThreadData*>(PIN_GetThreadData(tls_key, tid));
 //   tdata->isChild = false;
  sharedValue = (INT*)mmap(
    nullptr,
    sizeof(INT),
    PROT_READ|PROT_WRITE,
    MAP_SHARED|MAP_ANONYMOUS,
    -1,
    0
  );
  if (sharedValue == MAP_FAILED) {
    perror("mmap");
    PIN_ExitProcess(1);
  }

    PIN_ReleaseLock(&pinLock);
}

// Μετά το fork στον parent: βεβαιώσου ότι δεν άλλαξε
VOID AfterForkInParent(THREADID tid, const CONTEXT* ctxt, VOID* v) {
    PIN_GetLock(&pinLock, tid+1);
    isChildProcess = false;
//    ThreadData* tdata = static_cast<ThreadData*>(PIN_GetThreadData(tls_key, tid));
 //   tdata->isChild = false;
    std::cout<<PIN_GetPid()<<std::endl;
    inject=true;
    PIN_ReleaseLock(&pinLock);
}

// Μετά το fork στο child: σήκωσε το flag
VOID AfterForkInChild(THREADID tid, const CONTEXT* ctxt, VOID* v) {
    PIN_GetLock(&pinLock, tid+1);
    isChildProcess = true;
 //   ThreadData* tdata = static_cast<ThreadData*>(PIN_GetThreadData(tls_key, tid));
 //   tdata->isChild = true;
    inject=false;
    PIN_ReleaseLock(&pinLock);
}


/*
int generateRandomNumberNonDetermenistic() {
    // Seed with a combination of steady clock and current time for better randomness
    static std::mt19937 generator(
        std::chrono::steady_clock::now().time_since_epoch().count()
    );

    // 2) Warm up the engine exactly once (discard first 10 draws):
    static bool warmed = []{
        generator.discard(10);
        return true;
    }();

    // Define the range of random numbers (e.g., 1 to 100)
    std::uniform_int_distribution<int> distribution(1, 100);

    return distribution(generator);
}
*/
int generateRandomNumberNonDeterministic() {
    // 1) Create and seed + warm up the engine exactly once:
    static std::mt19937 generator = []{
        // Seed from a high-resolution clock
        std::mt19937 g{ 
            static_cast<std::uint32_t>(
                std::chrono::steady_clock::now()
                  .time_since_epoch()
                  .count()
            )
        };
        // Discard the first 10 outputs
        g.discard(10);
        return g;
    }();

    // 2) Static distribution so it’s only constructed once
    static std::uniform_int_distribution<int> distribution(1, 100);

    // 3) Draw and return
    return distribution(generator);
}



//static int seed=15;
int generateRandomNumber(int seed1) {
    // Παράμετροι του LCG (Numerical Recipes)
    seed = (1664525 * seed1 + 1013904223) % 0xFFFFFFFF;

    // Περιορισμός στο διάστημα [1, 100]
    return 1 + (seed1 % 100);
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



// Analysis function που θέτει το flag σε true (εισαγωγή στο window)
// Θα κληθεί μετά την εκτέλεση της FaultInjectionBegin
VOID SetInjectTrue(THREADID tid) {
   // ThreadData* tdata = static_cast<ThreadData*>(PIN_GetThreadData(tls_key, tid));
   // tdata->inject = true;
    trace=true;
}
//static UINT64 globalInstCount = 0;
//static UINT64 globalInstCountinject = 0;
//UINT64 v=-1;
// Analysis function που θέτει το flag σε false (έξοδος από το window)
// Θα κληθεί πριν την εκτέλεση της FaultInjectionEnd
VOID SetInjectFalse(THREADID tid) {
   // ThreadData* tdata = static_cast<ThreadData*>(PIN_GetThreadData(tls_key, tid));
//std::cout << "Parent pid: " << PIN_GetPid()<<" instr count = " <<globalInstCountinject<<"Parent/Child pid: "<<PIN_GetPid()<<"/"<<getppid()<<" instr count ="<<globalInstCount<< std::endl;
    trace = false;
}
//isshadow
/*
// Analysis callback για να μαρκάρουμε το shadow thread
VOID MarkShadowThread(THREADID tid) {
    ThreadData* td = static_cast<ThreadData*>(PIN_GetThreadData(tls_key, tid));
    if (td) {
        td->isShadowThread = true;
std::cout << "inside shadow thread" <<std::endl;
         //       std::cout << "inside shadow thread" <<globalInstCountinject<<globalInstCount<< std::endl;
        // Αν θέλεις, μπορείς εδώ να ανοίξεις και το outFile κτλ.
    }
}
*/
// Callback που "interpose" την BeginRequest και αποθηκεύει το query id στο TLS
VOID BeginRequestInterpose(int query_id, THREADID tid)
{
    // Αποθήκευση του query id για το τρέχον thread
  //  ThreadData* tdata = static_cast<ThreadData*>(PIN_GetThreadData(tls_key, tid));
   // tdata->queryId = query_id;
   // tdata->seed = query_id;
    queryId = query_id;
    seed = query_id;
    // printf("Thread %u finished query with id: %d\n", tid, query_id);
}
VOID setTraceOff(){
// ThreadData* tdata = static_cast<ThreadData*>(PIN_GetThreadData(tls_ke>std::cout << "Parent pid: " << PIN_GetPid()<<" instr count = " <<globalInst>
   trace = false;
   if(inject==true){
     std::cout << "This is Parent code. Is it Parent ?"<<!isChildProcess<< "pid = "<<PIN_GetPid()<< std::endl;
     select_spots=false;
     injectionSpots.clear();
     globalInstCount = 0;
     globalInstCountinject = 0;
   }
}

VOID RoutineInstrumentation(RTN rtn, VOID* v) {
    std::string name = RTN_Name(rtn);
    // std::cout << "ROUTINE :" << RTN_Name(rtn) << std::endl; // Debug output
    if (name == "FaultInjectionBegin") {
        //std::cout << "Found FaultInjectionBegin" << std::endl; // Debug output
        RTN_Open(rtn);
        // Μετά την FaultInjectionBegin θέτουμε το flag σε true
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)SetInjectTrue,
            IARG_THREAD_ID, IARG_END);
        RTN_Close(rtn);
    }
    else if (name == "FaultInjectionEnd") {
        // std::cout << "Found FaultInjectionEnd" << std::endl; // Debug output
        RTN_Open(rtn);
        // Πριν την FaultInjectionEnd θέτουμε το flag σε false
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)SetInjectFalse,
            IARG_THREAD_ID, IARG_END);
        RTN_Close(rtn);
    }
    else if (name == "FaultInjectionBegin_parent") {
        // std::cout << "Found FaultInjectionEnd" << std::endl; // Debug output
        RTN_Open(rtn);
        // Πριν την FaultInjectionEnd θέτουμε το flag σε false
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)SetInjectTrue,
            IARG_THREAD_ID, IARG_END);
        RTN_Close(rtn);
    }
    else if (name == "TraceFinish") {
        // std::cout << "Found FaultInjectionEnd" << std::endl; // Debug output
        RTN_Open(rtn);
        // Πριν την FaultInjectionEnd θέτουμε το flag σε false
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)setTraceOff,
            IARG_THREAD_ID, IARG_END);
        RTN_Close(rtn);
    }
    if (RTN_Name(rtn) == "QueryBegins")
    {
        RTN_Open(rtn);
        // Εισάγουμε κλήση πριν την εκτέλεση της BeginRequest
        // IARG_FUNCARG_ENTRYPOINT_VALUE, 0 παίρνει την πρώτη παράμετρο (query_id)
        // IARG_THREAD_ID δίνει το id του τρέχοντος thread
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)BeginRequestInterpose,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_THREAD_ID,
            IARG_END);
        RTN_Close(rtn);
    }
}







VOID log_bbl(THREADID tid, ADDRINT addr) {
  //ThreadData* tdata = static_cast<ThreadData*>(PIN_GetThreadData(tls_key, tid));
//PIN_GetLock(&pinLock, tid+1);        // παίρνουμε το lock (ίδιος με thread id)
//PIN_GetLock(&pinLock, tid+1);
  if(tid != 0){return;}
  if (trace == false){ return;}
  if(queryId == 12345){  return;}
  if (isChildProcess) {
 //PIN_ReleaseLock(&pinLock);
PIN_LockClient();
IMG img = IMG_FindByAddress(addr);
//PIN_UnlockClient();
SEC sec ;//= SEC_FindByAddress(addr);
std::string secName;
//PIN_LockClient();
RTN rtn = RTN_FindByAddress(addr);
//PIN_UnlockClient();
if (RTN_Valid(rtn)) {
    // 2) Get its enclosing section
    sec = RTN_Sec(rtn);
    if (SEC_Valid(sec)) {
        secName = SEC_Name(sec);
        // …
    }
}
PIN_UnlockClient();
PIN_GetLock(&pinLock, tid);
    // … shadow‐only behavior …
    std::ostringstream fname;
    fname << "ChildBBL_"<< std::dec<<queryId<<".txt";

    // Serialize the knn_answer stored in reply to file
    std::ofstream ofs(fname.str(), std::ios::app);
    if (ofs.is_open()) {
        // Assuming reply contains a DebugString method for human-readable output
        ofs <<  std::hex << addr          << " module=" << IMG_Name(img) 
          << " section=" << secName
          << " func=" << (RTN_Valid(rtn) ? RTN_Name(rtn) : "??")<<" thread: "<<tid<<" QUERY: "<< std::dec<<queryId
          << "\n";
        ofs.close();
    } else {
        fprintf(stderr, "Failed to open file %s for writing knn_answer\n", fname.str().c_str());
    }
PIN_ReleaseLock(&pinLock);
  } else {
PIN_LockClient();
IMG img = IMG_FindByAddress(addr);
//PIN_UnlockClient();
//SEC sec = SEC_FindByAddress(addr);
SEC sec ;//= SEC_FindByAddress(addr);
std::string secName;
//PIN_LockClient();
RTN rtn = RTN_FindByAddress(addr);
//PIN_UnlockClient();
if (RTN_Valid(rtn)) {
    // 2) Get its enclosing section
    sec = RTN_Sec(rtn);
    if (SEC_Valid(sec)) {
        secName = SEC_Name(sec);
        // …
    }
}
PIN_UnlockClient();
PIN_GetLock(&pinLock, tid);
    // … normal‐only behavior …
    std::ostringstream fname;
    fname << "ParentBBL_"<< std::dec<<queryId<<".txt";

    // Serialize the knn_answer stored in reply to file
    std::ofstream ofs(fname.str(), std::ios::app);
    if (ofs.is_open()) {
        // Assuming reply contains a DebugString method for human-readable output
        ofs <<  std::hex << addr          << " module=" << IMG_Name(img) 
          << " section=" << secName
          << " func=" << (RTN_Valid(rtn) ? RTN_Name(rtn) : "??")<<" thread: "<<tid<<" QUERY: "<< std::dec<<queryId
          << "\n";
        ofs.close();
    } else {
        fprintf(stderr, "Failed to open file %s for writing knn_answer\n", fname.str().c_str());
    }
  }
 PIN_ReleaseLock(&pinLock);
 //       PIN_ReleaseLock(&pinLock);        // παίρνουμε το lock (ίδιος με thread id)
}

VOID Trace(TRACE trace, VOID *v) {
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)log_bbl,
                       IARG_THREAD_ID,
                       IARG_ADDRINT, BBL_Address(bbl),
                       IARG_END);
    }
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
    category == XED_CATEGORY_X87_ALU || //ALU εντολές του x87 FPU
    category == XED_CATEGORY_FMA4 ||
    category == XED_CATEGORY_FP16 ||
    category == XED_CATEGORY_VFMA||
    category ==XED_CATEGORY_BINARY|| //ADD,SYB,MUL
    category ==XED_CATEGORY_LZCNT||//ALU-based counting instructions (POPCNT, LZCNT)
    category ==XED_CATEGORY_SSE||
    category ==XED_CATEGORY_LOGICAL_FP;
 //   category ==XED_CATEGORY_CONVERT||
  //  category ==XED_CATEGORY_SETCC;
//CONVERT,SETCC
}

/*


VOID FI_InjectFault_Mem(const string *disasm,VOID * ip,THREADID tid)
{

    PIN_GetLock(&globalLock, tid);
    if ((rand() % 100) >=70)return; // 30% πιθανότητα
    PIN_ReleaseLock(&globalLock);
      ThreadData* tdata = static_cast<ThreadData*>(PIN_GetThreadData(tls_key, tid));
  //  if (tdata && (tdata->inject)) {
    // Identify the routine containing this instruction
    if (!tdata->hasMemInfo) {
        delete disasm;
        return;
    }
    ADDRINT memp   = tdata->memEa;
    UINT32 size  = tdata->memSize;
    tdata->hasMemInfo = false;  // καταναλώνουμε το info
        PIN_LockClient();
        RTN rtn = RTN_FindByAddress(reinterpret_cast<ADDRINT>(ip));
        PIN_UnlockClient();
        std::string routineName = RTN_Valid(rtn) ? RTN_Name(rtn) : std::string("<unknown>");   
        PIN_GetLock(&globalLock, tid+1);
        injection_commands << "[Thread " << tid << "] Routine: " << routineName <<" Instruction:"<< disasm->c_str()<<" Injection at MEMORY instruction: 0x" << std::hex << ip
        << ", Memory: " << std::hex << memp
        << ", Original Value: 0x" << std::hex << (*((int*)memp));// << std::endl;
        PIN_ReleaseLock(&globalLock);
        UINT8* temp_p = (UINT8*) memp;
        PIN_GetLock(&globalLock, tid);
       //tdata->seed=generateRandomNumber(tdata->seed);
        UINT32 inject_bit = generateRandomNumber(seed) % (size * 8 // bits in one byte);
        PIN_ReleaseLock(&globalLock);
        UINT32 byte_num = inject_bit / 8;
        UINT32 offset_num = inject_bit % 8;

        *(temp_p + byte_num) = *(temp_p + byte_num) ^ (1U << offset_num);

        PIN_GetLock(&globalLock, tid);
        injection_commands
           << ", Mask: 0x" << std::hex << (1U << offset_num)
           << ", Injected Value: 0x" << std::hex << (*((int*)memp))
           << std::endl;
        PIN_ReleaseLock(&globalLock);
    delete disasm;
    //}
}
*/
//static UINT64 globalInstCount = 0;
//static UINT64 globalInstCountinject = 0;
//UINT64 v=-1;
//static UINT32 numInject = 0;
//static std::vector<UINT64> injectionSpots;
static std::mt19937_64 rng( std::random_device{}() );
//static bool select=false;
/////////elexo v////////////////

// call once per thread/run when you’re ready to pick all spots
VOID selectInjectionSpots(THREADID tid) {
//    PIN_GetLock(&globalLock, tid+1);
    select_spots=true;
    std::cout << "Selected: true   Instruction count = "<<globalInstCount<<std::endl;
    // clear any previous selection
    injectionSpots.clear();
    injectionSpots.reserve(numInject);
    globalInstCount = *sharedValue;
    std::cout << "Selected: true   Instruction count after accessing shared value = "<<globalInstCount<<std::endl;
    // guard: nothing to do if there are no instructions or no injections requested
    if (globalInstCount == 0 || numInject == 0) {
  //      PIN_ReleaseLock(&globalLock);
        return;
    }

    // distribution over [0, globalInstCount-1]
    std::uniform_int_distribution<UINT64> dist(0, globalInstCount - 1);

    // fill the vector with numInject random values
    for (UINT32 i = 0; i < numInject; ++i) {
        injectionSpots.push_back(dist(rng));
    }

    // sort ascending so you can binary_search or just iterate in order
    std::sort(injectionSpots.begin(), injectionSpots.end());

    // optional: print them out
    std::cout << "Selected " << numInject << " injection spots (sorted): ";
    for (UINT64 spot : injectionSpots) {
        std::cout << spot << ' ';
    }
    std::cout << "  [globalInstCount=" << globalInstCount << "]\n";

    //PIN_ReleaseLock(&globalLock);
}


// Injects a single bit flip into the specified register
VOID InjectBitFlip(ADDRINT ip, UINT32 regIndex, REG reg, CONTEXT *ctxt,THREADID tid) {
//   ThreadData* tdata = static_cast<ThreadData*>(PIN_GetThreadData(tls_key, tid));

   if(tid != 0)return;
//    std::cout << "thread that inject1 "  << std::endl;
   if (trace==false)return;//AN sto child epestrepse
   // std::cout << "thread that inject2 "  << std::endl;
  if(queryId == 12345) return;
   if (inject==false)return;
   // std::cout << "thread that inject3 "
    //          << std::endl;
 // PIN_GetLock(&globalLock, tid+1);
    if(select_spots==false)selectInjectionSpots(tid);
 // PIN_ReleaseLock(&globalLock);
// 3) If no more spots, just return
if (injectionSpots.empty()) {
    return;
}

// 4) Compare against the next spot (the front of the vector):
if (globalInstCountinject != injectionSpots[0]) {
    // Not our turn yet—skip injection
    globalInstCountinject++;
    return;
}
injectionSpots.erase(injectionSpots.begin());

    //if(globalInstCountinject!=v){
    //  globalInstCountinject++;
   //   return;
  //  }
    globalInstCountinject++;
//PIN_ReleaseLock(&globalLock);
//    return;/////////////////////
    if(REG_valid(reg)){
    reg = REG_FullRegName(reg);
    ADDRINT regValue = PIN_GetContextReg(ctxt, reg); // Get the current value of the register
    PIN_GetLock(&globalLock, tid+1);
    UINT32 injectBit = /*generateRandomNumber(seed)*/generateRandomNumberNonDeterministic() % (sizeof(UINT32) * 8); // MOST SDCs FOUND ON LEAST SIGNIFICANT BITS(UINT32)
    PIN_ReleaseLock(&globalLock);
    ADDRINT mask = 1UL << injectBit; // Create a mask for the bit flip
    ADDRINT injectedValue = regValue ^ mask; // Apply the bit flip
    PIN_SetContextReg(ctxt, reg, injectedValue); // Update the register with the new value

    // Log the details of the injection// LOGOUT
    PIN_GetLock(&globalLock, tid+1);
    injection_commands << "Injection at instruction: 0x" << std::hex << ip
           << ", Register: " << REG_StringShort(reg)
           << ", Original Value: 0x" << std::hex << regValue
           << ", Mask: 0x" << std::hex << mask
           << ", Injected Value: 0x" << std::hex << injectedValue<<", Query: "<<std::dec<< queryId
           << std::endl;
    PIN_ReleaseLock(&globalLock);
    PIN_ExecuteAt(ctxt);
 }
}
//static UINT64 globalInstCount = 0;
    VOID CountInstructionWithLock(THREADID tid) {
   //     ThreadData* tdata = static_cast<ThreadData*>(PIN_GetThreadData(tls_key, tid));
        if (trace == false)return;
        if(queryId == 12345) return;
        if (inject == true)return;
        PIN_GetLock(&pinLock, tid+1);        // παίρνουμε το lock (ίδιος με thread id)
        globalInstCount++;
        *sharedValue=globalInstCount;
        PIN_ReleaseLock(&pinLock);           // απελευθερώνουμε
    }


// Instruments write registers of each instruction for fault injection
VOID InstructionInstrumentation(INS ins, VOID *v) {
// Check if the instruction belongs to arithmetic or logic
   ///////////////////////////////////////////////////////////////////////////////////////////////////
   //if (!isValidInst(ins))
     //   return;
   ///////////////////////////////////////////////////////////////////////////////////////////////////

    if (!isValidInst(ins))
        return;
    if (!(IsArithmeticLogicInstruction(ins))) // Select a r>) {
        return; // Skip non-arithmetic/logic instructions
/*
    if (KnobInjectMem.Value() && INS_IsMemoryWrite(ins)) {

//       std::string *disasm = new std::string( INS_Disassemble(ins) );
        // 1) Στο IPOINT_BEFORE αποθηκεύουμε EA & size στο ThreadData
        INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)+[](
                THREADID tid,
                ADDRINT ea,
                UINT32 size) {
              auto *td = static_cast<ThreadData*>(PIN_GetThreadData(tls_key, tid));
              td->memEa     = ea;
              td->memSize   = size;
              td->hasMemInfo= true;
            },
            IARG_THREAD_ID,
            IARG_MEMORYWRITE_EA,
            IARG_MEMORYWRITE_SIZE,
            IARG_END
        );

        // 2) Στο IPOINT_AFTER κάνουμε το fault‐injection,
        //    διαβάζοντας EA & size από το ThreadData
        INS_InsertCall(
            ins, IPOINT_AFTER, AFUNPTR(FI_InjectFault_Mem),
            IARG_PTR,        new std::string(INS_Disassemble(ins)),
            IARG_ADDRINT,    INS_Address(ins),
            IARG_THREAD_ID,
            IARG_END
        );
      return;
    }
    if (KnobInjectMem.Value()) { //if option is 1 inject only on memomry instructions
      return;
    }
*/
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
    if (REG_is_xmm(reg)||REG_is_ymm(reg)) {return;}

//count possible injection instructions
    INS_InsertCall(
        ins, IPOINT_BEFORE,
        AFUNPTR(CountInstructionWithLock),
        IARG_THREAD_ID,
        IARG_END
    );



    INS_InsertCall(
        ins, IPOINT_AFTER, (AFUNPTR)InjectBitFlip,
        IARG_INST_PTR, // Pass the instruction pointer
        IARG_UINT32, randW, // Pass the register index
        IARG_UINT32, reg, // Pass the register identifier
        IARG_CONTEXT, // Pass the full execution context
        IARG_THREAD_ID,
        IARG_END
    );
}
/*
// Record each control-flow instruction to the thread's output file
VOID RecordBranch(ADDRINT ip, BOOL taken, ADDRINT target, THREADID tid){
ThreadData* tdata = static_cast<ThreadData*>(PIN_GetThreadData(tls_key, tid));
    if (!tdata || !tdata->outFile) return;
    std::ofstream& out = *(tdata->outFile);
    out << std::hex << ip
        << (taken ? " T" : " N")
        << " -> 0x" << target
        << std::dec << std::endl;
}

// Instrumentation routine: insert call for branches, calls, rets
VOID InstructionInstrumentationBranch(INS ins, VOID *v) {
    if (INS_IsBranch(ins) || INS_IsCall(ins) || INS_IsRet(ins)) {
        INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)RecordBranch,
            IARG_INST_PTR,
            IARG_BRANCH_TAKEN,
            IARG_BRANCH_TARGET_ADDR,
            IARG_THREAD_ID,
            IARG_END
        );
    }
}
*/

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
    srand(time(NULL)); // seed the randomness once
    PIN_InitLock(&pinLock);
    PIN_InitLock(&globalLock);
   // tls_key = PIN_CreateThreadDataKey(NULL);
    // Open the results file for writing
    numInject = KnobNumInjections.Value();
    if (numInject > 12) {
        std::cerr << "Error: -n must be between 0 and 8 (you passed " 
                  << numInject << ")\n";
        return 1;
    }
    injection_commands.open("injection_results.txt", std::ios::out | std::ios::trunc);
    if (!injection_commands.is_open()) {
        std::cerr << "Error opening results file!" << std::endl;
        return 1;
    }
    // Εγγραφή callbacks για το ξεκίνημα και το τέλος νημάτων
//    PIN_AddThreadStartFunction(ThreadStart, NULL);
 //   PIN_AddThreadFiniFunction(ThreadFini, NULL);
PIN_AddForkFunction(FPOINT_BEFORE,            BeforeFork,        NULL);
PIN_AddForkFunction(FPOINT_AFTER_IN_PARENT,   AfterForkInParent, NULL);
PIN_AddForkFunction(FPOINT_AFTER_IN_CHILD,    AfterForkInChild,  NULL);
    TRACE_AddInstrumentFunction(Trace, nullptr);

    // Εγγραφή instrumentation για routines (για την ανίχνευση των ορίων του w>
    RTN_AddInstrumentFunction(RoutineInstrumentation, NULL);

 //   INS_AddInstrumentFunction(InstructionInstrumentationBranch, NULL);
    INS_AddInstrumentFunction(InstructionInstrumentation, 0); // Register the instrumentation function
    PIN_AddFiniFunction(Fini, 0); // Register the finalization function

    PIN_StartProgram(); // Start the target program execution
    return 0; // Should never reach here
}
