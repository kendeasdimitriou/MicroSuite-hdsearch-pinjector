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
#include <cstdint>
#include <unistd.h>
#include <sys/mman.h>
#include <thread>

using namespace std;
using namespace std::chrono;
std::ofstream injection_commands;
//std::ofstream injection_commands2;
//std::ofstream OutFile1;
//std::ofstream OutFile2;
//std::ofstream OutFile3;
//std::ofstream OutFile4;
//int x;
#define LOGOUT std::cout
PIN_LOCK globalLock;
PIN_LOCK pinLock;
// Πιάσε το PID του parent πριν το fork
static ADDRINT parentPID = 0;
// Flag που λέει αν είμαστε στο child process
static bool isChildProcess = false;
//static bool inject = false;
//uint64_t seed = 42; // Μπορείς να αλλάξεις το seed
static INT *sharedValue = nullptr;
static UINT32 numInject = 0;

//KNOB<BOOL> KnobInjectMem(KNOB_MODE_WRITEONCE, "pintool", "inject_only_mem", "0", "Enable memory injection (1=yes, 0=no)");
KNOB<UINT32> KnobNumInjections(
    KNOB_MODE_WRITEONCE,
    "pintool",               // category
    "n",                     // switch name: -n
    "0",                     // default value
    "Number of bit‐flip injections to perform");



int generateRandomNumber(int seed) {
    // Παράμετροι του LCG (Numerical Recipes)
    int seed1 = (1664525 * seed + 1013904223) % 0xFFFFFFFF;

    // Περιορισμός στο διάστημα [1, 100]
    return 1 + (seed1 % 100);
}




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



struct ThreadData {////BAZO TO DIKO TOU SEED
    bool inject;
    bool trace;
    UINT64 InstCount;
    std::vector<UINT64> injectionSpots;
    bool select_spots;
    int queryId;
    int seed;
    bool isChild;      // <-- νέο πεδίο: true αν είμαστε στο child process
};


static TLS_KEY tls_key;


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
    *sharedValue=0;
    PIN_ReleaseLock(&pinLock);
}

// Μετά το fork στον parent: βεβαιώσου ότι δεν άλλαξε
VOID AfterForkInParent(THREADID tid, const CONTEXT* ctxt, VOID* v) {
    isChildProcess = false;
    ThreadData* tdata = static_cast<ThreadData*>(PIN_GetThreadData(tls_key, tid));
    tdata->isChild = false;
}

// Μετά το fork στο child: σήκωσε το flag
VOID AfterForkInChild(THREADID tid, const CONTEXT* ctxt, VOID* v) {
  //  PIN_GetLock(&pinLock, tid+1);
    isChildProcess = true;
    ThreadData* tdata = static_cast<ThreadData*>(PIN_GetThreadData(tls_key, tid));
    tdata->isChild = true;
//    PIN_ReleaseLock(&pinLock);
}


VOID ThreadStart(THREADID tid, CONTEXT* ctxt, INT32 flags, VOID* v) {
    ThreadData* data = new ThreadData();
    data->inject = false;
    data->trace=false;
    data->InstCount=0;
    data->select_spots=false;
    data->queryId = 0;
    data->seed = 0;
    data->isChild = false;
    PIN_SetThreadData(tls_key, data, tid);
}

VOID ThreadFini(THREADID tid, const CONTEXT* ctxt, INT32 code, VOID* v) {
    ThreadData* data = static_cast<ThreadData*>(PIN_GetThreadData(tls_key, tid));
    delete data;
}



// Analysis function που θέτει το flag σε true (εισαγωγή στο window)
// Θα κληθεί μετά την εκτέλεση της FaultInjectionBegin
VOID SetInjectTrue(int inject_flag,THREADID tid) {
    ThreadData* tdata = static_cast<ThreadData*>(PIN_GetThreadData(tls_key, tid));
    tdata->trace=true;
    tdata->inject = false;
  PIN_GetLock(&pinLock, tid + 1);
    std::cout <<"IN"<<inject_flag<<std::endl;
    if(inject_flag==1 && !tdata->isChild){tdata->inject = true;std::cout<<"This is parent ? "<<tdata->isChild<<"QUERY: "<<tdata->queryId<<std::endl;}
  PIN_ReleaseLock(&pinLock);
}

// Analysis function που θέτει το flag σε false (έξοδος από το window)
// Θα κληθεί πριν την εκτέλεση της FaultInjectionEnd
VOID SetInjectFalse(THREADID tid) {
    ThreadData* tdata = static_cast<ThreadData*>(PIN_GetThreadData(tls_key, tid));
    if(tdata->inject==true){
  PIN_GetLock(&pinLock, tid + 1);
  std::cout << "This is Parent code. Is it Parent ?"<<!isChildProcess<< "pid = "<<PIN_GetPid()<<"parent counter: "<<tdata->InstCount<<" Query: "<<tdata->queryId<<std::endl;
  PIN_ReleaseLock(&pinLock);
        tdata->select_spots=false;
        tdata->injectionSpots.clear();
    //    tdata->InstCount = 0;
        tdata->inject = false;
    }
    if(tdata->inject==false){PIN_GetLock(&pinLock, tid + 1);  std::cout << "This is child code. Is it child ?"<<!isChildProcess<< "pid = "<<PIN_GetPid()<<"child counter: "<<tdata->InstCount<<" Query: "<<tdata->queryId<<std::endl;  PIN_ReleaseLock(&pinLock);}
    tdata->InstCount = 0;
    tdata->trace=false;
}


// Callback που "interpose" την BeginRequest και αποθηκεύει το query id στο TLS
VOID BeginRequestInterpose(int query_id, THREADID tid)
{
    // Αποθήκευση του query id για το τρέχον thread
    ThreadData* tdata = static_cast<ThreadData*>(PIN_GetThreadData(tls_key, tid));
    tdata->queryId = query_id;
    tdata->seed = query_id;
   // printf("Thread %u finished query with id: %d\n", tid, query_id);
}

// Routine instrumentation: Εντοπίζει τις routines που ορίζουν το window
VOID RoutineInstrumentation(RTN rtn, VOID *v) {
    std::string name = RTN_Name(rtn);
   // std::cout << "ROUTINE :" << RTN_Name(rtn) << std::endl; // Debug output
    if(name == "FaultInjectionBegin") {
    //std::cout << "Found FaultInjectionBegin" << std::endl; // Debug output
        RTN_Open(rtn);
        // Μετά την FaultInjectionBegin θέτουμε το flag σε true
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)SetInjectTrue,
                     IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
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
 //   category == XED_CATEGORY_BMI1 ||
 //   category == XED_CATEGORY_BMI2 ||
    category == XED_CATEGORY_X87_ALU ||
    category == XED_CATEGORY_FMA4 ||
    category == XED_CATEGORY_FP16 ||
    category == XED_CATEGORY_VFMA||
    category ==XED_CATEGORY_BINARY||
    category ==XED_CATEGORY_SSE||
    category ==XED_CATEGORY_LOGICAL_FP;
 //   category ==XED_CATEGORY_CONVERT||
//    category ==XED_CATEGORY_SETCC;
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


/////////////////////////////////////////////STYLIANOS

/*
VOID ThreadLock (THREADID threadid)//proccess id
{
  PIN_GetLock(&pinLock, threadid + 1);
    ThreadData* tdata = static_cast<ThreadData*>(PIN_GetThreadData(tls_key, threadid));
    if(tdata && tdata->inject) {////////////////////////////////////      std::cout << "proc 0 [0] 1.1 1 instructions: ";
      if (x == 1)
    OutFile1 << "proc 0 [0] 1.1 1 instructions: ";
else if (x == 2)
    OutFile2 << "proc 0 [0] 1.1 1 instructions: ";
else if (x == 3)
    OutFile3 << "proc 0 [0] 1.1 1 instructions: ";
else if (x == 4)
    OutFile4 << "proc 0 [0] 1.1 1 instructions: ";
    }
}
*/


VOID log_bbl(THREADID tid, ADDRINT addr) {
 ThreadData* tdata = static_cast<ThreadData*>(PIN_GetThreadData(tls_key, tid));
  if(!tdata->trace||tdata->queryId == 12345){return;}
  //if (trace == false){ return;}
  //if(queryId == 12345){  return;}
  //if(tdata->queryId == 12345 || tdata->queryId == 74881) return;// NOTE: IF YOU HAVE CHILD AND PARENT WORK SIMUTANEOUSLY ADD PINLOCK RELEASEL>  
if (tdata->isChild) {
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
    fname << "Child_"<< std::dec<<tdata->queryId<<".txt";

    // Serialize the knn_answer stored in reply to file
    std::ofstream ofs(fname.str(), std::ios::app);
    if (ofs.is_open()) {
        // Assuming reply contains a DebugString method for human-readable output

        ofs <<  std::hex << addr          << " module=" << IMG_Name(img)
          << " section=" << secName
          << " func=" << (RTN_Valid(rtn) ? RTN_Name(rtn) : "??")<<" QUERY: "<< std::dec<<tdata->queryId
          <<"\n";
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
    fname << "Parent_"<< std::dec<<tdata->queryId<<".txt";

    // Serialize the knn_answer stored in reply to file
    std::ofstream ofs(fname.str(), std::ios::app);
    if (ofs.is_open()) {
        // Assuming reply contains a DebugString method for human-readable output
        ofs <<  std::hex << addr          << " module=" << IMG_Name(img)
          << " section=" << secName
          << " func=" << (RTN_Valid(rtn) ? RTN_Name(rtn) : "??")<<" QUERY: "<< std::dec<<tdata->queryId
          << "\n";
        ofs.close();
    } else {
        fprintf(stderr, "Failed to open file %s for writing knn_answer\n", fname.str().c_str());
    }
 PIN_ReleaseLock(&pinLock);
  }
}




VOID Trace(TRACE trace, VOID *v) {
    //if (!isValidInst(ins))
     //   return;
    //bool hasValid = false;
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
//        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
        BBL_InsertCall(bbl, IPOINT_AFTER, (AFUNPTR)log_bbl,
                       IARG_THREAD_ID,
                       IARG_ADDRINT, BBL_Address(bbl),
                       IARG_END);
    }
}



























VOID ThreadLock(THREADID threadid) // process id
{
    PIN_GetLock(&pinLock, threadid + 1);
    ThreadData* tdata = static_cast<ThreadData*>(PIN_GetThreadData(tls_key, threadid));
    if (tdata && (tdata->trace)) {
        // Υποθέτουμε ότι το x έχει ήδη την τιμή 1..4
//        int fileIndex = x;


    // --- Debug logging σε αρχείο ---
    {
        // Επιλέγουμε αρχείο βάσει process
        const char* fname = tdata->isChild
              ? "thread_lock_debug_child.txt"
        : "thread_lock_debug_parent.txt";
        std::ofstream dbg1(fname, std::ios::out | std::ios::app);
        if (dbg1) {
           dbg1 << (tdata->isChild ? "Child" : "Parent")
                << " entering FI at IP=0x. inject = " <<tdata->inject
                << " tid=" << std::dec << threadid
                << "\n";
//           dbg1 << (isChildProcess ? "Child" : "Parent")
  //              << " entering FI at IP=0x"
    //            << " tid=" << std::dec << threadid
      //          << "\n";
       dbg1.close();
       }
   }
    // ---------------------------------



   std::string prefix = isChildProcess
        ? "child_"
        : "parent_";
        // Φτιάχνουμε το όνομα: OutFile{1..4}_{queryId}.txt
        std::string filename = "OutFile_" + prefix
                             + std::to_string(tdata->queryId)
                             + ".txt";

        // Άνοιγμα σε append mode (αν υπάρχει το αρχείο κάνει append, αλλιώς το δημιουργεί)
        std::ofstream outfile(filename.c_str(), std::ios::out | std::ios::app);
        if (!outfile) {
            // Προαιρετικά: χειρισμός σφάλματος ανοίγματος
            std::cerr << "Failed to open " << filename << std::endl;
        } else {
            outfile << "proc 0 [0] 1.1 1 instructions: ";
            // ... ό,τι άλλο θες να τυπώσεις
            outfile.close();
        }
    }
}

VOID ThreadReleaseLock ()
{
//  std::cout << curr_instr.ip << "\n";
  PIN_ReleaseLock(&pinLock);
}

/*
void GetOpCode(VOID *ip, UINT32 size,THREADID tid) {
   ThreadData* tdata = static_cast<ThreadData*>(PIN_GetThreadData(tls_key, tid));
   if(tdata && tdata->inject) {
    //OutFile<< tdata->queryId<< std::endl;
    UINT8 opcodeBytes[64];

    UINT32 fetched = PIN_SafeCopy(opcodeBytes, ip, size);
    if (fetched != size) {
        printf("*** error fetching instruction at address 0x%lx",(unsigned long)ip);
        return;
    }
    std::stringstream ss;
    //ss << std::hex << std::nouppercase << ip;  // για μικρά γράμματα (χωρίς std::nouppercase θα είναι κεφαλαία)
    ss << std::hex << std::nouppercase << (uintptr_t)ip;
    std::string ip_str = ss.str();
    std::cout<< ip_str << " func module insn:";

    for (UINT32 i = 0; i < fetched; i++) {
        printf(" %02x", opcodeBytes[i]);
    }
    printf("\n");
  }

}
*/
/*
void GetOpCode(VOID *ip, UINT32 size,THREADID tid) {
   ThreadData* tdata = static_cast<ThreadData*>(PIN_GetThreadData(tls_key, tid));
   if(tdata && tdata->inject) {
    UINT8 opcodeBytes[64];

    UINT32 fetched = PIN_SafeCopy(opcodeBytes, ip, size);
    if (fetched != size) {
        printf("*** error fetching instruction at address 0x%lx",(unsigned long)ip);
        return;
    }
    std::stringstream ss;
    //ss << std::hex << std::nouppercase << (uintptr_t)ip;
  //  std::string ip_str = ss.str();
    ss << std::hex << std::nouppercase << (uintptr_t)ip;
    std::string ip_str = ss.str();
// Τύπωσε το queryId στο σωστό αρχείο
if (x == 1) {
    //OutFile1 << tdata->queryId << std::endl;
    OutFile1 << ip_str << " func module insn:";
} else if (x == 2) {
   // OutFile2 << tdata->queryId << std::endl;
    OutFile2 << ip_str << " func module insn:";
} else if (x == 3) {
   // OutFile3 << tdata->queryId << std::endl;
    OutFile3 << ip_str << " func module insn:";
} else if (x == 4) {
    //OutFile4 << tdata->queryId << std::endl;
    OutFile4 << ip_str << " func module insn:";
}

// Εκτύπωση opcodeBytes στο αντίστοιχο αρχείο
std::ostream* activeOut = nullptr;
if (x == 1) activeOut = &OutFile1;
else if (x == 2) activeOut = &OutFile2;
else if (x == 3) activeOut = &OutFile3;
else if (x == 4) activeOut = &OutFile4;

if (activeOut) {
    for (UINT32 i = 0; i < fetched; i++) {
        (*activeOut) << " " << std::hex << std::setw(2) << std::setfill('0') << (int)opcodeBytes[i];
    }
    (*activeOut) << std::endl;
  }
}
}
//////////////////////////////////////////////STYLIANOS
*/

void GetOpCode(VOID *ip, UINT32 size,const char* disas, THREADID tid) {
    ThreadData* tdata = static_cast<ThreadData*>(PIN_GetThreadData(tls_key, tid));
    if (tdata && (tdata->trace)) {
        UINT8 opcodeBytes[64];
        UINT32 fetched = PIN_SafeCopy(opcodeBytes, ip, size);
        if (fetched != size) {
            std::cerr << "*** error fetching instruction at address 0x"
                      << std::hex << (uintptr_t)ip << std::dec << std::endl;
            return;
        }
   std::string prefix = isChildProcess
        ? "child_"
        : "parent_";
PIN_LockClient();
        // (2) Βρες το routine
        ADDRINT addr = reinterpret_cast<ADDRINT>(ip);
        RTN rtn = RTN_FindByAddress(addr);
PIN_UnlockClient();
        std::string routineName = RTN_Valid(rtn)
                                  ? RTN_Name(rtn)
                                  : std::string("UNKNOWN");


        // Φτιάχνουμε το hex string της διεύθυνσης
        std::stringstream ss;
        ss << std::hex << std::nouppercase << (uintptr_t)ip;
        std::string ip_str = ss.str();

        // Υποθέτουμε ότι x έχει τιμή 1..4
        //int fileIndex = x;

        // Κατασκευή ονόματος αρχείου: OutFile{1..4}_{queryId}.txt
        std::string filename = "OutFile_" + prefix
                               + std::to_string(tdata->queryId)
                             + ".txt";

        // Άνοιγμα σε append mode
        std::ofstream outfile(filename.c_str(), std::ios::out | std::ios::app);
        if (!outfile) {
            std::cerr << "Failed to open " << filename << std::endl;
        } else {
            // Εκτύπωση queryId, διεύθυνσης και opcode bytes
            outfile <<"Routine: "<<routineName<<" " <<tdata->queryId << " 0x" << ip_str 
                    << " func module insn:"<<disas;
       //     for (UINT32 i = 0; i < fetched; ++i) {
       //         outfile << " "
       //                 << std::hex << std::setw(2) << std::setfill('0')
       //                 << static_cast<unsigned int>(opcodeBytes[i]);
            //}
            outfile << std::endl;
            outfile.close();
        }
    }
}






static std::mt19937_64 rng( std::random_device{}() );

VOID selectInjectionSpots(ThreadData* tdata,THREADID tid) {
//    PIN_GetLock(&globalLock, tid+1);
    tdata->select_spots=true;
    // clear any previous selection
    tdata->injectionSpots.clear();
    tdata->injectionSpots.reserve(numInject);
    //globalInstCount = *sharedValue;
    std::cout << "Selected: true   Instruction count after accessing shared value = "<<*sharedValue<<"Parent Instructio count: "<<tdata->InstCount<<std::endl;
    // guard: nothing to do if there are no instructions or no injections requested
    if (numInject == 0) {
  //      PIN_ReleaseLock(&globalLock);
        return;
    }

    // distribution over [0, globalInstCount-1]
    std::unordered_set<UINT64> uniqueSpots;
   // std::uniform_int_distribution<UINT64> dist(0, *sharedValue - 1);
    std::uniform_int_distribution<UINT64> dist(0, *sharedValue - 1);

    while (uniqueSpots.size() < numInject) {
        uniqueSpots.insert(dist(rng));
    }
    tdata->injectionSpots.assign(uniqueSpots.begin(), uniqueSpots.end());

    // fill the vector with numInject random values
//    for (UINT32 i = 0; i < numInject; ++i) {
 //       tdata->injectionSpots.push_back(dist(rng));
  //  }

    // sort ascending so you can binary_search or just iterate in order
    std::sort(tdata->injectionSpots.begin(), tdata->injectionSpots.end());

    // optional: print them out
    std::cout << "Selected " << numInject << " injection spots (sorted): ";
    for (UINT64 spot : tdata->injectionSpots) {
        std::cout << spot << ' ';
    }
    std::cout << "  [Shared InstCount=" << *sharedValue << "]\n";

    //PIN_ReleaseLock(&globalLock);
}





// FI: set the XMM[0-7] context register
VOID FI_XmmFloatPointFraction (ADDRINT ip, UINT32 regIndex, REG reg, UINT32 isvector, CONTEXT *ctxt,PrecisionType precision,THREADID tid)
{

    ThreadData* tdata = static_cast<ThreadData*>(PIN_GetThreadData(tls_key, tid));
      //Ελεγχος εδω, γιατι το injection window (δηλαδή το flag tdata->inject) μπορεί να αλλάζει δυναμικά κατά την εκτέλεση
//injection_commands <<"inside2";
  //  ThreadData* tdata = static_cast<ThreadData*>(PIN_GetThreadData(tls_key, tid));
    if( tdata->trace==false ||
          tdata->inject==false)return; //Ελεγχος εδω, γιατι το injection window (δηλαδή το flag tdata->inject) μπορεί να αλλάζει δ>
    if(tdata->select_spots==false)selectInjectionSpots(tdata,tid);
 
// PIN_ReleaseLock(&globalLock);
// 3) If no more spots, just return
    if (tdata->injectionSpots.empty()) {
        return;
    }

// 4) Compare against the next spot (the front of the vector):
    if (tdata->InstCount != tdata->injectionSpots[0]) {
    // Not our turn yet—skip injection
       tdata->InstCount++;
       return;
    }
    tdata->injectionSpots.erase(tdata->injectionSpots.begin());
       tdata->InstCount++;
    //if(globalInstCountinject!=v){
    //  globalInstCountinject++;
   //   return;
  //  }
    //tdata->InstCount++;

        // Επιλέγουμε αρχείο βάσει process
        UINT32 i =  REG_StringShort(reg)[ REG_StringShort(reg).size() - 1] - '0';
//        UINT32 p =  REG_StringShort(reg)[ REG_StringShort(reg).size() - 2] - '0';
// injection_commands <<"xmm"<<i<<" REGISTER";
  //      if(p==1||i>=2){return;}

        CHAR fpContextSpace[FPSTATE_SIZE];
        FPSTATE *fpContext = reinterpret_cast<FPSTATE *>(fpContextSpace);

        PIN_GetContextFPState(ctxt, fpContext);

        UINT32 bound_bit = (precision == DoublePrecision) ? 52 : 23;
        UINT32 inject_bit;
    PIN_GetLock(&globalLock, tid);
      //  if(i==2||i==3){inject_bit = 2;}//want to inject fraction part}
       // else if(i!=2||i!=3){
        tdata->seed = generateRandomNumberNonDeterministic();
        inject_bit = ( tdata->seed % bound_bit);//want to inject fraction part
       // }
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
                     tdata->seed = generateRandomNumberNonDeterministic();
                     j = tdata->seed % 5;
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
                injectedValue = fpContext->fxsave_legacy._xmms[i]._vec32[j];


        }
        PIN_SetContextFPState(ctxt, fpContext);


PIN_LockClient();
RTN rtn = RTN_FindByAddress(ip);
PIN_UnlockClient();



   PIN_GetLock(&globalLock, tid+1);



//       injection_commands << "Injection at instruction: 0x" << std::hex << ip
//           << ", Register: " << REG_StringShort(reg) << ", Vector: " << j
 //          << ", Original Value: 0x" << std::hex << xmmValue
  //         << ", Mask: 0x" << std::hex << mask
  //         << ", Injected Value: 0x" << std::hex <<injectedValue
  //         << " Query ID :" << std::dec <<queryId<< std::endl;
    std::ostringstream injections;
    injections << "injection_results.txt";

    // Serialize the knn_answer stored in reply to file
    std::ofstream ofs(injections.str(), std::ios::app);
    if (ofs.is_open()) {
        // Assuming reply contains a DebugString method for human-readable output
        ofs << "Injection at instruction: 0x" << std::hex << ip
           << ", Register: " << REG_StringShort(reg) << ", Vector: " << j
           << ", Original Value: 0x" << std::hex << xmmValue
           << ", Mask: 0x" << std::hex << mask
           << ", Injected Value: 0x" << std::hex <<injectedValue
           <<" func=" << (RTN_Valid(rtn) ? RTN_Name(rtn) : "??") <<" Query ID :" << std::dec <<tdata->queryId<< std::endl;
        ofs.close();
    } else {
        fprintf(stderr, "Failed to open file %s for writing knn_answer\n", injections.str().c_str());
    }
   PIN_ReleaseLock(&globalLock);

        PIN_ExecuteAt(ctxt);
}


// Injects a single bit flip into the specified register
VOID InjectBitFlip(ADDRINT ip,UINT32 regIndex, REG reg, CONTEXT *ctxt,THREADID tid) {
    ThreadData* tdata = static_cast<ThreadData*>(PIN_GetThreadData(tls_key, tid));
      //Ελεγχος εδω, γιατι το injection window (δηλαδή το flag tdata->inject) μπορεί να αλλάζει δυναμικά κατά την εκτέλεση
//injection_commands <<"inside2";
  //  ThreadData* tdata = static_cast<ThreadData*>(PIN_GetThreadData(tls_key, tid));
    if( tdata->trace==false ||
          tdata->inject==false||tdata->queryId == 12345)return; //Ελεγχος εδω, γιατι το injection window (δηλαδή το flag tdata->inject) μπορεί να αλλάζει δ>
    if(tdata->select_spots==false)selectInjectionSpots(tdata,tid);

// PIN_ReleaseLock(&globalLock);
// 3) If no more spots, just return
    if (tdata->injectionSpots.empty()) {
        return;
    }

// 4) Compare against the next spot (the front of the vector):
    if (tdata->InstCount != tdata->injectionSpots[0]) {
    // Not our turn yet—skip injection
       tdata->InstCount++;
       return;
    }
    tdata->injectionSpots.erase(tdata->injectionSpots.begin());
       tdata->InstCount++;
    //if(globalInstCountinject!=v){
    //  globalInstCountinject++;
   //   return;
//return;
//PIN_ReleaseLock(&globalLock);
//    return;/////////////////////
    if(REG_valid(reg)){
    reg = REG_FullRegName(reg);
    ADDRINT regValue = PIN_GetContextReg(ctxt, reg); // Get the current value of the register
    PIN_GetLock(&globalLock, tid+1);
    UINT32 injectBit = /*generateRandomNumber(seed)*/generateRandomNumberNonDeterministic() % (sizeof(UINT32) * 8); // MOST SDCs FOUND ON LEAST>    
    PIN_ReleaseLock(&globalLock);
    ADDRINT mask = 1UL << injectBit; // Create a mask for the bit flip
    ADDRINT injectedValue = regValue ^ mask; // Apply the bit flip
    PIN_SetContextReg(ctxt, reg, injectedValue); // Update the register with the new value

    // Log the details of the injection// LOGOUT
/*
    PIN_GetLock(&globalLock, tid+1);
    injection_commands << "Injection at instruction: 0x" << std::hex << ip
           << ", Register: " << REG_StringShort(reg)
           << ", Original Value: 0x" << std::hex << regValue
           << ", Mask: 0x" << std::hex << mask
           << ", Injected Value: 0x" << std::hex << injectedValue<<", Query: "<< tdata->queryId
           << std::endl;
    PIN_ReleaseLock(&globalLock);
*/

PIN_LockClient();
RTN rtn = RTN_FindByAddress(ip);
//INS ins = INS_FindByAddress(ip);
//std::string disasem = INS_Valid(ins) ? INS_Disassemble(ins) : "UNKNOWN_INSTRUCTION";
PIN_UnlockClient();



   PIN_GetLock(&globalLock, tid+1);



//       injection_commands << "Injection at instruction: 0x" << std::hex << ip
//           << ", Register: " << REG_StringShort(reg) << ", Vector: " << j
 //          << ", Original Value: 0x" << std::hex << xmmValue
  //         << ", Mask: 0x" << std::hex << mask
  //         << ", Injected Value: 0x" << std::hex <<injectedValue
  //         << " Query ID :" << std::dec <<queryId<< std::endl;
    std::ostringstream injections;
    injections << "injection_results.txt";

    // Serialize the knn_answer stored in reply to file
    std::ofstream ofs(injections.str(), std::ios::app);
    if (ofs.is_open()) {
        // Assuming reply contains a DebugString method for human-readable output
        ofs <<"Injection at instruction: 0x" << std::hex << ip
           <<", Register: " << REG_StringShort(reg)
           << ", Original Value: 0x" << std::hex << regValue
           << ", Mask: 0x" << std::hex << mask
           << ", Injected Value: 0x" << std::hex <<injectedValue
           <<" func=" << (RTN_Valid(rtn) ? RTN_Name(rtn) : "??") <<" Query ID :" << std::dec <<tdata->queryId<< std::endl;
        ofs.close();
    } else {
        fprintf(stderr, "Failed to open file %s for writing knn_answer\n", injections.str().c_str());
    }
   PIN_ReleaseLock(&globalLock);
    PIN_ExecuteAt(ctxt);
 }
}




///////////////////////////
/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////
    VOID CountInstructionWithLock(THREADID tid) {
        ThreadData* tdata = static_cast<ThreadData*>(PIN_GetThreadData(tls_key, tid));
        if (tdata->trace == false || tdata->queryId == 12345 || tdata->inject == true)return;
    //    if(queryId == 12345) return;
    //    if (inject == true)return;
        PIN_GetLock(&pinLock, tid+1);        // παίρνουμε το lock (ίδιος με thread id)
        tdata->InstCount++;
        *sharedValue=tdata->InstCount;
        PIN_ReleaseLock(&pinLock);           // απελευθερώνουμε
    }

// Instruments write registers of each instruction for fault injection
VOID InstructionInstrumentation(INS ins, VOID *v) {

///////////////////////////////////////////////////////////////////////////////////////////////////
 INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)ThreadLock, IARG_THREAD_ID, IARG_END);

 INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)GetOpCode, IARG_INST_PTR, IARG_UINT32, INS_Size(ins) , IARG_PTR, strdup(INS_Disassemble(ins).c_str()),IARG_THREAD_ID, IARG_END);

 INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)ThreadReleaseLock, IARG_END);
///////////////////////////////////////////////////////////////////////////////////////////////////
    if (!isValidInst(ins))
        return;
 //   if (INS_Mnemonic(ins) == "XOR") {
  //      return;
   // }
//injection_commands <<"inside10"<<std::endl;
//////////////////////////////////////////////////////////

    if (!(IsArithmeticLogicInstruction(ins))) // Select a r>) {
        return; // Skip non-arithmetic/logic instructions
//injection_commands <<"inside11"<<std::endl;

    int numW = INS_MaxNumWRegs(ins); // Get the number of write registers for the instruction
    if (numW == 0) return; // Skip if no write registers are available

    int randW = generateRandomNumber(17) % numW; // Select a random write register
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


    if (!REG_valid(reg) || (REG_is_any_app_flags(reg)||(reg == REG_RFLAGS || reg == REG_FLAGS || reg == REG_EFLAGS
|| reg == REG_STACK_PTR || reg == REG_RBP|| reg == REG_EBP))){
            LOG("!!!!!!!!!REGNOTVALID: inst " + INS_Disassemble(ins) + "!!!!!!!!!!!!!\n");
            return;
      }
    if (REG_is_xmm(reg)||REG_is_ymm(reg)) {return;}
    INS_InsertCall(
        ins, IPOINT_BEFORE,
        AFUNPTR(CountInstructionWithLock),
        IARG_THREAD_ID,
        IARG_END
    );



    INS_InsertCall(
        ins, IPOINT_AFTER, (AFUNPTR)InjectBitFlip,
        IARG_INST_PTR, // Pass the instruction pointer
       // IARG_PTR, strdup(INS_Disassemble(ins).c_str()),   // disassembly string ως pointer
        IARG_UINT32, randW, // Pass the register index
        IARG_UINT32, reg, // Pass the register identifier
        IARG_CONTEXT, // Pass the full execution context
        IARG_THREAD_ID,
        IARG_END
    );
}

////
//injection_commands <<"inside12"<<std::endl;
/*
  //  UINT32 isvector;
    // Insert a call to inject a fault into the selected write register
    if (REG_is_xmm(reg)) {
//injection_commands <<"inside50"<<std::endl;////////
       if (isDoublePrecision(ins)) {
//injection_commands <<"inside3"<<std::endl;////////
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
//injection_commands <<"inside4"<<std::endl;
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
//injection_commands <<"inside6"<<std::endl;
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
//injection_commands <<"inside7"<<std::endl;
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
       if(isDoublePrecision(ins) || isSinglePrecision(ins) || isVectorDoublePrecision(ins) || isVectorSinglePrecision(ins)){
           INS_InsertCall(
              ins, IPOINT_BEFORE,
              AFUNPTR(CountInstructionWithLock),
              IARG_THREAD_ID,
             IARG_END
           );
       }
    }*/







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

////////////////////////
    // Αρχικοποίηση του global lock
    PIN_InitLock(&globalLock);
    PIN_InitLock(&pinLock);
    // Δημιουργία TLS key
    tls_key = PIN_CreateThreadDataKey(NULL);
    numInject = KnobNumInjections.Value();
    // Εγγραφή callbacks για το ξεκίνημα και το τέλος νημάτων
    PIN_AddThreadStartFunction(ThreadStart, NULL);
    PIN_AddThreadFiniFunction(ThreadFini, NULL);

PIN_AddForkFunction(FPOINT_BEFORE,            BeforeFork,        NULL);
PIN_AddForkFunction(FPOINT_AFTER_IN_PARENT,   AfterForkInParent, NULL);
PIN_AddForkFunction(FPOINT_AFTER_IN_CHILD,    AfterForkInChild,  NULL);
//    TRACE_AddInstrumentFunction(Trace, nullptr);
    // Εγγραφή instrumentation για routines (για την ανίχνευση των ορίων του w>
    RTN_AddInstrumentFunction(RoutineInstrumentation, NULL);

    // Εγγραφή του callback για τις ρουτίνες
//    RTN_AddInstrumentFunctio
/////////


    INS_AddInstrumentFunction(InstructionInstrumentation, 0); // Register the instrumentation function

    // Εγγραφή του callback για τις ρουτίνες
//    RTN_AddInstrumentFunction(RoutinePrintQuery, 0);
   // Ενημέρωση (logging) ώστε να γνωρίζουμε σε ποιο process βρισκόμαστε
//    std::cout << "Process " << x << " is now running its instrumentation function." << std::endl;
    
    PIN_AddFiniFunction(Fini, 0); // Regiser the finalization function

    PIN_StartProgram(); // Start the target program execution
    return 0; // Should never reach here
}
