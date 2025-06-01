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
std::ofstream instructions;
std::ofstream OutFile;

#define LOGOUT std::cout
PIN_LOCK globalLock;



struct ThreadData {
    bool inject;
    int queryId;
};

static TLS_KEY tls_key;

VOID ThreadStart(THREADID tid, CONTEXT* ctxt, INT32 flags, VOID* v) {
    ThreadData* data = new ThreadData();
    data->inject = false;
    data->queryId = 0;
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
// Callback που "interpose" την BeginRequest και αποθηκεύει το query id στο TLS
VOID BeginRequestInterpose(int query_id, THREADID tid)
{
    // Αποθήκευση του query id για το τρέχον thread
    ThreadData* tdata = static_cast<ThreadData*>(PIN_GetThreadData(tls_key, tid));
    tdata->queryId = query_id;
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


VOID printInstruction (ADDRINT ip,THREADID tid,std::string* disasm)
{
    ThreadData* tdata = static_cast<ThreadData*>(PIN_GetThreadData(tls_key, tid));

    // Μετατροπή του queryId από string (16αδική μορφή) σε unsigned int
    //int queryId = std::stoul(tdata->queryId, nullptr, 16);
//    int queryId = std::stoi(tdata->queryId, nullptr, 16);
    int queryId= tdata->queryId;
    if(tdata && tdata->inject && (queryId == 130 || queryId == 270516 || queryId == 118093 || queryId == 10734) ) {//Ελεγχος εδω, γιατι το injection window (δηλαδή το flag tdata->inject) μπορεί να αλλάζει δυναμικά κατά την εκτέλεση
//        PIN_GetLock(&globalLock, tid);
PIN_LockClient();
        RTN rtn = RTN_FindByAddress(ip);
PIN_UnlockClient();
        const char* routineName = "Unknown";
        if (RTN_Valid(rtn))
            routineName = RTN_Name(rtn).c_str();
        
        // Ασφαλής πρόσβαση στο κοινόχρηστο output
        PIN_GetLock(&globalLock, tid);
        instructions << "At instruction: 0x" << std::hex << ip
                  << " in routine: " << routineName
                  << " | Instruction: " << disasm->c_str()
                  << " | Query ID: " << std::dec << tdata->queryId
                  << std::endl;
        PIN_ReleaseLock(&globalLock);
    }
}



// Instruments write registers of each instruction for fault injection
VOID InstructionInstrumentation(INS ins, VOID *v) {
    if (!isValidInst(ins))
        return;

    // Δημιουργία του string με την αποσυναρμολόγηση της instruction.
    // Η μνήμη δεσμεύεται μία φορά στο instrumentation και χρησιμοποιείται σε κάθε callback.
    std::string* disasm = new std::string(INS_Disassemble(ins));

    // Εισαγωγή του callback πριν την εκτέλεση της instruction,
    // μεταβιβάζοντας το instruction pointer, το thread id και το disassembled string.
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)printInstruction,
                   IARG_INST_PTR,
                   IARG_THREAD_ID,
                   IARG_PTR, disasm,
                   IARG_END);
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
    instructions.open("instructions.txt", std::ios::out | std::ios::trunc);
    if (!instructions.is_open()) {
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

    // Εγγραφή του callback για τις ρουτίνες
//    RTN_AddInstrumentFunction(RoutinePrintQuery, 0);

    INS_AddInstrumentFunction(InstructionInstrumentation, 0); // Register the instrumentation function

    // Εγγραφή του callback για τις ρουτίνες
//    RTN_AddInstrumentFunction(RoutinePrintQuery, 0);

    PIN_AddFiniFunction(Fini, 0); // Register the finalization function

    PIN_StartProgram(); // Start the target program execution
    return 0; // Should never reach here
}
