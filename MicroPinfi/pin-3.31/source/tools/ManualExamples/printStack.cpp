#include "pin.H"
#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>

// Αρχείο εξόδου για το stack dump
std::ofstream outFile;

// Συνάρτηση που εκτυπώνει το stack από τη διεύθυνση του ESP
VOID PrintStack(CONTEXT *ctxt)
{
    // Λήψη του ESP
    ADDRINT sp = PIN_GetContextReg(ctxt, REG_RSP);

    outFile << "Stack dump (x/32x esp):" << std::endl;
    
    const int numWords = 32; // Θα εκτυπωθούν 32 λέξεις (4-byte κάθε μία)
    for (int i = 0; i < numWords; i++) {
        uint32_t word = 0;
        // Ασφαλής ανάγνωση από τη μνήμη του target
        PIN_SafeCopy(&word, reinterpret_cast<VOID*>(sp + i * sizeof(uint32_t)), sizeof(uint32_t));
        outFile << "0x" << std::hex << std::setw(8) << std::setfill('0') << word << " ";
        if ((i + 1) % 8 == 0)
            outFile << std::endl;
    }
    outFile << std::dec << std::endl;
    outFile.flush();
}

// Instruction instrumentation για την εντοπισμό της συνάρτησης EndOfQuery
VOID InstrumentEndOfQuery(INS ins, VOID *v)
{
    // Ελέγχουμε αν η instruction ανήκει σε κάποια routine
    RTN rtn = INS_Rtn(ins);
    if (!RTN_Valid(rtn)) return;

    std::string rtnName = RTN_Name(rtn);
    // Εάν το όνομα της routine είναι EndOfQuery, προχωράμε
    if (rtnName == "EndOfQuery") {
        // Εάν η instruction είναι return instruction, τότε πριν αυτή εκτελεστεί, τυπώνουμε το stack
        if (INS_IsRet(ins)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)PrintStack, IARG_CONTEXT, IARG_END);
        }
    }
}

int main(int argc, char *argv[])
{
PIN_InitSymbols();
    // Αρχικοποίηση του Pin
    if (PIN_Init(argc, argv)) {
        std::cerr << "PIN_Init failed." << std::endl;
        return 1;
    }

    // Άνοιγμα αρχείου εξόδου για logging
    outFile.open("stack_dump.log");
    if (!outFile.is_open()) {
        std::cerr << "Could not open output file." << std::endl;
        return 1;
    }

    // Εγγραφή της συνάρτησης instrumentation για κάθε instruction
    INS_AddInstrumentFunction(InstrumentEndOfQuery, 0);

    // Ξεκινάει η εκτέλεση του target προγράμματος (δεν επιστρέφει)
    PIN_StartProgram();

    return 0;
}
