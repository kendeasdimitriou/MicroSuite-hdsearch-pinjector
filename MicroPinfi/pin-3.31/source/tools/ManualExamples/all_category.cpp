#include "pin.H"
#include <iostream>
#include <fstream>
#include <string>
#include <set>

// Global file and category tracker
static std::ofstream categoryLogFile;
static std::set<std::string> seenCategories;
static PIN_LOCK lock;


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

// Analysis routine: called for every instruction
VOID InstructionAnalysis(ADDRINT ip, INS ins, UINT32 numW, CONTEXT* ctxt) {
    std::string disassembled = INS_Disassemble(ins);
    std::string categoryName = CATEGORY_StringShort(INS_Category(ins));

    // Log first instruction of each new category
    if (seenCategories.find(categoryName) == seenCategories.end()) {
        // Thread-safe update
        PIN_GetLock(&lock, 1);
        if (seenCategories.find(categoryName) == seenCategories.end()) {
            categoryLogFile << categoryName << "->" << disassembled << std::endl;
            seenCategories.insert(categoryName);
        }
        PIN_ReleaseLock(&lock);
    }
}

// Instrumentation: insert call to analysis for every instruction
VOID InstructionInstrumentation(INS ins, VOID* v) {
    if (!isValidInst(ins))
        return;
    UINT32 numW = INS_MaxNumWRegs(ins);
    // Insert analysis before instruction executes
    INS_InsertCall(
        ins,
        IPOINT_BEFORE,
        (AFUNPTR)InstructionAnalysis,
        IARG_INST_PTR,
        IARG_PTR, ins,
        IARG_UINT32, numW,
        IARG_CONTEXT,
        IARG_END);
}

// Finalization routine: close file
VOID Fini(INT32 code, VOID* v) {
    if (categoryLogFile.is_open()) {
        categoryLogFile.close();
    }
    std::cout << "Done! Categories logged to category_log.txt" << std::endl;
}

int main(int argc, char* argv[]) {
    // Initialize PIN
    if (PIN_Init(argc, argv)) {
        std::cerr << "PIN Initialization failed!" << std::endl;
        return -1;
    }

    // Initialize lock and open log file
    PIN_InitLock(&lock);
    categoryLogFile.open("category_log.txt");
    if (!categoryLogFile) {
        std::cerr << "Failed to open category_log.txt for writing" << std::endl;
        return -1;
    }

    // Add instrumentation function
    INS_AddInstrumentFunction(InstructionInstrumentation, nullptr);

    // Register the finalization routine
    PIN_AddFiniFunction(Fini, nullptr);

    // Start the program
    PIN_StartProgram();
    return 0;
}

