#include "pin.H"
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>

// Αρχείο εξόδου για την καταγραφή των εντολών
std::ofstream outFile;

// Συνάρτηση για μετατροπή της κατηγορίας σε string (εδώ εμφανίζεται ο ακέραιος κωδικός)

// Συνάρτηση instrumentation που καλείται για κάθε εντολή
VOID Instruction(INS ins, VOID* v)
{
  if (!RTN_Valid(INS_Rtn(ins))) { // some library instructions do not have rtn !?
   // LOG("Invalid RTN " + INS_Disassemble(ins) + "\n");
    return;
  }

  if (!IMG_IsMainExecutable(SEC_Img(RTN_Sec(INS_Rtn(ins))))) {
//    LOG("Libraries " + IMG_Name(SEC_Img(RTN_Sec(INS_Rtn(ins)))) + "\n");
    return;
  }
  if (SEC_Name(RTN_Sec(INS_Rtn(ins))) != ".text") {
  // LOG("Section: " + SEC_Name(RTN_Sec(INS_Rtn(ins))) + "\n");
   return;
  }
//ψη της διεύθυνσης της εντολής
    ADDRINT addr = INS_Address(ins);
    
    // Λήψη ονόματος routine, αν υπάρχει
    std::string routineName = "unknown";
    RTN rtn = INS_Rtn(ins);
    if (RTN_Valid(rtn))
    {
        routineName = RTN_Name(rtn);
    }
    
    // Λήψη του disassembled κώδικα και της κατηγορίας της εντολής
    std::string disasm = INS_Disassemble(ins);
   // std::string categoryStr = CategoryToString(ins);
   std::string categoryName = CATEGORY_StringShort(INS_Category(ins));
    // Καταγραφή πληροφοριών: διεύθυνση, routine, disassembled εντολή και κατηγορία
    outFile << "Instruction at 0x" << std::hex << addr 
            << " in routine: " << routineName
            << " | " << disasm
            << " | Category: " << categoryName << std::endl;
}

INT32 Usage()
{
    std::cerr << "Χρήση: pin -t <tool> -- <application>" << std::endl;
    return -1;
}

int main(int argc, char * argv[])
{
    // Αρχικοποίηση του Pin
    if (PIN_Init(argc, argv))
    {
        return Usage();
    }
        PIN_InitSymbols(); // Initialize Pin's symbol manager
    // Άνοιγμα αρχείου εξόδου για καταγραφή
    outFile.open("instr_stats.log");
    
    // Προσθήκη της instrumentation συνάρτησης για κάθε εντολή
    INS_AddInstrumentFunction(Instruction, 0);
    
    // Εκκίνηση του προγράμματος υπό Pin
    PIN_StartProgram();
    
    return 0;
}
