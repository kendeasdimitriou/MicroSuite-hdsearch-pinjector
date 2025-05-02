#include "pin.H"
#include <iostream>
#include <unordered_map>
#include <set>
#include <string>
#include <fstream>
#include <sstream>

// Για συντομία χρησιμοποιούμε τον std namespace
using namespace std;
std::ofstream outputFile;
// Λίστα επικίνδυνων routines (χωρίς το ".text")
std::set<std::string> gDangerousRoutines;
//std::unordered_map<ADDRINT, std::string> routineCache; // Cache για τις αναλύσεις RTN
/**
 * Συνάρτηση που διαβάζει από το αρχείο "filename" (ένα όνομα routine ανά γραμμή)
 * και προσθέτει κάθε routine στο global set gDangerousRoutines.
 */
void loadDangerousRoutines(const std::string &filename) {
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
        gDangerousRoutines.insert(routine);
    }
    infile.close();
}

// Λίστα για τις routines που χαρακτηρίστηκαν επικίνδυνες λόγω κλήσεων προς επικίνδυνες routines
std::set<std::string> gExtendedDangerousRoutines;

/**
 * Συνάρτηση ελέγχου για κλήσεις (είτε direct είτε indirect).
 * Δέχεται ως όρισμα τη διεύθυνση του target και το όνομα της routine που περιέχει την εντολή.
 */
VOID CheckForCall(ADDRINT target, VOID* routineNamePtr)
{
  //  std::string *routineName1 = static_cast<std::string*>(routineNamePtr);

    //Έλεγχος αν το target address έχει ήδη αναλυθεί
  //  auto it = routineCache.find(target);
  //  if (it != routineCache.end()) {
  //      std::string calleeName = it->second;
   //     if (gDangerousRoutines.find(calleeName) != gDangerousRoutines.end()) {
   //         gExtendedDangerousRoutines.insert(*routineName1);
   //     }
   //     return;
   // }


    // Κλείδωμα για ασφαλή πρόσβαση στις εσωτερικές δομές του Pin
    PIN_LockClient();
    std::string *routineName = static_cast<std::string*>(routineNamePtr);
   ////// std::string *routineName = static_cast<std::string*>(routineNamePtr);
    RTN calledRtn = RTN_FindByAddress(target);
    if (RTN_Valid(calledRtn))
    {
        std::string calleeName = RTN_Name(calledRtn);
        if(calleeName == *routineName){PIN_UnlockClient();return;}
     //   routineCache[target] = calleeName;  // Αποθηκεύουμε το αποτέλεσμα για μελλοντική χρήση
    //    std::cout << *routineName << " -> " << calleeName << std::endl;
        if (gDangerousRoutines.find(calleeName) != gDangerousRoutines.end())
        {
//            std::cout << "[+] Routine \"" << *routineName 
  //                    << "\" calls dangerous routine \"" << calleeName << "\"" 
    //                  << std::endl;
            gExtendedDangerousRoutines.insert(*routineName);
        }
    }
    
    PIN_UnlockClient();
}

/**
 * Instruction instrumentation: Διατρέχει κάθε instruction στο binary και, αν είναι call,
 * εισάγει instrumentation για να ελεγχθεί αν καλεί κάποια επικίνδυνη routine.
 */
VOID InstructionInstrumentation(INS ins, VOID *v)
{
    UINT32 opcode = INS_Opcode(ins);
    if (INS_IsCall(ins) || opcode == XED_ICLASS_JMP || opcode == XED_ICLASS_JMP_FAR)
    {
        // Προσδιορίζουμε σε ποια routine ανήκει το instruction.
        // Χρησιμοποιούμε PIN_LockClient για να κάνουμε ασφαλή πρόσβαση σε RTN_FindByAddress.
        PIN_LockClient();
        RTN rtn = RTN_FindByAddress(INS_Address(ins));
        std::string routineName = "unknown";
        if (RTN_Valid(rtn))
        {
            routineName = RTN_Name(rtn);
        }
        PIN_UnlockClient();
        
        // Δημιουργούμε δυναμικά το όνομα της routine για να το μεταφέρουμε.
        std::string *routineNamePtr = new std::string(routineName);
        
        if (INS_IsDirectControlFlow(ins))
        {
            // Για direct call: λαμβάνουμε στατικά τον target.
            ADDRINT target = INS_DirectControlFlowTargetAddress(ins);
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)CheckForCall,
                           IARG_ADDRINT, target,
                           IARG_PTR, routineNamePtr,
                           IARG_END);
        }
        else
        {
            // Για indirect call: λαμβάνουμε τον target δυναμικά.
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)CheckForCall,
                           IARG_BRANCH_TARGET_ADDR,
                           IARG_PTR, routineNamePtr,
                           IARG_END);
        }
    }
}


// Συνάρτηση αρχικοποίησης του αρχείου
VOID InitializeOutputFile()
{
    outputFile.open("blacklisted_routines.txt"); // Άνοιγμα αρχείου

    if (!outputFile) 
    {
        std::cerr << "Error: Unable to open blacklisted.txt!" << std::endl;
        exit(1); // Τερματισμός αν αποτύχει το άνοιγμα
    }
}

/**
 * Συνάρτηση που καλείται στο τέλος της εκτέλεσης για εμφάνιση των αποτελεσμάτων.
 */
VOID Fini(INT32 code, VOID *v)
{
    outputFile << "\n=== Extended Dangerous Routines ===" << std::endl;
    for (const auto &name : gExtendedDangerousRoutines)
    {
        outputFile << name << std::endl;
    }
    outputFile.close();
}

/**
 * Κύρια συνάρτηση main του Pin Tool.
 */
int main(int argc, char * argv[])
{
    PIN_InitSymbols();
    if (PIN_Init(argc, argv))
    {
        std::cerr << "PIN initialization failed!" << std::endl;
        return 1;
    }
    InitializeOutputFile(); // Κλήση της συνάρτησης αρχικοποίησης του αρχείου
    loadDangerousRoutines("dangerous_routines.txt");    
    // Εγγραφή της λειτουργίας instrumentation για κάθε instruction.
    INS_AddInstrumentFunction(InstructionInstrumentation, 0);
    PIN_AddFiniFunction(Fini, 0);
    
    PIN_StartProgram();
    return 0;
}
