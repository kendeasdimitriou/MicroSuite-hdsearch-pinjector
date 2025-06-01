#include "pin.H"
#include <iostream>
#include <fstream>
#include <string>

std::ofstream outFile1;
ADDRINT targetStart = 0x40152c; // Διεύθυνση από το nm output
ADDRINT targetEnd = 0x40152c + 0x100; // Μπορείς να προσαρμόσεις αναλόγως

// Καταγραφή απλής εκτέλεσης με βάση τη διεύθυνση
VOID InstructionLogger(ADDRINT ip)
{
    if (ip >= targetStart && ip <= targetEnd)
    {
        outFile1 << "0x" << std::hex << ip << ": executed" << std::endl;
    }
}

// Καταγραφή disassembly χωρίς global αρχείο
VOID InstructionLoggerWithDisas(ADDRINT ip, const std::string* disas)
{
    static std::ofstream outFile("obj_min.txt", std::ios::out | std::ios::app);
    static bool header = false;
    if (!header) {
        outFile << "\n--- NEW RUN ---\n";
        header = true;
    }
    outFile << "0x" << std::hex << ip << ": " << *disas << std::endl;
}

// Επισκόπηση όλων των routine names για debugging (προαιρετικό)
VOID ImageLoad(IMG img, VOID* v)
{
    std::cerr << "[*] Loading image: " << IMG_Name(img) << std::endl;

    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)) {
            std::cerr << "Routine: " << RTN_Name(rtn) << " at 0x" << std::hex << RTN_Address(rtn) << std::endl;
        }
    }
}

// Εισαγωγή instrumentation σε κάθε εντολή
VOID Instruction(INS ins, VOID* v)
{
    ADDRINT ip = INS_Address(ins);

    if (ip >= targetStart && ip <= targetEnd)
    {
        // Logging διεύθυνσης
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)InstructionLogger,
                       IARG_INST_PTR,
                       IARG_END);

        // Logging disassembly
        std::string* disas = new std::string(INS_Disassemble(ins));
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)InstructionLoggerWithDisas,
                       IARG_INST_PTR,
                       IARG_PTR, disas,
                       IARG_END);
    }
}

VOID Fini(INT32 code, VOID* v)
{
    outFile1.close();
}

int main(int argc, char* argv[])
{
    if (PIN_Init(argc, argv)) {
        std::cerr << "PIN Init failed" << std::endl;
        return 1;
    }

    outFile1.open("min_element_trace.txt");

    IMG_AddInstrumentFunction(ImageLoad, nullptr);
    INS_AddInstrumentFunction(Instruction, nullptr);
    PIN_AddFiniFunction(Fini, nullptr);

    PIN_StartProgram();

    return 0;
}
