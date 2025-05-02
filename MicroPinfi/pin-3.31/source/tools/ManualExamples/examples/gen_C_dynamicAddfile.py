def generate_add_program_in_loop_with_asm(file_name, total_instructions=50000):
    """
    Generates a C program with a for loop executing 50,000 add instructions using inline assembly.

    :param file_name: Output C file name.
    :param total_instructions: Total number of add instructions to generate.
    """
    with open(file_name, "w") as f:
        f.write("#include <stdio.h>\n\n")
        f.write("int main() {\n")
        f.write("    int result = 0;\n")
        f.write(f"    for (int i = 0; i < {total_instructions}; i++) {{\n")
        f.write("        asm volatile (\"addl %%1, %%0\" : \"+r\"(result) : \"r\"(i));\n")
        f.write("    }\n")
        f.write("    printf(\"Final result: %d\\n\", result);\n")
        f.write("    return 0;\n")
        f.write("}\n")

# Generate the program
output_file = "dynamic_adds_in_loop_with_asm.c"
generate_add_program_in_loop_with_asm(output_file)
