def generate_add_program_with_asm(file_name, total_instructions=50000, instructions_per_function=100):
    """
    Generates a C program with static add instructions implemented using inline assembly.

    :param file_name: Output C file name.
    :param total_instructions: Total number of add instructions to generate.
    :param instructions_per_function: Number of add instructions per function.
    """
    with open(file_name, "w") as f:
        f.write("#include <stdio.h>\n\n")

        # Number of functions needed
        num_functions = total_instructions // instructions_per_function

        for i in range(num_functions):
            f.write(f"void add_function_{i}() {{\n")
            for j in range(instructions_per_function):
                f.write(f"    int result_{i}_{j} = 0;\n")
                f.write(f"    asm(\"addl $1, %0\" : \"=r\"(result_{i}_{j}) : \"0\"(result_{i}_{j}));\n")
            f.write("}\n\n")

        f.write("int main() {\n")
        for i in range(num_functions):
            f.write(f"    add_function_{i}();\n")
        f.write("    return 0;\n")
        f.write("}\n")

# Generate the program
output_file = "static_adds_with_asm.c"
generate_add_program_with_asm(output_file)
