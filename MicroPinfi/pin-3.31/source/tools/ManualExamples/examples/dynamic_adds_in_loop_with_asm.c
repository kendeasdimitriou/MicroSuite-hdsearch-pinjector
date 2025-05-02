#include <stdio.h>

int main() {
    int result = 0;
    for (int i = 0; i < 50000; i++) {
            asm("addl $1, %0" : "=r"(result) : "0"(result));
    }
    printf("Final result: %d\n", result);
    return 0;
}
