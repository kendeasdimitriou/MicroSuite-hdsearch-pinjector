#include <stdio.h>

void call(){
int a=5;
return;
}

void func1() {
    printf("This is function 1.\n");
    return;
}

void func2() {
    printf("This is function 2.\n");
    return;
}

void func3() {
    printf("This is function 3.\n");
    return;
}
int main() {
    int a = 10;
    int b = 5;
    int c = 20;
    int result1 = 0, result2 = 0;
    void (*operation)();
     int i=0;
  // code inside fault injection
     for ( i=0;i<5;i++){a++;}
  // code outside fault injection

    // First if statement
    if (a > b) {
        result1 = a + b; // Addition
        printf("Since a is greater than b, adding a and b gives: %d\n", result1);
    }

    // Second if statement
    if (c > a) {
        result2 = c - b; // Subtraction
        printf("Since c is greater than a, subtracting b from c gives: %d\n", result2);
    }
    operation = &call;
    operation();
    call();
    // Multiplication
    int product = a * c;
    printf("Multiplying a and c gives: %d\n", product);

    // Final result combining all operations
    int finalResult = result1 + result2 + product;
    printf("The sum of all results is: %d\n", finalResult);

    return 0;
}

