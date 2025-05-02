#include <stdio.h>
#include <math.h>



FILE *OutFile = NULL;

void FaultInjectionBegin() {
    if (OutFile) {
        fprintf(OutFile, "[Tool] Fault injection started.\n");
//        fflush(OutFile);
    }
}

void FaultInjectionEnd() {
    if (OutFile) {
        fprintf(OutFile, "[Tool] Fault injection ended.\n");
  //      fflush(OutFile);
    }
}

// Συνάρτηση προσομοίωσης Floating-Point Instructions
void simulate_floating_point_instructions() {
    // Παραδείγματα αριθμών
    float f1 = 7.5f, f2 = 3.3f;
    double d1 = 12.4, d2 = 4.2;

    printf("Simulating SPARC-like Floating-Point Instructions\n");

    // **1. Basic Arithmetic Operations**
    printf("Floating-Point Add (FADD): %.2f + %.2f = %.2f\n", f1, f2, f1 + f2);
    printf("Floating-Point Subtract (FSUB): %.2f - %.2f = %.2f\n", f1, f2, f1 - f2);
    printf("Floating-Point Multiply (FMUL): %.2f * %.2f = %.2f\n", f1, f2, f1 * f2);
    printf("Floating-Point Divide (FDIV): %.2f / %.2f = %.2f\n", f1, f2, f1 / f2);

    // **2. Square Root (FSQRT)**
    printf("Floating-Point Square Root (FSQRT): sqrt(%.2f) = %.2f\n", f1, sqrtf(f1));

    // **3. Floating-Point Comparisons**
    printf("Floating-Point Compare (FCMP): %.2f > %.2f = %d\n", f1, f2, f1 > f2);
    printf("Floating-Point Compare (FCMP): %.2f == %.2f = %d\n", f1, f2, f1 == f2);

    // **4. Conversion Between Float and Integer**
    printf("Floating-Point to Integer (FTOI): %.2f -> %d\n", f1, (int)f1);
    printf("Integer to Floating-Point (ITOF): %d -> %.2f\n", (int)d1, (float)((int)d1));

    // **5. Absolute Value (FABS)**
    printf("Floating-Point Absolute Value (FABS): |%.2f| = %.2f\n", -f1, fabsf(-f1));

    // **6. Negation (FNEG)**
    printf("Floating-Point Negation (FNEG): -%.2f = %.2f\n", f1, -f1);

    // **7. Remainder (FREM)**
    printf("Floating-Point Remainder (FREM): fmod(%.2f, %.2f) = %.2f\n", d1, d2, fmod(d1, d2));

    // **8. Trigonometric Operations**
    printf("Floating-Point Sin (FSIN): sin(%.2f) = %.2f\n", f1, sinf(f1));
    printf("Floating-Point Cos (FCOS): cos(%.2f) = %.2f\n", f1, cosf(f1));
    printf("Floating-Point Tan (FTAN): tan(%.2f) = %.2f\n", f1, tanf(f1));

    // **9. Exponentiation (FEXP)**
    printf("Floating-Point Exponentiation (FEXP): exp(%.2f) = %.2f\n", f1, expf(f1));

    // **10. Logarithmic Operations**
    printf("Floating-Point Natural Log (FLN): log(%.2f) = %.2f\n", f1, logf(f1));
    printf("Floating-Point Log Base 10 (FLOG10): log10(%.2f) = %.2f\n", f1, log10f(f1));

    // **11. Special Operations**
    printf("Floating-Point Power (FPOW): pow(%.2f, %.2f) = %.2f\n", f1, f2, powf(f1, f2));
    printf("Floating-Point Reciprocal (FRECIP): 1 / %.2f = %.2f\n", f1, 1.0f / f1);

    // **12. Handling NaN and Infinity**
    float nan_val = sqrtf(-1.0f);  // NaN
    float inf_val = 1.0f / 0.0f;   // Infinity
    printf("Floating-Point NaN: %.2f is NaN? %d\n", nan_val, isnan(nan_val));
    printf("Floating-Point Infinity: %.2f is Inf? %d\n", inf_val, isinf(inf_val));
}
void test_floating_point_operations() {
    // Παραδείγματα αριθμών
    float a = 3.5f, b = 2.2f;
    double x = 5.7, y = 3.3;

    // 1. Πρόσθεση
    printf("Float Add: %.2f + %.2f = %.2f\n", a, b, a + b);
    printf("Double Add: %.2lf + %.2lf = %.2lf\n", x, y, x + y);

    // 2. Αφαίρεση
    printf("Float Sub: %.2f - %.2f = %.2f\n", a, b, a - b);
    printf("Double Sub: %.2lf - %.2lf = %.2lf\n", x, y, x - y);

    // 3. Πολλαπλασιασμός
    printf("Float Mul: %.2f * %.2f = %.2f\n", a, b, a * b);
    printf("Double Mul: %.2lf * %.2lf = %.2lf\n", x, y, x * y);

    // 4. Διαίρεση
    printf("Float Div: %.2f / %.2f = %.2f\n", a, b, a / b);
    printf("Double Div: %.2lf / %.2lf = %.2lf\n", x, y, x / y);

    // 5. Τετραγωνική Ρίζα
    printf("Float Sqrt: sqrt(%.2f) = %.2f\n", a, sqrtf(a));
    printf("Double Sqrt: sqrt(%.2lf) = %.2lf\n", x, sqrt(x));

    // 6. Εκθετική Συνάρτηση
    printf("Float Exp: exp(%.2f) = %.2f\n", a, expf(a));
    printf("Double Exp: exp(%.2lf) = %.2lf\n", x, exp(x));
FaultInjectionBegin();
    // 7. Λογάριθμος
    printf("Float Log: log(%.2f) = %.2f\n", a, logf(a));
    printf("Double Log: log(%.2lf) = %.2lf\n", x, log(x));

 

   // 8. Τριγωνομετρικές Συναρτήσεις
    printf("Float Sin: sin(%.2f) = %.2f\n", a, sinf(a));
    printf("Double Sin: sin(%.2lf) = %.2lf\n", x, sin(x));

    printf("Float Cos: cos(%.2f) = %.2f\n", a, cosf(a));
    printf("Double Cos: cos(%.2lf) = %.2lf\n", x, cos(x));

    printf("Float Tan: tan(%.2f) = %.2f\n", a, tanf(a));
    printf("Double Tan: tan(%.2lf) = %.2lf\n", x, tan(x));

    // 9. Υπερβολικές Συναρτήσεις
    printf("Float Sinh: sinh(%.2f) = %.2f\n", a, sinhf(a));
    printf("Double Sinh: sinh(%.2lf) = %.2lf\n", x, sinh(x));

    printf("Float Cosh: cosh(%.2f) = %.2f\n", a, coshf(a));
    printf("Double Cosh: cosh(%.2lf) = %.2lf\n", x, cosh(x));

    printf("Float Tanh: tanh(%.2f) = %.2f\n", a, tanhf(a));
    printf("Double Tanh: tanh(%.2lf) = %.2lf\n", x, tanh(x));

    // 10. Αντίστροφες Τριγωνομετρικές Συναρτήσεις
    printf("Float Asin: asin(%.2f) = %.2f\n", a / 4, asinf(a / 4)); // Περιορισμός [-1, 1]
    printf("Double Asin: asin(%.2lf) = %.2lf\n", x / 10, asin(x / 10));

    printf("Float Acos: acos(%.2f) = %.2f\n", a / 4, acosf(a / 4));
    printf("Double Acos: acos(%.2lf) = %.2lf\n", x / 10, acos(x / 10));

    printf("Float Atan: atan(%.2f) = %.2f\n", a, atanf(a));
    printf("Double Atan: atan(%.2lf) = %.2lf\n", x, atan(x));

    // 11. Υπολοίπου Διαίρεσης
//FaultInjectionBegin();
    printf("Float Fmod: fmod(%.2f, %.2f) = %.2f\n", a, b, fmodf(a, b));
FaultInjectionEnd();
    printf("Double Fmod: fmod(%.2lf, %.2lf) = %.2lf\n", x, y, fmod(x, y));
//FaultInjectionEnd();
}

int main() {
    OutFile = fopen("fault_injection_log.txt", "w");
    if (OutFile == NULL) {
        perror("Error opening log file");
        return 1; // or handle error
    }
    printf("Testing Floating Point Instructions\n");
//FaultInjectionBegin();
    test_floating_point_operations();
//FaultInjectionEnd();
    simulate_floating_point_instructions();
//FaultInjectionEnd();
   return 0;
}
