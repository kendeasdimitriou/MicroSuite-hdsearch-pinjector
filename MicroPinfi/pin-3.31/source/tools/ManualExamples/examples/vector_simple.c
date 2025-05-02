#include <stdio.h>
#include <stdlib.h>
#include <immintrin.h>

// Compute the dot product of two double arrays using AVX and horizontal addition.
double compute_dot(const double *a, const double *b, size_t n) {
    // We assume n is a multiple of 4.
    __m256d sum = _mm256_setzero_pd();
    for (size_t i = 0; i < n; i += 4) {
        // Load 4 doubles from a and b.
        __m256d va = _mm256_loadu_pd(a + i);       // vmovupd
        __m256d vb = _mm256_loadu_pd(b + i);       // vmovupd
        // Multiply: prod = va * vb.
        __m256d prod = _mm256_mul_pd(va, vb);        // vmulpd
        // Accumulate the products.
        sum = _mm256_add_pd(sum, prod);              // vaddpd (vector add)
    }
    // At this point, sum contains 4 double results.
    // We perform a horizontal sum:
    // Extract the lower 128 bits (2 doubles) from the 256-bit sum.
    __m128d low = _mm256_castpd256_pd128(sum);       // gets lower half
    // Extract the upper 128 bits.
    __m128d high = _mm256_extractf128_pd(sum, 1);      // vextractf128
    // Add the two halves together.
    __m128d sum128 = _mm_add_pd(low, high);            // vaddpd on 128-bit vectors

    // Now, sum128 contains two double values that need to be added.
    // Shuffle sum128 so that its two doubles are swapped.
    __m128d shuf = _mm_shuffle_pd(sum128, sum128, 0x1);  // vshufpd with immediate 0x1
    // Add the lower double of sum128 with the lower double of shuf.
    __m128d dot = _mm_add_sd(sum128, shuf);            // vaddsd (scalar add)

    // Return the resulting double.
    return _mm_cvtsd_f64(dot);
}

int main(void) {
    // For simplicity, use an array size of 4 (must be a multiple of 4).
    size_t n = 4;
    double *a = (double *)malloc(n * sizeof(double));
    double *b = (double *)malloc(n * sizeof(double));
    if (!a || !b) {
        fprintf(stderr, "Allocation failed\n");
        return EXIT_FAILURE;
    }

    // Initialize arrays: a = [1.0, 2.0, 3.0, 4.0], b = [2.0, 4.0, 6.0, 8.0]
    for (size_t i = 0; i < n; i++) {
        a[i] = (double)(i + 1);
        b[i] = 2.0 * (i + 1);
    }

    // Compute the dot product.
    double result = compute_dot(a, b, n);
    printf("Dot product: %f\n", result);

    free(a);
    free(b);
    return 0;
}
