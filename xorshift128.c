#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// Use this program to generate outputs to feed into the other program, which will derive the seed from the outputs


void xorshift128_direct_step(uint64_t *state0, uint64_t *state1) {
    uint64_t old_state0 = *state0;
    uint64_t old_state1 = *state1;
    *state0 = old_state1;
    uint64_t t = old_state0;
    t ^= (t << 23);
    t ^= (t >> 17);
    t ^= old_state1;
    t ^= (old_state1 >> 26);
    *state1 = t;
}



int main(int argc, char **argv) {
    // defaults
    uint64_t seed0 = 123456789ULL;
    uint64_t seed1 = 987654321ULL;
    uint64_t outputs[9];

    printf("\n\n");
    if (argc >= 3) {
        printf("Taking seeds from command line\n");
        seed0 = strtoull(argv[1], NULL, 0); // accepts decimal or 0x...
        seed1 = strtoull(argv[2], NULL, 0);
    }
    else if (argc == 2) {
        printf("Taking one seed value from command line, using default for other value\n");
        seed0 = strtoull(argv[1], NULL, 0); // accepts decimal or 0x...
    }


    uint64_t x, s0, s1;
    int i;

    s0 = seed0;
    s1 = seed1;

    printf("Initial seed was 0x%llx 0x%llx\nThe observed outputs are:\n", seed0, seed1);

    for (i=0; i <8; ++i) {
      xorshift128_direct_step(&s0, &s1);
      x = s0 + s1;
      outputs[i] = x;
      printf("\t0x%llx\n", x);
    }

    printf("\nUse other program as follows:\n");
    printf("\n\t./inverter.out 0x%llx 0x%llx 0x%llx\n\n", outputs[0], outputs[1], outputs[2]);

}

