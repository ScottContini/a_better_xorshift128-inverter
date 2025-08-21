#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include <time.h>

// direct xorshift function 
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




// Given  state1_1  with an assumption that we know the least significant  known_bits  bits,
// and given outputs  x0  and  x1 ,
// Derive  known_bits  least significant bits of  state0_1  and  state1_2
void
update_states_from_known_state1_1_bits(uint64_t state1_1, uint64_t x0, uint64_t x1,
 int known_bits, uint64_t * state0_1, uint64_t * state1_2)
{
    uint64_t MASK;

    MASK = (1ULL << known_bits) - 1;
    if (known_bits < 64) {
      *state0_1 = ((x0 - state1_1) & MASK);
      *state1_2 = ((x1 - state1_1) & MASK);
    }
    else {
      *state0_1 = x0 - state1_1;
      *state1_2 = x1 - state1_1;
    }
}



// Given bits 0..25 of state0_1, state1_1, state1_2
// Figure out bits 26..63 of state1_1 using relations and corresponding state0_1, state1_2
// Specifically, for 32 <= i < 38 :
//    state1_2[i] = state0_1[i-23] ^ state0_1[i-6] ^ state0_1[i] ^ state0_1[i+17] ^ state1_1[i] ^ state1_1[i+26]
//
void
compute_bits26to63state1_1( uint64_t *state0_1, uint64_t *state1_1, uint64_t *state1_2, uint64_t x0, uint64_t x1 )
{
  int i;
  // the values up to  i < 6  do not involve state0_1[i-6] or state0_1[i-23]
  for (i=0; i < 6; ++i) {
    // state1_2[i] ^ state0_1[i] ^ state0_1[i+17] ^ state1_1[i] = state1_1[i+26]
    uint64_t bit = (*state1_2 >> i)&1;
    bit ^= (*state0_1 >> i)&1;
    bit ^= (*state0_1 >> (i+17))&1;
    bit ^= (*state1_1 >> i)&1;
    *state1_1 |= (bit << (i+26));
  }
  // optimisation below -- we don't really need to call this every time in the loop above
  // because all of the bits in the equation are completely dependent upon lower order bits
  update_states_from_known_state1_1_bits( *state1_1, x0, x1, i+27, state0_1, state1_2 );
  // We now have bits 0..32 of the states

  // the values from  6 <= i < 23  do not involve state0_1[i-23]
  for (; i < 23; ++i) {
    // state1_2[i] ^ state0_1[i-6] ^ state0_1[i] ^ state0_1[i+17] ^ state1_1[i] = state1_1[i+26]
    uint64_t bit = (*state1_2 >> i)&1;
    bit ^= (*state0_1 >> (i-6))&1;
    bit ^= (*state0_1 >> i)&1;
    bit ^= (*state0_1 >> (i+17))&1;
    bit ^= (*state1_1 >> i)&1;
    *state1_1 |= (bit << (i+26));
    // optimisation: we only need to update the states when  i+17  starts hitting bits we 
    // do not know.  It really comes down to the difference between 26 - 17 = 9, every 9 iterations.
    // I'm prefer counting every 8 iterations, just my binary nature and not a huge time penalty.
    if ((i&3)==0)
      update_states_from_known_state1_1_bits( *state1_1, x0, x1, i+27, state0_1, state1_2 );
  }
  // update states before the last loop
  update_states_from_known_state1_1_bits( *state1_1, x0, x1, i+27, state0_1, state1_2 );

  for (; i < 38; ++i) {
    // state1_2[i] ^ state0_1[i-23] ^ state0_1[i-6] ^ state0_1[i] ^ state0_1[i+17] ^ state1_1[i] = state1_1[i+26]
    uint64_t bit = (*state1_2 >> i)&1;
    bit ^= (*state0_1 >> (i-23))&1;
    bit ^= (*state0_1 >> (i-6))&1;
    bit ^= (*state0_1 >> i)&1;
    bit ^= (*state0_1 >> (i+17))&1;
    bit ^= (*state1_1 >> i)&1;
    *state1_1 |= (bit << (i+26));
    // same optimisation as above
    if ((i&3)==0)
      update_states_from_known_state1_1_bits( *state1_1, x0, x1, i+27, state0_1, state1_2 );
  }
  // final update of states
  update_states_from_known_state1_1_bits( *state1_1, x0, x1, i+27, state0_1, state1_2 );

}


static inline uint64_t invert_right_xorshift(uint64_t y, int k) {
    uint64_t x = 0;
    for (int i = 63; i >= 0; --i) {
        uint64_t bit = (y >> i) & 1ULL;
        if (i + k <= 63) bit ^= (x >> (i + k)) & 1ULL;
        x |= bit << i;
    }
    return x;
}

static inline uint64_t invert_left_xorshift(uint64_t y, int k) {
    uint64_t x = 0;
    for (int i = 0; i <= 63; ++i) {
        uint64_t bit = (y >> i) & 1ULL;
        if (i - k >= 0) bit ^= (x >> (i - k)) & 1ULL;
        x |= bit << i;
    }
    return x;
}

// This function, xorshift128_back_step(), was generously provided by ChatGPT
void xorshift128_back_step(uint64_t *state0, uint64_t *state1) {
    // inputs are (new_state0, new_state1)
    uint64_t new_state0 = *state0;
    uint64_t new_state1 = *state1;

    uint64_t old_state1 = new_state0;
    uint64_t u = new_state1 ^ old_state1 ^ (old_state1 >> 26);

    // Invert: u = old0 ^ (old0 << 23) ^ (old0 >> 17)
    uint64_t y1 = invert_right_xorshift(u, 17);
    uint64_t old_state0 = invert_left_xorshift(y1, 23);

    *state0 = old_state0;
    *state1 = old_state1;
}


void
search(uint64_t x0,  uint64_t x1, uint64_t * derived_seed0, uint64_t * derived_seed1) {
    

    for (uint64_t low26_guess_state1_1=0; low26_guess_state1_1 < (1ULL <<26); ++low26_guess_state1_1) {
      uint64_t comp_state0_1, comp_state1_1, comp_state1_2;

      comp_state1_1 = (uint64_t)low26_guess_state1_1;
      update_states_from_known_state1_1_bits( comp_state1_1, x0, x1, 26, &comp_state0_1, &comp_state1_2);
      compute_bits26to63state1_1( &comp_state0_1, &comp_state1_1, &comp_state1_2, x0, x1 );
      uint64_t s0 = comp_state0_1;
      uint64_t s1 = comp_state1_1;
      xorshift128_direct_step(&s0, &s1);
      if (s0 + s1 == x1)  {
        //printf("final states: %llx %llx %6llx\n", comp_state0_1, comp_state1_1, comp_state1_2);
        *derived_seed0 = comp_state0_1;
        *derived_seed1 = comp_state1_1;
        xorshift128_back_step( derived_seed0, derived_seed1);
        return;
      }

    }
    printf("Code is buggy or bogus data sent in -- could not find original seed\n");
    exit(1);

}




double now_seconds(clockid_t clock_id) {
    struct timespec ts;
    clock_gettime(clock_id, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}



int main(int argc, char **argv) {
    // defaults
    uint64_t seed0 = 123456789ULL;
    uint64_t seed1 = 987654321ULL;

    if (argc >= 3) {
        printf("Taking seeds from command line\n");
        seed0 = strtoull(argv[1], NULL, 0); // accepts decimal or 0x...
        seed1 = strtoull(argv[2], NULL, 0);
    }

    printf("==========================================================================\n");

    uint64_t x0, x1, s0, s1;

    s0 = seed0;
    s1 = seed1;

    // Step once
    xorshift128_direct_step(&s0, &s1);
    // Output x0 from state1
    x0 = s0 + s1;

    // Step again
    xorshift128_direct_step(&s0, &s1);
    x1 = s0 + s1;


    printf("Initial seed was 0x%llx 0x%llx\nThe observed outputs were 0x%llx 0x%llx\n", seed0, seed1, x0, x1);

    uint64_t derived_seed0;
    uint64_t derived_seed1;

    printf("Attempting to invert xorshift128, please wait...\n\n");

    double t_real0 = now_seconds(CLOCK_REALTIME);
    double t_cpu0  = now_seconds(CLOCK_PROCESS_CPUTIME_ID);
    search( x0, x1, &derived_seed0, &derived_seed1);
    double t_real1 = now_seconds(CLOCK_REALTIME);
    double t_cpu1  = now_seconds(CLOCK_PROCESS_CPUTIME_ID);
    printf("Search ended after %.6f seconds (%.6f seconds CPU time)\n",t_real1 - t_real0, t_cpu1 - t_cpu0);

    printf("Derived seed: \033[1m0x%llx 0x%llx\n", derived_seed0, derived_seed1);
    if (derived_seed0 == seed0 && derived_seed1 == seed1) {
      printf("\033[1mSuccess!  \033[0mDon't forget to leave a tip in the tip jar.\n");
      printf("Next 16 outputs are:\n");
      s0 = derived_seed0; s1 = derived_seed1;
      for (int i=0; i < 16; ++i) {
        xorshift128_direct_step(&s0, &s1);
        printf("0x%llx (= decimal %llu)\n", s0+s1, s0+s1);
      }
    }
    else {
      printf("\033[1mFailure!  \033[0mPlease don't hurt me.\n");
    }

    return 0;
}

