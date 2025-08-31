#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include <time.h>
#include <inttypes.h>

// This program will find a seed that matches outputs from xorshift128.c.
// You can feed in either 2 or 3 consecutive outputs from xorshift128.c.
//    - If you provide only 2, then there is a chance that it will not find the same seed as was 
//      used from xorshift128.c, but will find a seed that matches those 2 outputs.
//    - If you provide 3 outputs, then it always seems to find the exact same seed (this is expected)
//      and will match all outputs.
//
//  ------------------------------------      THEORY      ------------------------------------
//
//  NOTATION (required to make sense of this code): XorShift128+ takes two 64-bit state inputs (state0, state1)
//  and transforms them into a new (state0, state1).  This gets confusing, so I have decided to use L for
//  state0 (think of it is the state on the left) and R for state1 (on the right).  See my blog for a picture.
//  We use "_0" to indicate the state at time 0, i.e. (L_0, R_0) is the initial state, aka the seed.
//  After the first iteration, we call it "_1" so (L_1, R_1).  After the second iteration, it is called (L_2, R_2).
//
//  We get outputs after each iteration which are the sum of the states.  We call these:
//      x0 = L_1 + R_1  (the first output)
//      x1 = L_2 + R_2  (the second output)
//      x2 = L_3 + R_3  (the third output)
//
//  The way the XorShift128+( ) algorithm works, we have the following properties:
//      L_2 = R_1       (we use this)
//      L_3 = R_2
//
//  NAIVE ATTACK (we don't do this): Brute forcing the internal state (L_0, R_0) would take 2^128 iterations.
//  We can do better
//
//  OUR ATTACK (i.e. this code): This code does a search on the order of 2^26 operations to derive the internal state.
//  One of the tricks is that we only need to figure out R_1 and then we can derive R_2 and L_1 using
//  knowledge of x0, x1 (explained below).  That would reduce it to 2^64 to brute force R_1, but then we also show
//  that you can determine R_1 in 2^26 operations by using x0 and x1.
//
//  WHY KNOWING R_1 IS ENOUGH TO DETERMINE REMAINING INTERNAL STATE: Remember, we know x0 and x1.  Just knowing
//  x0 and R_1, it tells us L_1 = x0 - R_1: we know both terms on right hand side, hence we know
//  L_1.  So we know the whole internal state after the first iteration!  We can then predict all future states.
//  The XorShift128+ is also invertible so we can get the initial state (i.e. the seed) too.
//
//  REDUCING THE SEARCH SPACE DOWN TO 2^26: This is the more clever part.  We need to get into details of how
//  XorShift128+ works, and specifically the part of it we are going to attack, which is from iteration 1 to iteraion 2.
//  During that step we have:
//        (L_1, R_1) is mapped to (L_2, R_2),
//  but we also know L_2 = R_1 so let's write that as:
//        (L_1, R_1) -> (R_1, R_2).
//  If you look at exactly how XorShift128+ is defined, you can write bits of R_2 as a function of the bits
//  of L_1 and R_1.  We will use brackets [] to indicate bit indices, for example R_2[i] means the
//  bit of R_2 correspond to index i  (i.e. R_2[i] is (R_2 >> i)&1).  Then the formula expressing
//  output bits from input bits is:
//      R_2[i] = L_1[i-23] ^ L_1[i-6] ^ L_1[i] ^ L_1[i+17] ^ R_1[i] ^ R_1[i+26]
//  Where anything with negative index should be treated as no contribution in the forumla.  We change this around
//  to have R_1[i+26] on the left hand side, which give us this equation that we call the "inductive equation":
//
//      R_1[i+26] = R_2[i] ^ L_1[i-23] ^ L_1[i-6] ^ L_1[i] ^ L_1[i+17] ^ R_1[i]
//
//  The inductive equation tells use that we can determine bit index i+26 of R_1 by knowing lower index bits of
//  L_1 and R_2.  Now imagine that we know the least significant 26 bits of R_1 (this is what we are
//  going to brute force).  Then we can determine the same least significant bits of L_1 and R_2 using
//  x0 and and x1 (the trick in "WHY KNOWING R_1 IS ENOUGH TO DETERMINE REMAINING INTERNAL STATE" but restricted
//  to only the bits we need).  In other words, we can exactly determine the next bit of R_1.  Using the
//  inductive equation, we can iterate and recover the remaining unknown bits.
//
//  So the algorithm guesses the least significant bits of R_1, derives the remaining bits using the inductive
//  equation while at the same time deriving the bits of L_1 and R_2 using x0.  It then checks if the
//  guess is correct by running XorShift128+ on the derived state values to see if it matches x0 and x1.  If so,
//  it is assumed to be a correct find.  I was expecting that I only needed to match x0 to confirm it, but then
//  I found that there are multiple seeds that can match a particular x0 sometimes when I derive the remaining values
//  the way I do.  Hence we also use x2 to check thatw e got the right one.


#define MAX_SOLUTIONS     16    // Multiple solutions possible when only 2 outputs provided

// Function declarations for clarity
void xorshift128_direct_step(uint64_t *state0, uint64_t *state1);
void update_states_from_known_R_1_bits(uint64_t R_1, uint64_t x0, uint64_t x1, int known_bits, uint64_t * L_1, uint64_t * R_2);
void compute_unknown_bits_FASTER( uint64_t *L_1, uint64_t *R_1, uint64_t *R_2, uint64_t x0, uint64_t x1 );
void compute_unknown_bits_of_3_state_values( uint64_t *L_1, uint64_t *R_1, uint64_t *R_2, uint64_t x0, uint64_t x1 );
void xorshift128_back_step(uint64_t *state0, uint64_t *state1);
double now_seconds(clockid_t clock_id);
void output_single_solution( uint64_t derived_seed0, uint64_t derived_seed1 );

// This is the core search logic, structured to accept either the fast or slow computation function.
// It iterates through all 2^26 guesses, computes the full state using the provided function,
// and validates the result. It returns 1 on success and 0 on failure.
int search_logic(uint64_t x0, uint64_t x1, uint64_t x2, uint64_t* derived_seed0, uint64_t* derived_seed1,
                 void (*compute_func)(uint64_t*, uint64_t*, uint64_t*, uint64_t, uint64_t))
{
    for (uint64_t low26_guess_R_1 = 0; low26_guess_R_1 < (1ULL << 26); ++low26_guess_R_1) {
        uint64_t cand_L_1, cand_R_1, cand_R_2;

        cand_R_1 = (uint64_t)low26_guess_R_1;
        update_states_from_known_R_1_bits(cand_R_1, x0, x1, 26, &cand_L_1, &cand_R_2);
        
        // Use the computation function passed as an argument (either fast or slow)
        compute_func(&cand_L_1, &cand_R_1, &cand_R_2, x0, x1);

        uint64_t s0 = cand_L_1;
        uint64_t s1 = cand_R_1;
        xorshift128_direct_step(&s0, &s1);
        if (s0 + s1 == x1) {
            xorshift128_direct_step(&s0, &s1);
            if (s0 + s1 == x2) {
                *derived_seed0 = cand_L_1;
                *derived_seed1 = cand_R_1;
                xorshift128_back_step(derived_seed0, derived_seed1);
                return 1; // Success: Found the seed
            }
        }
    }
    return 0; // Failure: Looped through all guesses and found nothing
}


// Implements a hybrid "optimistic-fallback" search strategy.
// It first tries a highly optimized parallel computation (`FASTER`). This version is
// extremely fast but fails for some inputs due to a subtle bug related to the carry
// bits in subtraction.
// If the fast search fails to find a seed, it's because the bug was triggered. The
// function then falls back to a slower, but guaranteed correct, serial computation.
// This gives the best of both worlds: high speed for "lucky" inputs, and guaranteed
// correctness for all inputs.
void search_from_3_outputs_hybrid(uint64_t x0, uint64_t x1, uint64_t x2,
                                  uint64_t* derived_seed0, uint64_t* derived_seed1)
{
    printf("Attempting FAST (optimistic) search first...\n");
    if (search_logic(x0, x1, x2, derived_seed0, derived_seed1, compute_unknown_bits_FASTER)) {
        printf("...FAST search SUCCEEDED!\n\n");
        return;
    }

    printf("...FAST search failed. This is an expected outcome for certain inputs.\n");
    printf("Falling back to SLOW (guaranteed correct) search...\n");
    if (search_logic(x0, x1, x2, derived_seed0, derived_seed1, compute_unknown_bits_of_3_state_values)) {
        printf("...SLOW search SUCCEEDED!\n\n");
        return;
    }

    // This should ideally never be reached if the inputs are valid.
    printf("Code is buggy or bogus data sent in -- could not find original seed with either method.\n");
    exit(1);
}

// Main function now only handles 3 outputs for clarity and uses the hybrid search.
int main(int argc, char **argv) {
    if (argc < 4) {
      printf("Please provide 3 consecutive outputs in command line\n");
      printf("Example: %s 0x3a1c3eec124a1dc5 0x741d90cb5d0c0b93 0xaff84efb22a790be\n", argv[0]);
      exit(0);
    }

    uint64_t derived_seed0;
    uint64_t derived_seed1;
    printf("Taking 3 observed values from command line\n");
    uint64_t x0 = strtoull(argv[1], NULL, 0);
    uint64_t x1 = strtoull(argv[2], NULL, 0);
    uint64_t x2 = strtoull(argv[3], NULL, 0);
    printf("The observed outputs were 0x%" PRIX64 " 0x%" PRIX64 " 0x%" PRIX64 "\n", x0, x1, x2);
    printf("==========================================================================\n");
    printf("Attempting to invert xorshift128, please wait...\n\n");

    double t_real0 = now_seconds(CLOCK_REALTIME);
    double t_cpu0  = now_seconds(CLOCK_PROCESS_CPUTIME_ID);
    
    // Use the new hybrid strategy
    search_from_3_outputs_hybrid(x0, x1, x2, &derived_seed0, &derived_seed1);

    double t_real1 = now_seconds(CLOCK_REALTIME);
    double t_cpu1  = now_seconds(CLOCK_PROCESS_CPUTIME_ID);
    printf("Search ended after %.6f seconds (%.6f seconds CPU time)\n", t_real1 - t_real0, t_cpu1 - t_cpu0);
    output_single_solution(derived_seed0, derived_seed1);

    return 0;
}


// --- Function Implementations ---

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

void update_states_from_known_R_1_bits(uint64_t R_1, uint64_t x0, uint64_t x1, int known_bits, uint64_t * L_1, uint64_t * R_2) {
    uint64_t MASK = (known_bits >= 64) ? ~0ULL : (1ULL << known_bits) - 1;
    *L_1 = (x0 - R_1) & MASK;
    *R_2 = (x1 - R_1) & MASK;
}

// High-performance (but buggy for some inputs) version.
// It works by processing entire 64-bit words at once instead of one bit at a time.
// THE BUG: This parallel approach incorrectly handles the carry-bit propagation
// during the subtraction `L_1 = x0 - R_1`. For certain "unlucky" inputs, this
// results in a corrupted state that fails validation. For "lucky" inputs, it
// produces the correct result very quickly.
void compute_unknown_bits_FASTER( uint64_t *L_1, uint64_t *R_1, uint64_t *R_2, uint64_t x0, uint64_t x1 ) {
    uint64_t new_bits, mask;

    // Phase 1: Compute bits 26 through 31 of R_1
    new_bits = (*R_2) ^ (*L_1) ^ (*L_1 >> 17) ^ (*R_1);
    mask = (1ULL << 6) - 1;
    *R_1 |= (new_bits & mask) << 26;
    update_states_from_known_R_1_bits(*R_1, x0, x1, 32, L_1, R_2);

    // Phase 2: Compute bits 32 through 48 of R_1
    new_bits = (*R_2) ^ (*L_1 << 6) ^ (*L_1) ^ (*L_1 >> 17) ^ (*R_1);
    mask = ((1ULL << 17) - 1) << 6;
    *R_1 |= (new_bits & mask) << 26;
    update_states_from_known_R_1_bits(*R_1, x0, x1, 49, L_1, R_2);

    // Phase 3: Compute bits 49 through 63 of R_1
    new_bits = (*R_2) ^ (*L_1 << 23) ^ (*L_1 << 6) ^ (*L_1) ^ (*L_1 >> 17) ^ (*R_1);
    mask = ((1ULL << 15) - 1) << 23;
    *R_1 |= (new_bits & mask) << 26;
    
    update_states_from_known_R_1_bits(*R_1, x0, x1, 64, L_1, R_2);
}

// Slower, but guaranteed correct version.
// This bit-by-bit iterative approach is the only one guaranteed to be correct.
// The dependencies caused by the subtractions (L_1=x0-R_1) create a carry chain
// that prevents simpler, word-level parallel optimizations from being universally correct.
void compute_unknown_bits_of_3_state_values( uint64_t *L_1, uint64_t *R_1, uint64_t *R_2, uint64_t x0, uint64_t x1 ) {
  int i;
  for (i=0; i < 6; ++i) {
    uint64_t bit = (*R_2 >> i)&1; bit ^= (*L_1 >> i)&1; bit ^= (*L_1 >> (i+17))&1; bit ^= (*R_1 >> i)&1; *R_1 |= (bit << (i+26));
  }
  update_states_from_known_R_1_bits( *R_1, x0, x1, i+26, L_1, R_2 );
  for (; i < 23; ++i) {
    uint64_t bit = (*R_2 >> i)&1; bit ^= (*L_1 >> (i-6))&1; bit ^= (*L_1 >> i)&1; bit ^= (*L_1 >> (i+17))&1; bit ^= (*R_1 >> i)&1; *R_1 |= (bit << (i+26));
    if ((i&7)==0) update_states_from_known_R_1_bits( *R_1, x0, x1, i+26, L_1, R_2 );
  }
  update_states_from_known_R_1_bits( *R_1, x0, x1, i+26, L_1, R_2 );
  for (; i < 38; ++i) {
    uint64_t bit = (*R_2 >> i)&1; bit ^= (*L_1 >> (i-23))&1; bit ^= (*L_1 >> (i-6))&1; bit ^= (*L_1 >> i)&1; bit ^= (*L_1 >> (i+17))&1; bit ^= (*R_1 >> i)&1; *R_1 |= (bit << (i+26));
    if ((i&7)==0) update_states_from_known_R_1_bits( *R_1, x0, x1, i+26, L_1, R_2 );
  }
  update_states_from_known_R_1_bits( *R_1, x0, x1, 64, L_1, R_2 );
}

void xorshift128_back_step(uint64_t *state0, uint64_t *state1) {
    uint64_t new_state0 = *state0; uint64_t new_state1 = *state1;
    uint64_t old_state1 = new_state0;
    uint64_t u = new_state1 ^ old_state1 ^ (old_state1 >> 26);
    uint64_t temp = u; temp ^= temp >> 17; temp ^= temp >> 34;
    uint64_t old_state0 = temp ^ (temp << 23) ^ (temp << 46);
    *state0 = old_state0; *state1 = old_state1;
}

double now_seconds(clockid_t clock_id) {
    struct timespec ts; clock_gettime(clock_id, &ts); return ts.tv_sec + ts.tv_nsec * 1e-9;
}

void output_single_solution( uint64_t derived_seed0, uint64_t derived_seed1 ) {
    printf("Derived seed: \033[1m0x%" PRIX64 " 0x%" PRIX64 "\n\033[0m", derived_seed0, derived_seed1);
    printf("Next 8 outputs are:\n");
    uint64_t s0 = derived_seed0, s1 = derived_seed1;
    for (int i=0; i < 8; ++i) {
      xorshift128_direct_step(&s0, &s1);
      printf("\t0x%" PRIX64 " (= decimal %" PRIu64 ")\n", s0+s1, s0+s1);
    }
}
