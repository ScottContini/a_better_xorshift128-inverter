#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include <time.h>

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
//  and transforms them into a new (state0, state1).  We use "_0" to indicate the state at time 0, i.e.
//  (state0_0, state1_0) is the initial state, aka the seed.  After the first iteration, we call it "_1" so
//  (state0_1, state1_1).  After the second iteration, it is called (state0_2, state1_2).
//
//  We get outputs after each iteration which are the sum of the states.  We call these:
//      x0 = state0_1 + state1_1  (the first output)
//      x1 = state0_2 + state1_2  (the second output)
//      x2 = state0_3 + state1_3  (the third output)
//
//  The way the XorShift128+( ) algorithm works, we have the following properties:
//      state0_2 = state1_1       (we use this)
//      state0_3 = state1_2
//
//  NAIVE ATTACK (we don't do this): Brute forcing the internal state (state0_0, state1_0) would take 2^128 iterations.
//  We can do better
//
//  OUR ATTACK (i.e. this code): This code does a search on the order of 2^26 operations to derive the internal state.
//  One of the tricks is that we only need to figure out state1_1 and then we can derive state1_2 and state0_1 using
//  knowledge of x0, x1 (explained below).  That would reduce it to 2^64 to brute force state1_1, but then we also show
//  that you can determine state1_1 in 2^26 operations by using x0 and x1.
//
//  WHY KNOWING state1_1 IS ENOUGH TO DETERMINE REMAINING INTERNAL STATE: Remember, we know x0 and x1.  Just knowing
//  x0 and state1_1, it tells us state0_1 = x0 - state1_1: we know both terms on right hand side, hence we know
//  state0_1.  So we know the whole internal state after the first iteration!  We can then predict all future states.
//  The XorShift128+ is also invertible so we can get the initial state (i.e. the seed) too.
//
//  REDUCING THE SEARCH SPACE DOWN TO 2^26: This is the more clever part.  We need to get into details of how
//  XorShift128+ works, and specifically the part of it we are going to attack, which is from iteration 1 to iteraion 2.
//  During that step we have:
//        (state0_1, state1_1) is mapped to (state0_2, state1_2),
//  but we also know state0_2 = state1_1 so let's write that as:
//        (state0_1, state1_1) -> (state1_1, state1_2).
//  If you look at exactly how XorShift128+ is defined, you can write bits of state1_2 as a function of the bits
//  of state0_1 and state1_1.  We will use brackets [] to indicate bit indices, for example state1_2[i] means the
//  bit of state1_2 correspond to index i  (i.e. state1_2[i] is (state1_2 >> i)&1).  Then the formula expressing
//  output bits from input bits is:
//      state1_2[i] = state0_1[i-23] ^ state0_1[i-6] ^ state0_1[i] ^ state0_1[i+17] ^ state1_1[i] ^ state1_1[i+26]
//  Where anything with negative index should be treated as no contribution in the forumla.  We change this around
//  to have state1_1[i+26] on the left hand side, which give us this equation that we call the "inductive equation":
//
//      state1_1[i+26] = state1_2[i] ^ state0_1[i-23] ^ state0_1[i-6] ^ state0_1[i] ^ state0_1[i+17] ^ state1_1[i]
//
//  The inductive equation tells use that we can determine bit index i+26 of state1_1 by knowing lower index bits of
//  state0_1 and state1_2.  Now imagine that we know the least significant 26 bits of state1_1 (this is what we are
//  going to brute force).  Then we can determine the same least significant bits of state0_1 and state1_2 using
//  x0 and and x1 (the trick in "WHY KNOWING state1_1 IS ENOUGH TO DETERMINE REMAINING INTERNAL STATE" but restricted
//  to only the bits we need).  In other words, we can exactly determine the next bit of state1_1.  Using the
//  inductive equation, we can iterate and recover the remaining unknown bits.
//
//  So the algorithm guesses the least significant bits of state1_1, derives the remaining bits using the inductive
//  equation while at the same time deriving the bits of state0_1 and state1_2 using x0.  It then checks if the
//  guess is correct by running XorShift128+ on the derived state values to see if it matches x0 and x1.  If so,
//  it is assumed to be a correct find.  I was expecting that I only needed to match x0 to confirm it, but then
//  I found that there are multiple seeds that can match a particular x0 sometimes when I derive the remaining values
//  the way I do.  Hence we also use x2 to check thatw e got the right one.



#define MAX_SOLUTIONS     16    // Multiple solutions possible when only 2 outputs provided


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
// Specifically, for 0 <= i < 38 :
//    state1_2[i] = state0_1[i-23] ^ state0_1[i-6] ^ state0_1[i] ^ state0_1[i+17] ^ state1_1[i] ^ state1_1[i+26]
// where any index less than 0 is treated to have no contribution.
//
// Future TODO: Code below can be sped up a lot by using pre-computated tables involving all possible
// combinations of some known collections of bits.
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
    // optimisation: Normally we would call update_states_from_known_state1_1_bits() here
    // but in this case we don't need to because all of the bits in the equation are
    // completely dependent upon lower order bits, so postpone it to the end

  }
  update_states_from_known_state1_1_bits( *state1_1, x0, x1, i+27, state0_1, state1_2 );

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
    if ((i&7)==0)
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
    if ((i&7)==0)
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



// Given two outputs x0 and x1, find all seeds that generated them (up to MAX_SOLUTIONS).
// Returns the number of solutions found
int
search_from_2_outputs(uint64_t x0,  uint64_t x1, uint64_t derived_seed0[MAX_SOLUTIONS],
  uint64_t derived_seed1[MAX_SOLUTIONS]) {
    
    int soln_count = 0;
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
        derived_seed0[soln_count] = comp_state0_1;
        derived_seed1[soln_count] = comp_state1_1;
        xorshift128_back_step( &derived_seed0[soln_count], &derived_seed1[soln_count]);
        if (++soln_count == MAX_SOLUTIONS) {
          printf("exiting search early after discovering %d solutions\n",soln_count);
          return soln_count;
        }
      }

    }
    return soln_count;

}

// Given three outputs x0 and x1 and x2, try to find the seed that generated them.
void
search_from_3_outputs(uint64_t x0,  uint64_t x1, uint64_t x2,
  uint64_t * derived_seed0, uint64_t * derived_seed1)
{

    for (uint64_t low26_guess_state1_1=0; low26_guess_state1_1 < (1ULL <<26); ++low26_guess_state1_1) {
      uint64_t comp_state0_1, comp_state1_1, comp_state1_2;

      comp_state1_1 = (uint64_t)low26_guess_state1_1;
      update_states_from_known_state1_1_bits( comp_state1_1, x0, x1, 26, &comp_state0_1, &comp_state1_2);
      compute_bits26to63state1_1( &comp_state0_1, &comp_state1_1, &comp_state1_2, x0, x1 );
      uint64_t s0 = comp_state0_1;
      uint64_t s1 = comp_state1_1;
      xorshift128_direct_step(&s0, &s1);
      if (s0 + s1 == x1)  {
        // bring in x2 to check whether we got the right one
        xorshift128_direct_step(&s0, &s1);
        if (s0 + s1 != x2) {
          printf("Skipping a false positive that would have passed from 2 outputs only\n");
          continue;
        }
        *derived_seed0 = comp_state0_1;
        *derived_seed1 = comp_state1_1;
        xorshift128_back_step( derived_seed0, derived_seed1);
        return;
      }

    }
    printf("Code is buggy or bogus data sent in -- could not find original seed\n");
    exit(1);
}


// It's not often, but sometimes there are multiple solutions for the seed that produced x0, x1.
// To find the right one, you will need a third output, x2.
// This demo function shows an example where multiple seeds produce the same x0 and x1
void
demo_multiple_solutions( )
{
    uint64_t seed0;
    uint64_t seed1;
    uint64_t x0, x1, s0, s1;

    seed0 = 0xbabef00d12345678;
    seed1 = 1ULL;
    s0 = seed0;
    s1 = seed1;
    xorshift128_direct_step(&s0, &s1);
    x0 = s0 + s1;
    xorshift128_direct_step(&s0, &s1);
    x1 = s0 + s1;
    printf("\t\tDemo example: Seeds 0x%llx 0x%llx produce outputs %llx %llx\n", seed0, seed1, x0, x1);

    seed0 = 0x352e3b2a30800e34;
    seed1 = 0x2e36c694b0c71d9e;
    s0 = seed0;
    s1 = seed1;
    xorshift128_direct_step(&s0, &s1);
    x0 = s0 + s1;
    xorshift128_direct_step(&s0, &s1);
    x1 = s0 + s1;
    printf("\t\tDemo example: Seeds 0x%llx 0x%llx produce outputs %llx %llx\n", seed0, seed1, x0, x1);

    seed0 = 0xbaf0bc0d8f83042a;
    seed1 = 0xa0124bc0fdf8bd4c;
    s0 = seed0;
    s1 = seed1;
    // Step once
    xorshift128_direct_step(&s0, &s1);
    x0 = s0 + s1;
    xorshift128_direct_step(&s0, &s1);
    x1 = s0 + s1;
    printf("\t\tDemo example: Seeds 0x%llx 0x%llx produce outputs %llx %llx\n", seed0, seed1, x0, x1);
    
}


double now_seconds(clockid_t clock_id) {
    struct timespec ts;
    clock_gettime(clock_id, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

void
output_single_solution( uint64_t derived_seed0, uint64_t derived_seed1 )
{
    printf("Derived seed: \033[1m0x%llx 0x%llx\n", derived_seed0, derived_seed1);
    printf("Next 8 outputs are:\n");
    uint64_t s0, s1;
    s0 = derived_seed0; s1 = derived_seed1;
    for (int i=0; i < 8; ++i) {
      xorshift128_direct_step(&s0, &s1);
      printf("\t0x%llx (= decimal %llu)\n", s0+s1, s0+s1);
    }

}


void
output_all_solutions( int soln_count, uint64_t derived_seed0[MAX_SOLUTIONS], uint64_t derived_seed1[MAX_SOLUTIONS])
{
  if (soln_count > MAX_SOLUTIONS) {
    // Hey, I'm an AppSec guy.  Leave me alone.
    printf("Umm, something is weird, exiting.\n");
    exit(0);
  }
  if (soln_count == 0) {
    printf("Didn't find anything.  Either code is buggy or bogus inputs sent in.\n");
    exit(0);
  }
  if (soln_count == 1) {
    printf("Found the one solution which is definitely the answer!\n");
    output_single_solution( derived_seed0[0], derived_seed1[0] );
  }
  else {
    printf("There are %d solutions that generate these outputs.\n", soln_count );
    for (int j = 0; j < soln_count; ++j) {
      printf("\n--------------- Solution %d ---------------\n", j+1);
      output_single_solution( derived_seed0[j], derived_seed1[j] );
    }
  }
}


int
main(int argc, char **argv) {
    uint64_t x0, x1, x2;

    if (argc <  3) {
      printf("Please provide at least 2 (prefer 3) consecutive outputs in command line\n");
      printf("Example: %s 0x3a1c3eec124a1dc5 0x741d90cb5d0c0b93 0xaff84efb22a790be\n", argv[0]);
      exit(0);
    }
    else if (argc == 3) {
        uint64_t derived_seed0[MAX_SOLUTIONS];
        uint64_t derived_seed1[MAX_SOLUTIONS];
        int soln_count;
        printf("Taking 2 observed values from command line\n");
        x0 = strtoull(argv[1], NULL, 0); // accepts decimal or 0x...
        x1 = strtoull(argv[2], NULL, 0);
        printf("The observed outputs were 0x%llx 0x%llx\n", x0, x1);
        printf("==========================================================================\n");
        printf("Attempting to invert xorshift128, please wait...\n\n");

        double t_real0 = now_seconds(CLOCK_REALTIME);
        double t_cpu0  = now_seconds(CLOCK_PROCESS_CPUTIME_ID);
        soln_count = search_from_2_outputs( x0, x1, derived_seed0, derived_seed1);
        double t_real1 = now_seconds(CLOCK_REALTIME);
        double t_cpu1  = now_seconds(CLOCK_PROCESS_CPUTIME_ID);
        printf("Search ended after %.6f seconds (%.6f seconds CPU time)\n",t_real1 - t_real0, t_cpu1 - t_cpu0);
        output_all_solutions( soln_count, derived_seed0, derived_seed1 );
    }
    else if (argc >= 3) {
        uint64_t derived_seed0;
        uint64_t derived_seed1;
        printf("Taking 3 observed values from command line\n");
        x0 = strtoull(argv[1], NULL, 0); // accepts decimal or 0x...
        x1 = strtoull(argv[2], NULL, 0);
        x2 = strtoull(argv[3], NULL, 0);
        printf("The observed outputs were 0x%llx 0x%llx 0x%llx\n", x0, x1, x2);
        printf("==========================================================================\n");
        printf("Attempting to invert xorshift128, please wait...\n\n");

        double t_real0 = now_seconds(CLOCK_REALTIME);
        double t_cpu0  = now_seconds(CLOCK_PROCESS_CPUTIME_ID);
        search_from_3_outputs( x0, x1, x2, &derived_seed0, &derived_seed1);
        double t_real1 = now_seconds(CLOCK_REALTIME);
        double t_cpu1  = now_seconds(CLOCK_PROCESS_CPUTIME_ID);
        printf("Search ended after %.6f seconds (%.6f seconds CPU time)\n",t_real1 - t_real0, t_cpu1 - t_cpu0);
        output_single_solution( derived_seed0, derived_seed1 );
    }



    return 0;
}

