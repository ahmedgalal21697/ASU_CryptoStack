/*
 * PCG Random Number Generation for C.
 *
 * Copyright 2014 Melissa O'Neill <oneill@pcg-random.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * For additional information about the PCG random number generation scheme,
 * including its license and other licensing options, visit
 *
 *     http://www.pcg-random.org
 */

/*
 * This code is derived from the full C implementation, which is in turn
 * derived from the canonical C++ PCG implementation. The C++ version
 * has many additional features and is preferable if you can use C++ in
 * your project.
 */

#ifndef PCG_BASIC_H_INCLUDED
#define PCG_BASIC_H_INCLUDED 1

#include <inttypes.h>


typedef struct pcg_state_setseq_64 pcg32_random_t;
typedef struct pcg_state_setseq_8 pcg8i_random_t;

struct pcg_state_setseq_64 {    // Internals are *Private*.
    uint64_t state;             // RNG state.  All values are possible.
    uint64_t inc;               // Controls which RNG sequence (stream) is
                                // selected. Must *always* be odd.
};
struct pcg_state_setseq_8 {
    uint8_t state;
    uint8_t inc;
};

typedef struct {
    pcg32_random_t gen[2];
} pcg32x2_random_t;


// If you *must* statically initialize it, here's one.
/*typedef __uint128_t pcg128_t;
    #define PCG_128BIT_CONSTANT(high,low) \
            ((((pcg128_t)high) << 64) + low)
    #define PCG_HAS_128BIT_OPS 1 */
////////////////////////////////////////////////////////////////

 #define PCG_DEFAULT_MULTIPLIER_8   141U
 #define PCG_STATE_SETSEQ_8_INITIALIZER      { 0x9bU, 0xdbU }
//////////////////////////////////////////////////////////////////////
#define PCG32_INITIALIZER   { 0x853c49e6748fea9bULL, 0xda3e39cb94b95bdbULL }
#define PCG_DEFAULT_MULTIPLIER_128 \
        PCG_128BIT_CONSTANT(2549297995355413924ULL,4865540595714422341ULL)
///////////////////////////////////////////////////////////
#define PCG_DEFAULT_MULTIPLIER_128 \
        PCG_128BIT_CONSTANT(2549297995355413924ULL,4865540595714422341ULL)
#define PCG_DEFAULT_INCREMENT_128  \
        PCG_128BIT_CONSTANT(6364136223846793005ULL,1442695040888963407ULL)
/////////////////////////////////////////////////////////////////////////////////
inline uint32_t pcg32_random_r(pcg32_random_t* rng)
{
    uint64_t oldstate = rng->state;
//printf("oldstate  0x%08x \n",oldstate);
    rng->state = oldstate * 6364136223846793005ULL + rng->inc;
  //  printf("new one 0x%08x \n",rng->state);
    uint32_t xorshifted = ((oldstate >> 18u) ^ oldstate) >> 27u;
    uint32_t rot = oldstate >> 59u;
    return (xorshifted >> rot) | (xorshifted << ((-rot) & 31));
}
inline void pcg32_srandom_r(pcg32_random_t* rng, uint64_t initstate, uint64_t initseq)
{
    rng->state = 0U;
    rng->inc = (initseq << 1u) | 1u;
    pcg32_random_r(rng);
    rng->state += initstate;
    pcg32_random_r(rng);
}
inline void pcg_setseq_8_step_r(struct pcg_state_setseq_8* rng)
{
    rng->state = rng->state * PCG_DEFAULT_MULTIPLIER_8 + rng->inc;
}

inline void pcg_setseq_8_srandom_r(struct pcg_state_setseq_8* rng,
                                   uint8_t initstate, uint8_t initseq)
{
    rng->state = 0U;
    rng->inc = (initseq << 1u) | 1u;
    pcg_setseq_8_step_r(rng);
    rng->state += initstate;
    pcg_setseq_8_step_r(rng);
}
inline uint8_t pcg_output_rxs_m_xs_8_8(uint8_t state)
{
    uint8_t word = ((state >> ((state >> 6u) + 2u)) ^ state) * 217u;
    return (word >> 6u) ^ word;
}

inline uint8_t pcg8i_random_r(struct pcg_state_setseq_8* rng)
{
    uint8_t oldstate = rng->state;
    pcg_setseq_8_step_r(rng);
    return pcg_output_rxs_m_xs_8_8(oldstate);
}







/////////////////////////////////////////////////////////////////////////
/*uint64_t pcg_rotr_64(uint64_t value, unsigned int rot)
{

    return (value >> rot) | (value << ((- rot) & 63));

}
 void pcg_setseq_128_step_r(struct pcg_state_setseq_128* rng)
{
    rng->state = rng->state * PCG_DEFAULT_MULTIPLIER_128 + rng->inc;
}
 uint64_t pcg_output_xsl_rr_128_64(pcg128_t state)
{
    return pcg_rotr_64(((uint64_t)(state >> 64u)) ^ (uint64_t)state,
                       state >> 122u);
}
 uint64_t pcg64_random_r(struct pcg_state_setseq_128* rng)
{
    pcg_setseq_128_step_r(rng);
    return pcg_output_xsl_rr_128_64(rng->state);
}


*/
inline uint32_t pcg32_boundedrand_r(pcg32_random_t* rng, uint32_t bound)
{
    // To avoid bias, we need to make the range of the RNG a multiple of
    // bound, which we do by dropping output less than a threshold.
    // A naive scheme to calculate the threshold would be to do
    //
    //     uint32_t threshold = 0x100000000ull % bound;
    //
    // but 64-bit div/mod is slower than 32-bit div/mod (especially on
    // 32-bit platforms).  In essence, we do
    //
    //     uint32_t threshold = (0x100000000ull-bound) % bound;
    //
    // because this version will calculate the same modulus, but the LHS
    // value is less than 2^32.

    uint32_t threshold = -bound % bound;

    // Uniformity guarantees that this loop will terminate.  In practice, it
    // should usually terminate quickly; on average (assuming all bounds are
    // equally likely), 82.25% of the time, we can expect it to require just
    // one iteration.  In the worst case, someone passes a bound of 2^31 + 1
    // (i.e., 2147483649), which invalidates almost 50% of the range.  In
    // practice, bounds are typically small and only a tiny amount of the range
    // is eliminated.
    for (;;) {
        uint32_t r = pcg32_random_r(rng);
        if (r >= threshold)
            return r % bound;
    }
}







inline void pcg32x2_srandom_r(pcg32x2_random_t* rng, uint64_t seed1, uint64_t seed2,
                       uint64_t seq1,  uint64_t seq2)
{
    uint64_t mask = ~0ull >> 1;
    // The stream for each of the two generators *must* be distinct
    if ((seq1 & mask) == (seq2 & mask))
        seq2 = ~seq2;
    pcg32_srandom_r(rng->gen,   seed1, seq1);
    pcg32_srandom_r(rng->gen+1, seed2, seq2);
}

inline uint64_t pcg32x2_random_r(pcg32x2_random_t* rng)
{
    return ((uint64_t)(pcg32_random_r(rng->gen)) << 32)
           | pcg32_random_r(rng->gen+1);
}
inline uint64_t pcg32x2_boundedrand_r(pcg32x2_random_t* rng, uint64_t bound)
{
    uint64_t threshold = -bound % bound;
    for (;;) {
        uint64_t r = pcg32x2_random_r(rng);
        if (r >= threshold)
            return r % bound;
    }
}
inline uint64_t pcg_setseq_8_rxs_m_xs_8_boundedrand_r(struct pcg_state_setseq_8* rng,
                                      uint8_t bound)
{
    uint8_t threshold = ((uint8_t)(-bound)) % bound;
    for (;;) {
        uint8_t r =pcg8i_random_r(rng);
        if (r >= threshold)
            return r % bound;
    }
}

#endif // PCG_BASIC_H_INCLUDED
