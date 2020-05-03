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
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * For additional information about the PCG random number generation scheme,
 * including its license and other licensing options, visit
 *
 *       http://www.pcg-random.org
 */

/*
 * This code is derived from the full C implementation, which is in turn
 * derived from the canonical C++ PCG implementation. The C++ version
 * has many additional features and is preferable if you can use C++ in
 * your project.
 */

#include "pcg_basic.h"


extern inline void pcg_setseq_8_srandom_r(struct pcg_state_setseq_8* rng,
                                   uint8_t initstate, uint8_t initseq);
extern inline uint32_t pcg32_random_r(pcg32_random_t* rng);
extern inline void pcg32_srandom_r(pcg32_random_t* rng, uint64_t initstate,
                     uint64_t initseq);
extern inline void pcg_setseq_8_step_r(struct pcg_state_setseq_8* rng);

extern inline uint8_t  pcg8i_random_r(struct pcg_state_setseq_8* rng);

extern inline uint8_t pcg_output_rxs_m_xs_8_8(uint8_t state);

extern inline uint64_t pcg_setseq_8_rxs_m_xs_8_boundedrand_r(struct pcg_state_setseq_8* rng,
                                      uint8_t bound);

extern inline uint32_t pcg32_boundedrand_r(pcg32_random_t* rng, uint32_t bound);

