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
 *     http://www.pcg-random.org
 */

/*
 * This file was mechanically generated from tests/check-pcg32.c
 */

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>

#include "pcg_basic.h"

int main(int argc, char** argv)
{
    // Read command-line options

    int rounds = 5;


    pcg8i_random_t rng;




uint8_t seeding[2];
        FILE *fp;
 char* filename = "redo.txt";
 if ( ( fp = fopen ( filename, "r")) == NULL) {
        printf ( "could not open file\n");
        return 1;
    }


fscanf(fp,"%" PRIu8 " %" PRIu8,&seeding[0], &seeding[1]); //reading uint_64 from redo.txt
  pcg_setseq_8_srandom_r(&rng, seeding[0],seeding[1]);//passing seed

 printf("pcg8i_random_r:\n"
           "      -  result:      8-bit unsigned int (uint8_t)\n"
           "      -  period:      2^8   \n"
           " -  state type:  pcg8i_random_t (2 bytes)\n"
            "   -output func: RXS-M-XS\n"


           "\n",
           sizeof(pcg8i_random_t));



    for (int round = 1; round <= rounds; ++round) {
        printf("Round %d:\n", round);

        /* Make some 32-bit numbers */
        printf("  32bit:");
        for (int i = 0; i < 14; ++i)
            printf(" 0x%02x", pcg8i_random_r(&rng));
        printf("\n");


// only for testing //
        /* Toss some coins */
        printf("  Coins: ");
        for (int i = 0; i < 65; ++i)
            printf("%c", pcg_setseq_8_rxs_m_xs_8_boundedrand_r(&rng, 2) ? 'H' : 'T');
        printf("\n");

        /* Roll some dice */
        printf("  Rolls:");
        for (int i = 0; i < 33; ++i)
            printf(" %d", (int)pcg_setseq_8_rxs_m_xs_8_boundedrand_r(&rng, 6) + 1);
        printf("\n");

        /* Deal some cards */
        enum { SUITS = 4, NUMBERS = 13, CARDS = 52 };
        char cards[CARDS];

        for (int i = 0; i < CARDS; ++i)
            cards[i] = i;

        for (int i = CARDS; i > 1; --i) {
            int chosen =pcg_setseq_8_rxs_m_xs_8_boundedrand_r(&rng, i);
            char card = cards[chosen];
            cards[chosen] = cards[i - 1];
            cards[i - 1] = card;
        }

        printf("  Cards:");
        static const char number[] = {'A', '2', '3', '4', '5', '6', '7',
                                      '8', '9', 'T', 'J', 'Q', 'K'};
        static const char suit[] = {'h', 'c', 'd', 's'};
        for (int i = 0; i < CARDS; ++i) {
            printf(" %c%c", number[cards[i] / SUITS], suit[cards[i] % SUITS]);
            if ((i + 1) % 22 == 0)
                printf("\n\t");
        }
        printf("\n");

        printf("\n");
    }

    return 0;
}
