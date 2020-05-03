

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "pcg_basic.h"
//#include "entropy.h"                    // Wrapper around /dev/random

int main(int argc, char** argv)
{
	// Read command-line options

	int rounds = 5;

	pcg32_random_t rng;

	// You should *always* seed the RNG.  The usual time to do it is the
	// point in time when you create RNG (typically at the beginning of the
	// program).
	//
	// pcg32_srandom_r takes two 64-bit constants (the initial state, and the
	// rng sequence selector; rngs with different sequence selectors will
	// *never* have random sequences that coincide, at all) - the code below
	// shows three possible ways to do so.


	uint64_t seeding[2];
        FILE *fp;
 char* filename = "redo.txt";
 if ( ( fp = fopen ( filename, "r")) == NULL) {
        printf ( "could not open file\n");
        return 1;
    }


fscanf(fp,"%" PRIu64 " %" PRIu64,&seeding[0], &seeding[1]); //reading uint_64 from redo.txt
  pcg32_srandom_r(&rng, seeding[0],seeding[1]);//passing seed


	printf("pcg32_random_r:\n"
		"      -  result:      32-bit unsigned int (uint32_t)\n"
		"      -  period:      2^64   (* 2^63 streams)\n"
		"      -  state type:  pcg32_random_t (%zu bytes)\n"
		"      -  output func: XSH-RR\n"
		"\n",
		sizeof(pcg32_random_t));

	for (int round = 1; round <= rounds; ++round) {
		printf("Round %d:\n", round);

		/* Make some 32-bit numbers */
		printf("  32bit:");
		for (int i = 0; i < 6; ++i)
			printf(" 0x%08x", pcg32_random_r(&rng));
		printf("\n");

		//only for testing
   /* Toss some coins */
		printf("  Coins: ");
		for (int i = 0; i < 65; ++i)
			printf("%c", pcg32_boundedrand_r(&rng, 2) ? 'H' : 'T');
		printf("\n");

		/* Roll some dice */
		printf("  Rolls:");
		for (int i = 0; i < 33; ++i)
			printf(" %d", (int)pcg32_boundedrand_r(&rng, 6) + 1);
		printf("\n");

		/* Deal some cards */
		enum { SUITS = 4, NUMBERS = 13, CARDS = 52 };
		char cards[CARDS];

		for (int i = 0; i < CARDS; ++i)
			cards[i] = i;

		for (int i = CARDS; i > 1; --i) {
			int chosen = pcg32_boundedrand_r(&rng, i);
			char card = cards[chosen];
			cards[chosen] = cards[i - 1];
			cards[i - 1] = card;
		}

		printf("  Cards:");
		static const char number[] = { 'A', '2', '3', '4', '5', '6', '7',
									  '8', '9', 'T', 'J', 'Q', 'K' };
		static const char suit[] = { 'h', 'c', 'd', 's' };
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
