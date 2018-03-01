#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/wait.h>
#include <errno.h>
#include <semaphore.h>
#include <time.h>
#include <unistd.h>

/*	CAN Bus 9 nodes	*/
/*	
 *	Simulation of authentication method 
 *	described in 
 *	
 *	"Low Cost Multicast Network Authentication for Embedded Control Systems"(C.Szilagyi)
 */

#define SLEEP_TIME 1
#define SHA3_ASSERT( x )
#if defined(_MSC_VER)
#define SHA3_TRACE( format, ...)
#define SHA3_TRACE_BUF( format, buf, l, ...)
#else
#define SHA3_TRACE(format, args...)
#define SHA3_TRACE_BUF(format, buf, l, args...)
#endif

//#define SHA3_USE_KECCAK
/*
 * Define SHA3_USE_KECCAK to run "pure" Keccak, as opposed to SHA3.
 * The tests that this macro enables use the input and output from [Keccak]
 * (see the reference below). The used test vectors aren't correct for SHA3,
 * however, they are helpful to verify the implementation.
 * SHA3_USE_KECCAK only changes one line of code in Finalize.
 */

#if defined(_MSC_VER)
#define SHA3_CONST(x) x
#else
#define SHA3_CONST(x) x##L
#endif

/* The following state definition should normally be in a separate
 * header file
 */

/* 'Words' here refers to uint64_t */
#define SHA3_KECCAK_SPONGE_WORDS \
	(((1600)/8/*bits to byte*/)/sizeof(uint64_t))
typedef struct sha3_context_ {
	uint64_t saved;             /* the portion of the input message that we
				     * didn't consume yet */
	union {                     /* Keccak's state */
		uint64_t s[SHA3_KECCAK_SPONGE_WORDS];
		uint8_t sb[SHA3_KECCAK_SPONGE_WORDS * 8];
	};
	unsigned byteIndex;         /* 0..7--the next byte after the set one
				     * (starts from 0; 0--none are buffered) */
	unsigned wordIndex;         /* 0..24--the next word to integrate input
				     * (starts from 0) */
	unsigned capacityWords;     /* the double size of the hash output in
				     * words (e.g. 16 for Keccak 512) */
} sha3_context;

#ifndef SHA3_ROTL64
#define SHA3_ROTL64(x, y) \
	(((x) << (y)) | ((x) >> ((sizeof(uint64_t)*8) - (y))))
#endif

static const uint64_t keccakf_rndc[24] = {
	SHA3_CONST(0x0000000000000001UL), SHA3_CONST(0x0000000000008082UL),
	SHA3_CONST(0x800000000000808aUL), SHA3_CONST(0x8000000080008000UL),
	SHA3_CONST(0x000000000000808bUL), SHA3_CONST(0x0000000080000001UL),
	SHA3_CONST(0x8000000080008081UL), SHA3_CONST(0x8000000000008009UL),
	SHA3_CONST(0x000000000000008aUL), SHA3_CONST(0x0000000000000088UL),
	SHA3_CONST(0x0000000080008009UL), SHA3_CONST(0x000000008000000aUL),
	SHA3_CONST(0x000000008000808bUL), SHA3_CONST(0x800000000000008bUL),
	SHA3_CONST(0x8000000000008089UL), SHA3_CONST(0x8000000000008003UL),
	SHA3_CONST(0x8000000000008002UL), SHA3_CONST(0x8000000000000080UL),
	SHA3_CONST(0x000000000000800aUL), SHA3_CONST(0x800000008000000aUL),
	SHA3_CONST(0x8000000080008081UL), SHA3_CONST(0x8000000000008080UL),
	SHA3_CONST(0x0000000080000001UL), SHA3_CONST(0x8000000080008008UL)
};

static const unsigned keccakf_rotc[24] = {
	1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62,
	18, 39, 61, 20, 44
};

static const unsigned keccakf_piln[24] = {
	10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20,
	14, 22, 9, 6, 1
};

/* generally called after SHA3_KECCAK_SPONGE_WORDS-ctx->capacityWords words
 * are XORed into the state s
 */
	static void
keccakf(uint64_t s[25])
{
	int i, j, round;
	uint64_t t, bc[5];
#define KECCAK_ROUNDS 24

	for(round = 0; round < KECCAK_ROUNDS; round++) {

		/* Theta */
		for(i = 0; i < 5; i++)
			bc[i] = s[i] ^ s[i + 5] ^ s[i + 10] ^ s[i + 15] ^ s[i + 20];

		for(i = 0; i < 5; i++) {
			t = bc[(i + 4) % 5] ^ SHA3_ROTL64(bc[(i + 1) % 5], 1);
			for(j = 0; j < 25; j += 5)
				s[j + i] ^= t;
		}

		/* Rho Pi */
		t = s[1];
		for(i = 0; i < 24; i++) {
			j = keccakf_piln[i];
			bc[0] = s[j];
			s[j] = SHA3_ROTL64(t, keccakf_rotc[i]);
			t = bc[0];
		}

		/* Chi */
		for(j = 0; j < 25; j += 5) {
			for(i = 0; i < 5; i++)
				bc[i] = s[j + i];
			for(i = 0; i < 5; i++)
				s[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
		}

		/* Iota */
		s[0] ^= keccakf_rndc[round];
	}
}

/* *************************** Public Inteface ************************ */

/* For Init or Reset call these: */
	static void
sha3_Init256(void *priv)
{
	sha3_context *ctx = (sha3_context *) priv;
	memset(ctx, 0, sizeof(*ctx));
	ctx->capacityWords = 2 * 256 / (8 * sizeof(uint64_t));
}

	static void
sha3_Init384(void *priv)
{
	sha3_context *ctx = (sha3_context *) priv;
	memset(ctx, 0, sizeof(*ctx));
	ctx->capacityWords = 2 * 384 / (8 * sizeof(uint64_t));
}

	static void
sha3_Init512(void *priv)
{
	sha3_context *ctx = (sha3_context *) priv;
	memset(ctx, 0, sizeof(*ctx));
	ctx->capacityWords = 2 * 512 / (8 * sizeof(uint64_t));
}

	static void
sha3_Update(void *priv, void const *bufIn, size_t len)
{
	sha3_context *ctx = (sha3_context *) priv;

	/* 0...7 -- how much is needed to have a word */
	unsigned old_tail = (8 - ctx->byteIndex) & 7;

	size_t words;
	unsigned tail;
	size_t i;

	const uint8_t *buf = bufIn;

	SHA3_TRACE_BUF("called to update with:", buf, len);

	SHA3_ASSERT(ctx->byteIndex < 8);
	SHA3_ASSERT(ctx->wordIndex < sizeof(ctx->s) / sizeof(ctx->s[0]));

	if(len < old_tail) {
		/* have no complete word or haven't started
		 * the word yet */
		SHA3_TRACE("because %d<%d, store it and return", (unsigned)len,
				(unsigned)old_tail);
		/* endian-independent code follows: */
		while (len--)
			ctx->saved |= (uint64_t) (*(buf++)) << ((ctx->byteIndex++) * 8);
		SHA3_ASSERT(ctx->byteIndex < 8);
		return;
	}

	if(old_tail) {              /* will have one word to process */
		SHA3_TRACE("completing one word with %d bytes", (unsigned)old_tail);
		/* endian-independent code follows: */
		len -= old_tail;
		while (old_tail--)
			ctx->saved |= (uint64_t) (*(buf++)) << ((ctx->byteIndex++) * 8);

		/* now ready to add saved to the sponge */
		ctx->s[ctx->wordIndex] ^= ctx->saved;
		SHA3_ASSERT(ctx->byteIndex == 8);
		ctx->byteIndex = 0;
		ctx->saved = 0;
		if(++ctx->wordIndex ==
				(SHA3_KECCAK_SPONGE_WORDS - ctx->capacityWords)) {
			keccakf(ctx->s);
			ctx->wordIndex = 0;
		}
	}

	/* now work in full words directly from input */

	SHA3_ASSERT(ctx->byteIndex == 0);

	words = len / sizeof(uint64_t);
	tail = len - words * sizeof(uint64_t);

	SHA3_TRACE("have %d full words to process", (unsigned)words);

	for(i = 0; i < words; i++, buf += sizeof(uint64_t)) {
		const uint64_t t = (uint64_t) (buf[0]) |
			((uint64_t) (buf[1]) << 8 * 1) |
			((uint64_t) (buf[2]) << 8 * 2) |
			((uint64_t) (buf[3]) << 8 * 3) |
			((uint64_t) (buf[4]) << 8 * 4) |
			((uint64_t) (buf[5]) << 8 * 5) |
			((uint64_t) (buf[6]) << 8 * 6) |
			((uint64_t) (buf[7]) << 8 * 7);
#if defined(__x86_64__ ) || defined(__i386__)
		SHA3_ASSERT(memcmp(&t, buf, 8) == 0);
#endif
		ctx->s[ctx->wordIndex] ^= t;
		if(++ctx->wordIndex ==
				(SHA3_KECCAK_SPONGE_WORDS - ctx->capacityWords)) {
			keccakf(ctx->s);
			ctx->wordIndex = 0;
		}
	}

	SHA3_TRACE("have %d bytes left to process, save them", (unsigned)tail);

	/* finally, save the partial word */
	SHA3_ASSERT(ctx->byteIndex == 0 && tail < 8);
	while (tail--) {
		SHA3_TRACE("Store byte %02x '%c'", *buf, *buf);
		ctx->saved |= (uint64_t) (*(buf++)) << ((ctx->byteIndex++) * 8);
	}
	SHA3_ASSERT(ctx->byteIndex < 8);
	SHA3_TRACE("Have saved=0x%016" PRIx64 " at the end", ctx->saved);
}

/* This is simply the 'update' with the padding block.
 * The padding block is 0x01 || 0x00* || 0x80. First 0x01 and last 0x80
 * bytes are always present, but they can be the same byte.
 */
	static void const *
sha3_Finalize(void *priv)
{
	sha3_context *ctx = (sha3_context *) priv;

	SHA3_TRACE("called with %d bytes in the buffer", ctx->byteIndex);

	/* Append 2-bit suffix 01, per SHA-3 spec. Instead of 1 for padding we
	 * use 1<<2 below. The 0x02 below corresponds to the suffix 01.
	 * Overall, we feed 0, then 1, and finally 1 to start padding. Without
	 * M || 01, we would simply use 1 to start padding. */

#ifndef SHA3_USE_KECCAK
	/* SHA3 version */
	ctx->s[ctx->wordIndex] ^=
		(ctx->saved ^ ((uint64_t) ((uint64_t) (0x02 | (1 << 2)) <<
					   ((ctx->byteIndex) * 8))));
#else
	/* For testing the "pure" Keccak version */
	ctx->s[ctx->wordIndex] ^=
		(ctx->saved ^ ((uint64_t) ((uint64_t) 1 << (ctx->byteIndex *
							    8))));
#endif

	ctx->s[SHA3_KECCAK_SPONGE_WORDS - ctx->capacityWords - 1] ^=
		SHA3_CONST(0x8000000000000000UL);
	keccakf(ctx->s);

	/* Return first bytes of the ctx->s. This conversion is not needed for
	 * little-endian platforms e.g. wrap with #if !defined(__BYTE_ORDER__)
	 * || !defined(__ORDER_LITTLE_ENDIAN__) || \
	 * __BYTE_ORDER__!=__ORDER_LITTLE_ENDIAN__ ... the conversion below ...
	 * #endif */
	{
		unsigned i;
		for(i = 0; i < SHA3_KECCAK_SPONGE_WORDS; i++) {
			const unsigned t1 = (uint32_t) ctx->s[i];
			const unsigned t2 = (uint32_t) ((ctx->s[i] >> 16) >> 16);
			ctx->sb[i * 8 + 0] = (uint8_t) (t1);
			ctx->sb[i * 8 + 1] = (uint8_t) (t1 >> 8);
			ctx->sb[i * 8 + 2] = (uint8_t) (t1 >> 16);
			ctx->sb[i * 8 + 3] = (uint8_t) (t1 >> 24);
			ctx->sb[i * 8 + 4] = (uint8_t) (t2);
			ctx->sb[i * 8 + 5] = (uint8_t) (t2 >> 8);
			ctx->sb[i * 8 + 6] = (uint8_t) (t2 >> 16);
			ctx->sb[i * 8 + 7] = (uint8_t) (t2 >> 24);
		}
	}

	SHA3_TRACE_BUF("Hash: (first 32 bytes)", ctx->sb, 256 / 8);

	return (ctx->sb);
}

// Synchronization structures used
// for the simulation.

pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t broadcast_mtx = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t listen_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_barrier_t bar, bar2, listen;

// Payload with 4 bytes (32bits) for message,
// and space for four MAC tags of 8 bit each.

struct frame
{
	unsigned int msg;
	unsigned mac1:8;
	unsigned mac2:8;
	unsigned mac3:8;
	unsigned mac4:8;
	unsigned id:11;
} frame;

// Print out of the CAN Frame 
// (ID, Data, MAC1, MAC2, MAC3, MAC4)

void print_CAN_frame(void)
{
	printf("ID    Message    MAC1     MAC2     MAC3        MAC4\n");
	printf("%X    %8X   %3X      %3X       %3X         %3X\n",frame.id, frame.msg, frame.mac1, frame.mac2, frame.mac3, frame.mac4);
}

// Transforms an integer value to
// a hexadecimal stored in a character
// array.

void to_hex(int value, char *to) 
{
	int quotient, remainder;
	int i, k = 0, j = 0;
	char hexval[9];

	quotient = value;

	while(quotient) {

		remainder = quotient % 16;

		if (remainder < 10) 
			hexval[j++] = 48 + remainder;
		else
			hexval[j++] = 55 + remainder;

		quotient = quotient / 16;
	}

	for( i = j-1; i >=0; i--, k++)
		to[k] = hexval[i];
	to[k] = '\0';
}

unsigned int random_data(void)
{
	return rand();
}

void * node_one(void *unused)
{
	sha3_context c;
	uint8_t *hash;
	unsigned int data;
	unsigned int id = 132;
	int accepted = 0;
	int counter1, counter2, counter4, counter7, counter8;
	char key12[5] = { '7', 'B', 'A', '3', '\0'};
	char key14[5] = { 'B', '1', '2', '0', '\0'};
	char key17[5] = { '2', '1', '0', 'D', '\0'};
	char key18[5] = { '1', '8', 'E', '1', '\0'};

	char id_hash[11];
	char data_hash[9];
	char counter_hash[8];
	char input[33];	

	counter1 = counter2 = counter4 = counter7 = counter8 = 0;

	pthread_mutex_lock(&mtx);

	printf("Node 1 ID[%5X] initialized shared secret keys.\n",id);
	printf("%s	%s	%s	%s\n",key12, key14, key17, key18);

	pthread_mutex_unlock(&mtx);
	pthread_barrier_wait(&bar);

	while(1) {
		if(!pthread_mutex_trylock(&broadcast_mtx) ) {

			sha3_Init256(&c);
			printf("Node1 [%4X] broadcasting.\n",id);
			frame.id = id;
			frame.msg = random_data();

			to_hex(frame.msg, data_hash);
			to_hex(frame.id, id_hash);	
			to_hex(counter1, counter_hash);

			// creating MAC1 for node2.	
		
			strcpy(input, id_hash);
			strcat(input, data_hash);
			strcat(input, counter_hash);
			strcat(input, key12);
			sha3_Update(&c, input, strlen(input));
			hash = sha3_Finalize(&c);	
			frame.mac1 = *hash;

			// creating MAC2 for node4.

			strcpy(input, id_hash);
			strcat(input, data_hash);
			strcat(input, counter_hash);
			strcat(input, key14);
			sha3_Update(&c, input, strlen(input));
			hash = sha3_Finalize(&c);
			frame.mac2 = *hash;

			// creating MAC3 for node7.

			strcpy(input, id_hash);
			strcat(input, data_hash);
			strcat(input, counter_hash);
			strcat(input, key17);
			sha3_Update(&c, input, strlen(input));
			hash = sha3_Finalize(&c);	
			frame.mac3 = *hash;

			// creating MAC4 for node8.

			strcpy(input, id_hash);
			strcat(input, data_hash);
			strcat(input, counter_hash);
			strcat(input, key18);
			sha3_Update(&c, input, strlen(input));
			hash = sha3_Finalize(&c);	
			frame.mac4 = *hash;
			
			
			counter1++;	// incrementing counter after transmission.			
			print_CAN_frame();
			pthread_barrier_wait(&bar2);	//1 waiting for broadcast.
			pthread_mutex_unlock(&broadcast_mtx);
			pthread_barrier_wait(&listen);	//2 end of listening CAN.	
		} else {
			pthread_barrier_wait(&bar2);	//1 waiting for broadcast.
			
			pthread_mutex_lock(&listen_mutex);
			
			printf("\t\tNode1 listening.. id: %X :: ",id);	

			if(frame.id == 38) {
			
				sha3_Init256(&c);
				strcpy(input, "26");
				to_hex(frame.msg, data_hash);
				strcat(input, data_hash);
				to_hex(counter2, counter_hash);
				strcat(input, counter_hash);
				strcat(input, key12);
				sha3_Update(&c, input, strlen(input));
				hash = sha3_Finalize(&c);	
				if(*hash == frame.mac1) {
					printf("\tAccepts message from node2\n");
					accepted = 1;	
					counter2++;
				}	
			}
			
			if(frame.id == 812) {

				sha3_Init256(&c);
				strcpy(input,"32C");
				to_hex(frame.msg, data_hash);
				strcat(input, data_hash);
				to_hex(counter4, counter_hash);
				strcat(input, counter_hash);
				strcat(input, key14);
				sha3_Update(&c, input, strlen(input));
				hash = sha3_Finalize(&c);

				if(*hash == frame.mac2) {
					printf("\tAccepts message from node4\n");
					accepted++;
					counter4++;
				}	
			}
	
			if(frame.id == 378) {
				
				sha3_Init256(&c);
				strcpy(input,"17A");
				to_hex(frame.msg, data_hash);
				strcat(input, data_hash);
				to_hex(counter7, counter_hash);
				strcat(input, counter_hash);
				strcat(input, key17);
				sha3_Update(&c, input, strlen(input));
				hash = sha3_Finalize(&c);

				if(*hash == frame.mac3) {
					printf("\tAccepts message from node7\n");
					accepted++;
					counter7++;
				}	
			}

			if(frame.id == 99) {

				sha3_Init256(&c);
				strcpy(input,"63");
				to_hex(frame.msg, data_hash);
				strcat(input, data_hash);
				to_hex(counter8, counter_hash);
				strcat(input, counter_hash);
				strcat(input, key18);
				sha3_Update(&c, input, strlen(input));
				hash = sha3_Finalize(&c);

				if(*hash == frame.mac4) {
					printf("\tAccepts message from node8\n");
					accepted++;
					counter7++;
				}	
			}

			if( !accepted )
				printf("\tNode1 rejects message\n");
			accepted = 0;
			pthread_mutex_unlock(&listen_mutex);
			pthread_barrier_wait(&listen);	//2 end of listening CAN.	
                }
        }
}

void * node_two(void *unused)
{
	sha3_context c;
	uint8_t *hash;	
	int accepted = 0;
        unsigned int id = 38;
        int counter2, counter1, counter5, counter6, counter9;
        char key21[5] = { '7', 'B', 'A', '3', '\0'};
        char key25[5] = { '6', 'F', '2', '8', '\0'};
        char key26[5] = { 'B', '7', '3', '9', '\0'};
        char key29[5] = { 'C', 'C', '1', '7', '\0'};
	
	char id_hash[11];
	char data_hash[9];
	char counter_hash[8];
	char input[33];	

        counter2 = counter1 = counter5 = counter6 = counter9 = 0;

        pthread_mutex_lock(&mtx);

        printf("Node 2 ID[%5X] initialized shared secret keys.\n",id);
        printf("%s	%s	%s	%s\n",key21, key25, key26, key29);

        pthread_mutex_unlock(&mtx);
	pthread_barrier_wait(&bar);

	while(1) {
                if(!pthread_mutex_trylock(&broadcast_mtx) ) {
			sha3_Init256(&c);

                        
			printf("Node2 [%4X] broadcasting.\n",id);
			frame.id = id;
			frame.msg = random_data();

			to_hex(frame.msg, data_hash);
			to_hex(frame.id, id_hash);	
			to_hex(counter2, counter_hash);
	
			// creating MAC1 for node1.	
		
			strcpy(input, id_hash);
			strcat(input, data_hash);
			strcat(input, counter_hash);
			strcat(input, key21);
			sha3_Update(&c, input, strlen(input));
			hash = sha3_Finalize(&c);	
			frame.mac1 = *hash;

			// creating MAC2 for node5.
	
			strcpy(input, id_hash);
			strcat(input, data_hash);
			strcat(input, counter_hash);
			strcat(input, key25);
			sha3_Update(&c, input, strlen(input));
			hash = sha3_Finalize(&c);
			frame.mac2 = *hash;
			
			// creating MAC3 for node6.
		
			strcpy(input, id_hash);
			strcat(input, data_hash);
			strcat(input, counter_hash);
			strcat(input, key26);
			sha3_Update(&c, input, strlen(input));
			hash = sha3_Finalize(&c);	
			frame.mac3 = *hash;

			// creating MAC4 for node9.
		
			strcpy(input, id_hash);
			strcat(input, data_hash);
			strcat(input, counter_hash);
			strcat(input, key29);
			sha3_Update(&c, input, strlen(input));
			hash = sha3_Finalize(&c);	
			frame.mac4 = *hash;
		
			counter2++;	// incrementing counter after transmission.			
			print_CAN_frame();

                        pthread_barrier_wait(&bar2);	//1 waiting for broadcast.
			pthread_mutex_unlock(&broadcast_mtx);
			pthread_barrier_wait(&listen);  //2 end of listening CAN.
                } else {
                        pthread_barrier_wait(&bar2);	//1 waiting for broadcast.
			pthread_mutex_lock(&listen_mutex);

			printf("\t\tNode2 listening.. id: %X :: ",id);	
			
			//receive from node1.
			
			if(frame.id == 132) {
				sha3_Init256(&c);
				strcpy(input, "84");
				to_hex(frame.msg, data_hash);
				strcat(input, data_hash);
				to_hex(counter1, counter_hash);
				strcat(input, counter_hash);
				strcat(input, key21);
				sha3_Update(&c, input, strlen(input));
				hash = sha3_Finalize(&c);	
				
				if(*hash == frame.mac1) {
					printf("\tAccepts message from node1\n");
					accepted++;	
					counter1++;
				}	
			}
		
			// receive from node5.
			
			if(frame.id == 447) {

				sha3_Init256(&c);
				strcpy(input,"1BF");
				to_hex(frame.msg, data_hash);
				strcat(input, data_hash);
				to_hex(counter5, counter_hash);
				strcat(input, counter_hash);
				strcat(input, key25);
				sha3_Update(&c, input, strlen(input));
				hash = sha3_Finalize(&c);

				if(*hash == frame.mac2) {
					printf("\tAccepts message from node4\n");
					accepted++;
					counter5++;
				}	
			}

			// receive from node6.

			if(frame.id == 1013) {
				
				sha3_Init256(&c);
				strcpy(input,"3F5");
				to_hex(frame.msg, data_hash);
				strcat(input, data_hash);
				to_hex(counter6, counter_hash);
				strcat(input, counter_hash);
				strcat(input, key26);
				sha3_Update(&c, input, strlen(input));
				hash = sha3_Finalize(&c);

				if(*hash == frame.mac3) {
					printf("\tAccepts message from node6\n");
					accepted++;
					counter6++;
				}	
			}
			
			// receive from node9.

			if(frame.id == 281) {

				sha3_Init256(&c);
				strcpy(input,"119");
				to_hex(frame.msg, data_hash);
				strcat(input, data_hash);
				to_hex(counter9, counter_hash);
				strcat(input, counter_hash);
				strcat(input, key29);
				sha3_Update(&c, input, strlen(input));
				hash = sha3_Finalize(&c);

				if(*hash == frame.mac4) {
					printf("\tAccepts message from node8\n");
					accepted++;
					counter9++;
				}	
			}

			if( !accepted )
				printf("\tNode2 rejects message\n");
		


			accepted = 0;
			
			pthread_mutex_unlock(&listen_mutex);	
			pthread_barrier_wait(&listen);	//2 end of listening CAN.	
                }
        }
}

void * node_three(void *unused)
{
	sha3_context c;
	uint8_t *hash;
	int accepted = 0;
	unsigned int id = 389;
        int counter3, counter4, counter6, counter8, counter9;
        char key34[5] = { 'D', 'B', '1', '9', '\0'};
        char key36[5] = { 'A', 'A', '1', '9', '\0'};
        char key38[5] = { 'E', 'F', '0', '7', '\0'};
        char key39[5] = { '7', '1', '3', '9', '\0'};

	char id_hash[11];
	char data_hash[9];
	char counter_hash[8];
	char input[33];

        counter3 = counter4 = counter6 = counter8 = counter9 = 0;
        pthread_mutex_lock(&mtx);

        printf("Node 3 ID[%5X] initialized shared secret keys.\n",id);
        printf("%s	%s	%s	%s\n",key34, key36, key38, key39);

        pthread_mutex_unlock(&mtx);
	pthread_barrier_wait(&bar);

	while(1) {
                if(!pthread_mutex_trylock(&broadcast_mtx) ) {
			sha3_Init256(&c);

                        
			printf("Node3 [%4X] broadcasting.\n",id);
			frame.id = id;
			frame.msg = random_data();

			to_hex(frame.msg, data_hash);
			to_hex(frame.id, id_hash);	
			to_hex(counter3, counter_hash);
	
			// creating MAC1 for node4.	
		
			strcpy(input, id_hash);
			strcat(input, data_hash);
			strcat(input, counter_hash);
			strcat(input, key34);
			sha3_Update(&c, input, strlen(input));
			hash = sha3_Finalize(&c);	
			frame.mac1 = *hash;

			// creating MAC2 for node9.
	
			strcpy(input, id_hash);
			strcat(input, data_hash);
			strcat(input, counter_hash);
			strcat(input, key39);
			sha3_Update(&c, input, strlen(input));
			hash = sha3_Finalize(&c);
			frame.mac2 = *hash;
			
			// creating MAC3 for node8.
		
			strcpy(input, id_hash);
			strcat(input, data_hash);
			strcat(input, counter_hash);
			strcat(input, key38);
			sha3_Update(&c, input, strlen(input));
			hash = sha3_Finalize(&c);	
			frame.mac3 = *hash;

			// creating MAC4 for node6.
		
			strcpy(input, id_hash);
			strcat(input, data_hash);
			strcat(input, counter_hash);
			strcat(input, key36);
			sha3_Update(&c, input, strlen(input));
			hash = sha3_Finalize(&c);	
			frame.mac4 = *hash;
		
			counter3++;	// incrementing counter after transmission.			
			print_CAN_frame();

                        pthread_barrier_wait(&bar2);	//1 waiting for broadcast.
			pthread_mutex_unlock(&broadcast_mtx);
			pthread_barrier_wait(&listen);  //2 end of listening CAN.
                } else {
                        pthread_barrier_wait(&bar2);	//1 waiting for broadcast.
			pthread_mutex_lock(&listen_mutex);

			printf("\t\tNode3 listening.. id: %X :: ",id);	
			
			//receive from node4.
			
			if(frame.id == 812) {
				sha3_Init256(&c);
				strcpy(input, "32C");
				to_hex(frame.msg, data_hash);
				strcat(input, data_hash);
				to_hex(counter4, counter_hash);
				strcat(input, counter_hash);
				strcat(input, key34);
				sha3_Update(&c, input, strlen(input));
				hash = sha3_Finalize(&c);	
				
				if(*hash == frame.mac1) {
					printf("\tAccepts message from node4\n");
					accepted++;	
					counter4++;
				}	
			}
		
			// receive from node9.
			
			if(frame.id == 281) {

				sha3_Init256(&c);
				strcpy(input,"119");
				to_hex(frame.msg, data_hash);
				strcat(input, data_hash);
				to_hex(counter9, counter_hash);
				strcat(input, counter_hash);
				strcat(input, key39);
				sha3_Update(&c, input, strlen(input));
				hash = sha3_Finalize(&c);

				if(*hash == frame.mac2) {
					printf("\tAccepts message from node9\n");
					accepted++;
					counter9++;
				}	
			}

			// receive from node8.

			if(frame.id == 99) {
				
				sha3_Init256(&c);
				strcpy(input,"63");
				to_hex(frame.msg, data_hash);
				strcat(input, data_hash);
				to_hex(counter8, counter_hash);
				strcat(input, counter_hash);
				strcat(input, key38);
				sha3_Update(&c, input, strlen(input));
				hash = sha3_Finalize(&c);

				if(*hash == frame.mac3) {
					printf("\tAccepts message from node8\n");
					accepted++;
					counter8++;
				}	
			}
			
			// receive from node6.

			if(frame.id == 1013) {

				sha3_Init256(&c);
				strcpy(input,"3F5");
				to_hex(frame.msg, data_hash);
				strcat(input, data_hash);
				to_hex(counter6, counter_hash);
				strcat(input, counter_hash);
				strcat(input, key36);
				sha3_Update(&c, input, strlen(input));
				hash = sha3_Finalize(&c);

				if(*hash == frame.mac4) {
					printf("\tAccepts message from node6\n");
					accepted++;
					counter6++;
				}	
			}

			if( !accepted )
				printf("\tNode3 rejects message\n");

			accepted = 0;
			
			pthread_mutex_unlock(&listen_mutex);	
			pthread_barrier_wait(&listen);	//2 end of listening CAN.	
                }
        }
}

void * node_four(void *unused)
{
	sha3_context c;
	uint8_t *hash;
	unsigned int data;
	unsigned int id = 812;
	int accepted = 0;
        int counter4, counter1, counter3, counter7;
        char key41[5] = { 'B', '1', '2', '0', '\0'};
        char key43[5] = { 'D', 'B', '1', '9', '\0'};
        char key47[5] = { 'E', 'B', '0', '2', '\0'};

	char id_hash[11];
	char data_hash[9];
	char counter_hash[8];
	char input[33];

        counter4 = counter1 = counter3 = counter7 = 0;

        pthread_mutex_lock(&mtx);

        printf("Node 4 ID[%5X] initialized shared secret keys.\n",id);
        printf("%s	%s	%s	\n",key41, key43, key47);

        pthread_mutex_unlock(&mtx);
	pthread_barrier_wait(&bar);

	while(1) {
                if(!pthread_mutex_trylock(&broadcast_mtx) ) {
			sha3_Init256(&c);

                        
			printf("Node4 [%4X] broadcasting.\n",id);
			frame.id = id;
			frame.msg = random_data();

			to_hex(frame.msg, data_hash);
			to_hex(frame.id, id_hash);	
			to_hex(counter4, counter_hash);
	
			// creating MAC1 for node3.	
		
			strcpy(input, id_hash);
			strcat(input, data_hash);
			strcat(input, counter_hash);
			strcat(input, key43);
			sha3_Update(&c, input, strlen(input));
			hash = sha3_Finalize(&c);	
			frame.mac1 = *hash;

			// creating MAC2 for node1.
	
			strcpy(input, id_hash);
			strcat(input, data_hash);
			strcat(input, counter_hash);
			strcat(input, key41);
			sha3_Update(&c, input, strlen(input));
			hash = sha3_Finalize(&c);
			frame.mac2 = *hash;
			
			// creating MAC3 for nobody(value will be ignored)
		
			strcpy(input, id_hash);
			strcat(input, data_hash);
			strcat(input, counter_hash);
			strcat(input, key41);
			sha3_Update(&c, input, strlen(input));
			hash = sha3_Finalize(&c);	
			frame.mac3 = *hash;

			// creating MAC4 for node7.
		
			strcpy(input, id_hash);
			strcat(input, data_hash);
			strcat(input, counter_hash);
			strcat(input, key47);
			sha3_Update(&c, input, strlen(input));
			hash = sha3_Finalize(&c);	
			frame.mac4 = *hash;
		
			counter4++;	// incrementing counter after transmission.			
			print_CAN_frame();

                        pthread_barrier_wait(&bar2);	//1 waiting for broadcast.
			pthread_mutex_unlock(&broadcast_mtx);
			pthread_barrier_wait(&listen);  //2 end of listening CAN.
                } else {
                        pthread_barrier_wait(&bar2);	//1 waiting for broadcast.
			pthread_mutex_lock(&listen_mutex);

			printf("\t\tNode4 listening.. id: %X :: ",id);	
			
			//receive from node3.
			
			if(frame.id == 389) {
				sha3_Init256(&c);
				strcpy(input, "185");
				to_hex(frame.msg, data_hash);
				strcat(input, data_hash);
				to_hex(counter3, counter_hash);
				strcat(input, counter_hash);
				strcat(input, key43);
				sha3_Update(&c, input, strlen(input));
				hash = sha3_Finalize(&c);	
				
				if(*hash == frame.mac1) {
					printf("\tAccepts message from node3\n");
					accepted++;	
					counter3++;
				}	
			}
		
			// receive from node1.
			
			if(frame.id == 132) {

				sha3_Init256(&c);
				strcpy(input,"84");
				to_hex(frame.msg, data_hash);
				strcat(input, data_hash);
				to_hex(counter1, counter_hash);
				strcat(input, counter_hash);
				strcat(input, key41);
				sha3_Update(&c, input, strlen(input));
				hash = sha3_Finalize(&c);

				if(*hash == frame.mac2) {
					printf("\tAccepts message from node1\n");
					accepted++;
					counter1++;
				}	
			}

			// no node adds a MAC3 for node4.
			
			// receive from node7.

			if(frame.id == 378) {

				sha3_Init256(&c);
				strcpy(input,"17A");
				to_hex(frame.msg, data_hash);
				strcat(input, data_hash);
				to_hex(counter7, counter_hash);
				strcat(input, counter_hash);
				strcat(input, key47);
				sha3_Update(&c, input, strlen(input));
				hash = sha3_Finalize(&c);

				if(*hash == frame.mac4) {
					printf("\tAccepts message from node6\n");
					accepted++;
					counter7++;
				}	
			}

			if( !accepted )
				printf("\tNode4 rejects message\n");

			accepted = 0;
			
			pthread_mutex_unlock(&listen_mutex);	
			pthread_barrier_wait(&listen);	//2 end of listening CAN.	
                }
        }

}

void * node_five(void *unused)
{
        unsigned int id = 447;
        int counter5, counter2, counter6;
        char key52[5] = { '6', 'F', '2', '8', '\0'};
        char key56[5] = { 'A', 'B', '3', '4', '\0'};

        counter5 = counter2 = counter6 = 0;

        pthread_mutex_lock(&mtx);

        printf("Node 5 ID[%5X] initialized shared secret keys.\n",id);
        printf("%s	%s	\n",key52, key56);

        pthread_mutex_unlock(&mtx);
	pthread_barrier_wait(&bar);

}

void * node_six(void *unused)
{
        unsigned int id = 1013;
        int counter6, counter2, counter3, counter5, counter8;
        char key62[5] = { 'B', '7', '3', '9', '\0'};
        char key63[5] = { 'A', 'A', '1', '9', '\0'};
        char key65[5] = { 'A', 'B', '3', '4', '\0'};
        char key68[5] = { '8', 'D', '9', '3', '\0'};

        counter6 = counter2 = counter3 = counter5 = counter8 = 0;

        pthread_mutex_lock(&mtx);

        printf("Node 6 ID[%5X] initialized shared secret keys.\n",id);
        printf("%s	%s	%s	%s\n",key62, key63, key65, key68);

        pthread_mutex_unlock(&mtx);
	pthread_barrier_wait(&bar);

}

void * node_seven(void *unused)
{
        unsigned int id = 378;
        int counter7, counter1, counter4;
        char key71[5] = { '2', '1', '0', 'D', '\0'};
        char key74[5] = { 'E', 'B', '0', '2', '\0'};

        counter7 = counter1 = counter4 = 0;

        pthread_mutex_lock(&mtx);

        printf("Node 7 ID[%5X] initialized shared secret keys.\n",id);
        printf("%s	%s\n",key71, key74);

        pthread_mutex_unlock(&mtx);
	pthread_barrier_wait(&bar);

}
void *node_eight(void *unused)
{
        unsigned int id = 99;
        int counter8, counter1, counter3, counter6;
        char key81[5] = { '1', '8', 'E', '1', '\0'};
        char key83[5] = { 'E', 'F', '0', '7', '\0'};
        char key86[5] = { '8', 'D', '9', '3', '\0'};

        counter8 = counter1 = counter3 = counter6 = 0;

        pthread_mutex_lock(&mtx);

        printf("Node 8 ID[%5X] initialized shared secret keys.\n",id);
        printf("%s	%s	%s\n",key81, key83, key86);

        pthread_mutex_unlock(&mtx);
	pthread_barrier_wait(&bar);

}

void * node_nine(void *unused)
{
        unsigned id = 281;
        int counter9, counter2, counter3;
        char key92[5] = { 'C', 'C', '1', '7', '\0'};
        char key93[5] = { '7', '1', '3', '9', '\0'};

        counter9 = counter2 = counter3 = 0;

        pthread_mutex_lock(&mtx);

        printf("Node 9 ID[%5X] initialized shared secret keys.\n",id);
        printf("%s	%s\n",key92, key93);

        pthread_mutex_unlock(&mtx);
	pthread_barrier_wait(&bar);

}

int main(int argc,char *argv[])
{

        /* CAN Bus 9 nodes 	*/
        uint8_t buf[200];
        sha3_context c;
        const uint8_t *hash;
        unsigned i;
        const uint8_t c1 = 0xa3;

#ifndef SHA3_USE_KECCAK
        /* [FIPS 202] KAT follow */
        const static uint8_t sha3_256_empty[256 / 8] = {
                0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
                0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
                0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
                0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a
        };
        const static uint8_t sha3_256_0xa3_200_times[256 / 8] = {
                0x79, 0xf3, 0x8a, 0xde, 0xc5, 0xc2, 0x03, 0x07,
                0xa9, 0x8e, 0xf7, 0x6e, 0x83, 0x24, 0xaf, 0xbf,
                0xd4, 0x6c, 0xfd, 0x81, 0xb2, 0x2e, 0x39, 0x73,
                0xc6, 0x5f, 0xa1, 0xbd, 0x9d, 0xe3, 0x17, 0x87
        };
        const static uint8_t sha3_384_0xa3_200_times[384 / 8] = {
                0x18, 0x81, 0xde, 0x2c, 0xa7, 0xe4, 0x1e, 0xf9,
                0x5d, 0xc4, 0x73, 0x2b, 0x8f, 0x5f, 0x00, 0x2b,
                0x18, 0x9c, 0xc1, 0xe4, 0x2b, 0x74, 0x16, 0x8e,
                0xd1, 0x73, 0x26, 0x49, 0xce, 0x1d, 0xbc, 0xdd,
                0x76, 0x19, 0x7a, 0x31, 0xfd, 0x55, 0xee, 0x98,
                0x9f, 0x2d, 0x70, 0x50, 0xdd, 0x47, 0x3e, 0x8f
        };
        const static uint8_t sha3_512_0xa3_200_times[512 / 8] = {
                0xe7, 0x6d, 0xfa, 0xd2, 0x20, 0x84, 0xa8, 0xb1,
                0x46, 0x7f, 0xcf, 0x2f, 0xfa, 0x58, 0x36, 0x1b,
                0xec, 0x76, 0x28, 0xed, 0xf5, 0xf3, 0xfd, 0xc0,
                0xe4, 0x80, 0x5d, 0xc4, 0x8c, 0xae, 0xec, 0xa8,
                0x1b, 0x7c, 0x13, 0xc3, 0x0a, 0xdf, 0x52, 0xa3,
                0x65, 0x95, 0x84, 0x73, 0x9a, 0x2d, 0xf4, 0x6b,
                0xe5, 0x89, 0xc5, 0x1c, 0xa1, 0xa4, 0xa8, 0x41,
                0x6d, 0xf6, 0x54, 0x5a, 0x1c, 0xe8, 0xba, 0x00
        };
#endif

        memset(buf, c1, sizeof(buf));

#ifdef SHA3_USE_KECCAK          /* run tests against "pure" Keccak
                                 * algorithm; from [Keccak] */

        sha3_Init256(&c);
        sha3_Update(&c, "\xcc", 1);
        hash = sha3_Finalize(&c);
        if(memcmp(hash, "\xee\xad\x6d\xbf\xc7\x34\x0a\x56"
                        "\xca\xed\xc0\x44\x69\x6a\x16\x88"
                        "\x70\x54\x9a\x6a\x7f\x6f\x56\x96"
                        "\x1e\x84\xa5\x4b\xd9\x97\x0b\x8a", 256 / 8) != 0) {
                printf("SHA3-256(cc) "
                       "doesn't match known answer (single buffer)\n");
                return 11;
        }

        sha3_Init256(&c);
        sha3_Update(&c, "\x41\xfb", 2);
        hash = sha3_Finalize(&c);
        if(memcmp(hash, "\xa8\xea\xce\xda\x4d\x47\xb3\x28"
                        "\x1a\x79\x5a\xd9\xe1\xea\x21\x22"
                        "\xb4\x07\xba\xf9\xaa\xbc\xb9\xe1"
                        "\x8b\x57\x17\xb7\x87\x35\x37\xd2", 256 / 8) != 0) {
                printf("SHA3-256(41fb) "
                       "doesn't match known answer (single buffer)\n");
                return 12;
        }

        sha3_Init256(&c);
        sha3_Update(&c,
                    "\x52\xa6\x08\xab\x21\xcc\xdd\x8a"
                    "\x44\x57\xa5\x7e\xde\x78\x21\x76", 128 / 8);
        hash = sha3_Finalize(&c);
        if(memcmp(hash, "\x0e\x32\xde\xfa\x20\x71\xf0\xb5"
                        "\xac\x0e\x6a\x10\x8b\x84\x2e\xd0"
                        "\xf1\xd3\x24\x97\x12\xf5\x8e\xe0"
                        "\xdd\xf9\x56\xfe\x33\x2a\x5f\x95", 256 / 8) != 0) {
                printf("SHA3-256(52a6...76) "
                       "doesn't match known answer (single buffer)\n");
                return 13;
        }

        sha3_Init256(&c);
        sha3_Update(&c,
                    "\x43\x3c\x53\x03\x13\x16\x24\xc0"
                    "\x02\x1d\x86\x8a\x30\x82\x54\x75"
                    "\xe8\xd0\xbd\x30\x52\xa0\x22\x18"
                    "\x03\x98\xf4\xca\x44\x23\xb9\x82"
                    "\x14\xb6\xbe\xaa\xc2\x1c\x88\x07"
                    "\xa2\xc3\x3f\x8c\x93\xbd\x42\xb0"
                    "\x92\xcc\x1b\x06\xce\xdf\x32\x24"
                    "\xd5\xed\x1e\xc2\x97\x84\x44\x4f"
                    "\x22\xe0\x8a\x55\xaa\x58\x54\x2b"
                    "\x52\x4b\x02\xcd\x3d\x5d\x5f\x69"
                    "\x07\xaf\xe7\x1c\x5d\x74\x62\x22"
                    "\x4a\x3f\x9d\x9e\x53\xe7\xe0\x84" "\x6d\xcb\xb4\xce", 800 / 8);
        hash = sha3_Finalize(&c);
        if(memcmp(hash, "\xce\x87\xa5\x17\x3b\xff\xd9\x23"
                        "\x99\x22\x16\x58\xf8\x01\xd4\x5c"
                        "\x29\x4d\x90\x06\xee\x9f\x3f\x9d"
                        "\x41\x9c\x8d\x42\x77\x48\xdc\x41", 256 / 8) != 0) {
                printf("SHA3-256(433C...CE) "
                       "doesn't match known answer (single buffer)\n");
                return 14;
        }

        /* SHA3-256 byte-by-byte: 16777216 steps. ExtremelyLongMsgKAT_256
         * [Keccak] */
        i = 16777216;
        sha3_Init256(&c);
        while (i--) {
                sha3_Update(&c,
                            "abcdefghbcdefghicdefghijdefghijk"
                            "efghijklfghijklmghijklmnhijklmno", 64);
        }
        hash = sha3_Finalize(&c);
        if(memcmp(hash, "\x5f\x31\x3c\x39\x96\x3d\xcf\x79"
                        "\x2b\x54\x70\xd4\xad\xe9\xf3\xa3"
                        "\x56\xa3\xe4\x02\x17\x48\x69\x0a"
                        "\x95\x83\x72\xe2\xb0\x6f\x82\xa4", 256 / 8) != 0) {
                printf("SHA3-256( abcdefgh...[16777216 times] ) "
                       "doesn't match known answer\n");
                return 15;
        }
#else                           /* SHA3 testing begins */

        /* SHA-256 on an empty buffer */
        sha3_Init256(&c);
        hash = sha3_Finalize(&c);
        if(memcmp(sha3_256_empty, hash, sizeof(sha3_256_empty)) != 0) {
                printf("SHA3-256() doesn't match known answer\n");
                return 1;
        }

        /* SHA3-256 as a single buffer. [FIPS 202] */
        sha3_Init256(&c);
        sha3_Update(&c, buf, sizeof(buf));
        hash = sha3_Finalize(&c);
        if(memcmp(sha3_256_0xa3_200_times, hash,
                        sizeof(sha3_256_0xa3_200_times)) != 0) {
                printf("SHA3-256( 0xa3 ... [200 times] ) "
                       "doesn't match known answer (1 buffer)\n");
                return 1;
        }

        /* SHA3-256 in two steps. [FIPS 202] */
        sha3_Init256(&c);
        sha3_Update(&c, buf, sizeof(buf) / 2);
        sha3_Update(&c, buf + sizeof(buf) / 2, sizeof(buf) / 2);
        hash = sha3_Finalize(&c);
        if(memcmp(sha3_256_0xa3_200_times, hash,
                        sizeof(sha3_256_0xa3_200_times)) != 0) {
                printf("SHA3-256( 0xa3 ... [200 times] ) "
                       "doesn't match known answer (2 steps)\n");
                return 2;
        }

        /* SHA3-256 byte-by-byte: 200 steps. [FIPS 202] */
        i = 200;
        sha3_Init256(&c);
        while (i--) {
                sha3_Update(&c, &c1, 1);
        }
        hash = sha3_Finalize(&c);
        if(memcmp(sha3_256_0xa3_200_times, hash,
                        sizeof(sha3_256_0xa3_200_times)) != 0) {
                printf("SHA3-256( 0xa3 ... [200 times] ) "
                       "doesn't match known answer (200 steps)\n");
                return 3;
        }

        /* SHA3-256 byte-by-byte: 135 bytes. Input from [Keccak]. Output
         * matched with sha3sum. */
        sha3_Init256(&c);
        sha3_Update(&c,
                    "\xb7\x71\xd5\xce\xf5\xd1\xa4\x1a"
                    "\x93\xd1\x56\x43\xd7\x18\x1d\x2a"
                    "\x2e\xf0\xa8\xe8\x4d\x91\x81\x2f"
                    "\x20\xed\x21\xf1\x47\xbe\xf7\x32"
                    "\xbf\x3a\x60\xef\x40\x67\xc3\x73"
                    "\x4b\x85\xbc\x8c\xd4\x71\x78\x0f"
                    "\x10\xdc\x9e\x82\x91\xb5\x83\x39"
                    "\xa6\x77\xb9\x60\x21\x8f\x71\xe7"
                    "\x93\xf2\x79\x7a\xea\x34\x94\x06"
                    "\x51\x28\x29\x06\x5d\x37\xbb\x55"
                    "\xea\x79\x6f\xa4\xf5\x6f\xd8\x89"
                    "\x6b\x49\xb2\xcd\x19\xb4\x32\x15"
                    "\xad\x96\x7c\x71\x2b\x24\xe5\x03"
                    "\x2d\x06\x52\x32\xe0\x2c\x12\x74"
                    "\x09\xd2\xed\x41\x46\xb9\xd7\x5d"
                    "\x76\x3d\x52\xdb\x98\xd9\x49\xd3"
                    "\xb0\xfe\xd6\xa8\x05\x2f\xbb", 1080 / 8);
        hash = sha3_Finalize(&c);
        if(memcmp(hash, "\xa1\x9e\xee\x92\xbb\x20\x97\xb6"
                        "\x4e\x82\x3d\x59\x77\x98\xaa\x18"
                        "\xbe\x9b\x7c\x73\x6b\x80\x59\xab"
                        "\xfd\x67\x79\xac\x35\xac\x81\xb5", 256 / 8) != 0) {
                printf("SHA3-256( b771 ... ) doesn't match the known answer\n");
                return 4;
        }

        /* SHA3-384 as a single buffer. [FIPS 202] */
        sha3_Init384(&c);
        sha3_Update(&c, buf, sizeof(buf));
        hash = sha3_Finalize(&c);
        if(memcmp(sha3_384_0xa3_200_times, hash,
                        sizeof(sha3_384_0xa3_200_times)) != 0) {
                printf("SHA3-384( 0xa3 ... [200 times] ) "
                       "doesn't match known answer (1 buffer)\n");
                return 5;
        }

        /* SHA3-384 in two steps. [FIPS 202] */
        sha3_Init384(&c);
        sha3_Update(&c, buf, sizeof(buf) / 2);
        sha3_Update(&c, buf + sizeof(buf) / 2, sizeof(buf) / 2);
        hash = sha3_Finalize(&c);
        if(memcmp(sha3_384_0xa3_200_times, hash,
                        sizeof(sha3_384_0xa3_200_times)) != 0) {
                printf("SHA3-384( 0xa3 ... [200 times] ) "
                       "doesn't match known answer (2 steps)\n");
                return 6;
        }

        /* SHA3-384 byte-by-byte: 200 steps. [FIPS 202] */
        i = 200;
        sha3_Init384(&c);
        while (i--) {
                sha3_Update(&c, &c1, 1);
        }
        hash = sha3_Finalize(&c);
        if(memcmp(sha3_384_0xa3_200_times, hash,
                        sizeof(sha3_384_0xa3_200_times)) != 0) {
                printf("SHA3-384( 0xa3 ... [200 times] ) "
                       "doesn't match known answer (200 steps)\n");
                return 7;
        }

        /* SHA3-512 as a single buffer. [FIPS 202] */
        sha3_Init512(&c);
        sha3_Update(&c, buf, sizeof(buf));
        hash = sha3_Finalize(&c);
        if(memcmp(sha3_512_0xa3_200_times, hash,
                        sizeof(sha3_512_0xa3_200_times)) != 0) {
                printf("SHA3-512( 0xa3 ... [200 times] ) "
                       "doesn't match known answer (1 buffer)\n");
                return 8;
        }

        /* SHA3-512 in two steps. [FIPS 202] */
        sha3_Init512(&c);
        sha3_Update(&c, buf, sizeof(buf) / 2);
        sha3_Update(&c, buf + sizeof(buf) / 2, sizeof(buf) / 2);
        hash = sha3_Finalize(&c);
        if(memcmp(sha3_512_0xa3_200_times, hash,
                        sizeof(sha3_512_0xa3_200_times)) != 0) {
                printf("SHA3-512( 0xa3 ... [200 times] ) "
                       "doesn't match known answer (2 steps)\n");
                return 9;
        }

        /* SHA3-512 byte-by-byte: 200 steps. [FIPS 202] */
        i = 200;
        sha3_Init512(&c);
        while (i--) {
                sha3_Update(&c, &c1, 1);
        }
        hash = sha3_Finalize(&c);
        if(memcmp(sha3_512_0xa3_200_times, hash,
                        sizeof(sha3_512_0xa3_200_times)) != 0) {
                printf("SHA3-512( 0xa3 ... [200 times] ) "
                       "doesn't match known answer (200 steps)\n");
                return 10;
        }
#endif

        printf("SHA3-256, SHA3-384, SHA3-512 tests passed OK\n");
	/*	Can Bus 9 nodes */

        pthread_t tid[9];
        pthread_attr_t attr;

	pthread_barrier_init(&bar, NULL,4);
	pthread_barrier_init(&bar2, NULL,4);
	pthread_barrier_init(&listen, NULL,4);
        pthread_attr_init(&attr);
	srand(time(NULL));	

        pthread_create(&tid[0], &attr, (void *) node_one, NULL);
        pthread_create(&tid[1], &attr, (void *) node_two, NULL);
        pthread_create(&tid[2], &attr, (void *) node_three, NULL);
        pthread_create(&tid[3], &attr, (void *) node_four, NULL);
/*      pthread_create(&tid[4], &attr, (void *) node_five, NULL);
        pthread_create(&tid[5], &attr, (void *) node_six, NULL);
        pthread_create(&tid[6], &attr, (void *) node_seven, NULL);
        pthread_create(&tid[7], &attr, (void *) node_eight, NULL);
        pthread_create(&tid[8], &attr, (void *) node_nine, NULL);
*/
        for(int i = 0; i < 4; i++)
                pthread_join(tid[i],NULL);

        printf("Simulation complete\n");

        return 0;
}
