#include <openssl/objects.h>
#include <openssl/rand_drbg.h>

typedef unsigned char uuid_t[16];

static const int type_nid[3] = { 0, NID_aes_128_ctr, NID_aes_256_ctr };
static const size_t type_entropy_input_len[3] = { 0, 16, 32 };
static const size_t type_nonce_len[3] = { 0, 8, 16 };
static const int type_max_iterations[3] = { 0, 2048, 2048 };

static int current_type;
static unsigned char *current_seed;
static int current_iterations;
static RAND_DRBG *current_drbg;

static size_t get_entropy(RAND_DRBG *drbg, unsigned char **pout, int entropy,
			  size_t min_len, size_t max_len, int predict_resist) {
	*pout = current_seed;
	return type_entropy_input_len[current_type];
}

static size_t get_nonce(RAND_DRBG *drbg, unsigned char **pout, int entropy,
			size_t min_len, size_t max_len) {
	*pout = current_seed + type_entropy_input_len[current_type];
	return type_nonce_len[current_type];
}

void generator_instantiate(int type, const unsigned char *seed) {
	current_type = type;
	current_seed = (unsigned char *) seed;

	current_drbg = RAND_DRBG_new(type_nid[type], 0, NULL);
	RAND_DRBG_set_reseed_interval(current_drbg, 0);
	RAND_DRBG_set_reseed_time_interval(current_drbg, 0);
	RAND_DRBG_set_callbacks(current_drbg, get_entropy, NULL,
				get_nonce, NULL);
	RAND_DRBG_instantiate(current_drbg, NULL, 0);

	current_seed = NULL;
	current_iterations = 0;
}

const uuid_t * generator_iterate(void) {
	static uuid_t uuid;

	if (current_iterations >= type_max_iterations[current_type])
		return NULL;
	current_iterations++;

	RAND_DRBG_generate(current_drbg, uuid, sizeof(uuid), 0, NULL, 0);
	uuid[8] = (uuid[8] & ~0xc0) | 0x80; // clock_seq_hi_and_reserved
	uuid[6] = (uuid[6] & ~0xf0) | 0x40; // time_hi_and_version

	return &uuid;
}

void generator_uninstantiate(void) {
	RAND_DRBG_uninstantiate(current_drbg);
	RAND_DRBG_free(current_drbg);
	current_drbg = NULL;
}
