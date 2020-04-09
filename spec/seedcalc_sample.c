#include <openssl/objects.h>
#include <openssl/rand_drbg.h>
#include <openssl/x509.h>

#define SEEDLEN_MAX 48

static const int type_nid[3] = { 0, NID_aes_128_ctr, NID_aes_256_ctr };
static const size_t type_entropy_input_len[3] = { 0, 16, 32 };
static const size_t type_nonce_len[3] = { 0, 8, 16 };

static int current_type;
static unsigned char *current_preseed;
static RAND_DRBG *current_drbg;

static size_t get_entropy(RAND_DRBG *drbg, unsigned char **pout, int entropy,
			  size_t min_len, size_t max_len, int predict_resist) {
	*pout = current_preseed;
	return type_entropy_input_len[current_type];
}

static size_t get_nonce(RAND_DRBG *drbg, unsigned char **pout, int entropy,
			size_t min_len, size_t max_len) {
	*pout = current_preseed + type_entropy_input_len[current_type];
	return type_nonce_len[current_type];
}

void seedcalc_instantiate(int type, const unsigned char *preseed,
			  X509_PUBKEY *key) {
	unsigned char *key_der = NULL;
	int key_der_len;

	current_type = type;
	current_preseed = (unsigned char *) preseed;

	key_der_len = i2d_X509_PUBKEY(key, &key_der);
	current_drbg = RAND_DRBG_new(type_nid[type], 0, NULL);
	RAND_DRBG_set_reseed_interval(current_drbg, 0);
	RAND_DRBG_set_reseed_time_interval(current_drbg, 0);
	RAND_DRBG_set_callbacks(current_drbg, get_entropy, NULL,
				get_nonce, NULL);
	RAND_DRBG_instantiate(current_drbg, key_der, key_der_len);
	OPENSSL_free(key_der);

	current_preseed = NULL;
}

const unsigned char * seedcalc_generate(void) {
	static unsigned char seed[SEEDLEN_MAX];
	size_t seedlen;

	seedlen = (type_entropy_input_len[current_type] +
		   type_nonce_len[current_type]);
	RAND_DRBG_generate(current_drbg, seed, seedlen, 0, NULL, 0);

	return seed;
}

void seedcalc_uninstantiate(void) {
	RAND_DRBG_uninstantiate(current_drbg);
	RAND_DRBG_free(current_drbg);
	current_drbg = NULL;
}
