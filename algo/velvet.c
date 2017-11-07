#include "miner.h"

#include <gmp.h> /* user MPIR lib for vstudio */
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <float.h>
#include <math.h>

#include "crypto/magimath.h"

#include "sha3/sph_bmw.h"
#include "sha3/sph_groestl.h"
#include "sha3/sph_jh.h"
#include "sha3/sph_keccak.h"
#include "sha3/sph_skein.h"
#include "sha3/sph_luffa.h"
#include "sha3/sph_cubehash.h"
#include "sha3/sph_shavite.h"
#include "sha3/sph_simd.h"
#include "sha3/sph_echo.h"
#include "sha3/sph_hamsi.h"
#include "sha3/sph_fugue.h"
#include "sha3/sph_shabal.h"
#include "sha3/sph_whirlpool.h"
#include "sha3/sph_sha2.h"
#include "sha3/sph_haval.h"

#define BITS_PER_DIGIT 3.32192809488736234787
#define EPS (DBL_EPSILON)

#define NM25M 23
#define SW_DIVS 23

static inline void mpz_set_uint256(mpz_t r, uint32_t *u) {
	mpz_import(r, 32 / sizeof(unsigned long), -1, sizeof(unsigned long), -1, 0, u);
}

static inline void mpz_set_uint512(mpz_t r, uint32_t *u) {
	mpz_import(r, 64 / sizeof(unsigned long), -1, sizeof(unsigned long), -1, 0, u);
}

static int is_zero_hash(uint32_t* hash) {
	for (int w=0; w<8; w++)
		if (hash[w]) return false;
	return true;
}

void velvethash(void *output, const void *input)
{
	uint32_t _ALIGN(128) hash[25][16];
	uint32_t _ALIGN(128) echo[16] = { 0 };
	uint32_t _ALIGN(128) finalhash[8] = { 0 };

	const void* ptr = input;
	const uint32_t nnNonce = ((uint32_t*)input)[19];
	const int nnNonce2 = (int) (nnNonce / 2);
	const int sz = 80;

	sph_shabal512_context     ctx_shabal;
	sph_bmw512_context        ctx_bmw512;
	sph_groestl512_context    ctx_groestl;
	sph_jh512_context         ctx_jh;
	sph_keccak512_context     ctx_keccak;
	sph_skein512_context      ctx_skein;
	sph_luffa512_context      ctx_luffa;
	sph_cubehash512_context   ctx_cubehash;
	sph_shavite512_context    ctx_shavite;
	sph_simd512_context       ctx_simd;
	sph_echo512_context       ctx_echo;
	sph_hamsi512_context      ctx_hamsi;
	sph_fugue512_context      ctx_fugue;
	sph_whirlpool_context     ctx_whirlpool;
	sph_sha512_context        ctx_sha2;
	sph_haval256_5_context    ctx_haval;
	sph_shabal256_context	  ctx_shabal256;

	sph_shabal512_init(&ctx_shabal);
	sph_shabal512(&ctx_shabal, ptr, sz);
	sph_shabal512_close(&ctx_shabal, hash[0]);

	sph_groestl512_init(&ctx_groestl);
	sph_groestl512(&ctx_groestl, ptr, sz);
	sph_groestl512_close(&ctx_groestl, hash[3]);

	if (hash[0][0] & 25)
	{
		sph_bmw512_init(&ctx_bmw512);
		sph_bmw512(&ctx_bmw512, ptr, sz);
		sph_bmw512_close(&ctx_bmw512, hash[1]);
	} else {
		memcpy(hash[1], hash[3], 64); // groestl
	}

	memcpy(hash[2], hash[0], 64); // shabal
	memcpy(hash[4], hash[0], 64); // shabal

	bool jhDone;
	if (hash[4][0] & 25) {
		sph_skein512_init(&ctx_skein);
		sph_skein512 (&ctx_skein, ptr, sz);
		sph_skein512_close(&ctx_skein, (void*)hash[5]);
		jhDone = false;
	} else {
		sph_jh512_init(&ctx_jh);
		sph_jh512 (&ctx_jh, ptr, sz);
		sph_jh512_close(&ctx_jh, (void*)hash[5]);
		jhDone = true;
	}

	if (hash[5][0] & 25) {
		if (jhDone)
			memcpy(hash[6], hash[5], 64);
		else {
			sph_jh512_init(&ctx_jh);
			sph_jh512 (&ctx_jh, ptr, sz);
			sph_jh512_close(&ctx_jh, (void*)hash[6]);
		}
	} else {
		if (!jhDone)
			memcpy(hash[6], hash[5], 64);
		else {
			sph_skein512_init(&ctx_skein);
			sph_skein512 (&ctx_skein, ptr, sz);
			sph_skein512_close(&ctx_skein, (void*)hash[6]);
		}
	}

	sph_cubehash512_init(&ctx_cubehash);
	sph_cubehash512 (&ctx_cubehash, ptr, sz);
	sph_cubehash512_close(&ctx_cubehash, (void*)hash[7]);

	sph_shavite512_init(&ctx_shavite);
	sph_shavite512(&ctx_shavite, ptr, sz);
	sph_shavite512_close(&ctx_shavite, (void*)hash[8]);

	if (hash[8][0] & 25) {
		sph_keccak512_init(&ctx_keccak);
		sph_keccak512 (&ctx_keccak, ptr, sz);
		sph_keccak512_close(&ctx_keccak, (void*)hash[9]);
	} else {
		sph_luffa512_init(&ctx_luffa);
		sph_luffa512 (&ctx_luffa, (void*)hash[8], 64);
		sph_luffa512_close(&ctx_luffa, (void*)hash[9]);
	}

	sph_echo512_init(&ctx_echo);
	sph_echo512 (&ctx_echo, ptr, sz);
	sph_echo512_close(&ctx_echo, (void*)echo);

	if (hash[9][0] & 25) {
		sph_simd512_init(&ctx_simd);
		sph_simd512 (&ctx_simd, ptr, sz);
		sph_simd512_close(&ctx_simd, (void*)hash[10]);
	} else {
		memcpy(hash[10], echo, 64);
	}

	// all shabal512
	memcpy(hash[11], hash[0], 64);
	memcpy(hash[12], hash[0], 64);
	memcpy(hash[13], hash[0], 64);
	memcpy(hash[14], hash[0], 64);
	memcpy(hash[15], hash[0], 64);

	if (hash[15][0] & 25) {
		sph_hamsi512_init(&ctx_hamsi);
		sph_hamsi512 (&ctx_hamsi, ptr, sz);
		sph_hamsi512_close(&ctx_hamsi, (void*)hash[16]);
	} else {
		memcpy(hash[16], echo, 64);
	}

	sph_fugue512_init(&ctx_fugue);
	sph_fugue512 (&ctx_fugue, ptr, sz);
	sph_fugue512_close(&ctx_fugue, (void*)hash[17]);

	if (hash[17][0] & 25) {
		memcpy(hash[18], hash[0], 64); // shabal
	} else {
		memcpy(hash[18], echo, 64);
	}

	sph_whirlpool_init(&ctx_whirlpool);
	sph_whirlpool (&ctx_whirlpool, ptr, sz);
	sph_whirlpool_close(&ctx_whirlpool, (void*)hash[19]);

	sph_sha512_init(&ctx_sha2);
	sph_sha512 (&ctx_sha2, ptr, sz);
	sph_sha512_close(&ctx_sha2, (void*)hash[20]);

	sph_haval256_5_init(&ctx_haval);
	sph_haval256_5 (&ctx_haval, ptr, sz);
	memset(&hash[21][8], 0, 32);
	sph_haval256_5_close(&ctx_haval, (void*)hash[21]);

	if (hash[21][0] & 25) {
		memcpy(hash[22], hash[0], 64); // shabal
	} else {
		memcpy(hash[22], echo, 64);
	}

	if (hash[22][0] & 25) {
		memcpy(hash[23], hash[0], 64); // shabal
	} else {
		memcpy(hash[23], echo, 64);
	}

	if (hash[23][0] & 25) {
		memcpy(hash[24], hash[0], 64); // shabal
	} else {
		memcpy(hash[24], echo, 64);
	}

	mpz_t bns[26];

	// Take care of zeros and load gmp
	for(int i=0; i < 25; i++) {
		if (is_zero_hash(hash[i]))
			hash[i][0] = 1;
		mpz_init(bns[i]);
		mpz_set_uint512(bns[i], hash[i]);
	}

	mpz_init(bns[25]);
	mpz_set_ui(bns[25], 0);
	for(int i=0; i < 25; i++)
		mpz_add(bns[25], bns[25], bns[i]);

	mpz_t product;
	mpz_init(product);
	mpz_set_ui(product,1);

	for(int i=0; i < 26; i++)
		mpz_mul(product, product, bns[i]);
	mpz_pow_ui(product, product, 2);

	size_t bytes = mpz_sizeinbase(product, 256);
//	printf("M25M data space: %iB\n", bytes);
	char *data = (char*)malloc(bytes);
	mpz_export(data, NULL, -1, 1, 0, 0, product);

	sph_shabal256_init(&ctx_shabal256);
	sph_shabal256 (&ctx_shabal256, data, bytes);
	sph_shabal256_close(&ctx_shabal256, (void*) finalhash);
	free(data);

	int digits = (int) ((sqrt((double)(nnNonce2))*(1.+EPS))/9000+255);
	int iterations = 20; // <= 500
	mpf_set_default_prec((long int)(digits*BITS_PER_DIGIT+16));

	mpz_t magipi;
	mpz_t magisw;
	mpf_t magifpi;
	mpf_t mpa1, mpb1, mpt1, mpp1;
	mpf_t mpa2, mpb2, mpt2, mpp2;
	mpf_t mpsft;

	mpz_init(magipi);
	mpz_init(magisw);
	mpf_init(magifpi);
	mpf_init(mpsft);
	mpf_init(mpa1);
	mpf_init(mpb1);
	mpf_init(mpt1);
	mpf_init(mpp1);

	mpf_init(mpa2);
	mpf_init(mpb2);
	mpf_init(mpt2);
	mpf_init(mpp2);

	uint32_t usw_;
	usw_ = sw_(nnNonce2, SW_DIVS);
	if (usw_ < 1) usw_ = 1;

	mpz_set_ui(magisw, usw_);
	size_t mpzscale = mpz_size(magisw);
	for(int i=0; i < NM25M; i++)
	{
		if (mpzscale > 1000) mpzscale = 1000;
		else if (mpzscale < 1) mpzscale = 1;

		mpf_set_ui(mpa1, 1);
		mpf_set_ui(mpp1, 1);
		mpf_set_ui(mpb1, 2);
		mpf_sqrt(mpb1, mpb1);
		mpf_ui_div(mpb1, 1, mpb1);
		mpf_set_ui(mpsft, 10);
		mpf_set_d(mpt1, 0.25*mpzscale);

		for(int it=0; it <= iterations; it++)
		{
			mpf_add(mpa2, mpa1, mpb1);
			mpf_div_ui(mpa2, mpa2, 2);
			mpf_mul(mpb2, mpa1, mpb1);
			mpf_abs(mpb2, mpb2);
			mpf_sqrt(mpb2, mpb2);
			mpf_sub(mpt2, mpa1, mpa2);
			mpf_abs(mpt2, mpt2);
			mpf_sqrt(mpt2, mpt2);
			mpf_mul(mpt2, mpt2, mpp1);
			mpf_sub(mpt2, mpt1, mpt2);
			mpf_mul_ui(mpp2, mpp1, 2);
			mpf_swap(mpa1, mpa2);
			mpf_swap(mpb1, mpb2);
			mpf_swap(mpt1, mpt2);
			mpf_swap(mpp1, mpp2);
		}

		mpf_add(magifpi, mpa1, mpb1);
		mpf_pow_ui(magifpi, magifpi, 2);
		mpf_div_ui(magifpi, magifpi, 4);
		mpf_abs(mpt1, mpt1);
		mpf_div(magifpi, magifpi, mpt1);

		mpf_pow_ui(mpsft, mpsft, digits/2);
		mpf_mul(magifpi, magifpi, mpsft);
		mpz_set_f(magipi, magifpi);

		mpz_add(product, product, magipi);
		mpz_add(product, product, magisw);

		if (is_zero_hash(finalhash)) finalhash[0] = 1;
		mpz_set_uint256(bns[0], finalhash);
		mpz_add(bns[25], bns[25], bns[0]);

		mpz_mul(product, product, bns[25]);
		mpz_cdiv_q(product, product, bns[0]);
		if (mpz_sgn(product) <= 0) mpz_set_ui(product,1);

		bytes = mpz_sizeinbase(product, 256);
		mpzscale = bytes;
	//	printf("M25M data space: %iB\n", bytes);

		char *bdata = (char*) malloc(bytes);
		if (!bdata) {
			applog(LOG_ERR, "velvet mem alloc problem!");
			memset(finalhash, 0xff, 32);
			break;
		}
		mpz_export(bdata, NULL, -1, 1, 0, 0, product);

		sph_shabal256_init(&ctx_shabal256);
		sph_shabal256 (&ctx_shabal256, bdata, bytes);
		sph_shabal256_close(&ctx_shabal256, (void*)(&finalhash));

		free(bdata);
	//	applog(LOG_DEBUG, "finalhash:");
	//	applog_hash((char*)finalhash);
	}

	// Free gmp memory
	for(int i=0; i < 26; i++)
		mpz_clear(bns[i]);

	mpz_clear(product);

	mpz_clear(magipi);
	mpz_clear(magisw);
	mpf_clear(magifpi);
	mpf_clear(mpsft);
	mpf_clear(mpa1);
	mpf_clear(mpb1);
	mpf_clear(mpt1);
	mpf_clear(mpp1);

	mpf_clear(mpa2);
	mpf_clear(mpb2);
	mpf_clear(mpt2);
	mpf_clear(mpp2);

	memcpy(output, finalhash, 32);
}

int scanhash_velvet(int thr_id, struct work *work, uint64_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(64) vhash[8];
	uint32_t _ALIGN(64) endiandata[20];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];

	uint32_t n = first_nonce;

	for (int i=0; i < 19; i++) {
		be32enc(&endiandata[i], pdata[i]);
	}

	do {
		be32enc(&endiandata[19], n);
		velvethash((char*)vhash, (char*)endiandata);
		if (vhash[7] < Htarg && fulltest(vhash, ptarget)) {
			work_set_target_ratio(work, vhash);
			*hashes_done = n - first_nonce + 1;
			pdata[19] = n;
			return true;
		}
		n++;

	} while (n < max_nonce && !work_restart[thr_id].restart);

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;

	return 0;
}