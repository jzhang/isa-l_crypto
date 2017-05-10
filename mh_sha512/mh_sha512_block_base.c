/**********************************************************************
  Copyright(c) 2011-2017 Intel Corporation All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Intel Corporation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**********************************************************************/

#include "mh_sha512_internal.h"
#include <string.h>

////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////
// Base multi-hash SHA512 Functions
////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////
// store_w is only used for step 0 ~ 15
#define store_w(s, i, w, ww) (w[i][s] = bswap(ww[i*HASH_SEGS+s]))
#define Ws(x, s) w[(x) & 15][s]
// update_w is used for step > 15
#define update_w(s, i, w) \
	Ws(i, s) = Ws(i-16, s) + S0(Ws(i-15, s)) + Ws(i-7, s) + S1(Ws(i-2, s))
#define update_t2(s, a, b, c) t2[s] = s0(a[s]) + maj(a[s],b[s],c[s])
#define update_t1(s, h, e, f, g, i, k) \
	t1[s] = h[s] + s1(e[s]) + ch(e[s],f[s],g[s]) + k + Ws(i, s);
#define update_d(s) d[s] += t1[s]
#define update_h(s) h[s] = t1[s] + t2[s]

// s is a iterator
#define STORE_W(s, i, w, ww) \
	for(s = 0; s < HASH_SEGS; s++) \
		store_w(s, i, w, ww);
#define UPDATE_W(s, i, w) \
	for(s = 0; s < HASH_SEGS; s++) \
		update_w(s, i, w);
#define UPDATE_T2(s, a, b, c) \
	for(s = 0; s < HASH_SEGS; s++) \
		update_t2(s, a, b, c);
#define UPDATE_T1(s, h, e, f, g, i, k) \
	for(s = 0; s < HASH_SEGS; s++) \
		update_t1(s, h, e, f, g, i, k);
#define UPDATE_D(s) \
	for(s = 0; s < HASH_SEGS; s++) \
		update_d(s);
#define UPDATE_H(s) \
	for(s = 0; s < HASH_SEGS; s++) \
		update_h(s);

static inline void step(int i, uint64_t * a, uint64_t * b, uint64_t * c,
			uint64_t * d, uint64_t * e, uint64_t * f,
			uint64_t * g, uint64_t * h, uint64_t k,
			uint64_t * t1, uint64_t * t2, uint64_t(*w)[HASH_SEGS], uint64_t * ww)
{
	uint8_t s;
	if (i < 16) {
		STORE_W(s, i, w, ww);
	} else {
		UPDATE_W(s, i, w);
	}
	UPDATE_T2(s, a, b, c);
	UPDATE_T1(s, h, e, f, g, i, k);
	UPDATE_D(s);
	UPDATE_H(s);
}

static inline void init_abcdefgh(uint64_t * xx, uint64_t n,
				 uint64_t digests[SHA512_DIGEST_WORDS][HASH_SEGS])
{
	uint8_t s;
	for (s = 0; s < HASH_SEGS; s++)
		xx[s] = digests[n][s];
}

static inline void add_abcdefgh(uint64_t * xx, uint64_t n,
				uint64_t digests[SHA512_DIGEST_WORDS][HASH_SEGS])
{
	uint8_t s;
	for (s = 0; s < HASH_SEGS; s++)
		digests[n][s] += xx[s];
}

/*
 * API to perform 0-64 steps of the multi-hash algorithm for
 * a single block of data. The caller is responsible for ensuring
 * a full block of data input.
 *
 * Argument:
 *   input  - the pointer to the data
 *   digest - the space to hold the digests for all segments.
 *
 * Return:
 *   N/A
 */
void mh_sha512_single(const uint8_t * input, uint64_t(*digests)[HASH_SEGS],
		      uint8_t * frame_buffer)
{
	uint8_t i;
	uint64_t aa[HASH_SEGS], bb[HASH_SEGS], cc[HASH_SEGS], dd[HASH_SEGS];
	uint64_t ee[HASH_SEGS], ff[HASH_SEGS], gg[HASH_SEGS], hh[HASH_SEGS];
	uint64_t t1[HASH_SEGS], t2[HASH_SEGS];
	uint64_t *ww = (uint64_t *) input;
	uint64_t(*w)[HASH_SEGS];

	const static uint64_t k[80] = {
		      0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 
              0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 
              0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 
              0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 
              0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab, 
              0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 
              0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 
              0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 
              0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 
              0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 
              0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 
              0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 
              0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 
              0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 
              0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 
              0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
	};

	w = (uint64_t(*)[HASH_SEGS]) frame_buffer;

	init_abcdefgh(aa, 0, digests);
	init_abcdefgh(bb, 1, digests);
	init_abcdefgh(cc, 2, digests);
	init_abcdefgh(dd, 3, digests);
	init_abcdefgh(ee, 4, digests);
	init_abcdefgh(ff, 5, digests);
	init_abcdefgh(gg, 6, digests);
	init_abcdefgh(hh, 7, digests);

	for (i = 0; i < 80; i += 8) {
		step(i, aa, bb, cc, dd, ee, ff, gg, hh, k[i], t1, t2, w, ww);
		step(i + 1, hh, aa, bb, cc, dd, ee, ff, gg, k[i + 1], t1, t2, w, ww);
		step(i + 2, gg, hh, aa, bb, cc, dd, ee, ff, k[i + 2], t1, t2, w, ww);
		step(i + 3, ff, gg, hh, aa, bb, cc, dd, ee, k[i + 3], t1, t2, w, ww);
		step(i + 4, ee, ff, gg, hh, aa, bb, cc, dd, k[i + 4], t1, t2, w, ww);
		step(i + 5, dd, ee, ff, gg, hh, aa, bb, cc, k[i + 5], t1, t2, w, ww);
		step(i + 6, cc, dd, ee, ff, gg, hh, aa, bb, k[i + 6], t1, t2, w, ww);
		step(i + 7, bb, cc, dd, ee, ff, gg, hh, aa, k[i + 7], t1, t2, w, ww);
	}

	add_abcdefgh(aa, 0, digests);
	add_abcdefgh(bb, 1, digests);
	add_abcdefgh(cc, 2, digests);
	add_abcdefgh(dd, 3, digests);
	add_abcdefgh(ee, 4, digests);
	add_abcdefgh(ff, 5, digests);
	add_abcdefgh(gg, 6, digests);
	add_abcdefgh(hh, 7, digests);
}

void mh_sha512_block_base(const uint8_t * input_data,
			  uint64_t digests[SHA512_DIGEST_WORDS][HASH_SEGS],
			  uint8_t frame_buffer[MH_SHA512_BLOCK_SIZE], uint64_t num_blocks)
{
	uint64_t i;

	for (i = 0; i < num_blocks; i++) {
		mh_sha512_single(input_data, digests, frame_buffer);
		input_data += MH_SHA512_BLOCK_SIZE;
	}

	return;
}
