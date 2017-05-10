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

#include <string.h>
#include "mh_sha512_internal.h"

////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////
 //  Macros and sub-functions which already exist in source code file
 //  (sha512_for_mh_sha512.c) is part of ISA-L library as internal functions.
 //  The reason why writing them twice is the linking issue caused by
 //  mh_sha512_ref(). mh_sha512_ref() needs these macros and sub-functions
 //  without linking ISA-L library. So mh_sha512_ref() includes them in
 //  order to contain essential sub-functions in its own object file.
////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////

#define W(x) w[(x) & 15]

#define step(i,a,b,c,d,e,f,g,h,k) \
	if (i<16) W(i) = bswap(ww[i]); \
	else \
	W(i) = W(i-16) + S0(W(i-15)) + W(i-7) + S1(W(i-2)); \
	t2 = s0(a) + maj(a,b,c); \
	t1 = h + s1(e) + ch(e,f,g) + k + W(i); \
	d += t1; \
	h = t1 + t2;

void sha512_single_for_mh_sha512_ref(const uint8_t * data, uint64_t digest[])
{
	uint64_t a, b, c, d, e, f, g, h, t1, t2;
	uint64_t w[16];
	uint64_t *ww = (uint64_t *) data;

	a = digest[0];
	b = digest[1];
	c = digest[2];
	d = digest[3];
	e = digest[4];
	f = digest[5];
	g = digest[6];
	h = digest[7];

	step(0, a, b, c, d, e, f, g, h, 0x428a2f98d728ae22);
	step(1, h, a, b, c, d, e, f, g, 0x7137449123ef65cd);
	step(2, g, h, a, b, c, d, e, f, 0xb5c0fbcfec4d3b2f);
	step(3, f, g, h, a, b, c, d, e, 0xe9b5dba58189dbbc);
	step(4, e, f, g, h, a, b, c, d, 0x3956c25bf348b538);
	step(5, d, e, f, g, h, a, b, c, 0x59f111f1b605d019);
	step(6, c, d, e, f, g, h, a, b, 0x923f82a4af194f9b);
	step(7, b, c, d, e, f, g, h, a, 0xab1c5ed5da6d8118);
	step(8, a, b, c, d, e, f, g, h, 0xd807aa98a3030242);
	step(9, h, a, b, c, d, e, f, g, 0x12835b0145706fbe);
	step(10, g, h, a, b, c, d, e, f, 0x243185be4ee4b28c);
	step(11, f, g, h, a, b, c, d, e, 0x550c7dc3d5ffb4e2);
	step(12, e, f, g, h, a, b, c, d, 0x72be5d74f27b896f);
	step(13, d, e, f, g, h, a, b, c, 0x80deb1fe3b1696b1);
	step(14, c, d, e, f, g, h, a, b, 0x9bdc06a725c71235);
	step(15, b, c, d, e, f, g, h, a, 0xc19bf174cf692694);
	step(16, a, b, c, d, e, f, g, h, 0xe49b69c19ef14ad2);
	step(17, h, a, b, c, d, e, f, g, 0xefbe4786384f25e3);
	step(18, g, h, a, b, c, d, e, f, 0x0fc19dc68b8cd5b5);
	step(19, f, g, h, a, b, c, d, e, 0x240ca1cc77ac9c65);
	step(20, e, f, g, h, a, b, c, d, 0x2de92c6f592b0275);
	step(21, d, e, f, g, h, a, b, c, 0x4a7484aa6ea6e483);
	step(22, c, d, e, f, g, h, a, b, 0x5cb0a9dcbd41fbd4);
	step(23, b, c, d, e, f, g, h, a, 0x76f988da831153b5);
	step(24, a, b, c, d, e, f, g, h, 0x983e5152ee66dfab);
	step(25, h, a, b, c, d, e, f, g, 0xa831c66d2db43210);
	step(26, g, h, a, b, c, d, e, f, 0xb00327c898fb213f);
	step(27, f, g, h, a, b, c, d, e, 0xbf597fc7beef0ee4);
	step(28, e, f, g, h, a, b, c, d, 0xc6e00bf33da88fc2);
	step(29, d, e, f, g, h, a, b, c, 0xd5a79147930aa725);
	step(30, c, d, e, f, g, h, a, b, 0x06ca6351e003826f);
	step(31, b, c, d, e, f, g, h, a, 0x142929670a0e6e70);
	step(32, a, b, c, d, e, f, g, h, 0x27b70a8546d22ffc);
	step(33, h, a, b, c, d, e, f, g, 0x2e1b21385c26c926);
	step(34, g, h, a, b, c, d, e, f, 0x4d2c6dfc5ac42aed);
	step(35, f, g, h, a, b, c, d, e, 0x53380d139d95b3df);
	step(36, e, f, g, h, a, b, c, d, 0x650a73548baf63de);
	step(37, d, e, f, g, h, a, b, c, 0x766a0abb3c77b2a8);
	step(38, c, d, e, f, g, h, a, b, 0x81c2c92e47edaee6);
	step(39, b, c, d, e, f, g, h, a, 0x92722c851482353b);
	step(40, a, b, c, d, e, f, g, h, 0xa2bfe8a14cf10364);
	step(41, h, a, b, c, d, e, f, g, 0xa81a664bbc423001);
	step(42, g, h, a, b, c, d, e, f, 0xc24b8b70d0f89791);
	step(43, f, g, h, a, b, c, d, e, 0xc76c51a30654be30);
	step(44, e, f, g, h, a, b, c, d, 0xd192e819d6ef5218);
	step(45, d, e, f, g, h, a, b, c, 0xd69906245565a910);
	step(46, c, d, e, f, g, h, a, b, 0xf40e35855771202a);
	step(47, b, c, d, e, f, g, h, a, 0x106aa07032bbd1b8);
	step(48, a, b, c, d, e, f, g, h, 0x19a4c116b8d2d0c8);
	step(49, h, a, b, c, d, e, f, g, 0x1e376c085141ab53);
	step(50, g, h, a, b, c, d, e, f, 0x2748774cdf8eeb99);
	step(51, f, g, h, a, b, c, d, e, 0x34b0bcb5e19b48a8);
	step(52, e, f, g, h, a, b, c, d, 0x391c0cb3c5c95a63);
	step(53, d, e, f, g, h, a, b, c, 0x4ed8aa4ae3418acb);
	step(54, c, d, e, f, g, h, a, b, 0x5b9cca4f7763e373);
	step(55, b, c, d, e, f, g, h, a, 0x682e6ff3d6b2b8a3);
	step(56, a, b, c, d, e, f, g, h, 0x748f82ee5defb2fc);
	step(57, h, a, b, c, d, e, f, g, 0x78a5636f43172f60);
	step(58, g, h, a, b, c, d, e, f, 0x84c87814a1f0ab72);
	step(59, f, g, h, a, b, c, d, e, 0x8cc702081a6439ec);
	step(60, e, f, g, h, a, b, c, d, 0x90befffa23631e28);
	step(61, d, e, f, g, h, a, b, c, 0xa4506cebde82bde9);
	step(62, c, d, e, f, g, h, a, b, 0xbef9a3f7b2c67915);
	step(63, b, c, d, e, f, g, h, a, 0xc67178f2e372532b);	// step 63
	step(64, a, b, c, d, e, f, g, h, 0xca273eceea26619c);
	step(65, h, a, b, c, d, e, f, g, 0xd186b8c721c0c207);
	step(66, g, h, a, b, c, d, e, f, 0xeada7dd6cde0eb1e);
	step(67, f, g, h, a, b, c, d, e, 0xf57d4f7fee6ed178);
	step(68, e, f, g, h, a, b, c, d, 0x06f067aa72176fba);
	step(69, d, e, f, g, h, a, b, c, 0x0a637dc5a2c898a6);
	step(70, c, d, e, f, g, h, a, b, 0x113f9804bef90dae);
	step(71, b, c, d, e, f, g, h, a, 0x1b710b35131c471b);
	step(72, a, b, c, d, e, f, g, h, 0x28db77f523047d84);
	step(73, h, a, b, c, d, e, f, g, 0x32caab7b40c72493);
	step(74, g, h, a, b, c, d, e, f, 0x3c9ebe0a15c9bebc);
	step(75, f, g, h, a, b, c, d, e, 0x431d67c49c100d4c);
	step(76, e, f, g, h, a, b, c, d, 0x4cc5d4becb3e42b6);
	step(77, d, e, f, g, h, a, b, c, 0x597f299cfc657e2a);
	step(78, c, d, e, f, g, h, a, b, 0x5fcb6fab3ad6faec);
	step(79, b, c, d, e, f, g, h, a, 0x6c44198c4a475817);	// step 79

	digest[0] += a;
	digest[1] += b;
	digest[2] += c;
	digest[3] += d;
	digest[4] += e;
	digest[5] += f;
	digest[6] += g;
	digest[7] += h;
}

void sha512_for_mh_sha512_ref(const uint8_t * input_data, uint64_t * digest,
			      const uint64_t len)
{
	uint64_t i, j;
	uint8_t buf[2 * SHA512_BLOCK_SIZE];
	union {
		uint64_t uint;
		uint8_t uchar[8];
	} convert;
	uint8_t *p;

	digest[0] = MH_SHA512_H0;
	digest[1] = MH_SHA512_H1;
	digest[2] = MH_SHA512_H2;
	digest[3] = MH_SHA512_H3;
	digest[4] = MH_SHA512_H4;
	digest[5] = MH_SHA512_H5;
	digest[6] = MH_SHA512_H6;
	digest[7] = MH_SHA512_H7;

	i = len;
	while (i >= SHA512_BLOCK_SIZE) {
		sha512_single_for_mh_sha512_ref(input_data, digest);
		input_data += SHA512_BLOCK_SIZE;
		i -= SHA512_BLOCK_SIZE;
	}

	memcpy(buf, input_data, i);
	buf[i++] = 0x80;
	for (j = i; j < ((2 * SHA512_BLOCK_SIZE) - 8); j++)
		buf[j] = 0;

	if (i > SHA512_BLOCK_SIZE - 8)
		i = 2 * SHA512_BLOCK_SIZE;
	else
		i = SHA512_BLOCK_SIZE;

	convert.uint = 8 * len;
	p = buf + i - 8;
	p[0] = convert.uchar[7];
	p[1] = convert.uchar[6];
	p[2] = convert.uchar[5];
	p[3] = convert.uchar[4];
	p[4] = convert.uchar[3];
	p[5] = convert.uchar[2];
	p[6] = convert.uchar[1];
	p[7] = convert.uchar[0];

	sha512_single_for_mh_sha512_ref(buf, digest);
	if (i == (2 * SHA512_BLOCK_SIZE))
		sha512_single_for_mh_sha512_ref(buf + SHA512_BLOCK_SIZE, digest);
}

/*
 * buffer to rearrange one segment data from one block.
 *
 * Layout of new_data:
 *  segment
 *  -------------------------
 *   w0  |  w1  | ... |  w15
 *
 */
static inline void transform_input_single(uint64_t * new_data, uint64_t * input,
					  uint64_t segment)
{
	new_data[16 * segment + 0] = input[16 * 0 + segment];
	new_data[16 * segment + 1] = input[16 * 1 + segment];
	new_data[16 * segment + 2] = input[16 * 2 + segment];
	new_data[16 * segment + 3] = input[16 * 3 + segment];
	new_data[16 * segment + 4] = input[16 * 4 + segment];
	new_data[16 * segment + 5] = input[16 * 5 + segment];
	new_data[16 * segment + 6] = input[16 * 6 + segment];
	new_data[16 * segment + 7] = input[16 * 7 + segment];
	new_data[16 * segment + 8] = input[16 * 8 + segment];
	new_data[16 * segment + 9] = input[16 * 9 + segment];
	new_data[16 * segment + 10] = input[16 * 10 + segment];
	new_data[16 * segment + 11] = input[16 * 11 + segment];
	new_data[16 * segment + 12] = input[16 * 12 + segment];
	new_data[16 * segment + 13] = input[16 * 13 + segment];
	new_data[16 * segment + 14] = input[16 * 14 + segment];
	new_data[16 * segment + 15] = input[16 * 15 + segment];
}

// Adapt parameters to sha512_single_for_mh_sha512_ref
#define sha512_update_one_seg(data, digest) \
	sha512_single_for_mh_sha512_ref((const uint8_t *)(data), (uint64_t *)(digest))

/*
 * buffer to Rearrange all segments data from one block.
 *
 * Layout of new_data:
 *  segment
 *  -------------------------
 *   seg0:   | w0  |  w1  | ... |  w15
 *   seg1:   | w0  |  w1  | ... |  w15
 *   seg2:   | w0  |  w1  | ... |  w15
 *   ....
 *   seg15: | w0  |  w1  | ... |  w15
 *
 */
static inline void transform_input(uint64_t * new_data, uint64_t * input, uint64_t block)
{
	uint64_t *current_input = input + block * MH_SHA512_BLOCK_SIZE / 4;

	transform_input_single(new_data, current_input, 0);
	transform_input_single(new_data, current_input, 1);
	transform_input_single(new_data, current_input, 2);
	transform_input_single(new_data, current_input, 3);
	transform_input_single(new_data, current_input, 4);
	transform_input_single(new_data, current_input, 5);
	transform_input_single(new_data, current_input, 6);
	transform_input_single(new_data, current_input, 7);
	transform_input_single(new_data, current_input, 8);
	transform_input_single(new_data, current_input, 9);
	transform_input_single(new_data, current_input, 10);
	transform_input_single(new_data, current_input, 11);
	transform_input_single(new_data, current_input, 12);
	transform_input_single(new_data, current_input, 13);
	transform_input_single(new_data, current_input, 14);
	transform_input_single(new_data, current_input, 15);

}

/*
 * buffer to Calculate all segments' digests from one block.
 *
 * Layout of seg_digest:
 *  segment
 *  -------------------------
 *   seg0:   | H0  |  H1  | ... |  H7
 *   seg1:   | H0  |  H1  | ... |  H7
 *   seg2:   | H0  |  H1  | ... |  H7
 *   ....
 *   seg15: | H0  |  H1  | ... |  H7
 *
 */
static inline void sha512_update_all_segs(uint64_t * new_data, uint64_t(*mh_sha512_seg_digests)
					  [SHA512_DIGEST_WORDS])
{
	sha512_update_one_seg(&(new_data)[16 * 0], mh_sha512_seg_digests[0]);
	sha512_update_one_seg(&(new_data)[16 * 1], mh_sha512_seg_digests[1]);
	sha512_update_one_seg(&(new_data)[16 * 2], mh_sha512_seg_digests[2]);
	sha512_update_one_seg(&(new_data)[16 * 3], mh_sha512_seg_digests[3]);
	sha512_update_one_seg(&(new_data)[16 * 4], mh_sha512_seg_digests[4]);
	sha512_update_one_seg(&(new_data)[16 * 5], mh_sha512_seg_digests[5]);
	sha512_update_one_seg(&(new_data)[16 * 6], mh_sha512_seg_digests[6]);
	sha512_update_one_seg(&(new_data)[16 * 7], mh_sha512_seg_digests[7]);
	sha512_update_one_seg(&(new_data)[16 * 8], mh_sha512_seg_digests[8]);
	sha512_update_one_seg(&(new_data)[16 * 9], mh_sha512_seg_digests[9]);
	sha512_update_one_seg(&(new_data)[16 * 10], mh_sha512_seg_digests[10]);
	sha512_update_one_seg(&(new_data)[16 * 11], mh_sha512_seg_digests[11]);
	sha512_update_one_seg(&(new_data)[16 * 12], mh_sha512_seg_digests[12]);
	sha512_update_one_seg(&(new_data)[16 * 13], mh_sha512_seg_digests[13]);
	sha512_update_one_seg(&(new_data)[16 * 14], mh_sha512_seg_digests[14]);
	sha512_update_one_seg(&(new_data)[16 * 15], mh_sha512_seg_digests[15]);
}

void mh_sha512_block_ref(const uint8_t * input_data, uint64_t(*digests)[HASH_SEGS],
			 uint8_t frame_buffer[MH_SHA512_BLOCK_SIZE], uint64_t num_blocks)
{
	uint64_t i, j;
	uint64_t *temp_buffer = (uint64_t *) frame_buffer;
	uint64_t(*trans_digests)[SHA512_DIGEST_WORDS];

	trans_digests = (uint64_t(*)[SHA512_DIGEST_WORDS]) digests;

	// Re-structure seg_digests from 5*16 to 16*5
	for (j = 0; j < HASH_SEGS; j++) {
		for (i = 0; i < SHA512_DIGEST_WORDS; i++) {
			temp_buffer[j * SHA512_DIGEST_WORDS + i] = digests[i][j];
		}
	}
	memcpy(trans_digests, temp_buffer, 4 * SHA512_DIGEST_WORDS * HASH_SEGS);

	// Calculate digests for all segments, leveraging sha512 API
	for (i = 0; i < num_blocks; i++) {
		transform_input(temp_buffer, (uint64_t *) input_data, i);
		sha512_update_all_segs(temp_buffer, trans_digests);
	}

	// Re-structure seg_digests from 16*5 to 5*16
	for (j = 0; j < HASH_SEGS; j++) {
		for (i = 0; i < SHA512_DIGEST_WORDS; i++) {
			temp_buffer[i * HASH_SEGS + j] = trans_digests[j][i];
		}
	}
	memcpy(digests, temp_buffer, 4 * SHA512_DIGEST_WORDS * HASH_SEGS);

	return;
}

void mh_sha512_tail_ref(uint8_t * partial_buffer, uint64_t total_len,
			uint64_t(*mh_sha512_segs_digests)[HASH_SEGS], uint8_t * frame_buffer,
			uint64_t digests[SHA512_DIGEST_WORDS])
{
	uint64_t partial_buffer_len, len_in_bit;

	partial_buffer_len = total_len % MH_SHA512_BLOCK_SIZE;

	// Padding the first block
	partial_buffer[partial_buffer_len] = 0x80;
	partial_buffer_len++;
	memset(partial_buffer + partial_buffer_len, 0,
	       MH_SHA512_BLOCK_SIZE - partial_buffer_len);

	// Calculate the first block without total_length if padding needs 2 block
	if (partial_buffer_len > (MH_SHA512_BLOCK_SIZE - SHA512_PADLENGTHFIELD_SIZE)) {
		mh_sha512_block_ref(partial_buffer, mh_sha512_segs_digests, frame_buffer, 1);
		//Padding the second block
		memset(partial_buffer, 0, MH_SHA512_BLOCK_SIZE);
	}
	//Padding the block
	len_in_bit = bswap64((uint64_t) total_len * 8);
	*(uint64_t *) (partial_buffer + MH_SHA512_BLOCK_SIZE - SHA512_PADLENGTHFIELD_SIZE) = len_in_bit;
	mh_sha512_block_ref(partial_buffer, mh_sha512_segs_digests, frame_buffer, 1);

	//Calculate multi-hash SHA512 digests (segment digests as input message)
	sha512_for_mh_sha512_ref((uint8_t *) mh_sha512_segs_digests, digests,
				 4 * SHA512_DIGEST_WORDS * HASH_SEGS);

	return;
}

void mh_sha512_ref(const void *buffer, uint64_t len, uint64_t * mh_sha512_digest)
{
	uint64_t total_len;
	uint64_t num_blocks;
	uint64_t mh_sha512_segs_digests[SHA512_DIGEST_WORDS][HASH_SEGS];
	uint8_t frame_buffer[MH_SHA512_BLOCK_SIZE];
	uint8_t partial_block_buffer[MH_SHA512_BLOCK_SIZE * 2];
	uint64_t mh_sha512_hash_dword[SHA512_DIGEST_WORDS];
	uint64_t i;
	const uint8_t *input_data = (const uint8_t *)buffer;

	/* Initialize digests of all segments */
	for (i = 0; i < HASH_SEGS; i++) {
		mh_sha512_segs_digests[0][i] = MH_SHA512_H0;
		mh_sha512_segs_digests[1][i] = MH_SHA512_H1;
		mh_sha512_segs_digests[2][i] = MH_SHA512_H2;
		mh_sha512_segs_digests[3][i] = MH_SHA512_H3;
		mh_sha512_segs_digests[4][i] = MH_SHA512_H4;
		mh_sha512_segs_digests[5][i] = MH_SHA512_H5;
		mh_sha512_segs_digests[6][i] = MH_SHA512_H6;
		mh_sha512_segs_digests[7][i] = MH_SHA512_H7;
	}

	total_len = len;

	// Calculate blocks
	num_blocks = len / MH_SHA512_BLOCK_SIZE;
	if (num_blocks > 0) {
		//do num_blocks process
		mh_sha512_block_ref(input_data, mh_sha512_segs_digests, frame_buffer,
				    num_blocks);
		len -= num_blocks * MH_SHA512_BLOCK_SIZE;
		input_data += num_blocks * MH_SHA512_BLOCK_SIZE;
	}
	// Store the partial block
	if (len != 0) {
		memcpy(partial_block_buffer, input_data, len);
	}

	/* Finalize */
	mh_sha512_tail_ref(partial_block_buffer, total_len, mh_sha512_segs_digests,
			   frame_buffer, mh_sha512_hash_dword);

	// Output the digests of mh_sha512
	if (mh_sha512_digest != NULL) {
		mh_sha512_digest[0] = mh_sha512_hash_dword[0];
		mh_sha512_digest[1] = mh_sha512_hash_dword[1];
		mh_sha512_digest[2] = mh_sha512_hash_dword[2];
		mh_sha512_digest[3] = mh_sha512_hash_dword[3];
		mh_sha512_digest[4] = mh_sha512_hash_dword[4];
		mh_sha512_digest[5] = mh_sha512_hash_dword[5];
		mh_sha512_digest[6] = mh_sha512_hash_dword[6];
		mh_sha512_digest[7] = mh_sha512_hash_dword[7];
	}

	return;
}
