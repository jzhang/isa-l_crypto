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

#ifndef _MH_SHA512_INTERNAL_H_
#define _MH_SHA512_INTERNAL_H_

/**
 *  @file mh_sha512_internal.h
 *  @brief mh_sha512 internal function prototypes and macros
 *
 *  Interface for mh_sha512 internal functions
 *
 */
#include <stdint.h>
#include "mh_sha512.h"

#ifdef __cplusplus
 extern "C" {
#endif

#ifdef _MSC_VER
# define inline __inline
#endif

 // 64byte pointer align
#define ALIGN_64(pointer) ( ((uint64_t)(pointer) + 0x3F)&(~0x3F) )

 /*******************************************************************
  *mh_sha512 constants and macros
  ******************************************************************/
 /* mh_sha512 constants */
#define MH_SHA512_H0 0x6a09e667f3bcc908UL
#define MH_SHA512_H1 0xbb67ae8584caa73bUL
#define MH_SHA512_H2 0x3c6ef372fe94f82bUL
#define MH_SHA512_H3 0xa54ff53a5f1d36f1UL
#define MH_SHA512_H4 0x510e527fade682d1UL
#define MH_SHA512_H5 0x9b05688c2b3e6c1fUL
#define MH_SHA512_H6 0x1f83d9abfb41bd6bUL
#define MH_SHA512_H7 0x5be0cd19137e2179UL

#define SHA512_PADLENGTHFIELD_SIZE	16

 /* mh_sha512 macros */
#define ror64(x, r) (((x)>>(r)) ^ ((x)<<(64-(r))))

#define bswap(x)  (((x) & (0xffull << 0)) << 56) \
		| (((x) & (0xffull << 8)) << 40) \
		| (((x) & (0xffull <<16)) << 24) \
		| (((x) & (0xffull <<24)) << 8)  \
		| (((x) & (0xffull <<32)) >> 8)  \
		| (((x) & (0xffull <<40)) >> 24) \
		| (((x) & (0xffull <<48)) >> 40) \
		| (((x) & (0xffull <<56)) >> 56)

#define S0(w) (ror64(w,1) ^ ror64(w,8) ^ (w >> 7))
#define S1(w) (ror64(w,19) ^ ror64(w,61) ^ (w >> 6))

#define s0(a) (ror64(a,28) ^ ror64(a,34) ^ ror64(a,39))
#define s1(e) (ror64(e,14) ^ ror64(e,18) ^ ror64(e,41))

#define maj(a,b,c) ((a & b) ^ (a & c) ^ (b & c))
#define ch(e,f,g) ((e & f) ^ (g & ~e))

 /*******************************************************************
  * SHA512 API internal function prototypes
  ******************************************************************/

 /**
  * @brief Performs complete SHA512 algorithm.
  *
  * @param input  Pointer to buffer containing the input message.
  * @param digest Pointer to digest to update.
  * @param len	  Length of buffer.
  * @returns None
  */
 void sha512_for_mh_sha512(const uint8_t * input_data, uint64_t * digest, const uint64_t len);

 /**
  * @brief Calculate sha512 digest of blocks which size is SHA512_BLOCK_SIZE
  *
  * @param data   Pointer to data buffer containing the input message.
  * @param digest Pointer to sha512 digest.
  * @returns None
  */
 void sha512_single_for_mh_sha512(const uint8_t * data, uint64_t digest[]);

 /*******************************************************************
  * mh_sha512 API internal function prototypes
  * Multiple versions of Update and Finalize functions are supplied which use
  * multiple versions of block and tail process subfunctions.
  ******************************************************************/

 /**
  * @brief  Tail process for multi-hash sha512.
  *
  * Calculate the remainder of input data which is less than MH_SHA512_BLOCK_SIZE.
  * It will output the final SHA512 digest based on mh_sha512_segs_digests.
  *
  * This function determines what instruction sets are enabled and selects the
  * appropriate version at runtime.
  *
  * @param  partial_buffer Pointer to the start addr of remainder
  * @param  total_len The total length of all sections of input data.
  * @param  mh_sha512_segs_digests The digests of all 16 segments .
  * @param  frame_buffer Pointer to buffer which is a temp working area
  * @returns none
  *
  */
 void mh_sha512_tail(uint8_t *partial_buffer, uint64_t total_len,
			 uint64_t (*mh_sha512_segs_digests)[HASH_SEGS],
			 uint8_t *frame_buffer, uint64_t mh_sha512_digest[SHA512_DIGEST_WORDS]);

 /**
  * @brief  Tail process for multi-hash sha512.
  *
  * Calculate the remainder of input data which is less than MH_SHA512_BLOCK_SIZE.
  * It will output the final SHA512 digest based on mh_sha512_segs_digests.
  *
  * @param  partial_buffer Pointer to the start addr of remainder
  * @param  total_len The total length of all sections of input data.
  * @param  mh_sha512_segs_digests The digests of all 16 segments .
  * @param  frame_buffer Pointer to buffer which is a temp working area
  * @param  mh_sha512_digest mh_sha512 digest
  * @returns none
  *
  */
 void mh_sha512_tail_base(uint8_t *partial_buffer, uint64_t total_len,
			 uint64_t (*mh_sha512_segs_digests)[HASH_SEGS],
			 uint8_t *frame_buffer, uint64_t mh_sha512_digest[SHA512_DIGEST_WORDS]);

 /**
  * @brief  Tail process for multi-hash sha512.
  *
  * Calculate the remainder of input data which is less than MH_SHA512_BLOCK_SIZE.
  * It will output the final SHA512 digest based on mh_sha512_segs_digests.
  *
  * @requires SSE
  *
  * @param  partial_buffer Pointer to the start addr of remainder
  * @param  total_len The total length of all sections of input data.
  * @param  mh_sha512_segs_digests The digests of all 16 segments .
  * @param  frame_buffer Pointer to buffer which is a temp working area
  * @param  mh_sha512_digest mh_sha512 digest
  * @returns none
  *
  */
 void mh_sha512_tail_sse(uint8_t *partial_buffer, uint64_t total_len,
			 uint64_t (*mh_sha512_segs_digests)[HASH_SEGS],
			 uint8_t *frame_buffer, uint64_t mh_sha512_digest[SHA512_DIGEST_WORDS]);

 /**
  * @brief  Tail process for multi-hash sha512.
  *
  * Calculate the remainder of input data which is less than MH_SHA512_BLOCK_SIZE.
  * It will output the final SHA512 digest based on mh_sha512_segs_digests.
  *
  * @requires AVX
  *
  * @param  partial_buffer Pointer to the start addr of remainder
  * @param  total_len The total length of all sections of input data.
  * @param  mh_sha512_segs_digests The digests of all 16 segments .
  * @param  frame_buffer Pointer to buffer which is a temp working area
  * @param  mh_sha512_digest mh_sha512 digest
  * @returns none
  *
  */
 void mh_sha512_tail_avx(uint8_t *partial_buffer, uint64_t total_len,
			 uint64_t (*mh_sha512_segs_digests)[HASH_SEGS],
			 uint8_t *frame_buffer, uint64_t mh_sha512_digest[SHA512_DIGEST_WORDS]);

 /**
  * @brief  Tail process for multi-hash sha512.
  *
  * Calculate the remainder of input data which is less than MH_SHA512_BLOCK_SIZE.
  * It will output the final SHA512 digest based on mh_sha512_segs_digests.
  *
  * @requires AVX2
  *
  * @param  partial_buffer Pointer to the start addr of remainder
  * @param  total_len The total length of all sections of input data.
  * @param  mh_sha512_segs_digests The digests of all 16 segments .
  * @param  frame_buffer Pointer to buffer which is a temp working area
  * @param  mh_sha512_digest mh_sha512 digest
  * @returns none
  *
  */
 void mh_sha512_tail_avx2(uint8_t *partial_buffer, uint64_t total_len,
			 uint64_t (*mh_sha512_segs_digests)[HASH_SEGS],
			 uint8_t *frame_buffer, uint64_t mh_sha512_digest[SHA512_DIGEST_WORDS]);

 /**
  * @brief  Tail process for multi-hash sha512.
  *
  * Calculate the remainder of input data which is less than MH_SHA512_BLOCK_SIZE.
  * It will output the final SHA512 digest based on mh_sha512_segs_digests.
  *
  * @requires AVX512
  *
  * @param  partial_buffer Pointer to the start addr of remainder
  * @param  total_len The total length of all sections of input data.
  * @param  mh_sha512_segs_digests The digests of all 16 segments .
  * @param  frame_buffer Pointer to buffer which is a temp working area
  * @param  mh_sha512_digest mh_sha512 digest
  * @returns none
  *
  */
 void mh_sha512_tail_avx512(uint8_t *partial_buffer, uint64_t total_len,
			 uint64_t (*mh_sha512_segs_digests)[HASH_SEGS],
			 uint8_t *frame_buffer, uint64_t mh_sha512_digest[SHA512_DIGEST_WORDS]);

 /**
  * @brief  Calculate mh_sha512 digest of blocks which size is MH_SHA512_BLOCK_SIZE*N.
  *
  * This function determines what instruction sets are enabled and selects the
  * appropriate version at runtime.
  *
  * @param  input_data Pointer to input data to be processed
  * @param  digests 16 segments digests
  * @param  frame_buffer Pointer to buffer which is a temp working area
  * @param  num_blocks The number of blocks.
  * @returns none
  *
  */
 void mh_sha512_block(const uint8_t * input_data, uint64_t digests[SHA512_DIGEST_WORDS][HASH_SEGS],
			 uint8_t frame_buffer[MH_SHA512_BLOCK_SIZE], uint64_t num_blocks);

 /**
  * @brief  Calculate mh_sha512 digest of blocks which size is MH_SHA512_BLOCK_SIZE*N.
  *
  * @param  input_data Pointer to input data to be processed
  * @param  digests 16 segments digests
  * @param  frame_buffer Pointer to buffer which is a temp working area
  * @param  num_blocks The number of blocks.
  * @returns none
  *
  */
 void mh_sha512_block_base(const uint8_t * input_data, uint64_t digests[SHA512_DIGEST_WORDS][HASH_SEGS],
			 uint8_t frame_buffer[MH_SHA512_BLOCK_SIZE], uint64_t num_blocks);

 /**
  * @brief  Calculate mh_sha512 digest of blocks which size is MH_SHA512_BLOCK_SIZE*N.
  *
  * @requires SSE
  * @param  input_data Pointer to input data to be processed
  * @param  digests 16 segments digests
  * @param  frame_buffer Pointer to buffer which is a temp working area
  * @param  num_blocks The number of blocks.
  * @returns none
  *
  */
 void mh_sha512_block_sse(const uint8_t * input_data, uint64_t digests[SHA512_DIGEST_WORDS][HASH_SEGS],
			 uint8_t frame_buffer[MH_SHA512_BLOCK_SIZE], uint64_t num_blocks);

 /**
  * @brief  Calculate mh_sha512 digest of blocks which size is MH_SHA512_BLOCK_SIZE*N.
  *
  * @requires AVX
  *
  * @param  input_data Pointer to input data to be processed
  * @param  digests 16 segments digests
  * @param  frame_buffer Pointer to buffer which is a temp working area
  * @param  num_blocks The number of blocks.
  * @returns none
  *
  */
 void mh_sha512_block_avx(const uint8_t * input_data, uint64_t digests[SHA512_DIGEST_WORDS][HASH_SEGS],
			 uint8_t frame_buffer[MH_SHA512_BLOCK_SIZE], uint64_t num_blocks);

 /**
  * @brief  Calculate mh_sha512 digest of blocks which size is MH_SHA512_BLOCK_SIZE*N.
  *
  * @requires AVX2
  *
  * @param  input_data Pointer to input data to be processed
  * @param  digests 16 segments digests
  * @param  frame_buffer Pointer to buffer which is a temp working area
  * @param  num_blocks The number of blocks.
  * @returns none
  *
  */
 void mh_sha512_block_avx2(const uint8_t * input_data, uint64_t digests[SHA512_DIGEST_WORDS][HASH_SEGS],
			 uint8_t frame_buffer[MH_SHA512_BLOCK_SIZE], uint64_t num_blocks);

 /**
  * @brief  Calculate mh_sha512 digest of blocks which size is MH_SHA512_BLOCK_SIZE*N.
  *
  * @requires AVX512
  *
  * @param  input_data Pointer to input data to be processed
  * @param  digests 16 segments digests
  * @param  frame_buffer Pointer to buffer which is a temp working area
  * @param  num_blocks The number of blocks.
  * @returns none
  *
  */
 void mh_sha512_block_avx512(const uint8_t * input_data, uint64_t digests[SHA512_DIGEST_WORDS][HASH_SEGS],
			 uint8_t frame_buffer[MH_SHA512_BLOCK_SIZE], uint64_t num_blocks);

#ifdef __cplusplus
}
#endif

#endif
