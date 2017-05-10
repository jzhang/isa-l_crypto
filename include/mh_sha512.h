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

#ifndef _MH_SHA512_H_
#define _MH_SHA512_H_

/**
 *  @file mh_sha512.h
 *  @brief mh_sha512 function prototypes and structures
 *
 *  Interface for mh_sha512 functions
 *
 * <b> mh_sha512  Init-Update..Update-Finalize </b>
 *
 * This file defines the interface to optimized functions used in mh_sha512.
 * The definition of multi-hash SHA512(mh_sha512, for short) is: Pad the buffer
 * in SHA512 style until the total length is a multiple of 4*16*16
 * (words-width * parallel-segments * block-size); Hash the buffer in
 * parallel, generating digests of 4*16*8 (words-width*parallel-segments*
 * digest-size); Treat the set of digests as another data buffer, and
 * generate a final SHA512 digest for it.
 *
 *
 * Example
 * \code
 * uint64_t mh_sha512_digest[SHA512_DIGEST_WORDS];
 * struct mh_sha512_ctx *ctx;
 *
 * ctx = malloc(sizeof(struct mh_sha512_ctx));
 * mh_sha512_init(ctx);
 * mh_sha512_update(ctx, buff, block_len);
 * mh_sha512_finalize(ctx, mh_sha512_digest);
 * \endcode
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif


// External Interface Definition
#define HASH_SEGS					      16
#define SHA512_BLOCK_SIZE				128
#define MH_SHA512_BLOCK_SIZE    (HASH_SEGS * SHA512_BLOCK_SIZE)
#define SHA512_DIGEST_WORDS			8
#define AVX512_ALIGNED					64

/** @brief Holds info describing a single mh_sha512
 *
 * It is better to use heap to allocate this data structure to avoid stack overflow.
 *
*/
struct mh_sha512_ctx {
	uint64_t  mh_sha512_digest[SHA512_DIGEST_WORDS]; //!< the digest of multi-hash SHA512

	uint64_t  total_length;
	//!<  Parameters for update feature, describe the lengths of input buffers in bytes
	uint8_t   partial_block_buffer [MH_SHA512_BLOCK_SIZE * 2];
	//!<  Padding the tail of input data for SHA512
	uint8_t   mh_sha512_interim_digests[sizeof(uint64_t) * SHA512_DIGEST_WORDS * HASH_SEGS];
	//!<  Storing the SHA512 interim digests of  all 16 segments. Each time, it will be copied to stack for 64-byte alignment purpose.
	uint8_t   frame_buffer[MH_SHA512_BLOCK_SIZE + AVX512_ALIGNED];
	//!<  Re-structure sha512 block data from different segments to fit big endian. Use AVX512_ALIGNED for 64-byte alignment purpose.
};

/**
 *  @enum mh_sha512_ctx_error
 *  @brief CTX error flags
 */
enum mh_sha512_ctx_error{
	MH_SHA512_CTX_ERROR_NONE			=  0, //!< MH_SHA512_CTX_ERROR_NONE
	MH_SHA512_CTX_ERROR_NULL			= -1, //!< MH_SHA512_CTX_ERROR_NULL
};


/*******************************************************************
 * mh_sha512 API function prototypes
 ******************************************************************/

/**
 * @brief Initialize the mh_sha512_ctx structure.
 *
 * @param  ctx Structure holding mh_sha512 info
 * @returns int Return 0 if the function runs without errors
 */
int mh_sha512_init (struct mh_sha512_ctx* ctx);

/**
 * @brief Multi-hash sha512 update.
 *
 * Can be called repeatedly to update hashes with new input data.
 * This function determines what instruction sets are enabled and selects the
 * appropriate version at runtime.
 *
 * @param  ctx Structure holding mh_sha512 info
 * @param  buffer Pointer to buffer to be processed
 * @param  len Length of buffer (in bytes) to be processed
 * @returns int Return 0 if the function runs without errors
 */
int mh_sha512_update (struct mh_sha512_ctx * ctx, const void* buffer, uint64_t len);

/**
 * @brief Finalize the message digests for multi-hash sha512.
 *
 * Place the message digest in mh_sha512_digest which must have enough space
 * for the outputs.
 * This function determines what instruction sets are enabled and selects the
 * appropriate version at runtime.
 *
 * @param   ctx Structure holding mh_sha512 info
 * @param   mh_sha512_digest The digest of mh_sha512
 * @returns int Return 0 if the function runs without errors
 */
int mh_sha512_finalize (struct mh_sha512_ctx* ctx, void* mh_sha512_digest);

/*******************************************************************
 * multi-types of mh_sha512 internal API
 *
 * XXXX		The multi-binary version
 * XXXX_base	The C code version which used to display the algorithm
 * XXXX_sse	The version uses a ASM function optimized for SSE
 * XXXX_avx	The version uses a ASM function optimized for AVX
 * XXXX_avx2	The version uses a ASM function optimized for AVX2
 * XXXX_avx512	The version uses a ASM function optimized for AVX512
 *
 ******************************************************************/

/**
 * @brief Multi-hash sha512 update.
 *
 * Can be called repeatedly to update hashes with new input data.
 * Base update() function that does not require SIMD support.
 *
 * @param   ctx Structure holding mh_sha512 info
 * @param   buffer Pointer to buffer to be processed
 * @param   len Length of buffer (in bytes) to be processed
 * @returns int Return 0 if the function runs without errors
 *
 */
int mh_sha512_update_base (struct mh_sha512_ctx* ctx, const void* buffer, uint64_t len);

/**
 * @brief Multi-hash sha512 update.
 *
 * Can be called repeatedly to update hashes with new input data.
 * @requires SSE
 *
 * @param   ctx Structure holding mh_sha512 info
 * @param   buffer Pointer to buffer to be processed
 * @param   len Length of buffer (in bytes) to be processed
 * @returns int Return 0 if the function runs without errors
 *
 */
int mh_sha512_update_sse (struct mh_sha512_ctx * ctx,
						const void* buffer, uint64_t len);

/**
 * @brief Multi-hash sha512 update.
 *
 * Can be called repeatedly to update hashes with new input data.
 * @requires AVX
 *
 * @param   ctx Structure holding mh_sha512 info
 * @param   buffer Pointer to buffer to be processed
 * @param   len Length of buffer (in bytes) to be processed
 * @returns int Return 0 if the function runs without errors
 *
 */
int mh_sha512_update_avx (struct mh_sha512_ctx * ctx,
						const void* buffer, uint64_t len);

/**
 * @brief Multi-hash sha512 update.
 *
 * Can be called repeatedly to update hashes with new input data.
 * @requires AVX2
 *
 * @param   ctx Structure holding mh_sha512 info
 * @param   buffer Pointer to buffer to be processed
 * @param   len Length of buffer (in bytes) to be processed
 * @returns int Return 0 if the function runs without errors
 *
 */
int mh_sha512_update_avx2 (struct mh_sha512_ctx * ctx,
						const void* buffer, uint64_t len);

/**
 * @brief Multi-hash sha512 update.
 *
 * Can be called repeatedly to update hashes with new input data.
 * @requires AVX512
 *
 * @param   ctx Structure holding mh_sha512 info
 * @param   buffer Pointer to buffer to be processed
 * @param   len Length of buffer (in bytes) to be processed
 * @returns int Return 0 if the function runs without errors
 *
 */
int mh_sha512_update_avx512 (struct mh_sha512_ctx * ctx,
						const void* buffer, uint64_t len);


/**
  * @brief Finalize the message digests for multi-hash sha512.
 *
 * Place the message digests in mh_sha512_digest,
 * which must have enough space for the outputs.
 * Base Finalize() function that does not require SIMD support.
 *
 * @param   ctx Structure holding mh_sha512 info
 * @param   mh_sha512_digest The digest of mh_sha512
 * @returns int Return 0 if the function runs without errors
 *
 */
int mh_sha512_finalize_base (struct mh_sha512_ctx* ctx,
						void* mh_sha512_digest);

/**
 * @brief Finalize the message digests for combined multi-hash and murmur.
 *
 * Place the message digest in mh_sha512_digest which must have enough space
 * for the outputs.
 *
 * @requires SSE
 *
 * @param   ctx Structure holding mh_sha512 info
 * @param   mh_sha512_digest The digest of mh_sha512
 * @returns int Return 0 if the function runs without errors
 *
 */
int mh_sha512_finalize_sse (struct mh_sha512_ctx* ctx,
						void* mh_sha512_digest);

/**
 * @brief Finalize the message digests for combined multi-hash and murmur.
 *
 * Place the message digest in mh_sha512_digest which must have enough space
 * for the outputs.
 *
 * @requires AVX
 *
 * @param   ctx Structure holding mh_sha512 info
 * @param   mh_sha512_digest The digest of mh_sha512
 * @returns int Return 0 if the function runs without errors
 *
 */
int mh_sha512_finalize_avx (struct mh_sha512_ctx* ctx,
						void* mh_sha512_digest);

/**
 * @brief Finalize the message digests for combined multi-hash and murmur.
 *
 * Place the message digest in mh_sha512_digest which must have enough space
 * for the outputs.
 *
 * @requires AVX2
 *
 * @param   ctx Structure holding mh_sha512 info
 * @param   mh_sha512_digest The digest of mh_sha512
 * @returns int Return 0 if the function runs without errors
 *
 */
int mh_sha512_finalize_avx2 (struct mh_sha512_ctx* ctx,
						void* mh_sha512_digest);

/**
 * @brief Finalize the message digests for combined multi-hash and murmur.
 *
 * Place the message digest in mh_sha512_digest which must have enough space
 * for the outputs.
 *
 * @requires AVX512
 *
 * @param   ctx Structure holding mh_sha512 info
 * @param   mh_sha512_digest The digest of mh_sha512
 * @returns int Return 0 if the function runs without errors
 *
 */
int mh_sha512_finalize_avx512 (struct mh_sha512_ctx* ctx,
						void* mh_sha512_digest);

#ifdef __cplusplus
}
#endif

#endif

