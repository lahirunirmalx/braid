// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * br_crypto.h - Braid crypto primitives (spec 8.3, 8.4; keys 8.2).
 *
 * Construction (8.3):
 * - End-to-end: AES-128-CCM, 13-byte nonce, 8-byte tag.
 * - Per hop: hop_tag = HMAC-SHA256(K_hop(E), frame[0 .. end of auth_tag])[0..3].
 * - HMAC-SHA256 is also the HKDF primitive (RFC 5869).
 *
 * Backend: mbedtls on both the host and the device (ESP-IDF's mbedtls
 * component; CONFIG_MBEDTLS_HARDWARE_AES / _SHA change latency only, never
 * output, 12.12). This header exposes the mbedtls HMAC context type so the
 * caller can own the storage (static or allocated once at init).
 *
 * Memory rule (Appendix B): br_crypto_init() is the only function that may
 * allocate (mbedtls_md_setup() allocates the HMAC state once). Every other
 * function uses the HMAC context inside br_crypto_t and the stack; no heap.
 *
 * Why AES-CCM is built here on the AES block primitive (not mbedtls_ccm_*):
 * - mbedtls_ccm_setkey() allocates on every call. In mbedtls 3.6 without
 *   MBEDTLS_BLOCK_CIPHER_C (the case for the host config and ESP-IDF 5.5's
 *   config) ccm.c keys through the generic cipher layer, and
 *   mbedtls_cipher_setup() callocs an AES context per re-key. Every frame
 *   uses a different Ke_*, so that is one heap allocation per frame, which
 *   the memory rule above forbids.
 * - br_crypto.c therefore implements RFC 3610 / SP 800-38C CCM (M = 8,
 *   L = 2, 13-byte nonce, 2-byte AAD length prefix) over a stack
 *   mbedtls_aes_context: mbedtls_aes_setkey_enc + mbedtls_aes_crypt_ecb.
 *   On ESP32 / ESP32-S3 those calls are the hardware AES driver, so the
 *   accelerator is still used; no CCM-specific code runs in hardware.
 * - Evidence that it is CCM: (1) every Appendix A CCM vector (A.7, A.8 SEEK,
 *   A.9 HELLO / BIND, A.10, A.11, A.12 REQ / RESP, A.14 bundle, A.15 SEEK /
 *   HELLO), produced by tools/vectors.py with Python `cryptography` AESCCM,
 *   is reproduced byte for byte in test/host/test_crypto.c; (2) a phase 1a
 *   differential run against Python `cryptography` AESCCM over plaintext
 *   lengths 0..255 and AAD lengths 0..269 plus tag / ciphertext / AAD tamper
 *   cases (one-off run, script not kept in the repo); (3) RFC 3610 section 8
 *   packet vectors #1-#6 and #13-#18 (the M = 8, L = 2 ones), independent
 *   of this repository, in test/host/test_ccm_standard.c; (4) the Appendix A
 *   vectors replayed on the chip's hardware AES by br_selftest_run()
 *   (BR_SELFTEST builds, firmware/SELFTEST.txt).
 *
 * Argument error precedence (every function taking a br_crypto_t, SPEC-NOTES
 * N20): (1) a NULL pointer that is not allowed -> BR_ERR_ARG; then (2) c not
 * initialised (never br_crypto_init()ed, or freed) -> BR_ERR_STATE; then
 * (3) length / range violations -> BR_ERR_ARG. So a NULL argument on an
 * uninitialised context reports ARG, and an out-of-range length on an
 * uninitialised context reports STATE.
 *
 * Threading: a br_crypto_t is used by one task at a time (br_task); separate
 * tasks need separate contexts.
 *
 * Keys are ALWAYS caller-supplied. No key material lives in this component.
 * Appendix A key vectors are TEST ONLY and are refused by field builds (12.1,
 * br_key_check_field()).
 *
 * Every function that produces secret-dependent output zeroes its scratch
 * before returning. Every *_verify / decrypt compares in constant time.
 */
#ifndef BRAID_BR_CRYPTO_H
#define BRAID_BR_CRYPTO_H

#include "braid/br_types.h"

#include "mbedtls/md.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BR_AES_KEY_LEN      16u  /**< Ke_* (AES-128). */
#define BR_HOP_KEY_LEN      32u  /**< K_hop(E) (A.6: 32 bytes). */
#define BR_SHA256_LEN       32u
#define BR_CCM_NONCE_LEN    13u
#define BR_CCM_TAG_LEN      BR_AUTH_TAG_LEN  /**< 8 */
#define BR_HKDF_MAX_OKM     (255u * BR_SHA256_LEN)
#define BR_AAD_MAX_LEN      (BR_E2E_HDR_LEN + 4u + 255u) /**< e2e header + ctr_hi + clear prefix */

/**
 * KDF domain-separation labels (8.2). ASCII; the trailing NUL of the C
 * literal is NOT part of the label, so always pass BR_LABEL_LEN(label)
 * bytes. This is the single definition for the core, the self-test and the
 * host tests; tools/vectors.py LBL_* must name the same bytes.
 * BR_LABEL_LEN only works on these literal macros (sizeof of a pointer would
 * be wrong).
 */
#define BR_LABEL_V1         "Braid-v1"    /**< Extract salt: PRK, K_hop, Ke_mesh, K_mgmt, Kb, edge keys */
#define BR_LABEL_MESH       "Braid-mesh"  /**< K_mesh(E) = HKDF(K_site, BR_LABEL_MESH, E u8, 32) */
#define BR_LABEL_PAIR       "Braid-pair"  /**< K_pair(A, B, E) = HKDF(K_site, BR_LABEL_PAIR, ..., 32) */
#define BR_LABEL_NODE       "Braid-node"  /**< K_node(N) = HKDF(K_site, BR_LABEL_NODE, N u16, 32); bench tool only */
#define BR_LABEL_LEN(label) (sizeof(label) - 1u)
#define BR_LABEL_U8(label)  ((const uint8_t *)(label))

/** Nonce dir byte (8.3). */
#define BR_DIR_TO_PROBE     0u   /**< sender -> probe, node -> manager */
#define BR_DIR_FROM_PROBE   1u   /**< probe -> sender, manager -> node */
#define BR_DIR_BUNDLE       2u   /**< key bundle nonce (8.6); different layout, see br_ccm_nonce() */

/** Caller-owned crypto state. Treat fields as private. */
typedef struct {
    mbedtls_md_context_t hmac;   /**< HMAC-SHA256, set up once by br_crypto_init(). */
    bool                 ready;  /**< Set by br_crypto_init(), cleared by br_crypto_free(). */
} br_crypto_t;

/**
 * Initialise a crypto context (the one allocation point).
 *
 * @param c  Storage owned by the caller.
 * @return BR_OK; BR_ERR_ARG if c is NULL; BR_ERR_NO_MEM if mbedtls could not
 *         allocate the HMAC state; BR_ERR_CRYPTO for other backend errors.
 *         On failure *c is left freed (safe to call br_crypto_free()).
 * @spec Appendix B (heap once at init), 8.3
 */
br_err_t br_crypto_init(br_crypto_t *c);

/**
 * Release a context and wipe it. Safe on a zeroed or already-freed context
 * and on NULL (no-op).
 */
void br_crypto_free(br_crypto_t *c);

/**
 * HMAC-SHA256.
 *
 * @param c        Initialised context.
 * @param key      Key bytes; NULL only if key_len == 0.
 * @param key_len  Any length (keys > 64 bytes are hashed per RFC 2104).
 * @param data     Message; NULL only if len == 0.
 * @param len      Message length.
 * @param mac_out  Receives 32 bytes.
 * @return BR_OK; BR_ERR_ARG on NULL pointers; BR_ERR_STATE if c is not
 *         initialised; BR_ERR_CRYPTO on backend failure.
 * @spec 8.3
 */
br_err_t br_hmac_sha256(br_crypto_t *c, const uint8_t *key, size_t key_len,
                        const uint8_t *data, size_t len, uint8_t mac_out[BR_SHA256_LEN]);

/**
 * HKDF-Extract (RFC 5869): PRK = HMAC-SHA256(salt, ikm).
 *
 * A.6: PRK = Extract("Braid-v1", K_pair), i.e. salt is the 8 ASCII bytes
 * "Braid-v1" (BR_LABEL_V1, no NUL) and ikm the 32-byte pair key.
 *
 * @param c         Initialised context.
 * @param salt      Salt; NULL with salt_len 0 means 32 zero bytes (RFC 5869).
 * @param salt_len  Salt length.
 * @param ikm       Input key material; NULL only if ikm_len == 0.
 * @param ikm_len   IKM length.
 * @param prk_out   Receives 32 bytes.
 * @return BR_OK; BR_ERR_ARG; BR_ERR_STATE; BR_ERR_CRYPTO.
 * @spec 8.2, A.6
 */
br_err_t br_hkdf_extract(br_crypto_t *c, const uint8_t *salt, size_t salt_len,
                         const uint8_t *ikm, size_t ikm_len, uint8_t prk_out[BR_SHA256_LEN]);

/**
 * HKDF-Expand (RFC 5869): OKM = T(1) || T(2) || ... truncated to okm_len.
 *
 * A.9: Ke_hello = Expand(PRK, "hello" || src LE || dst LE || T0, 16).
 *
 * @param c         Initialised context.
 * @param prk       Pseudorandom key.
 * @param prk_len   >= 32.
 * @param info      Info; NULL only if info_len == 0.
 * @param info_len  Info length.
 * @param okm_out   Output.
 * @param okm_len   1..BR_HKDF_MAX_OKM (8160).
 * @return BR_OK; BR_ERR_ARG (NULL, prk_len < 32, okm_len 0 or > 8160);
 *         BR_ERR_STATE; BR_ERR_CRYPTO.
 * @spec 8.2, A.6, A.9
 */
br_err_t br_hkdf_expand(br_crypto_t *c, const uint8_t *prk, size_t prk_len,
                        const uint8_t *info, size_t info_len, uint8_t *okm_out, size_t okm_len);

/**
 * HKDF (RFC 5869) = Expand(Extract(salt, ikm), info, okm_len).
 * Same arguments and errors as br_hkdf_extract() + br_hkdf_expand().
 * @spec 8.2
 */
br_err_t br_hkdf_sha256(br_crypto_t *c, const uint8_t *salt, size_t salt_len,
                        const uint8_t *ikm, size_t ikm_len,
                        const uint8_t *info, size_t info_len, uint8_t *okm_out, size_t okm_len);

/**
 * Build a 13-byte CCM nonce.
 *
 * Frame nonce, dir BR_DIR_TO_PROBE (0) or BR_DIR_FROM_PROBE (1) (8.3, line 817):
 *   dir u8 || src_id u16 LE || dst_id u16 LE || session_id u8 ||
 *   ctr_hi u32 LE || seq u16 LE || 0x00
 * ctr_hi is the ROC for session frames (RESUME included) and pre_ctr >> 16
 * for session_id 0 frames.
 * Example (A.7): dir 0, 0x1234, 0x0042, session 7, ctr_hi 0, seq 5 ->
 *   00 34 12 42 00 07 00 00 00 00 05 00 00.
 *
 * Bundle nonce, dir BR_DIR_BUNDLE (2) (8.6, line 905; SPEC-NOTES N19):
 *   0x02 || N u16 LE || bundle_no u32 LE || 0x00 x 6
 * Pass the node ID N as src_id and bundle_no as ctr_hi; dst_id, session_id
 * and seq must be 0 (they have no place in this layout).
 * Example (A.14): br_ccm_nonce(BR_DIR_BUNDLE, 0x0042, 0, 0, 3, 0, n) ->
 *   02 42 00 03 00 00 00 00 00 00 00 00 00.
 * The leading byte keeps the two nonce spaces disjoint.
 *
 * @param dir        BR_DIR_TO_PROBE, BR_DIR_FROM_PROBE or BR_DIR_BUNDLE.
 * @param nonce_out  Receives 13 bytes.
 * @return BR_OK; BR_ERR_ARG if nonce_out is NULL, dir > 2, or dir == 2 with
 *         a non-zero dst_id, session_id or seq.
 * @spec 8.3, 8.6, A.7, A.8, A.9, A.10, A.14
 */
br_err_t br_ccm_nonce(uint8_t dir, uint16_t src_id, uint16_t dst_id, uint8_t session_id,
                      uint32_t ctr_hi, uint16_t seq, uint8_t nonce_out[BR_CCM_NONCE_LEN]);

/**
 * Build the CCM AAD from a laid-out frame (8.3, line 826):
 *   e2e_header (10) || ctr_hi u32 LE || clear prefix
 * where e2e_header = frame bytes 0..5 || session_id || seq (2) || len, taken
 * from their type-dependent offsets (SEEK: 18, 19, 21), and the clear prefix is
 * the first clear_len payload bytes (br_frame_clear_len()).
 * Example (A.9 HELLO): 12 02 42 00 34 12 00 07 00 1c || 01 00 00 00 || 07 00 01 00.
 *
 * @param frame     Frame bytes (header + at least clear_len payload bytes).
 * @param frame_len Bytes available in frame.
 * @param ctr_hi    As for br_ccm_nonce().
 * @param clear_len Clear prefix length, 0..len.
 * @param aad_out   Output buffer.
 * @param cap       Capacity; BR_AAD_MAX_LEN is always enough.
 * @param aad_len   Receives 14 + clear_len.
 * @return BR_OK; BR_ERR_ARG on NULL pointers or clear_len > header len field;
 *         BR_ERR_DECODE if frame_len does not cover header + clear_len;
 *         BR_ERR_TOO_BIG if cap is too small.
 * @spec 8.3, A.7, A.8, A.9
 */
br_err_t br_ccm_aad(const uint8_t *frame, size_t frame_len, uint32_t ctr_hi, size_t clear_len,
                    uint8_t *aad_out, size_t cap, size_t *aad_len);

/**
 * AES-128-CCM encrypt and tag (8-byte tag, 13-byte nonce, L = 2).
 *
 * pt_len may be 0 (SEEK / RESUME: authentication only, A.8 SEEK).
 *
 * @param c        Initialised context.
 * @param key      16-byte Ke_*.
 * @param nonce    13 bytes from br_ccm_nonce().
 * @param aad      AAD; NULL only if aad_len == 0.
 * @param aad_len  0..BR_AAD_MAX_LEN.
 * @param pt       Plaintext; NULL only if pt_len == 0.
 * @param pt_len   0..255.
 * @param ct_out   Receives pt_len bytes; may equal pt (in place), must not
 *                 otherwise overlap.
 * @param tag_out  Receives 8 bytes.
 * @return BR_OK; BR_ERR_ARG (NULL, pt_len > 255, aad_len too long);
 *         BR_ERR_STATE; BR_ERR_CRYPTO.
 * @spec 8.3, A.7, A.9, A.10, A.11
 */
br_err_t br_ccm_encrypt(br_crypto_t *c, const uint8_t key[BR_AES_KEY_LEN],
                        const uint8_t nonce[BR_CCM_NONCE_LEN],
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *pt, size_t pt_len,
                        uint8_t *ct_out, uint8_t tag_out[BR_CCM_TAG_LEN]);

/**
 * AES-128-CCM verify and decrypt.
 *
 * The tag is compared in constant time. On BR_ERR_AUTH pt_out is zeroed
 * (never released unauthenticated) and the caller counts auth_fail.
 *
 * @param c        Initialised context.
 * @param key      16-byte Ke_*.
 * @param nonce    13 bytes.
 * @param aad      AAD; NULL only if aad_len == 0.
 * @param aad_len  0..BR_AAD_MAX_LEN.
 * @param ct       Ciphertext; NULL only if ct_len == 0.
 * @param ct_len   0..255.
 * @param tag      8 received tag bytes.
 * @param pt_out   Receives ct_len bytes; may equal ct (in place).
 * @return BR_OK; BR_ERR_AUTH on tag mismatch; BR_ERR_ARG; BR_ERR_STATE;
 *         BR_ERR_CRYPTO.
 * @spec 8.3, 3.6 (CCM tag row)
 */
br_err_t br_ccm_decrypt(br_crypto_t *c, const uint8_t key[BR_AES_KEY_LEN],
                        const uint8_t nonce[BR_CCM_NONCE_LEN],
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *ct, size_t ct_len,
                        const uint8_t tag[BR_CCM_TAG_LEN], uint8_t *pt_out);

/**
 * Compute the hop_tag: HMAC-SHA256(K_hop(E), frame[0 .. covered_len-1])[0..3].
 *
 * covered_len is the offset of the hop_tag field (= end of auth_tag,
 * br_frame_view_t.hop_tag_off). A.7: covered_len 38 for a 44-byte DATA frame;
 * A.8 keyed SEEK: 48.
 *
 * Minimum covered_len: header + auth_tag, i.e.
 * br_hdr_len_for_type(frame[1]) + BR_AUTH_TAG_LEN = 27 for every type except
 * SEEK, 30 for SEEK (22-byte header; SPEC-NOTES N18). Checked in that order:
 * covered_len < 27 is refused before frame[1] is read, then a SEEK with
 * covered_len 27..29 is refused.
 *
 * @param c            Initialised context.
 * @param k_hop        32-byte K_hop(E) (or K_hop_edge on edge_only links).
 * @param frame        Frame bytes with the current per-hop fields.
 * @param covered_len  >= br_hdr_len_for_type(frame[1]) + BR_AUTH_TAG_LEN (27, SEEK 30).
 * @param tag_out      Receives 4 bytes.
 * @return BR_OK; BR_ERR_ARG (NULL pointers, covered_len below the minimum);
 *         BR_ERR_STATE; BR_ERR_CRYPTO.
 * @spec 8.3, A.7, A.8
 */
br_err_t br_hop_tag(br_crypto_t *c, const uint8_t k_hop[BR_HOP_KEY_LEN],
                    const uint8_t *frame, size_t covered_len, uint8_t tag_out[BR_HOP_TAG_LEN]);

/**
 * Verify a received hop_tag under one K_hop epoch (constant-time compare).
 * The caller tries each held epoch (8.5) and counts hop_tag_fail when none
 * verifies. Same arguments and covered_len minimum as br_hop_tag().
 *
 * @return BR_OK if equal; BR_ERR_AUTH if not; BR_ERR_ARG; BR_ERR_STATE;
 *         BR_ERR_CRYPTO.
 * @spec 8.3, 3.6 (hop_tag row)
 */
br_err_t br_hop_tag_verify(br_crypto_t *c, const uint8_t k_hop[BR_HOP_KEY_LEN],
                           const uint8_t *frame, size_t covered_len,
                           const uint8_t tag[BR_HOP_TAG_LEN]);

/**
 * Constant-time equality of two byte strings. Run time depends only on len.
 *
 * @param a, b  Inputs; NULL only if len == 0.
 * @param len   Bytes to compare.
 * @return BR_OK if equal (or len == 0); BR_ERR_AUTH if they differ;
 *         BR_ERR_ARG if a or b is NULL with len > 0.
 * @spec 8.3, 8.7
 */
br_err_t br_ct_equal(const uint8_t *a, const uint8_t *b, size_t len);

/**
 * Field-profile key check (12.1, line 1364; SPEC-NOTES N13, N14).
 *
 * Field builds call this on every key before installing it (K_site-derived
 * keys arriving in bundles, provisioned keys). It refuses exactly:
 *  1. any key whose bytes are all equal (all-zero included), any
 *     key_len >= 1;
 *  2. a 32-byte key (key_len == 32) whose SHA-256[0..7] equals
 *     SHA-256(K_mesh(E))[0..7] for some E in 0..255, where
 *     K_mesh(E) = HKDF(salt "Braid-mesh", IKM K_site, info E u8, 32) and
 *     K_site is the Appendix A TEST ONLY site key 00 01 .. 1f. The image
 *     carries only the 256 x 8-byte hash prefixes (2 KB), not the keys.
 * It does NOT refuse anything else. In particular the other Appendix A test
 * keys (K_site itself, K_node, K_pair, K_hop, Ke_mesh, Ke_*, K_mgmt, Kb) pass
 * (errata candidate, SPEC-NOTES N14), and a key of any length other than 32
 * is only checked by rule 1.
 * The comparison runs over the whole table with no early exit, so the run
 * time does not reveal which entry matched.
 *
 * @param key      Key bytes.
 * @param key_len  >= 1.
 * @return BR_OK if the key may be used in the field; BR_ERR_AUTH if it is
 *         refused; BR_ERR_ARG if key is NULL or key_len == 0; BR_ERR_CRYPTO
 *         on a SHA-256 backend failure.
 * @spec 12.1
 */
br_err_t br_key_check_field(const uint8_t *key, size_t key_len);

/**
 * Wipe memory in a way the compiler cannot elide (mbedtls_platform_zeroize).
 * NULL with len 0 is a no-op.
 */
void br_secure_zero(void *p, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* BRAID_BR_CRYPTO_H */
