// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * test_crypto.c - HMAC/HKDF/AES-CCM/hop_tag (spec 8.2, 8.3, 8.6; A.6-A.12, A.14, A.15).
 *
 * Key schedule is recomputed from K_site with the public primitives and checked
 * against the vectors; every end-to-end frame vector is nonce/AAD/encrypt/decrypt
 * checked; every hop_tag is recomputed and verified. Independent oracle:
 * SHA-256 transcripts (T0, T) use mbedtls_sha256() directly because br_crypto.h
 * exposes no plain SHA-256.
 */
#include "braid/br_crypto.h"
#include "mbedtls/sha256.h"
#include "test_util.h"
#include "test_vectab.h"

static br_crypto_t C;

static const uint8_t *S(const char *s) { return (const uint8_t *)s; }

/* ------------------------------------------------------------------------- */
/* derivation helpers (spec 8.2 formulas)                                     */
/* ------------------------------------------------------------------------- */

/** Expand(Extract(BR_LABEL_V1, ikm32), label || tail, outlen) */
static void kdf_v1(const uint8_t *ikm, const char *label, const uint8_t *tail, size_t tail_len,
                   uint8_t *out, size_t outlen)
{
    uint8_t prk[32], info[128];
    size_t ll = strlen(label);
    memcpy(info, label, ll);
    if (tail_len) {
        memcpy(info + ll, tail, tail_len);
    }
    CHECK_ERR(br_hkdf_extract(&C, S(BR_LABEL_V1), BR_LABEL_LEN(BR_LABEL_V1), ikm, 32, prk), BR_OK);
    CHECK_ERR(br_hkdf_expand(&C, prk, 32, info, ll + tail_len, out, outlen), BR_OK);
}

static void k_mesh(const uint8_t *k_site, uint8_t e, uint8_t out[32])
{
    CHECK_ERR(br_hkdf_sha256(&C, S(BR_LABEL_MESH), BR_LABEL_LEN(BR_LABEL_MESH), k_site, 32, &e, 1, out, 32), BR_OK);
}

static void k_pair(const uint8_t *k_site, uint16_t a, uint16_t b, uint8_t e, uint8_t out[32])
{
    uint8_t info[5];
    uint16_t lo = a < b ? a : b, hi = a < b ? b : a;
    tu_put16(info, lo);
    tu_put16(info + 2, hi);
    info[4] = e;
    CHECK_ERR(br_hkdf_sha256(&C, S(BR_LABEL_PAIR), BR_LABEL_LEN(BR_LABEL_PAIR), k_site, 32, info, 5, out, 32), BR_OK);
}

static void k_node(const uint8_t *k_site, uint16_t n, uint8_t out[32])
{
    uint8_t info[2];
    tu_put16(info, n);
    CHECK_ERR(br_hkdf_sha256(&C, S(BR_LABEL_NODE), BR_LABEL_LEN(BR_LABEL_NODE), k_site, 32, info, 2, out, 32), BR_OK);
}

/* e2e header = bytes 0..5 || session_id || seq || len, from the type-dependent offsets (8.3) */
static void e2e_hdr(const uint8_t *frame, uint8_t out[10])
{
    memcpy(out, frame, 6);
    size_t o = (frame[1] == 0x01) ? 18u : 15u;
    out[6] = frame[o];
    out[7] = frame[o + 1];
    out[8] = frame[o + 2];
    out[9] = frame[o + 3];
}

static void sha256(const uint8_t *a, size_t an, uint8_t out[32])
{
    CHECK(mbedtls_sha256(a, an, out, 0) == 0);
}

/* ------------------------------------------------------------------------- */
/* primitives                                                                 */
/* ------------------------------------------------------------------------- */

static void test_init_and_state(void)
{
    tu_ctx("init/free/state");
    CHECK_ERR(br_crypto_init(NULL), BR_ERR_ARG);
    br_crypto_free(NULL); /* no-op */
    br_crypto_t z;
    memset(&z, 0, sizeof z);
    br_crypto_free(&z); /* safe on a zeroed context */
    uint8_t mac[32], k16[16] = {0}, k32[32] = {0}, n13[13] = {0}, tag8[8] = {0}, tag4[4] = {0}, b[16] = {0};
    CHECK_ERR(br_hmac_sha256(&z, k32, 32, b, 16, mac), BR_ERR_STATE);
    CHECK_ERR(br_hkdf_extract(&z, k32, 32, k32, 32, mac), BR_ERR_STATE);
    CHECK_ERR(br_hkdf_expand(&z, k32, 32, b, 4, mac, 16), BR_ERR_STATE);
    CHECK_ERR(br_hkdf_sha256(&z, k32, 32, k32, 32, b, 4, mac, 16), BR_ERR_STATE);
    CHECK_ERR(br_ccm_encrypt(&z, k16, n13, b, 4, b, 4, b, tag8), BR_ERR_STATE);
    CHECK_ERR(br_ccm_decrypt(&z, k16, n13, b, 4, b, 4, tag8, b), BR_ERR_STATE);
    CHECK_ERR(br_hop_tag(&z, k32, b, 16, tag4), BR_ERR_STATE);
    CHECK_ERR(br_hop_tag_verify(&z, k32, b, 16, tag4), BR_ERR_STATE);

    br_crypto_t t;
    CHECK_ERR(br_crypto_init(&t), BR_OK);
    CHECK_ERR(br_hmac_sha256(&t, k32, 32, b, 16, mac), BR_OK);
    br_crypto_free(&t);
    CHECK_ERR(br_hmac_sha256(&t, k32, 32, b, 16, mac), BR_ERR_STATE); /* freed -> not initialised */
    br_crypto_free(&t); /* double free is safe */
    /* re-init works */
    CHECK_ERR(br_crypto_init(&t), BR_OK);
    CHECK_ERR(br_hmac_sha256(&t, k32, 32, b, 16, mac), BR_OK);
    br_crypto_free(&t);
}

static void test_hmac(void)
{
    tu_ctx("HMAC-SHA256 (RFC 4231)");
    uint8_t mac[32];
    {
        uint8_t key[20];
        memset(key, 0x0b, sizeof key);
        const uint8_t exp[32] = {0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
                                 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7};
        CHECK_ERR(br_hmac_sha256(&C, key, sizeof key, S("Hi There"), 8, mac), BR_OK);
        CHECK_MEM(exp, mac, 32);
    }
    {
        const uint8_t exp[32] = {0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
                                 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43};
        CHECK_ERR(br_hmac_sha256(&C, S("Jefe"), 4, S("what do ya want for nothing?"), 28, mac), BR_OK);
        CHECK_MEM(exp, mac, 32);
    }
    {
        /* key longer than the block size is hashed first (RFC 2104) */
        uint8_t key[131];
        memset(key, 0xaa, sizeof key);
        const uint8_t exp[32] = {0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f, 0x0d, 0x8a, 0x26, 0xaa, 0xcb, 0xf5, 0xb7, 0x7f,
                                 0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14, 0x05, 0x46, 0x04, 0x0f, 0x0e, 0xe3, 0x7f, 0x54};
        const char *msg = "Test Using Larger Than Block-Size Key - Hash Key First";
        CHECK_ERR(br_hmac_sha256(&C, key, sizeof key, S(msg), strlen(msg), mac), BR_OK);
        CHECK_MEM(exp, mac, 32);
    }
    {
        const uint8_t exp[32] = {0xb6, 0x13, 0x67, 0x9a, 0x08, 0x14, 0xd9, 0xec, 0x77, 0x2f, 0x95, 0xd7, 0x78, 0xc3, 0x5f, 0xc5,
                                 0xff, 0x16, 0x97, 0xc4, 0x93, 0x71, 0x56, 0x53, 0xc6, 0xc7, 0x12, 0x14, 0x42, 0x92, 0xc5, 0xad};
        CHECK_ERR(br_hmac_sha256(&C, NULL, 0, NULL, 0, mac), BR_OK); /* empty key, empty message */
        CHECK_MEM(exp, mac, 32);
    }
    CHECK_ERR(br_hmac_sha256(&C, NULL, 1, S("a"), 1, mac), BR_ERR_ARG);
    CHECK_ERR(br_hmac_sha256(&C, S("k"), 1, NULL, 1, mac), BR_ERR_ARG);
    CHECK_ERR(br_hmac_sha256(&C, S("k"), 1, S("a"), 1, NULL), BR_ERR_ARG);
    CHECK_ERR(br_hmac_sha256(NULL, S("k"), 1, S("a"), 1, mac), BR_ERR_ARG);
}

static void test_hkdf_rfc(void)
{
    tu_ctx("HKDF (RFC 5869)");
    uint8_t ikm[22], salt[13], info[10], prk[32], okm[82];
    memset(ikm, 0x0b, sizeof ikm);
    for (unsigned i = 0; i < 13; i++) {
        salt[i] = (uint8_t)i;
    }
    for (unsigned i = 0; i < 10; i++) {
        info[i] = (uint8_t)(0xf0 + i);
    }
    const uint8_t prk1[32] = {0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
                              0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5};
    const uint8_t okm1[42] = {0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
                              0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
                              0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65};
    CHECK_ERR(br_hkdf_extract(&C, salt, sizeof salt, ikm, sizeof ikm, prk), BR_OK);
    CHECK_MEM(prk1, prk, 32);
    CHECK_ERR(br_hkdf_expand(&C, prk, 32, info, sizeof info, okm, 42), BR_OK);
    CHECK_MEM(okm1, okm, 42);
    memset(okm, 0, sizeof okm);
    CHECK_ERR(br_hkdf_sha256(&C, salt, sizeof salt, ikm, sizeof ikm, info, sizeof info, okm, 42), BR_OK);
    CHECK_MEM(okm1, okm, 42);

    /* TC2: 80-byte inputs, 82-byte output */
    {
        uint8_t ikm2[80], salt2[80], info2[80];
        for (unsigned i = 0; i < 80; i++) {
            ikm2[i] = (uint8_t)i;
            salt2[i] = (uint8_t)(0x60 + i);
            info2[i] = (uint8_t)(0xb0 + i);
        }
        const uint8_t prk2[32] = {0x06, 0xa6, 0xb8, 0x8c, 0x58, 0x53, 0x36, 0x1a, 0x06, 0x10, 0x4c, 0x9c, 0xeb, 0x35, 0xb4, 0x5c,
                                  0xef, 0x76, 0x00, 0x14, 0x90, 0x46, 0x71, 0x01, 0x4a, 0x19, 0x3f, 0x40, 0xc1, 0x5f, 0xc2, 0x44};
        const uint8_t okm2[82] = {
            0xb1, 0x1e, 0x39, 0x8d, 0xc8, 0x03, 0x27, 0xa1, 0xc8, 0xe7, 0xf7, 0x8c, 0x59, 0x6a, 0x49, 0x34, 0x4f, 0x01,
            0x2e, 0xda, 0x2d, 0x4e, 0xfa, 0xd8, 0xa0, 0x50, 0xcc, 0x4c, 0x19, 0xaf, 0xa9, 0x7c, 0x59, 0x04, 0x5a, 0x99,
            0xca, 0xc7, 0x82, 0x72, 0x71, 0xcb, 0x41, 0xc6, 0x5e, 0x59, 0x0e, 0x09, 0xda, 0x32, 0x75, 0x60, 0x0c, 0x2f,
            0x09, 0xb8, 0x36, 0x77, 0x93, 0xa9, 0xac, 0xa3, 0xdb, 0x71, 0xcc, 0x30, 0xc5, 0x81, 0x79, 0xec, 0x3e, 0x87,
            0xc1, 0x4c, 0x01, 0xd5, 0xc1, 0xf3, 0x43, 0x4f, 0x1d, 0x87};
        CHECK_ERR(br_hkdf_extract(&C, salt2, 80, ikm2, 80, prk), BR_OK);
        CHECK_MEM(prk2, prk, 32);
        CHECK_ERR(br_hkdf_expand(&C, prk, 32, info2, 80, okm, 82), BR_OK);
        CHECK_MEM(okm2, okm, 82);
    }
    /* TC3: empty salt and info */
    {
        const uint8_t prk3[32] = {0x19, 0xef, 0x24, 0xa3, 0x2c, 0x71, 0x7b, 0x16, 0x7f, 0x33, 0xa9, 0x1d, 0x6f, 0x64, 0x8b, 0xdf,
                                  0x96, 0x59, 0x67, 0x76, 0xaf, 0xdb, 0x63, 0x77, 0xac, 0x43, 0x4c, 0x1c, 0x29, 0x3c, 0xcb, 0x04};
        const uint8_t okm3[42] = {0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f, 0x71, 0x5f, 0x80, 0x2a, 0x06, 0x3c, 0x5a, 0x31,
                                  0xb8, 0xa1, 0x1f, 0x5c, 0x5e, 0xe1, 0x87, 0x9e, 0xc3, 0x45, 0x4e, 0x5f, 0x3c, 0x73, 0x8d, 0x2d,
                                  0x9d, 0x20, 0x13, 0x95, 0xfa, 0xa4, 0xb6, 0x1a, 0x96, 0xc8};
        CHECK_ERR(br_hkdf_extract(&C, NULL, 0, ikm, sizeof ikm, prk), BR_OK);
        CHECK_MEM(prk3, prk, 32);
        CHECK_ERR(br_hkdf_expand(&C, prk, 32, NULL, 0, okm, 42), BR_OK);
        CHECK_MEM(okm3, okm, 42);
        CHECK_ERR(br_hkdf_sha256(&C, NULL, 0, ikm, sizeof ikm, NULL, 0, okm, 42), BR_OK);
        CHECK_MEM(okm3, okm, 42);
        /* an empty (non-NULL) salt is the same as NULL */
        CHECK_ERR(br_hkdf_extract(&C, ikm, 0, ikm, sizeof ikm, prk), BR_OK);
        CHECK_MEM(prk3, prk, 32);
    }
    /* output length handling: shorter outputs are prefixes of longer ones */
    uint8_t a[300], b[300];
    CHECK_ERR(br_hkdf_expand(&C, prk1, 32, info, 10, a, 300), BR_OK);
    for (size_t l = 1; l <= 100; l += (l < 70 ? 1u : 11u)) {
        memset(b, 0xEE, sizeof b);
        CHECK_ERR(br_hkdf_expand(&C, prk1, 32, info, 10, b, l), BR_OK);
        CHECK_MEM(a, b, l);
        CHECK_EQ_U32(b[l], 0xEEu); /* exactly okm_len bytes written */
    }
    /* limits */
    CHECK_ERR(br_hkdf_expand(&C, prk1, 32, info, 10, a, 0), BR_ERR_ARG);
    CHECK_ERR(br_hkdf_expand(&C, prk1, 31, info, 10, a, 16), BR_ERR_ARG);
    CHECK_ERR(br_hkdf_expand(&C, prk1, 32, info, 10, a, BR_HKDF_MAX_OKM + 1u), BR_ERR_ARG);
    CHECK_ERR(br_hkdf_expand(&C, NULL, 32, info, 10, a, 16), BR_ERR_ARG);
    CHECK_ERR(br_hkdf_expand(&C, prk1, 32, NULL, 1, a, 16), BR_ERR_ARG);
    CHECK_ERR(br_hkdf_expand(&C, prk1, 32, info, 10, NULL, 16), BR_ERR_ARG);
    CHECK_ERR(br_hkdf_extract(&C, NULL, 1, ikm, 22, prk), BR_ERR_ARG);
    CHECK_ERR(br_hkdf_extract(&C, salt, 13, NULL, 1, prk), BR_ERR_ARG);
    CHECK_ERR(br_hkdf_extract(&C, salt, 13, ikm, 22, NULL), BR_ERR_ARG);
    {
        uint8_t *big = tu_alloc(BR_HKDF_MAX_OKM);
        CHECK_ERR(br_hkdf_expand(&C, prk1, 32, info, 10, big, BR_HKDF_MAX_OKM), BR_OK); /* 8160 = 255 * 32 */
        CHECK_MEM(a, big, 300);
        free(big);
    }
    CHECK_EQ_U32(BR_HKDF_MAX_OKM, 8160u);
}

/* ------------------------------------------------------------------------- */
/* key schedule (A.6, A.9, A.12, A.14, A.15)                                   */
/* ------------------------------------------------------------------------- */

static void test_a6_keys(void)
{
    tu_ctx("A.6 key schedule");
    uint8_t k[32], k2[32];
    uint8_t site[32];
    for (unsigned i = 0; i < 32; i++) {
        site[i] = (uint8_t)i;
    }
    CHECK_MEM(BRV_A6_K_SITE, site, 32); /* K_site is bytes 0x00..0x1F */

    k_mesh(BRV_A6_K_SITE, 1, k);
    CHECK_MEM(BRV_A6_K_MESH_1, k, 32);
    uint8_t km1[32];
    memcpy(km1, k, 32);
    kdf_v1(km1, "hop", NULL, 0, k, 32);
    CHECK_MEM(BRV_A6_K_HOP_1, k, 32);
    kdf_v1(km1, "mesh-enc", NULL, 0, k, 16);
    CHECK_MEM(BRV_A6_KE_MESH_1, k, 16);
    k_mesh(BRV_A6_K_SITE, 0, k2);
    kdf_v1(k2, "hop", NULL, 0, k, 32);
    CHECK_MEM(BRV_A6_K_HOP_0, k, 32);
    /* different epochs give different keys */
    CHECK(memcmp(k2, km1, 32) != 0);

    k_pair(BRV_A6_K_SITE, 0x0042, 0x1234, 1, k);
    CHECK_MEM(BRV_A6_K_PAIR_0042_1234_1, k, 32);
    k_pair(BRV_A6_K_SITE, 0x1234, 0x0042, 1, k2); /* min/max: argument order does not matter */
    CHECK_MEM(BRV_A6_K_PAIR_0042_1234_1, k2, 32);
    uint8_t prk[32];
    CHECK_ERR(br_hkdf_extract(&C, S(BR_LABEL_V1), BR_LABEL_LEN(BR_LABEL_V1), BRV_A6_K_PAIR_0042_1234_1, 32, prk), BR_OK);
    CHECK_MEM(BRV_A6_PRK, prk, 32);
    CHECK_ERR(br_hkdf_sha256(&C, S(BR_LABEL_V1), BR_LABEL_LEN(BR_LABEL_V1), BRV_A6_K_PAIR_0042_1234_1, 32, NULL, 0, k, 32), BR_OK);
    /* HKDF() with empty info is Expand(Extract(), "", 32): consistent with the two-step form */
    uint8_t k3[32];
    CHECK_ERR(br_hkdf_expand(&C, prk, 32, NULL, 0, k3, 32), BR_OK);
    CHECK_MEM(k3, k, 32);
}

static void test_a9_keys(void)
{
    tu_ctx("A.9 handshake keys");
    const uint16_t S_ID = 0x1234, P_ID = 0x0042;
    /* T0 = SHA-256(SEEK e2e header || SEEK payload) of the A.8 keyed SEEK */
    uint8_t buf[512], e2e[10], t0[32], t[32], ke[16];
    e2e_hdr(BRV_A8_SEEK_HDR_HOP1, e2e);
    CHECK_MEM(BRV_A8_SEEK_AAD, e2e, 10); /* first 10 AAD bytes are the e2e header */
    memcpy(buf, e2e, 10);
    memcpy(buf + 10, BRV_A8_SEEK_PAYLOAD, 18);
    sha256(buf, 28, t0);
    CHECK_MEM(BRV_A9_T0, t0, 32);

    uint8_t info[64];
    size_t n = 0;
    memcpy(info + n, "hello", 5); n += 5;
    tu_put16(info + n, S_ID); n += 2;
    tu_put16(info + n, P_ID); n += 2;
    memcpy(info + n, BRV_A9_T0, 32); n += 32;
    CHECK_ERR(br_hkdf_expand(&C, BRV_A6_PRK, 32, info, n, ke, 16), BR_OK);
    CHECK_MEM(BRV_A9_KE_HELLO, ke, 16);

    /* T = SHA-256(SEEK e2e || SEEK payload || HELLO e2e || HELLO plaintext payload (clear pre_ctr || secret)) */
    uint8_t he2e[10];
    e2e_hdr(BRV_A9_HELLO_HEADER, he2e);
    memcpy(buf, e2e, 10);
    memcpy(buf + 10, BRV_A8_SEEK_PAYLOAD, 18);
    memcpy(buf + 28, he2e, 10);
    memcpy(buf + 38, BRV_A9_HELLO_CLEAR, 4);
    memcpy(buf + 42, BRV_A9_HELLO_SECRET, 24);
    sha256(buf, 66, t);
    CHECK_MEM(BRV_A9_T, t, 32);

    n = 0;
    memcpy(info + n, "hs", 2); n += 2;
    tu_put16(info + n, S_ID); n += 2;
    tu_put16(info + n, P_ID); n += 2;
    memcpy(info + n, BRV_A9_T, 32); n += 32;
    CHECK_ERR(br_hkdf_expand(&C, BRV_A6_PRK, 32, info, n, ke, 16), BR_OK);
    CHECK_MEM(BRV_A9_KE_HS, ke, 16);

    for (unsigned dir = 0; dir < 2; dir++) {
        n = 0;
        memcpy(info + n, dir ? "p2s" : "s2p", 3); n += 3;
        tu_put16(info + n, S_ID); n += 2;
        tu_put16(info + n, P_ID); n += 2;
        info[n++] = (uint8_t)BRV_A9_SESSION_ID;
        memcpy(info + n, BRV_A9_T, 32); n += 32;
        CHECK_ERR(br_hkdf_expand(&C, BRV_A6_PRK, 32, info, n, ke, 16), BR_OK);
        CHECK_MEM(dir ? BRV_A9_KE_P2S : BRV_A9_KE_S2P, ke, 16);
    }
    CHECK_MEM(BRV_A7_KEY, BRV_A9_KE_S2P, 16); /* A.7 uses Ke_s2p of A.9 */
}

static void test_a12_a14_a15_keys(void)
{
    tu_ctx("A.12 K_mgmt");
    uint8_t k[32], km[16];
    k_pair(BRV_A6_K_SITE, 0x0001, 0x0042, 1, k);
    CHECK_MEM(BRV_A12_K_PAIR_0001_0042_1, k, 32);
    uint8_t tail[4];
    tu_put16(tail, 0x0042); /* N */
    tu_put16(tail + 2, 0x0001); /* M */
    kdf_v1(k, "mgmt", tail, 4, km, 16);
    CHECK_MEM(BRV_A12_K_MGMT_0042_0001, km, 16);

    tu_ctx("A.14 bundle keys");
    k_node(BRV_A6_K_SITE, 0x0042, k);
    CHECK_MEM(BRV_A14_K_NODE_0042, k, 32);
    uint8_t kb[16];
    kdf_v1(k, "bundle", NULL, 0, kb, 16);
    CHECK_MEM(BRV_A14_KB, kb, 16);
    k_mesh(BRV_A6_K_SITE, 2, k);
    CHECK_MEM(BRV_A14_K_MESH_2, k, 32);
    k_pair(BRV_A6_K_SITE, 0x0042, 0x1234, 2, k);
    CHECK_MEM(BRV_A14_K_PAIR_0042_1234_2, k, 32);
    /* K_node differs per node */
    uint8_t k2[32];
    k_node(BRV_A6_K_SITE, 0x0043, k2);
    CHECK(memcmp(k, k2, 32) != 0);

    tu_ctx("A.15 edge keys");
    k_pair(BRV_A6_K_SITE, 0x0020, 0x0021, 1, k);
    CHECK_MEM(BRV_A15_K_PAIR_0020_0021_1, k, 32);
    uint8_t he[32], ee[16];
    kdf_v1(BRV_A15_K_PAIR_0020_0021_1, "edge-hop", NULL, 0, he, 32);
    CHECK_MEM(BRV_A15_K_HOP_EDGE, he, 32);
    kdf_v1(BRV_A15_K_PAIR_0020_0021_1, "edge-enc", NULL, 0, ee, 16);
    CHECK_MEM(BRV_A15_KE_EDGE, ee, 16);

    /* T0 of the IR SEEK and Ke_hello for the edge pair: S = L 0x0020, P = A 0x0021 */
    uint8_t buf[64], e2e[10], t0[32], prk[32], ke[16], info[64];
    e2e_hdr(BRV_A15_SEEK_HEADER, e2e);
    memcpy(buf, e2e, 10);
    memcpy(buf + 10, BRV_A15_SEEK_PAYLOAD, 18);
    sha256(buf, 28, t0);
    CHECK_MEM(BRV_A15_T0_EDGE, t0, 32);
    CHECK_ERR(br_hkdf_extract(&C, S(BR_LABEL_V1), BR_LABEL_LEN(BR_LABEL_V1), BRV_A15_K_PAIR_0020_0021_1, 32, prk), BR_OK);
    size_t n = 0;
    memcpy(info + n, "hello", 5); n += 5;
    tu_put16(info + n, 0x0020); n += 2;
    tu_put16(info + n, 0x0021); n += 2;
    memcpy(info + n, t0, 32); n += 32;
    CHECK_ERR(br_hkdf_expand(&C, prk, 32, info, n, ke, 16), BR_OK);
    CHECK_MEM(BRV_A15_KE_HELLO_EDGE, ke, 16);
}

/* ------------------------------------------------------------------------- */
/* nonce / AAD                                                                */
/* ------------------------------------------------------------------------- */

static void test_nonce_aad(void)
{
    tu_ctx("nonce");
    uint8_t n[13];
    memset(n, 0xEE, sizeof n);
    /* A.7: dir 0, 0x1234, 0x0042, session 7, ctr_hi 0, seq 5 */
    CHECK_ERR(br_ccm_nonce(BR_DIR_TO_PROBE, 0x1234, 0x0042, 7, 0, 5, n), BR_OK);
    CHECK_MEM(BRV_A7_NONCE, n, 13);
    CHECK_ERR(br_ccm_nonce(BR_DIR_TO_PROBE, 0x1234, 0x0042, 7, 1, 5, n), BR_OK); /* A.10: ROC 1 */
    CHECK_MEM(BRV_A10_NONCE, n, 13);
    CHECK_ERR(br_ccm_nonce(BR_DIR_FROM_PROBE, 0x0042, 0x1234, 0, 1, 7, n), BR_OK); /* A.9 HELLO */
    CHECK_MEM(BRV_A9_HELLO_NONCE, n, 13);
    CHECK_ERR(br_ccm_nonce(BR_DIR_TO_PROBE, 0x1234, 0x0042, 0, 1, 2, n), BR_OK); /* A.9 BIND */
    CHECK_MEM(BRV_A9_BIND_NONCE, n, 13);
    CHECK_ERR(br_ccm_nonce(BR_DIR_TO_PROBE, 0x1234, 0xFF01, 0, 1, 1, n), BR_OK); /* A.8 SEEK */
    CHECK_MEM(BRV_A8_SEEK_NONCE, n, 13);
    CHECK_ERR(br_ccm_nonce(BR_DIR_TO_PROBE, 0x1234, 0x0042, 7, 0, 0x42, n), BR_OK); /* A.11 */
    CHECK_MEM(BRV_A11_NONCE, n, 13);
    CHECK_ERR(br_ccm_nonce(BR_DIR_TO_PROBE, 0x0042, 0x0001, 0, 1, 8, n), BR_OK); /* A.12 REQ */
    CHECK_MEM(BRV_A12_REQ_NONCE, n, 13);
    CHECK_ERR(br_ccm_nonce(BR_DIR_FROM_PROBE, 0x0001, 0x0042, 0, 2, 5, n), BR_OK); /* A.12 RESP */
    CHECK_MEM(BRV_A12_RESP_NONCE, n, 13);
    /* field layout with distinctive values */
    CHECK_ERR(br_ccm_nonce(1, 0xAABB, 0xCCDD, 0xEE, 0x01020304u, 0x5566, n), BR_OK);
    const uint8_t exp[13] = {0x01, 0xBB, 0xAA, 0xDD, 0xCC, 0xEE, 0x04, 0x03, 0x02, 0x01, 0x66, 0x55, 0x00};
    CHECK_MEM(exp, n, 13);
    CHECK_ERR(br_ccm_nonce(2, 1, 2, 3, 4, 5, n), BR_ERR_ARG); /* dir must be 0 or 1 */
    CHECK_ERR(br_ccm_nonce(0xFF, 1, 2, 3, 4, 5, n), BR_ERR_ARG);
    CHECK_ERR(br_ccm_nonce(0, 1, 2, 3, 4, 5, NULL), BR_ERR_ARG);

    tu_ctx("AAD args");
    uint8_t aad[BR_AAD_MAX_LEN];
    size_t al = 0;
    /* DATA frame, clear 0 -> 14 bytes */
    CHECK_ERR(br_ccm_aad(BRV_A7_FRAME, BRV_A7_FRAME_LEN, 0, 0, aad, sizeof aad, &al), BR_OK);
    CHECK_EQ_U32(al, 14u);
    CHECK_MEM(BRV_A7_AAD, aad, 14);
    CHECK_ERR(br_ccm_aad(BRV_A7_FRAME, BRV_A7_FRAME_LEN, 0, 0, aad, 13, &al), BR_ERR_TOO_BIG);
    CHECK_ERR(br_ccm_aad(BRV_A7_FRAME, BRV_A7_FRAME_LEN, 0, 0, aad, 14, &al), BR_OK);
    CHECK_ERR(br_ccm_aad(NULL, 44, 0, 0, aad, sizeof aad, &al), BR_ERR_ARG);
    CHECK_ERR(br_ccm_aad(BRV_A7_FRAME, 44, 0, 0, NULL, sizeof aad, &al), BR_ERR_ARG);
    CHECK_ERR(br_ccm_aad(BRV_A7_FRAME, 44, 0, 0, aad, sizeof aad, NULL), BR_ERR_ARG);
    CHECK_ERR(br_ccm_aad(BRV_A7_FRAME, 44, 0, 12, aad, sizeof aad, &al), BR_ERR_ARG); /* clear_len > len field (11) */
    CHECK_ERR(br_ccm_aad(BRV_A7_FRAME, 44, 0, 11, aad, sizeof aad, &al), BR_OK);
    CHECK_EQ_U32(al, 25u);
    CHECK_ERR(br_ccm_aad(BRV_A7_FRAME, 29, 0, 0, aad, sizeof aad, &al), BR_OK); /* header only is enough for clear_len 0 */
    CHECK_ERR(br_ccm_aad(BRV_A7_FRAME, 18, 0, 0, aad, sizeof aad, &al), BR_ERR_DECODE); /* shorter than the header */
    CHECK_ERR(br_ccm_aad(BRV_A7_FRAME, 19 + 5, 0, 6, aad, sizeof aad, &al), BR_ERR_DECODE); /* header + clear_len missing */
    CHECK_ERR(br_ccm_aad(BRV_A7_FRAME, 19 + 6, 0, 6, aad, sizeof aad, &al), BR_OK);
    /* SEEK offsets (18, 19, 21): the 32-byte A.8 AAD */
    CHECK_ERR(br_ccm_aad(BRV_A8_SEEK_HOP1_FRAME, BRV_A8_SEEK_HOP1_FRAME_LEN, 1, 18, aad, sizeof aad, &al), BR_OK);
    CHECK_EQ_U32(al, 32u);
    CHECK_MEM(BRV_A8_SEEK_AAD, aad, 32);
    CHECK_ERR(br_ccm_aad(BRV_A8_SEEK_HOP1_FRAME, 22 + 17, 1, 18, aad, sizeof aad, &al), BR_ERR_DECODE);
    /* per-hop fields do not enter the AAD */
    uint8_t aad2[BR_AAD_MAX_LEN];
    CHECK_ERR(br_ccm_aad(BRV_A8_SEEK_HOP2_FRAME, BRV_A8_SEEK_HOP2_FRAME_LEN, 1, 18, aad2, sizeof aad2, &al), BR_OK);
    CHECK_MEM(aad, aad2, 32);
    /* ctr_hi is little-endian after the e2e header */
    CHECK_ERR(br_ccm_aad(BRV_A7_FRAME, BRV_A7_FRAME_LEN, 0x04030201u, 0, aad, sizeof aad, &al), BR_OK);
    CHECK_EQ_U32(aad[10], 1u);
    CHECK_EQ_U32(aad[13], 4u);
    CHECK_EQ_U32(BR_AAD_MAX_LEN, 10u + 4u + 255u);
}

/* ------------------------------------------------------------------------- */
/* end-to-end CCM over every frame vector                                      */
/* ------------------------------------------------------------------------- */

typedef struct {
    const char *name;
    const uint8_t *frame;
    size_t flen;
    const uint8_t *key;     /* Ke_* (16) */
    const uint8_t *hop_key; /* K_hop (32) */
    uint8_t dir;
    uint32_t ctr_hi;
    const uint8_t *plain;   /* plaintext of the encrypted part; NULL if empty */
    size_t clear_len;
    const uint8_t *exp_nonce; /* may be NULL */
    const uint8_t *exp_aad;   /* may be NULL */
    size_t exp_aad_len;
    const uint8_t *exp_tag;   /* may be NULL */
} e2e_t;

static const e2e_t E2E[] = {
    {"A.7 DATA", BRV_A7_FRAME, BRV_A7_FRAME_LEN, BRV_A7_KEY, BRV_A7_HOP_KEY, BR_DIR_TO_PROBE, 0, BRV_A7_PLAINTEXT, 0,
     BRV_A7_NONCE, BRV_A7_AAD, BRV_A7_AAD_LEN, BRV_A7_CCM_TAG},
    {"A.8 SEEK hop 1", BRV_A8_SEEK_HOP1_FRAME, BRV_A8_SEEK_HOP1_FRAME_LEN, BRV_A8_SEEK_KEY, BRV_A8_SEEK_HOP_KEY,
     BR_DIR_TO_PROBE, 1, NULL, 18, BRV_A8_SEEK_NONCE, BRV_A8_SEEK_AAD, BRV_A8_SEEK_AAD_LEN, BRV_A8_SEEK_CCM_TAG},
    {"A.8 SEEK hop 2", BRV_A8_SEEK_HOP2_FRAME, BRV_A8_SEEK_HOP2_FRAME_LEN, BRV_A8_SEEK_KEY, BRV_A8_SEEK_HOP_KEY,
     BR_DIR_TO_PROBE, 1, NULL, 18, BRV_A8_SEEK_NONCE, BRV_A8_SEEK_AAD, BRV_A8_SEEK_AAD_LEN, BRV_A8_SEEK_CCM_TAG},
    {"A.8 DATA hop 1", BRV_A8_DATA_HOP1_FRAME, BRV_A8_DATA_HOP1_FRAME_LEN, BRV_A7_KEY, BRV_A7_HOP_KEY, BR_DIR_TO_PROBE,
     0, BRV_A7_PLAINTEXT, 0, BRV_A7_NONCE, BRV_A7_AAD, BRV_A7_AAD_LEN, BRV_A7_CCM_TAG},
    {"A.8 DATA hop 2", BRV_A8_DATA_HOP2_FRAME, BRV_A8_DATA_HOP2_FRAME_LEN, BRV_A7_KEY, BRV_A7_HOP_KEY, BR_DIR_TO_PROBE,
     0, BRV_A7_PLAINTEXT, 0, BRV_A7_NONCE, BRV_A7_AAD, BRV_A7_AAD_LEN, BRV_A7_CCM_TAG},
    {"A.8 DATA hop 2 under K_hop(0)", BRV_A8_DATA_HOP2_K0_FRAME, BRV_A8_DATA_HOP2_K0_FRAME_LEN, BRV_A7_KEY,
     BRV_A8_DATA_HOP2_K0_KEY, BR_DIR_TO_PROBE, 0, BRV_A7_PLAINTEXT, 0, BRV_A7_NONCE, BRV_A7_AAD, BRV_A7_AAD_LEN,
     BRV_A7_CCM_TAG},
    {"A.9 HELLO", BRV_A9_HELLO_FRAME, BRV_A9_HELLO_FRAME_LEN, BRV_A9_KE_HELLO, BRV_A7_HOP_KEY, BR_DIR_FROM_PROBE, 1,
     BRV_A9_HELLO_SECRET, 4, BRV_A9_HELLO_NONCE, BRV_A9_HELLO_AAD, BRV_A9_HELLO_AAD_LEN, BRV_A9_HELLO_TAG},
    {"A.9 BIND", BRV_A9_BIND_FRAME, BRV_A9_BIND_FRAME_LEN, BRV_A9_KE_HS, BRV_A7_HOP_KEY, BR_DIR_TO_PROBE, 1,
     BRV_A9_BIND_SECRET, 4, BRV_A9_BIND_NONCE, NULL, 0, BRV_A9_BIND_TAG},
    {"A.10 DATA ROC 1", BRV_A10_DATA_ROC1_FRAME, BRV_A10_DATA_ROC1_FRAME_LEN, BRV_A7_KEY, BRV_A7_HOP_KEY,
     BR_DIR_TO_PROBE, BRV_A10_ROC, BRV_A7_PLAINTEXT, 0, BRV_A10_NONCE, NULL, 0, BRV_A10_CCM_TAG},
    {"A.11 RESUME", BRV_A11_RESUME_FRAME, BRV_A11_RESUME_FRAME_LEN, BRV_A11_KEY, BRV_A7_HOP_KEY, BR_DIR_TO_PROBE, 0,
     NULL, 5, BRV_A11_NONCE, NULL, 0, BRV_A11_CCM_TAG},
    {"A.12 MGMT_REQ", BRV_A12_REQ_FRAME, BRV_A12_REQ_FRAME_LEN, BRV_A12_K_MGMT_0042_0001, BRV_A7_HOP_KEY,
     BR_DIR_TO_PROBE, 1, BRV_A12_REQ_SECRET, 4, BRV_A12_REQ_NONCE, BRV_A12_REQ_AAD, BRV_A12_REQ_AAD_LEN,
     BRV_A12_REQ_TAG},
    {"A.12 MGMT_RESP", BRV_A12_RESP_FRAME, BRV_A12_RESP_FRAME_LEN, BRV_A12_K_MGMT_0042_0001, BRV_A7_HOP_KEY,
     BR_DIR_FROM_PROBE, 2, BRV_A12_RESP_SECRET, 4, BRV_A12_RESP_NONCE, BRV_A12_RESP_AAD, BRV_A12_RESP_AAD_LEN,
     BRV_A12_RESP_TAG},
    {"A.15 IR SEEK (Ke_edge)", BRV_A15_SEEK_FRAME, BRV_A15_SEEK_FRAME_LEN, BRV_A15_KE_EDGE, BRV_A15_K_HOP_EDGE,
     BR_DIR_TO_PROBE, 0, NULL, 18, NULL, NULL, 0, BRV_A15_SEEK_CCM_TAG},
    {"A.15 IR HELLO (Ke_hello edge)", BRV_A15_HELLO_FRAME, BRV_A15_HELLO_FRAME_LEN, BRV_A15_KE_HELLO_EDGE,
     BRV_A15_K_HOP_EDGE, BR_DIR_FROM_PROBE, 0, BRV_A15_HELLO_SECRET, 4, NULL, NULL, 0, BRV_A15_HELLO_TAG},
};
#define N_E2E (sizeof E2E / sizeof E2E[0])

static void flip(uint8_t *p, size_t i) { p[i] ^= (uint8_t)(1u << (i % 8u)); }

static void run_e2e(const e2e_t *e)
{
    tu_ctx(e->name);
    tu_ref_hdr_t h;
    tu_ref_parse(e->frame, &h);
    const size_t hl = h.hdr_len, plen = h.len;
    const size_t ct_len = plen - e->clear_len;
    const uint8_t *ct = e->frame + hl + e->clear_len;
    const uint8_t *tag = e->frame + hl + plen;
    const size_t covered = hl + plen + 8u;

    /* nonce from header fields */
    uint8_t nonce[13];
    CHECK_ERR(br_ccm_nonce(e->dir, h.src, h.dst, h.session_id, e->ctr_hi, h.seq, nonce), BR_OK);
    uint8_t ref_nonce[13];
    ref_nonce[0] = e->dir;
    tu_put16(ref_nonce + 1, h.src);
    tu_put16(ref_nonce + 3, h.dst);
    ref_nonce[5] = h.session_id;
    tu_put32(ref_nonce + 6, e->ctr_hi);
    tu_put16(ref_nonce + 10, h.seq);
    ref_nonce[12] = 0;
    CHECK_MEM(ref_nonce, nonce, 13);
    if (e->exp_nonce) {
        CHECK_MEM(e->exp_nonce, nonce, 13);
    }

    /* AAD */
    uint8_t aad[BR_AAD_MAX_LEN], raad[BR_AAD_MAX_LEN];
    size_t al = 0;
    CHECK_ERR(br_ccm_aad(e->frame, e->flen, e->ctr_hi, e->clear_len, aad, sizeof aad, &al), BR_OK);
    CHECK_EQ_U32(al, 14u + e->clear_len);
    e2e_hdr(e->frame, raad);
    tu_put32(raad + 10, e->ctr_hi);
    memcpy(raad + 14, e->frame + hl, e->clear_len);
    CHECK_MEM(raad, aad, 14u + e->clear_len);
    if (e->exp_aad) {
        CHECK_EQ_U32(e->exp_aad_len, al);
        CHECK_MEM(e->exp_aad, aad, e->exp_aad_len);
    }
    if (e->exp_tag) {
        CHECK_MEM(e->exp_tag, tag, 8); /* the vector's tag macro agrees with the frame */
    }

    /* encrypt reproduces ciphertext and tag */
    uint8_t *out_ct = tu_alloc(ct_len);
    uint8_t out_tag[8];
    memset(out_tag, 0xEE, sizeof out_tag);
    CHECK_ERR(br_ccm_encrypt(&C, e->key, nonce, aad, al, e->plain, ct_len, out_ct, out_tag), BR_OK);
    CHECK_MEM(ct, out_ct, ct_len);
    CHECK_MEM(tag, out_tag, 8);
    /* in-place encrypt */
    if (ct_len) {
        uint8_t *buf = tu_dup(e->plain, ct_len);
        memset(out_tag, 0xEE, sizeof out_tag);
        CHECK_ERR(br_ccm_encrypt(&C, e->key, nonce, aad, al, buf, ct_len, buf, out_tag), BR_OK);
        CHECK_MEM(ct, buf, ct_len);
        CHECK_MEM(tag, out_tag, 8);
        free(buf);
    }
    /* encrypt with no AAD pointer problems: aad_len 0 allowed with NULL (different tag, no crash) */
    {
        uint8_t t2[8];
        CHECK_ERR(br_ccm_encrypt(&C, e->key, nonce, NULL, 0, e->plain, ct_len, out_ct, t2), BR_OK);
        CHECK(memcmp(t2, tag, 8) != 0); /* AAD is authenticated */
    }

    /* decrypt */
    uint8_t *pt = tu_alloc(ct_len);
    uint8_t *ctc = tu_dup(ct, ct_len);
    memset(pt, 0xAA, ct_len);
    CHECK_ERR(br_ccm_decrypt(&C, e->key, nonce, aad, al, ctc, ct_len, tag, pt), BR_OK);
    if (e->plain) {
        CHECK_MEM(e->plain, pt, ct_len);
    }
    /* in-place decrypt */
    memcpy(ctc, ct, ct_len);
    CHECK_ERR(br_ccm_decrypt(&C, e->key, nonce, aad, al, ctc, ct_len, tag, ctc), BR_OK);
    if (e->plain) {
        CHECK_MEM(e->plain, ctc, ct_len);
    }

    /* tamper one bit of: every ciphertext byte, every tag byte, every AAD byte, every nonce byte, the key */
    uint8_t tg[8];
    for (size_t i = 0; i < ct_len; i++) {
        memcpy(ctc, ct, ct_len);
        flip(ctc, i);
        memset(pt, 0xAA, ct_len);
        CHECK_ERR(br_ccm_decrypt(&C, e->key, nonce, aad, al, ctc, ct_len, tag, pt), BR_ERR_AUTH);
        bool zeroed = true;
        for (size_t j = 0; j < ct_len; j++) {
            if (pt[j] != 0) {
                zeroed = false;
            }
        }
        CHECK_MSG(zeroed, "plaintext must be zeroed on auth failure");
    }
    memcpy(ctc, ct, ct_len);
    for (size_t i = 0; i < 8; i++) {
        memcpy(tg, tag, 8);
        flip(tg, i);
        memset(pt, 0xAA, ct_len);
        CHECK_ERR(br_ccm_decrypt(&C, e->key, nonce, aad, al, ctc, ct_len, tg, pt), BR_ERR_AUTH);
        for (size_t j = 0; j < ct_len; j++) {
            CHECK_EQ_U32(pt[j], 0u);
        }
    }
    for (size_t i = 0; i < al; i++) {
        uint8_t a2[BR_AAD_MAX_LEN];
        memcpy(a2, aad, al);
        flip(a2, i);
        CHECK_ERR(br_ccm_decrypt(&C, e->key, nonce, a2, al, ctc, ct_len, tag, pt), BR_ERR_AUTH);
    }
    CHECK_ERR(br_ccm_decrypt(&C, e->key, nonce, aad, al - 1u, ctc, ct_len, tag, pt), BR_ERR_AUTH); /* truncated AAD */
    for (size_t i = 0; i < 13; i++) {
        uint8_t n2[13];
        memcpy(n2, nonce, 13);
        flip(n2, i);
        CHECK_ERR(br_ccm_decrypt(&C, e->key, n2, aad, al, ctc, ct_len, tag, pt), BR_ERR_AUTH);
    }
    for (size_t i = 0; i < 16; i += 5) {
        uint8_t k2[16];
        memcpy(k2, e->key, 16);
        flip(k2, i);
        CHECK_ERR(br_ccm_decrypt(&C, k2, nonce, aad, al, ctc, ct_len, tag, pt), BR_ERR_AUTH);
    }
    /* ciphertext length change (CCM binds the length) */
    if (ct_len > 0) {
        CHECK_ERR(br_ccm_decrypt(&C, e->key, nonce, aad, al, ctc, ct_len - 1u, tag, pt), BR_ERR_AUTH);
    }

    /* hop_tag: recomputed over frame[0 .. end of auth_tag] */
    uint8_t ht[4];
    memset(ht, 0xEE, sizeof ht);
    CHECK_ERR(br_hop_tag(&C, e->hop_key, e->frame, covered, ht), BR_OK);
    CHECK_MEM(e->frame + covered, ht, 4);
    CHECK_ERR(br_hop_tag_verify(&C, e->hop_key, e->frame, covered, e->frame + covered), BR_OK);
    /* HMAC cross-check of the truncation */
    uint8_t mac[32];
    CHECK_ERR(br_hmac_sha256(&C, e->hop_key, 32, e->frame, covered, mac), BR_OK);
    CHECK_MEM(mac, ht, 4);
    /* tamper any covered byte, the tag, the key, or the covered length */
    uint8_t fr[320];
    for (size_t i = 0; i < covered; i++) {
        memcpy(fr, e->frame, e->flen);
        flip(fr, i);
        CHECK_ERR(br_hop_tag_verify(&C, e->hop_key, fr, covered, e->frame + covered), BR_ERR_AUTH);
    }
    for (size_t i = 0; i < 4; i++) {
        uint8_t t4[4];
        memcpy(t4, e->frame + covered, 4);
        flip(t4, i);
        CHECK_ERR(br_hop_tag_verify(&C, e->hop_key, e->frame, covered, t4), BR_ERR_AUTH);
    }
    for (size_t i = 0; i < 32; i += 13) {
        uint8_t k2[32];
        memcpy(k2, e->hop_key, 32);
        flip(k2, i);
        CHECK_ERR(br_hop_tag_verify(&C, k2, e->frame, covered, e->frame + covered), BR_ERR_AUTH);
    }
    CHECK_ERR(br_hop_tag_verify(&C, e->hop_key, e->frame, covered - 1u, e->frame + covered), BR_ERR_AUTH);
    CHECK_ERR(br_hop_tag_verify(&C, e->hop_key, e->frame, covered + 1u, e->frame + covered), BR_ERR_AUTH);

    free(out_ct);
    free(pt);
    free(ctc);
}

static void test_e2e_vectors(void)
{
    for (size_t i = 0; i < N_E2E; i++) {
        run_e2e(&E2E[i]);
    }
    /* embedded ciphertext / tag macros of A.7 and A.10 */
    tu_ctx("A.7/A.10 macros");
    CHECK_MEM(BRV_A7_CIPHERTEXT, BRV_A7_FRAME + 19, BRV_A7_CIPHERTEXT_LEN);
    CHECK_MEM(BRV_A7_CCM_TAG, BRV_A7_FRAME + 30, 8);
    CHECK_MEM(BRV_A7_HOP_TAG, BRV_A7_FRAME + 38, 4);
    CHECK_MEM(BRV_A10_CIPHERTEXT, BRV_A10_DATA_ROC1_FRAME + 19, BRV_A10_CIPHERTEXT_LEN);
    CHECK_MEM(BRV_A10_CCM_TAG, BRV_A10_DATA_ROC1_FRAME + 30, 8);
    CHECK_MEM(BRV_A9_HELLO_HOP_TAG, BRV_A9_HELLO_FRAME + 55, 4);
    CHECK_MEM(BRV_A9_BIND_HOP_TAG, BRV_A9_BIND_FRAME + 44, 4);
    CHECK_MEM(BRV_A11_HOP_TAG, BRV_A11_RESUME_FRAME + 32, 4);
    CHECK_MEM(BRV_A12_REQ_HOP_TAG, BRV_A12_REQ_FRAME + 57, 4);
    CHECK_MEM(BRV_A12_RESP_HOP_TAG, BRV_A12_RESP_FRAME + 60, 4);
    CHECK_MEM(BRV_A9_HELLO_PAYLOAD, BRV_A9_HELLO_FRAME + 19, 28);
    CHECK_MEM(BRV_A9_BIND_PAYLOAD, BRV_A9_BIND_FRAME + 19, 17);
    CHECK_MEM(BRV_A12_REQ_PAYLOAD, BRV_A12_REQ_FRAME + 19, 30);
    CHECK_MEM(BRV_A12_RESP_PAYLOAD, BRV_A12_RESP_FRAME + 19, 33);
    CHECK_MEM(BRV_A15_HELLO_PAYLOAD, BRV_A15_HELLO_FRAME + 19, 28);
}

static void test_hop_epochs(void)
{
    tu_ctx("A.8 hop 2 under epoch 1 and epoch 0 (8.5)");
    uint8_t ht[4];
    const size_t cov = 19u + 11u + 8u;
    CHECK_EQ_U32(cov, 38u); /* A.7: frame[0..37] */
    CHECK_ERR(br_hop_tag(&C, BRV_A8_DATA_HOP2_K0_KEY, BRV_A8_DATA_HOP2_FRAME, cov, ht), BR_OK);
    CHECK_MEM(BRV_A8_DATA_HOP2_K0_HOP_TAG, ht, 4);
    CHECK_ERR(br_hop_tag(&C, BRV_A7_HOP_KEY, BRV_A8_DATA_HOP2_FRAME, cov, ht), BR_OK);
    CHECK_MEM(BRV_A8_DATA_HOP2_FRAME + cov, ht, 4);
    /* the receiver tries each held epoch: the epoch-1 frame verifies under 1 only, the re-tagged one under 0 only */
    CHECK_ERR(br_hop_tag_verify(&C, BRV_A7_HOP_KEY, BRV_A8_DATA_HOP2_FRAME, cov, BRV_A8_DATA_HOP2_FRAME + cov), BR_OK);
    CHECK_ERR(br_hop_tag_verify(&C, BRV_A8_DATA_HOP2_K0_KEY, BRV_A8_DATA_HOP2_FRAME, cov, BRV_A8_DATA_HOP2_FRAME + cov),
              BR_ERR_AUTH);
    CHECK_ERR(br_hop_tag_verify(&C, BRV_A8_DATA_HOP2_K0_KEY, BRV_A8_DATA_HOP2_K0_FRAME, cov,
                                BRV_A8_DATA_HOP2_K0_FRAME + cov), BR_OK);
    CHECK_ERR(br_hop_tag_verify(&C, BRV_A7_HOP_KEY, BRV_A8_DATA_HOP2_K0_FRAME, cov, BRV_A8_DATA_HOP2_K0_FRAME + cov),
              BR_ERR_AUTH);
    CHECK_ERR(br_hop_tag_verify(&C, BRV_A6_K_HOP_1, BRV_A8_DATA_HOP2_FRAME, cov, BRV_A8_DATA_HOP2_FRAME + cov), BR_OK);
    CHECK_ERR(br_hop_tag_verify(&C, BRV_A6_K_HOP_0, BRV_A8_DATA_HOP2_K0_FRAME, cov, BRV_A8_DATA_HOP2_K0_FRAME + cov),
              BR_OK);
    /* the end-to-end part is identical in all three hop copies */
    CHECK_MEM(BRV_A7_FRAME + 15, BRV_A8_DATA_HOP1_FRAME + 15, 4 + 11 + 8);
    CHECK_MEM(BRV_A7_FRAME + 15, BRV_A8_DATA_HOP2_FRAME + 15, 4 + 11 + 8);
    /* a hop_tag is bound to the per-hop fields: changing hop_seq invalidates it */
    uint8_t f[44];
    memcpy(f, BRV_A7_FRAME, 44);
    f[11] ^= 1;
    CHECK_ERR(br_hop_tag_verify(&C, BRV_A7_HOP_KEY, f, cov, BRV_A7_FRAME + cov), BR_ERR_AUTH);
    /* args */
    CHECK_ERR(br_hop_tag(&C, NULL, f, cov, ht), BR_ERR_ARG);
    CHECK_ERR(br_hop_tag(&C, BRV_A7_HOP_KEY, NULL, cov, ht), BR_ERR_ARG);
    CHECK_ERR(br_hop_tag(&C, BRV_A7_HOP_KEY, f, cov, NULL), BR_ERR_ARG);
    CHECK_ERR(br_hop_tag(&C, BRV_A7_HOP_KEY, f, 0, ht), BR_ERR_ARG);
    CHECK_ERR(br_hop_tag_verify(&C, NULL, f, cov, ht), BR_ERR_ARG);
    CHECK_ERR(br_hop_tag_verify(&C, BRV_A7_HOP_KEY, NULL, cov, ht), BR_ERR_ARG);
    CHECK_ERR(br_hop_tag_verify(&C, BRV_A7_HOP_KEY, f, cov, NULL), BR_ERR_ARG);
}

static void test_a14_bundle(void)
{
    tu_ctx("A.14 bundle");
    /* TLVs: 01 21 02 <K_mesh(2)> 02 23 34 12 02 <K_pair(0042,1234,2)> */
    uint8_t tlv[72];
    size_t n = 0;
    tlv[n++] = 0x01;
    tlv[n++] = 0x21;
    tlv[n++] = 0x02;
    memcpy(tlv + n, BRV_A14_K_MESH_2, 32);
    n += 32;
    tlv[n++] = 0x02;
    tlv[n++] = 0x23;
    tlv[n++] = 0x34;
    tlv[n++] = 0x12;
    tlv[n++] = 0x02;
    memcpy(tlv + n, BRV_A14_K_PAIR_0042_1234_2, 32);
    n += 32;
    CHECK_EQ_U32(n, BRV_A14_TLVS_LEN);
    CHECK_MEM(BRV_A14_TLVS, tlv, BRV_A14_TLVS_LEN);

    /* nonce 02 || N u16 || bundle_no u32 || 0 x 6 ; AAD "PLB1" || N u16 || bundle_no u32 (8.6) */
    uint8_t nonce[13] = {0}, aad[10];
    nonce[0] = 0x02;
    tu_put16(nonce + 1, 0x0042);
    tu_put32(nonce + 3, BRV_A14_BUNDLE_NO);
    CHECK_MEM(BRV_A14_NONCE, nonce, 13);
    memcpy(aad, "PLB1", 4);
    tu_put16(aad + 4, 0x0042);
    tu_put32(aad + 6, BRV_A14_BUNDLE_NO);
    CHECK_MEM(BRV_A14_AAD, aad, 10);
    {   /* bundle nonce via br_ccm_nonce(BR_DIR_BUNDLE): N in src_id, bundle_no in ctr_hi (N19) */
        uint8_t bn[13];
        CHECK_ERR(br_ccm_nonce(BR_DIR_BUNDLE, 0x0042, 0, 0, BRV_A14_BUNDLE_NO, 0, bn), BR_OK);
        CHECK_MEM(BRV_A14_NONCE, bn, 13);
        CHECK_ERR(br_ccm_nonce(BR_DIR_BUNDLE, 0x0042, 1, 0, BRV_A14_BUNDLE_NO, 0, bn), BR_ERR_ARG);
        CHECK_ERR(br_ccm_nonce(3, 0x0042, 0, 0, 0, 0, bn), BR_ERR_ARG);
    }

    uint8_t ct[72], tag[8], wire[84];
    memcpy(nonce, BRV_A14_NONCE, 13);
    CHECK_ERR(br_ccm_encrypt(&C, BRV_A14_KB, nonce, aad, 10, BRV_A14_TLVS, 72, ct, tag), BR_OK);
    tu_put32(wire, BRV_A14_BUNDLE_NO);
    memcpy(wire + 4, ct, 72);
    memcpy(wire + 76, tag, 8);
    CHECK_MEM(BRV_A14_BUNDLE_WIRE, wire, BRV_A14_BUNDLE_WIRE_LEN);
    uint8_t pt[72];
    CHECK_ERR(br_ccm_decrypt(&C, BRV_A14_KB, nonce, aad, 10, BRV_A14_BUNDLE_WIRE + 4, 72, BRV_A14_BUNDLE_WIRE + 76, pt), BR_OK);
    CHECK_MEM(BRV_A14_TLVS, pt, 72);
    /* a lower bundle_no (different nonce/AAD) or any flipped byte fails */
    for (size_t i = 0; i < BRV_A14_BUNDLE_WIRE_LEN; i += 3) {
        uint8_t w[84];
        memcpy(w, BRV_A14_BUNDLE_WIRE, 84);
        flip(w, i);
        if (i < 4) {
            /* bundle_no is in the clear: changing it changes nonce and AAD */
            uint8_t n2[13], a2[10];
            memcpy(n2, nonce, 13);
            memcpy(a2, aad, 10);
            tu_put32(n2 + 3, tu_get32(w));
            tu_put32(a2 + 6, tu_get32(w));
            CHECK_ERR(br_ccm_decrypt(&C, BRV_A14_KB, n2, a2, 10, w + 4, 72, w + 76, pt), BR_ERR_AUTH);
        } else {
            CHECK_ERR(br_ccm_decrypt(&C, BRV_A14_KB, nonce, aad, 10, w + 4, 72, w + 76, pt), BR_ERR_AUTH);
        }
    }
    TU_SKIP("A.14 bundle TLV parse/apply (bundle_no monotonicity, epoch retire)", "bundle TLV parser (8.6) - no br_bundle_* in the Phase 1a headers");
}

static void test_ccm_args_and_roundtrip(void)
{
    tu_ctx("CCM args");
    uint8_t key[16] = {1}, nonce[13] = {2}, aad[8] = {3}, pt[16] = {4}, ct[16], tag[8];
    CHECK_ERR(br_ccm_encrypt(&C, NULL, nonce, aad, 8, pt, 16, ct, tag), BR_ERR_ARG);
    CHECK_ERR(br_ccm_encrypt(&C, key, NULL, aad, 8, pt, 16, ct, tag), BR_ERR_ARG);
    CHECK_ERR(br_ccm_encrypt(&C, key, nonce, NULL, 8, pt, 16, ct, tag), BR_ERR_ARG);
    CHECK_ERR(br_ccm_encrypt(&C, key, nonce, aad, 8, NULL, 16, ct, tag), BR_ERR_ARG);
    CHECK_ERR(br_ccm_encrypt(&C, key, nonce, aad, 8, pt, 16, NULL, tag), BR_ERR_ARG);
    CHECK_ERR(br_ccm_encrypt(&C, key, nonce, aad, 8, pt, 16, ct, NULL), BR_ERR_ARG);
    CHECK_ERR(br_ccm_encrypt(NULL, key, nonce, aad, 8, pt, 16, ct, tag), BR_ERR_ARG);
    {
        uint8_t *big = tu_alloc(BR_AAD_MAX_LEN + 1u), *bigpt = tu_alloc(256), *bigct = tu_alloc(256);
        CHECK_ERR(br_ccm_encrypt(&C, key, nonce, big, BR_AAD_MAX_LEN + 1u, pt, 16, ct, tag), BR_ERR_ARG);
        CHECK_ERR(br_ccm_encrypt(&C, key, nonce, big, BR_AAD_MAX_LEN, pt, 16, ct, tag), BR_OK);
        CHECK_ERR(br_ccm_encrypt(&C, key, nonce, aad, 8, bigpt, 256, bigct, tag), BR_ERR_ARG);
        CHECK_ERR(br_ccm_encrypt(&C, key, nonce, aad, 8, bigpt, 255, bigct, tag), BR_OK);
        CHECK_ERR(br_ccm_decrypt(&C, key, nonce, aad, 8, bigct, 256, tag, bigpt), BR_ERR_ARG);
        CHECK_ERR(br_ccm_decrypt(&C, key, nonce, aad, 8, bigct, 255, tag, bigpt), BR_OK);
        CHECK_ERR(br_ccm_decrypt(&C, key, nonce, big, BR_AAD_MAX_LEN + 1u, ct, 16, tag, pt), BR_ERR_ARG);
        free(big);
        free(bigpt);
        free(bigct);
    }
    CHECK_ERR(br_ccm_decrypt(&C, NULL, nonce, aad, 8, ct, 16, tag, pt), BR_ERR_ARG);
    CHECK_ERR(br_ccm_decrypt(&C, key, NULL, aad, 8, ct, 16, tag, pt), BR_ERR_ARG);
    CHECK_ERR(br_ccm_decrypt(&C, key, nonce, NULL, 8, ct, 16, tag, pt), BR_ERR_ARG);
    CHECK_ERR(br_ccm_decrypt(&C, key, nonce, aad, 8, NULL, 16, tag, pt), BR_ERR_ARG);
    CHECK_ERR(br_ccm_decrypt(&C, key, nonce, aad, 8, ct, 16, NULL, pt), BR_ERR_ARG);
    CHECK_ERR(br_ccm_decrypt(&C, key, nonce, aad, 8, ct, 16, tag, NULL), BR_ERR_ARG);
    CHECK_ERR(br_ccm_decrypt(NULL, key, nonce, aad, 8, ct, 16, tag, pt), BR_ERR_ARG);

    tu_ctx("CCM round trip");
    tu_rng_t rng;
    tu_rng_seed(&rng, 0xCC77u);
    for (unsigned it = 0; it < 600; it++) {
        uint8_t k[16], n[13];
        tu_rng_fill(&rng, k, 16);
        tu_rng_fill(&rng, n, 13);
        size_t al = (it % 5 == 0) ? 0u : tu_rng_below(&rng, BR_AAD_MAX_LEN + 1u);
        size_t pl = (it % 7 == 0) ? 0u : tu_rng_below(&rng, 256);
        uint8_t abuf[BR_AAD_MAX_LEN], pbuf[255], cbuf[255], rbuf[255], t[8];
        tu_rng_fill(&rng, abuf, sizeof abuf);
        tu_rng_fill(&rng, pbuf, sizeof pbuf);
        CHECK_ERR(br_ccm_encrypt(&C, k, n, al ? abuf : NULL, al, pl ? pbuf : NULL, pl, cbuf, t), BR_OK);
        CHECK_ERR(br_ccm_decrypt(&C, k, n, al ? abuf : NULL, al, pl ? cbuf : NULL, pl, t, rbuf), BR_OK);
        CHECK_MEM(pbuf, rbuf, pl);
        if (pl >= 8) {
            CHECK(memcmp(pbuf, cbuf, pl) != 0); /* really encrypted */
        }
        /* one random bit flip in (ct | aad | tag) is detected */
        size_t total = pl + al + 8u;
        size_t at = tu_rng_below(&rng, (uint32_t)total);
        uint8_t c2[255], a2[BR_AAD_MAX_LEN], t2[8];
        memcpy(c2, cbuf, pl);
        memcpy(a2, abuf, al);
        memcpy(t2, t, 8);
        uint8_t bit = (uint8_t)(1u << tu_rng_below(&rng, 8));
        if (at < pl) {
            c2[at] ^= bit;
        } else if (at < pl + al) {
            a2[at - pl] ^= bit;
        } else {
            t2[at - pl - al] ^= bit;
        }
        memset(rbuf, 0x55, sizeof rbuf);
        CHECK_ERR(br_ccm_decrypt(&C, k, n, al ? a2 : NULL, al, pl ? c2 : NULL, pl, t2, rbuf), BR_ERR_AUTH);
        for (size_t j = 0; j < pl; j++) {
            CHECK_EQ_U32(rbuf[j], 0u);
        }
    }
}

static void test_ct_equal_and_zero(void)
{
    tu_ctx("ct_equal");
    uint8_t a[64], b[64];
    CHECK_ERR(br_ct_equal(NULL, NULL, 0), BR_OK);
    CHECK_ERR(br_ct_equal(a, NULL, 0), BR_OK);
    CHECK_ERR(br_ct_equal(NULL, b, 5), BR_ERR_ARG);
    CHECK_ERR(br_ct_equal(a, NULL, 5), BR_ERR_ARG);
    tu_rng_t rng;
    tu_rng_seed(&rng, 0xC7E9u);
    for (size_t len = 1; len <= 64; len++) {
        tu_rng_fill(&rng, a, len);
        memcpy(b, a, len);
        CHECK_ERR(br_ct_equal(a, b, len), BR_OK);
        for (size_t i = 0; i < len; i++) { /* differ in exactly one byte, any position, any bit */
            for (unsigned bit = 0; bit < 8; bit += 3) {
                b[i] ^= (uint8_t)(1u << bit);
                CHECK_ERR(br_ct_equal(a, b, len), BR_ERR_AUTH);
                b[i] ^= (uint8_t)(1u << bit);
            }
        }
        CHECK_ERR(br_ct_equal(a, b, len), BR_OK);
        /* only the first len bytes are compared */
        if (len < 64) {
            b[len] ^= 0xFF;
            CHECK_ERR(br_ct_equal(a, b, len), BR_OK);
        }
    }
    /* all-zero and all-ones, and a difference that cancels in a naive sum/xor of bytes */
    memset(a, 0, 8);
    memset(b, 0, 8);
    CHECK_ERR(br_ct_equal(a, b, 8), BR_OK);
    a[0] = 1;
    a[1] = 1;
    b[0] = 0;
    b[1] = 2;
    CHECK_ERR(br_ct_equal(a, b, 2), BR_ERR_AUTH);
    a[0] = 0xFF; b[0] = 0xFF; a[1] = 0x80; b[1] = 0x00;
    CHECK_ERR(br_ct_equal(a, b, 2), BR_ERR_AUTH);
    CHECK_ERR(br_ct_equal(a, a, 2), BR_OK); /* same buffer */

    tu_ctx("secure_zero");
    uint8_t z[40];
    memset(z, 0xA5, sizeof z);
    br_secure_zero(z + 4, 20);
    for (size_t i = 0; i < sizeof z; i++) {
        CHECK_EQ_U32(z[i], (i >= 4 && i < 24) ? 0u : 0xA5u);
    }
    br_secure_zero(NULL, 0);
    br_secure_zero(z, 0);
    CHECK_EQ_U32(z[0], 0xA5u);
}

static void test_skips(void)
{
    TU_SKIP("A.13 LOW quantisation (scale 3.3/65534, offset 1.65, clip +-32767)", "quantiser (br_quant_* / sample codec) - no sample or MODE API in the Phase 1a headers");
    TU_SKIP("A.9 HELLO/BIND handshake state machine (OFFERED/BINDING matching, nonce_s, seek_ctr)", "session / handshake API (br_init, br_seek, br_task) - not in Phase 1a");
    TU_SKIP("A.12 MGMT TLV parsing (section 0 report, req_ctr match)", "MGMT codec (11.10) - not in Phase 1a");
    TU_SKIP("A.11 RESUME parked-session index check", "session table API - not in Phase 1a");
    printf("test_crypto: note - SHA-256 (T0, T transcripts) is checked with mbedtls_sha256() directly; br_crypto.h has no SHA-256 entry point\n");
}

int main(void)
{
    if (br_crypto_init(&C) != BR_OK) {
        printf("test_crypto: br_crypto_init failed; remaining checks will report failures\n");
        tu_checks++;
        tu_failed++;
    }
    test_init_and_state();
    test_hmac();
    test_hkdf_rfc();
    test_a6_keys();
    test_a9_keys();
    test_a12_a14_a15_keys();
    test_nonce_aad();
    test_e2e_vectors();
    test_hop_epochs();
    test_a14_bundle();
    test_ccm_args_and_roundtrip();
    test_ct_equal_and_zero();
    test_skips();
    br_crypto_free(&C);
    return tu_summary("test_crypto");
}
