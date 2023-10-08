/**
 *  Copyright (C) 2018  Juho Vähä-Herttua
 *  Copyright (C) 2020  Jaslo Ziska
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *==================================================================
 * modified by fduncanh 2021-2023
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <openssl/sha.h> // for SHA512_DIGEST_LENGTH

#include "pairing.h"
#include "crypto.h"

#define SALT_KEY "Pair-Verify-AES-Key"
#define SALT_IV "Pair-Verify-AES-IV"

struct pairing_s {
    ed25519_key_t *ed;
};

typedef enum {
    STATUS_INITIAL,
    STATUS_SETUP,
    STATUS_HANDSHAKE,
    STATUS_FINISHED
} status_t;

struct pairing_session_s {
    status_t status;

    ed25519_key_t *ed_ours;
    ed25519_key_t *ed_theirs;

    x25519_key_t *ecdh_ours;
    x25519_key_t *ecdh_theirs;
    unsigned char ecdh_secret[X25519_KEY_SIZE];

    char *device_id;
    char *pin;
    char* salt;
};

static int
derive_key_internal(pairing_session_t *session, const unsigned char *salt, unsigned int saltlen, unsigned char *key, unsigned int keylen)
{
    unsigned char hash[SHA512_DIGEST_LENGTH];

    if (keylen > sizeof(hash)) {
        return -1;
    }

    sha_ctx_t *ctx = sha_init();
    sha_update(ctx, salt, saltlen);
    sha_update(ctx, session->ecdh_secret, X25519_KEY_SIZE);
    sha_final(ctx, hash, NULL);
    sha_destroy(ctx);

    memcpy(key, hash, keylen);
    return 0;
}

pairing_t *
pairing_init_generate()
{
    pairing_t *pairing;

    pairing = calloc(1, sizeof(pairing_t));
    if (!pairing) {
        return NULL;
    }

    pairing->ed = ed25519_key_generate();

    return pairing;
}

void
pairing_get_public_key(pairing_t *pairing, unsigned char public_key[ED25519_KEY_SIZE])
{
    assert(pairing);
    ed25519_key_get_raw(public_key, pairing->ed);
}

int
pairing_get_ecdh_secret_key(pairing_session_t *session, unsigned char ecdh_secret[X25519_KEY_SIZE])
{
    assert(session);
    switch (session->status) {
    case STATUS_INITIAL:
        return 0;
    default:
        memcpy(ecdh_secret, session->ecdh_secret, X25519_KEY_SIZE);
        return 1;
    }
}

pairing_session_t *
pairing_session_init(pairing_t *pairing)
{
    pairing_session_t *session;

    if (!pairing) {
        return NULL;
    }

    session = calloc(1, sizeof(pairing_session_t));
    if (!session) {
        return NULL;
    }

    session->ed_ours = ed25519_key_copy(pairing->ed);

    session->status = STATUS_INITIAL;

    session->device_id = NULL;
    session->pin = NULL;
    session->salt = NULL;
    
    return session;
}

void
pairing_session_set_setup_status(pairing_session_t *session)
{
    assert(session);
    session->status = STATUS_SETUP;
}

int
pairing_session_check_handshake_status(pairing_session_t *session)
{
    assert(session);
    switch (session->status) {
    case STATUS_SETUP:
    case STATUS_HANDSHAKE:
        return 0;
    default:
        return -1;
    }
}

int
pairing_session_handshake(pairing_session_t *session, const unsigned char ecdh_key[X25519_KEY_SIZE],
                          const unsigned char ed_key[ED25519_KEY_SIZE])
{
    assert(session);

    if (session->status == STATUS_FINISHED) {
        return -1;
    }

    session->ecdh_theirs = x25519_key_from_raw(ecdh_key);
    session->ed_theirs = ed25519_key_from_raw(ed_key);

    session->ecdh_ours = x25519_key_generate();

    x25519_derive_secret(session->ecdh_secret, session->ecdh_ours, session->ecdh_theirs);

    session->status = STATUS_HANDSHAKE;
    return 0;
}

int
pairing_session_get_public_key(pairing_session_t *session, unsigned char ecdh_key[X25519_KEY_SIZE])
{
    assert(session);

    if (session->status != STATUS_HANDSHAKE) {
        return -1;
    }

    x25519_key_get_raw(ecdh_key, session->ecdh_ours);

    return 0;
}

int
pairing_session_get_signature(pairing_session_t *session, unsigned char signature[PAIRING_SIG_SIZE])
{
    unsigned char sig_msg[PAIRING_SIG_SIZE];
    unsigned char key[AES_128_BLOCK_SIZE];
    unsigned char iv[AES_128_BLOCK_SIZE];
    aes_ctx_t *aes_ctx;

    assert(session);

    if (session->status != STATUS_HANDSHAKE) {
        return -1;
    }

    /* First sign the public ECDH keys of both parties */
    x25519_key_get_raw(sig_msg, session->ecdh_ours);
    x25519_key_get_raw(sig_msg + X25519_KEY_SIZE, session->ecdh_theirs);

    ed25519_sign(signature, PAIRING_SIG_SIZE, sig_msg, PAIRING_SIG_SIZE, session->ed_ours);

    /* Then encrypt the result with keys derived from the shared secret */
    derive_key_internal(session, (const unsigned char *) SALT_KEY, strlen(SALT_KEY), key, sizeof(key));
    derive_key_internal(session, (const unsigned char *) SALT_IV, strlen(SALT_IV), iv, sizeof(iv));

    aes_ctx = aes_ctr_init(key, iv);
    aes_ctr_encrypt(aes_ctx, signature, signature, PAIRING_SIG_SIZE);
    aes_ctr_destroy(aes_ctx);

    return 0;
}

int
pairing_session_finish(pairing_session_t *session, const unsigned char signature[PAIRING_SIG_SIZE])
{
    unsigned char sig_buffer[PAIRING_SIG_SIZE];
    unsigned char sig_msg[PAIRING_SIG_SIZE];
    unsigned char key[AES_128_BLOCK_SIZE];
    unsigned char iv[AES_128_BLOCK_SIZE];
    aes_ctx_t *aes_ctx;

    assert(session);

    if (session->status != STATUS_HANDSHAKE) {
        return -1;
    }

    /* First decrypt the signature with keys derived from the shared secret */
    derive_key_internal(session, (const unsigned char *) SALT_KEY, strlen(SALT_KEY), key, sizeof(key));
    derive_key_internal(session, (const unsigned char *) SALT_IV, strlen(SALT_IV), iv, sizeof(iv));

    aes_ctx = aes_ctr_init(key, iv);
    /* One fake round for the initial handshake encryption */
    aes_ctr_encrypt(aes_ctx, sig_buffer, sig_buffer, PAIRING_SIG_SIZE);
    aes_ctr_encrypt(aes_ctx, signature, sig_buffer, PAIRING_SIG_SIZE);
    aes_ctr_destroy(aes_ctx);

    /* Then verify the signature with public ECDH keys of both parties */
    x25519_key_get_raw(sig_msg, session->ecdh_theirs);
    x25519_key_get_raw(sig_msg + X25519_KEY_SIZE, session->ecdh_ours);

    if (!ed25519_verify(sig_buffer, PAIRING_SIG_SIZE, sig_msg, PAIRING_SIG_SIZE, session->ed_theirs)) {
        return -2;
    }

    session->status = STATUS_FINISHED;
    return 0;
}

void
pairing_session_destroy(pairing_session_t *session)
{
    if (session) {
        ed25519_key_destroy(session->ed_ours);
        ed25519_key_destroy(session->ed_theirs);

        x25519_key_destroy(session->ecdh_ours);
        x25519_key_destroy(session->ecdh_theirs);

        if (session->device_id) free(session->device_id);
        if (session->pin) free(session->pin);
	if (session->salt) free(session->salt);

        free(session);
    }
}

void
pairing_destroy(pairing_t *pairing)
{
    if (pairing) {
        ed25519_key_destroy(pairing->ed);
        free(pairing);
    }
}

int
pairing_create_pin(pairing_session_t *session, const char *device_id) {
    int ret;
    unsigned char random_bytes[PAIRING_SALT_SIZE + 2];
    unsigned short random_short;

    if (!session) {
        return 0;
    }

    if (session->salt) free(session->salt);
    session->salt = NULL;
    if (session->device_id) free(session->device_id);
    session->device_id = NULL;
    if (session->pin) free(session->pin);
    session->pin = NULL;
    if ((ret = get_random_bytes(random_bytes, 18))  < 1) {
        return (ret);
    }
    
    session->pin = (char *) malloc(PAIRING_PIN_SIZE + 1);        //store as ascii string "1234"
    session->salt = (char *) malloc(1 + 2 * PAIRING_SALT_SIZE);  //store as ascii string "a02f349ae...."
    session->device_id = (char *) malloc(1 + (int) strlen(device_id));
    if (!session->pin || !session->salt || !session->device_id) {
        if (session->pin) free (session->pin);
        if (session->salt) free (session->salt);
        if (session->device_id) free (session->device_id);	    
        return 0;
    }
    
    strncpy(session->device_id, device_id, strlen(device_id));

    for (int i = 0 ; i <  PAIRING_SALT_SIZE; i++ ) {
        snprintf(session->salt + 2*i, 3, "%02x", random_bytes[i]);
    }
    
    memcpy(&random_short, random_bytes + PAIRING_PIN_SIZE, 2);
    random_short = random_short % 10000;
    snprintf(session->pin, 5, "%04u", random_short);
    return 1;
}

int
pairing_get_pin(pairing_session_t *session, const char *device_id, char **pin, char **salt) {
    *pin = NULL;
    *salt = NULL
      
    if (!session  || !session->device_id || !session->pin || 1session->salt) {
        return -1;
    }

    if (strlen(device_id) != strlen(session->device_id)  || strncmp(device_id, session->device_id, strlen(device_id))) {
        return 1;
    }
    
    *pin  = session->pin;
    *salt = session->salt;
    return 0;
}
