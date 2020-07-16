/**
 *
 *  Copyright (C) 2020  Raul Casanova Marques
 *
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "verifier.h"

/**
 * Generates a nonce and an epoch to be used in the proof of knowledge.
 *
 * @param nonce the nonce to be generated
 * @param nonce_length the length of the nonce
 * @param epoch the epoch to be generated
 * @param epoch_length the length of the epoch
 * @return 0 if success else -1
 */
int ve_generate_nonce_epoch(void *nonce, size_t nonce_length, void *epoch, size_t epoch_length)
{
    struct tm *tm_info;
    time_t time_info;

    int r;

    if (nonce == NULL || nonce_length != NONCE_LENGTH || epoch == NULL || epoch_length != EPOCH_LENGTH)
    {
        return -1;
    }

    // random nonce
    r = RAND_bytes(nonce, nonce_length);
    if (r != 1)
    {
        return -1;
    }

    // current epoch
    time(&time_info);
    tm_info = localtime(&time_info);
    ((uint8_t *) epoch)[0] = tm_info->tm_mday; // day of the month
    ((uint8_t *) epoch)[1] = tm_info->tm_mon; // month of the year
    ((uint8_t *) epoch)[2] = ((unsigned int) tm_info->tm_year >> 8u) & 0xFFu; // year (high byte)
    ((uint8_t *) epoch)[3] = tm_info->tm_year; // year (low byte)

    return 0;
}

/**
 * Verifies the proof of knowledge of the user attributes.
 *
 * @param sys_parameters the system parameters
 * @param ra_parameters the revocation authority parameters
 * @param ra_public_key the revocation authority public key
 * @param ie_keys the issuer keys
 * @param nonce the nonce generated by the verifier
 * @param nonce_length the length of the nonce
 * @param epoch the epoch generated by the verifier
 * @param epoch_length the length of the epoch
 * @param attributes the attributes disclosed by the user
 * @param ue_credential the credential struct computed by the user
 * @param ue_pi the pi struct computed by the user
 * @return 0 if success else -1
 */
int ve_verify_proof_of_knowledge(system_par_t sys_parameters, revocation_authority_par_t ra_parameters, revocation_authority_public_key_t ra_public_key,
                                 issuer_keys_t ie_keys, const void *nonce, size_t nonce_length, const void *epoch, size_t epoch_length,
                                 user_attributes_t attributes, user_credential_t ue_credential, user_pi_t ue_pi)
{
    mclBnFr attribute;
    mclBnGT el, er;

    mclBnFr mul_result;
    mclBnG1 mul_result_g1;

    mclBnFr e;
    mclBnFr neg_e;

    mclBnG1 t_verify, t_revoke;
    mclBnG1 t_sig, t_sig1, t_sig2;

    mclBnFr fr_hash, fr_hash_neg; // H(epoch), -H(epoch)

    // used to obtain the point data independently of the platform
    char digest_platform_point[192] = {0};

    /*
     * IMPORTANT!
     *
     * We are using SHA1 on the Smart Card. However, because the length
     * of the SHA1 hash is 20 and the size of Fr is 32, it is necessary
     * to enlarge 12 characters and fill them with 0's.
     */
    unsigned char hash[SHA_DIGEST_PADDING + SHA_DIGEST_LENGTH] = {0};
    SHA_CTX ctx;

    size_t it;
    int r;

    if (nonce == NULL || nonce_length == 0 || epoch == NULL || epoch_length == 0)
    {
        return -1;
    }

    /// t values
    // t_verify
    mclBnFr_neg(&neg_e, &ue_pi.e); // neg_e = -e
    mclBnFr_mul(&mul_result, &neg_e, &ie_keys.issuer_private_key.sk); // mul_result = -e·x(0)
    mclBnG1_mul(&t_verify, &ue_credential.sigma_hat, &mul_result); // t_verify = sigma_hat·mul_result
    mclBnG1_mul(&mul_result_g1, &sys_parameters.G1, &ue_pi.s_v); // mul_result_g1 = G1·s_v
    mclBnG1_add(&t_verify, &t_verify, &mul_result_g1); // t_verify = t_verify + mul_result_g1
    mclBnFr_mul(&mul_result, &ie_keys.revocation_private_key.sk, &ue_pi.s_mr); // mul_result = x(r)·s_mr
    mclBnG1_mul(&mul_result_g1, &ue_credential.sigma_hat, &mul_result); // mul_result_g1 = sigma_hat·mul_result
    mclBnG1_add(&t_verify, &t_verify, &mul_result_g1); // t_verify = t_verify + mul_result_g1
    // product of non-disclosed attributes
    for (it = 0; it < attributes.num_attributes; it++)
    {
        if (attributes.attributes[it].disclosed == false)
        {
            mclBnFr_mul(&mul_result, &ie_keys.attribute_private_keys[it].sk, &ue_pi.s_mz[it]); // mul_result = x(it)·s_mz(it)
            mclBnG1_mul(&mul_result_g1, &ue_credential.sigma_hat, &mul_result); // mul_result_g1 = sigma_hat·mul_result
            mclBnG1_add(&t_verify, &t_verify, &mul_result_g1); // t_verify = t_verify + mul_result_g1
        }
    }
    // product of disclosed attributes
    for (it = 0; it < attributes.num_attributes; it++)
    {
        if (attributes.attributes[it].disclosed == true)
        {
            mcl_bytes_to_Fr(&attribute, attributes.attributes[it].value, EC_SIZE);
            mclBnFr_mul(&mul_result, &neg_e, &ie_keys.attribute_private_keys[it].sk); // mul_result = -e·x(it)
            mclBnFr_mul(&mul_result, &mul_result, &attribute); // mul_result = mul_result·mz
            mclBnG1_mul(&mul_result_g1, &ue_credential.sigma_hat, &mul_result); // mul_result_g1 = sigma_hat·mul_result
            mclBnG1_add(&t_verify, &t_verify, &mul_result_g1); // t_verify = t_verify + mul_result_g1
        }
    }
    mclBnG1_normalize(&t_verify, &t_verify);
    r = mclBnG1_isValid(&t_verify);
    if (r != 1)
    {
        return -1;
    }

    // H(epoch)
    SHA1(epoch, epoch_length, &hash[SHA_DIGEST_PADDING]);

    /*
     * IMPORTANT!
     *
     * We are using SHA1 on the Smart Card. However, because the length
     * of the SHA1 hash is 20 and the size of Fr is 32, it is necessary
     * to enlarge 12 characters and fill them with 0's.
     */
    mcl_bytes_to_Fr(&fr_hash, hash, EC_SIZE);
    r = mclBnFr_isValid(&fr_hash);
    if (r != 1)
    {
        return -1;
    }
    // -H(epoch)
    mclBnFr_neg(&fr_hash_neg, &fr_hash);

    // t_revoke
    mclBnG1_mul(&t_revoke, &ue_credential.pseudonym, &fr_hash_neg); // t_revoke = C·(-H(epoch))
    mclBnG1_add(&t_revoke, &sys_parameters.G1, &t_revoke); // t_revoke = G1 + t_revoke
    mclBnG1_mul(&t_revoke, &t_revoke, &neg_e); // t_revoke = t_revoke·(-e)
    mclBnG1_mul(&mul_result_g1, &ue_credential.pseudonym, &ue_pi.s_mr); // mul_result_g1 = C·s_mr
    mclBnG1_add(&t_revoke, &t_revoke, &mul_result_g1); // t_revoke = t_revoke + mul_result_g1
    mclBnG1_mul(&mul_result_g1, &ue_credential.pseudonym, &ue_pi.s_i); // mul_result_g1 = C·s_i
    mclBnG1_add(&t_revoke, &t_revoke, &mul_result_g1); // t_revoke = t_revoke + mul_result_g1
    mclBnG1_normalize(&t_revoke, &t_revoke);
    r = mclBnG1_isValid(&t_revoke);
    if (r != 1)
    {
        return -1;
    }

    // t_sig
    mclBnG1_mul(&t_sig, &sys_parameters.G1, &ue_pi.s_i); // t_sig = G1·s_i
    mclBnG1_mul(&mul_result_g1, &ra_parameters.alphas_mul[0], &ue_pi.s_e1); // mul_result_g1 = h1·s_e1
    mclBnG1_add(&t_sig, &t_sig, &mul_result_g1); // t_sig = t_sig + mul_result_g1 (G1·s_i + h1·s_e1)
    mclBnG1_mul(&mul_result_g1, &ra_parameters.alphas_mul[1], &ue_pi.s_e2); // mul_result_g1 = h2·s_e2
    mclBnG1_add(&t_sig, &t_sig, &mul_result_g1); // t_sig = t_sig + mul_result_g1 (G1·s_i + h1·s_e1 + h2·s_e2)
    mclBnG1_normalize(&t_sig, &t_sig);
    r = mclBnG1_isValid(&t_sig);
    if (r != 1)
    {
        return -1;
    }

    // t_sig1
    mclBnG1_mul(&t_sig1, &ue_credential.sigma_minus_e1, &neg_e); // t_sig1 = sigma_minus_e1·(-e)
    mclBnG1_mul(&mul_result_g1, &ue_credential.sigma_hat_e1, &ue_pi.s_e1); // mul_result_g1 = sigma_hat_e1·s_e1
    mclBnG1_add(&t_sig1, &t_sig1, &mul_result_g1); // t_sig2 = t_sig2 + mul_result_g1
    mclBnG1_mul(&mul_result_g1, &sys_parameters.G1, &ue_pi.s_v); // mul_result_g1 = G1·s_v
    mclBnG1_add(&t_sig1, &t_sig1, &mul_result_g1); // t_sig2 = t_sig2 + mul_result_g1
    mclBnG1_normalize(&t_sig1, &t_sig1);
    r = mclBnG1_isValid(&t_sig1);
    if (r != 1)
    {
        return -1;
    }

    // t_sig2
    mclBnG1_mul(&t_sig2, &ue_credential.sigma_minus_e2, &neg_e); // t_sig2 = sigma_minus_e2·(-e)
    mclBnG1_mul(&mul_result_g1, &ue_credential.sigma_hat_e2, &ue_pi.s_e2); // mul_result_g1 = sigma_hat_e2·s_e2
    mclBnG1_add(&t_sig2, &t_sig2, &mul_result_g1); // t_sig2 = t_sig2 + mul_result_g1
    mclBnG1_mul(&mul_result_g1, &sys_parameters.G1, &ue_pi.s_v); // mul_result_g1 = G1·s_v
    mclBnG1_add(&t_sig2, &t_sig2, &mul_result_g1); // t_sig2 = t_sig2 + mul_result_g1
    mclBnG1_normalize(&t_sig2, &t_sig2);
    r = mclBnG1_isValid(&t_sig2);
    if (r != 1)
    {
        return -1;
    }

#ifndef NDEBUG
    mcl_display_G1("t_verify", t_verify);
    mcl_display_G1("t_revoke", t_revoke);
    mcl_display_G1("t_sig", t_sig);
    mcl_display_G1("t_sig1", t_sig1);
    mcl_display_G1("t_sig2", t_sig2);
    mcl_display_G1("sigma_hat", ue_credential.sigma_hat);
    mcl_display_G1("sigma_hat_e1", ue_credential.sigma_hat_e1);
    mcl_display_G1("sigma_hat_e2", ue_credential.sigma_hat_e2);
    mcl_display_G1("sigma_minus_e1", ue_credential.sigma_minus_e1);
    mcl_display_G1("sigma_minus_e2", ue_credential.sigma_minus_e2);
    mcl_display_G1("pseudonym", ue_credential.pseudonym);
#endif

    /// e <-- H(...)
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, digest_get_platform_point_data(digest_platform_point, t_verify), digest_get_platform_point_size());
    SHA1_Update(&ctx, digest_get_platform_point_data(digest_platform_point, t_revoke), digest_get_platform_point_size());
    SHA1_Update(&ctx, digest_get_platform_point_data(digest_platform_point, t_sig), digest_get_platform_point_size());
    SHA1_Update(&ctx, digest_get_platform_point_data(digest_platform_point, t_sig1), digest_get_platform_point_size());
    SHA1_Update(&ctx, digest_get_platform_point_data(digest_platform_point, t_sig2), digest_get_platform_point_size());
    SHA1_Update(&ctx, digest_get_platform_point_data(digest_platform_point, ue_credential.sigma_hat), digest_get_platform_point_size());
    SHA1_Update(&ctx, digest_get_platform_point_data(digest_platform_point, ue_credential.sigma_hat_e1), digest_get_platform_point_size());
    SHA1_Update(&ctx, digest_get_platform_point_data(digest_platform_point, ue_credential.sigma_hat_e2), digest_get_platform_point_size());
    SHA1_Update(&ctx, digest_get_platform_point_data(digest_platform_point, ue_credential.sigma_minus_e1), digest_get_platform_point_size());
    SHA1_Update(&ctx, digest_get_platform_point_data(digest_platform_point, ue_credential.sigma_minus_e2), digest_get_platform_point_size());
    SHA1_Update(&ctx, digest_get_platform_point_data(digest_platform_point, ue_credential.pseudonym), digest_get_platform_point_size());
    SHA1_Update(&ctx, nonce, nonce_length);
    SHA1_Final(&hash[SHA_DIGEST_PADDING], &ctx);

    /*
     * IMPORTANT!
     *
     * We are using SHA1 on the Smart Card. However, because the length
     * of the SHA1 hash is 20 and the size of Fr is 32, it is necessary
     * to enlarge 12 characters and fill them with 0's.
     */
    mcl_bytes_to_Fr(&e, hash, EC_SIZE);
    r = mclBnFr_isValid(&e);
    if (r != 1)
    {
        return -1;
    }

#ifndef NDEBUG
    mcl_display_Fr("e", e);
#endif

    r = mclBnFr_isEqual(&ue_pi.e, &e);
    if (r != 1)
    {
        return -1;
    }

    /// pairing
    // e(sigma_minus_e1, G2)
    mclBn_pairing(&el, &ue_credential.sigma_minus_e1, &sys_parameters.G2);
    // e(sigma_hat_e1, G2)
    mclBn_pairing(&er, &ue_credential.sigma_hat_e1, &ra_public_key.pk);
    // e(sigma_minus_e1, G2) ?= e(sigma_hat_e1, G2)
    r = mclBnGT_isEqual(&el, &er);
    if (r != 1)
    {
        return -1;
    }

    // e(sigma_minus_e2, G2)
    mclBn_pairing(&el, &ue_credential.sigma_minus_e2, &sys_parameters.G2);
    // e(sigma_hat_e2, G2)
    mclBn_pairing(&er, &ue_credential.sigma_hat_e2, &ra_public_key.pk);
    // e(sigma_minus_e2, G2) ?= e(sigma_hat_e2, G2)
    r = mclBnGT_isEqual(&el, &er);
    if (r != 1)
    {
        return -1;
    }

    /// pseudonym C not in revocation list RL
    // ???

    return 0;
}
