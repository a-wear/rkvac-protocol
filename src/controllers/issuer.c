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

#include "issuer.h"

/**
 * Outputs the issuer parameters, generates the private keys.
 *
 * @param parameters the issuer parameters
 * @param keys the issuer private keys
 * @return 0 if success else -1
 */
int ie_setup(issuer_par_t parameters, issuer_keys_t *keys)
{
    size_t it;
    int r;

    if (keys == NULL || parameters.num_attributes == 0 || parameters.num_attributes > USER_MAX_NUM_ATTRIBUTES)
    {
        return -1;
    }

    // issuer private key - x(0)
    mclBnFr_setByCSPRNG(&keys->issuer_private_key.sk);
    r = mclBnFr_isValid(&keys->issuer_private_key.sk);
    if (r != 1)
    {
        return -1;
    }

    // private keys - x(1)...x(n-1)
    for (it = 0; it < parameters.num_attributes; it++)
    {
        mclBnFr_setByCSPRNG(&keys->attribute_private_keys[it].sk);
        r = mclBnFr_isValid(&keys->attribute_private_keys[it].sk);
        if (r != 1)
        {
            return -1;
        }
    }

    // revocation private key - x(r)
    mclBnFr_setByCSPRNG(&keys->revocation_private_key.sk);
    r = mclBnFr_isValid(&keys->revocation_private_key.sk);
    if (r != 1)
    {
        return -1;
    }

    return 0;
}

/**
 * Computes the signature of the user attributes using the private keys.
 *
 * @param sys_parameters the system parameters
 * @param parameters the issuer parameters
 * @param keys the issuer keys
 * @param ue_identifier the user identifier
 * @param ue_attributes the user attributes
 * @param revocation_authority_public_key the revocation authority public key
 * @param revocation_authority_signature the revocation authority signature (mr, ra_sigma)
 * @param signature the signature of the user attributes
 * @return 0 if success else -1
 */
int ie_issue(system_par_t sys_parameters, issuer_par_t parameters, issuer_keys_t keys, user_identifier_t ue_identifier, user_attributes_t ue_attributes,
             revocation_authority_public_key_t revocation_authority_public_key, revocation_authority_signature_t revocation_authority_signature,
             issuer_signature_t *signature)
{
    mclBnGT el, er;
    mclBnGT e1, e2, e3;

    mclBnFr number_one, attribute;
    mclBnFr add_result, mul_result, div_result;

    unsigned char fr_data[EC_SIZE];
    mclBnFr fr_hash;

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

    if (ue_attributes.num_attributes == 0 || ue_attributes.num_attributes > USER_MAX_NUM_ATTRIBUTES || signature == NULL)
    {
        return -1;
    }

    // signature->mr to bytes
    mcl_Fr_to_bytes(fr_data, EC_SIZE, revocation_authority_signature.mr);

    // H(mr || id)
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, fr_data, EC_SIZE);
    SHA1_Update(&ctx, ue_identifier.buffer, ue_identifier.buffer_length);
    SHA1_Final(&hash[SHA_DIGEST_PADDING], &ctx);

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

    /// pairing
    // e(ra_sigma, ra_pk)
    mclBn_pairing(&e1, &revocation_authority_signature.sigma, &revocation_authority_public_key.pk);

    // e(ra_sigma^hash, G2) == e(ra_sigma, G2)^hash
    mclBn_pairing(&e2, &revocation_authority_signature.sigma, &sys_parameters.G2);
    mclBnGT_pow(&e3, &e2, &fr_hash);

    // e(ra_sigma, ra_pk) * e(ra_sigma^hash, G2)
    mclBnGT_mul(&el, &e1, &e3);

    // e(G1, G2)
    mclBn_pairing(&er, &sys_parameters.G1, &sys_parameters.G2);

    // e(ra_sigma, ra_pk) * e(ra_sigma^hash, G2) ?= e(G1, G2)
    r = mclBnGT_isEqual(&el, &er);
    if (r != 1)
    {
        return -1;
    }

    /// signature of the user attributes
    // set 1 to Fr data type
    mclBnFr_setInt32(&number_one, 1);

    // add_result = x(0)
    memcpy(&add_result, &keys.issuer_private_key.sk, sizeof(mclBnFr));
    // add_result = add_result + m(it)·x(it)
    for (it = 0; it < parameters.num_attributes; it++)
    {
        mcl_bytes_to_Fr(&attribute, ue_attributes.attributes[it].value, EC_SIZE);
        mclBnFr_mul(&mul_result, &attribute, &keys.attribute_private_keys[it].sk);
        mclBnFr_add(&add_result, &add_result, &mul_result);
    }
    // add_result = add_result + m(r)·x(r)
    mclBnFr_mul(&mul_result, &revocation_authority_signature.mr, &keys.revocation_private_key.sk);
    mclBnFr_add(&add_result, &add_result, &mul_result);

    mclBnFr_div(&div_result, &number_one, &add_result); // div_result = 1 / add_result
    mclBnG1_mul(&signature->sigma, &sys_parameters.G1, &div_result); // sigma = G1 * div_result
    mclBnG1_normalize(&signature->sigma, &signature->sigma);
    r = mclBnG1_isValid(&signature->sigma);
    if (r != 1)
    {
        return -1;
    }

    /// sigma attributes
    // sigma_x_it = sigma·x_it
    for (it = 0; it < parameters.num_attributes; it++)
    {
        mclBnG1_mul(&signature->attribute_sigmas[it], &signature->sigma, &keys.attribute_private_keys[it].sk);
        mclBnG1_normalize(&signature->attribute_sigmas[it], &signature->attribute_sigmas[it]);
        r = mclBnG1_isValid(&signature->attribute_sigmas[it]);
        if (r != 1)
        {
            return -1;
        }
    }

    mclBnG1_mul(&signature->revocation_sigma, &signature->sigma, &keys.revocation_private_key.sk);
    mclBnG1_normalize(&signature->revocation_sigma, &signature->revocation_sigma);
    r = mclBnG1_isValid(&signature->revocation_sigma);
    if (r != 1)
    {
        return -1;
    }

    return 0;
}
