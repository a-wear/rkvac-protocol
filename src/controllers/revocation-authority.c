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

#include "revocation-authority.h"

/**
 * Outputs the revocation authority parameters, generates the
 * private key and computes the public key.
 *
 * @param sys_parameters the system parameters
 * @param parameters the revocation authority parameters
 * @param keys the revocation authority private and public keys
 * @return 0 if success else -1
 */
int ra_setup(system_par_t sys_parameters, revocation_authority_par_t *parameters, revocation_authority_keys_t *keys)
{
    mclBnFr number_one;
    mclBnFr add_result, div_result;

    size_t it;
    int r;

    if (parameters == NULL || keys == NULL)
    {
        return -1;
    }

    /// chooses integers (k, j)
    parameters->k = REVOCATION_AUTHORITY_VALUE_K;
    parameters->j = REVOCATION_AUTHORITY_VALUE_J;

    /// chooses random integers (alphas)
    for (it = 0; it < parameters->j; it++)
    {
        mclBnFr_setByCSPRNG(&parameters->alphas[it]);
        r = mclBnFr_isValid(&parameters->alphas[it]);
        if (r != 1)
        {
            return -1;
        }

        mclBnG1_mul(&parameters->alphas_mul[it], &sys_parameters.G1, &parameters->alphas[it]);
        mclBnG1_normalize(&parameters->alphas_mul[it], &parameters->alphas_mul[it]);
        r = mclBnG1_isValid(&parameters->alphas_mul[it]);
        if (r != 1)
        {
            return -1;
        }
    }

    /// computes RA key pair
    // private key
    mclBnFr_setByCSPRNG(&keys->private_key.sk);
    r = mclBnFr_isValid(&keys->private_key.sk);
    if (r != 1)
    {
        return -1;
    }

    // public key (multiplication in elliptic curves)
    mclBnG2_mul(&keys->public_key.pk, &sys_parameters.G2, &keys->private_key.sk);
    mclBnG2_normalize(&keys->public_key.pk, &keys->public_key.pk);
    r = mclBnG2_isValid(&keys->public_key.pk);
    if (r != 1)
    {
        return -1;
    }

    /// chooses randomizers and signs each of them
    // set 1 to Fr data type
    mclBnFr_setInt32(&number_one, 1);

    for (it = 0; it < parameters->k; it++)
    {
        mclBnFr_setByCSPRNG(&parameters->randomizers[it]);
        r = mclBnFr_isValid(&parameters->randomizers[it]);
        if (r != 1)
        {
            return -1;
        }

        // randomizers_sigma = (1 / (ez + sk)) * G1
        mclBnFr_add(&add_result, &parameters->randomizers[it], &keys->private_key.sk); // add_result = ez + sk
        mclBnFr_div(&div_result, &number_one, &add_result); // div_result = 1 / add_result
        mclBnG1_mul(&parameters->randomizers_sigma[it], &sys_parameters.G1, &div_result); // sigma = G1 * div_result
        mclBnG1_normalize(&parameters->randomizers_sigma[it], &parameters->randomizers_sigma[it]);
        r = mclBnG1_isValid(&parameters->randomizers_sigma[it]);
        if (r != 1)
        {
            return -1;
        }
    }

    /// generates revocation list RL, empty list of revocation handlers RH
    /// and revocation database RD
    // ???

    return 0;
}

/**
 * Computes the signature of the user identifier using the private key.
 *
 * @param sys_parameters the system parameters
 * @param private_key the revocation authority private key
 * @param ue_identifier the user identifier
 * @param signature the signature of the user identifier
 * @return 0 if success else -1
 */
int ra_mac(system_par_t sys_parameters, revocation_authority_private_key_t private_key, user_identifier_t ue_identifier, revocation_authority_signature_t *signature)
{
    mclBnFr number_one;
    mclBnFr add_result, div_result;

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

    int r;

    if (signature == NULL)
    {
        return -1;
    }

    mclBnFr_setByCSPRNG(&signature->mr);
    r = mclBnFr_isValid(&signature->mr);
    if (r != 1)
    {
        return -1;
    }

    // signature->mr to bytes
    mcl_Fr_to_bytes(fr_data, EC_SIZE, signature->mr);

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

    // set 1 to Fr data type
    mclBnFr_setInt32(&number_one, 1);

    // sigma = (1 / H(mr || id) + sk) * G1
    mclBnFr_add(&add_result, &fr_hash, &private_key.sk); // add_result = H(mr || id) + sk
    mclBnFr_div(&div_result, &number_one, &add_result); // div_result = 1 / add_result
    mclBnG1_mul(&signature->sigma, &sys_parameters.G1, &div_result); // sigma = G1 * div_result
    mclBnG1_normalize(&signature->sigma, &signature->sigma);
    r = mclBnG1_isValid(&signature->sigma);
    if (r != 1)
    {
        return -1;
    }

    return 0;
}
