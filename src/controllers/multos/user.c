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

#include "user.h"

/**
 * Gets the user identifier using the specified reader.
 *
 * @param reader the reader to be used
 * @param identifier the user identifier
 * @return 0 if success else -1
 */
int ue_get_user_identifier(reader_t reader, user_identifier_t *identifier)
{
    uint8_t pbSendBuffer[MAX_APDU_LENGTH_T0] = {0};
    uint8_t pbRecvBuffer[MAX_APDU_LENGTH_T0] = {0};
    uint32_t dwSendLength;
    uint32_t dwRecvLength;

    int r;

    if (identifier == NULL)
    {
        return -1;
    }

    dwSendLength = sizeof(pbSendBuffer);
    r = apdu_build_command(CASE2, CLA_APPLICATION, INS_GET_USER_IDENTIFIER, 0x00, 0x00, 0, NULL, USER_MAX_ID_LENGTH, pbSendBuffer, &dwSendLength);
    if (r < 0)
    {
        return -1;
    }

    dwRecvLength = sizeof(pbRecvBuffer);
    r = sc_transmit_data(reader, pbSendBuffer, dwSendLength, pbRecvBuffer, &dwRecvLength, NULL);
    if (r < 0)
    {
        fprintf(stderr, "Error: %s\n", sc_get_error(r));
        return r;
    }

    memcpy(identifier->buffer, pbRecvBuffer, USER_MAX_ID_LENGTH);
    identifier->buffer_length = USER_MAX_ID_LENGTH;

    return 0;
}

/**
 * Sets the revocation authority parameters and the revocation attributes.
 *
 * @param reader the reader to be used
 * @param ra_parameters the revocation authority parameters
 * @param ra_signature the signature of the user identifier
 * @return 0 if success else -1
 */
int ue_set_revocation_authority_data(reader_t reader, revocation_authority_par_t ra_parameters, revocation_authority_signature_t ra_signature)
{
    uint8_t pbSendBuffer[MAX_APDU_LENGTH_T0] = {0};
    uint8_t pbRecvBuffer[MAX_APDU_LENGTH_T0] = {0};
    uint32_t dwSendLength;
    uint32_t dwRecvLength;

    uint8_t data[2048] = {0};
    size_t data_length;

    size_t transmissions;
    size_t offset;
    size_t lc;

    size_t it;
    int r;

    data_length = 0;

    // ra_signature.mr
    mcl_Fr_to_multos_Fr(&data[data_length], sizeof(elliptic_curve_fr_t), ra_signature.mr);
    data_length += sizeof(elliptic_curve_fr_t);

    // ra_signature.sigma
    mcl_G1_to_multos_G1(&data[data_length], sizeof(elliptic_curve_point_t), ra_signature.sigma);
    data_length += sizeof(elliptic_curve_point_t);

    // k, j
    data[data_length++] = ra_parameters.k;
    data[data_length++] = ra_parameters.j;

    // alphas
    for (it = 0; it < REVOCATION_AUTHORITY_VALUE_J; it++)
    {
        mcl_Fr_to_multos_Fr(&data[data_length], sizeof(elliptic_curve_fr_t), ra_parameters.alphas[it]);
        data_length += sizeof(elliptic_curve_fr_t);
    }

    // alphas_mul
    for (it = 0; it < REVOCATION_AUTHORITY_VALUE_J; it++)
    {
        mcl_G1_to_multos_G1(&data[data_length], sizeof(elliptic_curve_point_t), ra_parameters.alphas_mul[it]);
        data_length += sizeof(elliptic_curve_point_t);
    }

    // randomizers
    for (it = 0; it < REVOCATION_AUTHORITY_VALUE_K; it++)
    {
        mcl_Fr_to_multos_Multiplier(&data[data_length], sizeof(elliptic_curve_multiplier_t), ra_parameters.randomizers[it]);
        data_length += sizeof(elliptic_curve_multiplier_t);
    }

    // randomizers_sigma
    for (it = 0; it < REVOCATION_AUTHORITY_VALUE_K; it++)
    {
        mcl_G1_to_multos_G1(&data[data_length], sizeof(elliptic_curve_point_t), ra_parameters.randomizers_sigma[it]);
        data_length += sizeof(elliptic_curve_point_t);
    }

    // calculate how many data transmissions are necessary
    transmissions = data_length / MAX_APDU_SEND_SIZE_T0 + (data_length % MAX_APDU_SEND_SIZE_T0 > 0 ? 1 : 0);

    offset = 0;
    lc = sizeof(elliptic_curve_fr_t) + sizeof(elliptic_curve_point_t); // send revocation authority data (mr, sigma) at the beginning
    for (it = 0; it < transmissions; it++)
    {
        dwSendLength = sizeof(pbSendBuffer);
        r = apdu_build_command(CASE3, CLA_APPLICATION, INS_SET_REVOCATION_AUTHORITY_DATA, it + 1, transmissions, lc, &data[offset], 0, pbSendBuffer, &dwSendLength);
        if (r < 0)
        {
            return -1;
        }

        dwRecvLength = sizeof(pbRecvBuffer);
        r = sc_transmit_data(reader, pbSendBuffer, dwSendLength, pbRecvBuffer, &dwRecvLength, NULL);
        if (r < 0)
        {
            fprintf(stderr, "Error: %s\n", sc_get_error(r));
            return r;
        }

        offset += lc;
        lc = (offset + MAX_APDU_SEND_SIZE_T0 < data_length ? MAX_APDU_SEND_SIZE_T0 : data_length - offset);
    }

    return 0;
}

/**
 * Sets the user attributes using the specified reader.
 *
 * @param reader the reader to be used
 * @param num_attributes the number of the user attributes
 * @return 0 if success else -1
 */
int ue_set_user_attributes(reader_t reader, size_t num_attributes)
{
    uint8_t pbSendBuffer[MAX_APDU_LENGTH_T0] = {0};
    uint8_t pbRecvBuffer[MAX_APDU_LENGTH_T0] = {0};
    uint32_t dwSendLength;
    uint32_t dwRecvLength;

    uint8_t data[2048] = {0};
    size_t data_length;

    size_t transmissions;
    size_t offset;
    size_t lc;

    size_t it;
    int r;

    data_length = 0;

    // copy number of attributes
    data[data_length++] = num_attributes;
    // copy attributes
    for (it = 0; it < num_attributes; it++)
    {
        memcpy(&data[data_length], &USER_ATTRIBUTES[it * sizeof(elliptic_curve_fr_t)], sizeof(elliptic_curve_fr_t));
        data_length += sizeof(elliptic_curve_fr_t);
    }

    // calculate how many data transmissions are necessary
    transmissions = data_length / MAX_APDU_SEND_SIZE_T0 + (data_length % MAX_APDU_SEND_SIZE_T0 > 0 ? 1 : 0);

    offset = 0;
    lc = (MAX_APDU_SEND_SIZE_T0 < data_length ? MAX_APDU_SEND_SIZE_T0 : data_length);
    for (it = 0; it < transmissions; it++)
    {
        dwSendLength = sizeof(pbSendBuffer);
        r = apdu_build_command(CASE3, CLA_APPLICATION, INS_SET_USER_ATTRIBUTES, it + 1, transmissions, lc, &data[offset], 0, pbSendBuffer, &dwSendLength);
        if (r < 0)
        {
            return -1;
        }

        dwRecvLength = sizeof(pbRecvBuffer);
        r = sc_transmit_data(reader, pbSendBuffer, dwSendLength, pbRecvBuffer, &dwRecvLength, NULL);
        if (r < 0)
        {
            fprintf(stderr, "Error: %s\n", sc_get_error(r));
            return r;
        }

        offset += lc;
        lc = (offset + MAX_APDU_SEND_SIZE_T0 < data_length ? MAX_APDU_SEND_SIZE_T0 : data_length - offset);
    }

    return 0;
}

/**
 * Gets the user attributes and identifier using the specified reader.
 *
 * @param reader the reader to be used
 * @param attributes the user attributes
 * @param identifier the user identifier
 * @param ra_signature the signature of the user identifier
 * @return 0 if success else -1
 */
int ue_get_user_attributes_identifier(reader_t reader, user_attributes_t *attributes, user_identifier_t *identifier, revocation_authority_signature_t *ra_signature)
{
    uint8_t pbSendBuffer[MAX_APDU_LENGTH_T0] = {0};
    uint8_t pbRecvBuffer[MAX_APDU_LENGTH_T0] = {0};
    uint32_t dwSendLength;
    uint32_t dwRecvLength;

    uint8_t data[2048] = {0};
    size_t data_length;

    size_t transmissions;
    size_t offset;
    size_t le;

    size_t it;

    int r;

    if (attributes == NULL || identifier == NULL || ra_signature == NULL)
    {
        return -1;
    }

    data_length = 0;

    // calculate how many data transmissions are necessary (1 at the beginning)
    transmissions = 1;

    offset = 0;
    le = USER_MAX_ID_LENGTH + sizeof(elliptic_curve_fr_t) + sizeof(elliptic_curve_point_t) + 1; // user_identifier + revocation_authority_signature + num_attributes
    for (it = 0; it < transmissions; it++)
    {
        dwSendLength = sizeof(pbSendBuffer);
        r = apdu_build_command(CASE2, CLA_APPLICATION, INS_GET_USER_IDENTIFIER_ATTRIBUTES, it + 1, transmissions, 0, NULL, le, pbSendBuffer, &dwSendLength);
        if (r < 0)
        {
            return -1;
        }

        dwRecvLength = sizeof(pbRecvBuffer);
        r = sc_transmit_data(reader, pbSendBuffer, dwSendLength, pbRecvBuffer, &dwRecvLength, NULL);
        if (r < 0)
        {
            fprintf(stderr, "Error: %s\n", sc_get_error(r));
            return r;
        }

        // expected length
        assert(dwRecvLength == le + 2);

        // copy received data
        memcpy((void *) &data[offset], (const void *) pbRecvBuffer, dwRecvLength - 2);

        // calculates how many transmissions are needed
        if (it == 0)
        {
            attributes->num_attributes = pbRecvBuffer[dwRecvLength - 3];
            data_length = attributes->num_attributes * sizeof(elliptic_curve_fr_t);
            transmissions += data_length / MAX_APDU_SEND_SIZE_T0 + (data_length % MAX_APDU_SEND_SIZE_T0 > 0 ? 1 : 0);
            data_length += le; // fix data length by adding the data already sent
        }

        offset += le;
        data_length -= le; // subtract the amount of data to be received
        le = (data_length > MAX_APDU_SEND_SIZE_T0 ? MAX_APDU_SEND_SIZE_T0 : data_length);
    }

    data_length = 0;

    // user_identifier
    memcpy(identifier->buffer, &data[data_length], USER_MAX_ID_LENGTH);
    identifier->buffer_length = USER_MAX_ID_LENGTH;
    data_length += USER_MAX_ID_LENGTH;

    // ra_signature.mr
    multos_Fr_to_mcl_Fr(&ra_signature->mr, &data[data_length], sizeof(elliptic_curve_fr_t));
    r = mclBnFr_isValid(&ra_signature->mr);
    if (r != 1)
    {
        return -1;
    }
    data_length += sizeof(elliptic_curve_fr_t);

    // ra_signature.sigma
    multos_G1_to_mcl_G1(&ra_signature->sigma, &data[data_length], sizeof(elliptic_curve_point_t));
    r = mclBnG1_isValid(&ra_signature->sigma);
    if (r != 1)
    {
        return -1;
    }
    data_length += sizeof(elliptic_curve_point_t);

    // num_attributes
    attributes->num_attributes = data[data_length];
    data_length += 1;

    // attributes
    for (it = 0; it < attributes->num_attributes; it++)
    {
        memcpy(attributes->attributes[it].value, &data[data_length], sizeof(elliptic_curve_fr_t));
        data_length += sizeof(elliptic_curve_fr_t);
    }

    return 0;
}

/**
 * Sets the issuer signatures of the user's attributes.
 *
 * @param reader the reader to be used
 * @param ie_parameters the issuer parameters
 * @param ie_signature the issuer signature
 * @return 0 if success else -1
 */
int ue_set_issuer_signatures(reader_t reader, issuer_par_t ie_parameters, issuer_signature_t ie_signature)
{
    uint8_t pbSendBuffer[MAX_APDU_LENGTH_T0] = {0};
    uint8_t pbRecvBuffer[MAX_APDU_LENGTH_T0] = {0};
    uint32_t dwSendLength;
    uint32_t dwRecvLength;

    uint8_t data[2048] = {0};
    size_t data_length;

    size_t transmissions;
    size_t offset;
    size_t lc;

    size_t it;
    int r;

    data_length = 0;

    // ie_signature.sigma
    mcl_G1_to_multos_G1(&data[data_length], sizeof(elliptic_curve_point_t), ie_signature.sigma);
    data_length += sizeof(elliptic_curve_point_t);

    // ie_signature.revocation_sigma
    mcl_G1_to_multos_G1(&data[data_length], sizeof(elliptic_curve_point_t), ie_signature.revocation_sigma);
    data_length += sizeof(elliptic_curve_point_t);

    // ie_signature.attribute_sigmas
    for (it = 0; it < ie_parameters.num_attributes; it++)
    {
        mcl_G1_to_multos_G1(&data[data_length], sizeof(elliptic_curve_point_t), ie_signature.attribute_sigmas[it]);
        data_length += sizeof(elliptic_curve_point_t);
    }

    // calculate how many data transmissions are necessary
    transmissions = data_length / MAX_APDU_SEND_SIZE_T0 + (data_length % MAX_APDU_SEND_SIZE_T0 > 0 ? 1 : 0);

    offset = 0;
    lc = (MAX_APDU_SEND_SIZE_T0 < data_length ? MAX_APDU_SEND_SIZE_T0 : data_length);
    for (it = 0; it < transmissions; it++)
    {
        dwSendLength = sizeof(pbSendBuffer);
        r = apdu_build_command(CASE3, CLA_APPLICATION, INS_SET_ISSUER_SIGNATURES, it + 1, transmissions, lc, &data[offset], 0, pbSendBuffer, &dwSendLength);
        if (r < 0)
        {
            return -1;
        }

        dwRecvLength = sizeof(pbRecvBuffer);
        r = sc_transmit_data(reader, pbSendBuffer, dwSendLength, pbRecvBuffer, &dwRecvLength, NULL);
        if (r < 0)
        {
            fprintf(stderr, "Error: %s\n", sc_get_error(r));
            return r;
        }

        offset += lc;
        lc = (offset + MAX_APDU_SEND_SIZE_T0 < data_length ? MAX_APDU_SEND_SIZE_T0 : data_length - offset);
    }

    return 0;
}

/**
 * Computes the proof of knowledge of the user attributes and discloses those requested
 * by the verifier.
 *
 * @param reader the reader to be used
 * @param sys_parameters the system parameters
 * @param ra_parameters the revocation authority parameters
 * @param ra_signature the signature of the user identifier
 * @param ie_signature the issuer signature
 * @param I the first pseudo-random value used to select the first randomizer
 * @param II the second pseudo-random value used to select the second randomizer
 * @param nonce the nonce generated by the verifier
 * @param nonce_length the length of the nonce
 * @param epoch the epoch generated by the verifier
 * @param epoch_length the length of the epoch
 * @param attributes the user attributes
 * @param num_disclosed_attributes the number of attributes the verifier wants to disclose
 * @param credential the credential struct to be computed by the user
 * @param pi the pi struct to be computed by the user
 * @return 0 if success else -1
 */
int ue_compute_proof_of_knowledge(reader_t reader, system_par_t sys_parameters, revocation_authority_par_t ra_parameters, revocation_authority_signature_t ra_signature,
                                  issuer_signature_t ie_signature, uint8_t I, uint8_t II, const void *nonce, size_t nonce_length, const void *epoch, size_t epoch_length,
                                  user_attributes_t *attributes, size_t num_disclosed_attributes, user_credential_t *credential, user_pi_t *pi)
{
    uint8_t pbSendBuffer[MAX_APDU_LENGTH_T0] = {0};
    uint8_t pbRecvBuffer[MAX_APDU_LENGTH_T0] = {0};
    uint32_t dwSendLength;
    uint32_t dwRecvLength;

    uint8_t data[2048] = {0};
    size_t data_length;

    size_t transmissions;
    size_t offset;
    size_t lc, le;

    /*
     * IMPORTANT!
     *
     * The attributes are disclosed from the end to the beginning,
     * i.e., if a user has 4 attributes and the verifier wants to
     * disclose 2, the disclosed attributes will be the 3rd and 4th,
     * keeping hidden the 1st and 2nd.
     *
     * +---+---+---+---+
     * | 1 | 2 | 3 | 4 |
     * +---+---+---+---+
     * | H | H | D | D |
     * +---+---+---+---+
     */
    size_t num_non_disclosed_attributes;

    /*
     * IMPORTANT!
     *
     * We are using SHA1 on the Smart Card. However, because the length
     * of the SHA1 hash is 20 and the size of Fr is 32, it is necessary
     * to enlarge 12 characters and fill them with 0's.
     */
    unsigned char hash[SHA_DIGEST_PADDING + SHA_DIGEST_LENGTH] = {0};

    double elapsed_time;

    size_t it;
    int r;

    if (nonce == NULL || nonce_length == 0 || epoch == NULL || epoch_length == 0 || attributes == NULL || pi == NULL || credential == NULL)
    {
        return -1;
    }

    if (attributes->num_attributes == 0 || attributes->num_attributes > USER_MAX_NUM_ATTRIBUTES || attributes->num_attributes < num_disclosed_attributes)
    {
        return -1;
    }

    /// disclose attributes
    num_non_disclosed_attributes = attributes->num_attributes - num_disclosed_attributes;

    /*
     * IMPORTANT!
     *
     * The attributes are disclosed from the end to the beginning,
     * i.e., if a user has 4 attributes and the verifier wants to
     * disclose 2, the disclosed attributes will be the 3rd and 4th,
     * keeping hidden the 1st and 2nd.
     *
     * +---+---+---+---+
     * | 1 | 2 | 3 | 4 |
     * +---+---+---+---+
     * | H | H | D | D |
     * +---+---+---+---+
     */
    for (it = num_non_disclosed_attributes; it < attributes->num_attributes; it++)
    {
        attributes->attributes[it].disclosed = true;
    }

    lc = 0;

    // nonce
    memcpy(&data[lc], nonce, nonce_length);
    lc += NONCE_LENGTH;

    // epoch
    memcpy(&data[lc], epoch, epoch_length);
    lc += EPOCH_LENGTH;

    dwSendLength = sizeof(pbSendBuffer);
    r = apdu_build_command(CASE3, CLA_APPLICATION, INS_COMPUTE_PROOF_OF_KNOWLEDGE, num_non_disclosed_attributes, attributes->num_attributes, lc, data, 0, pbSendBuffer, &dwSendLength);
    if (r < 0)
    {
        return -1;
    }

    // proof of knowledge
    dwRecvLength = sizeof(pbRecvBuffer);
    r = sc_transmit_data(reader, pbSendBuffer, dwSendLength, pbRecvBuffer, &dwRecvLength, &elapsed_time);
    if (r < 0)
    {
        fprintf(stderr, "Error: %s\n", sc_get_error(r));
        return r;
    }

    printf("[!] Elapsed time (compute_proof_of_knowledge) = %f\n", elapsed_time);

    /// get user pi
    data_length = SHA_DIGEST_LENGTH + 2 * sizeof(elliptic_curve_multiplier_t) + 2 * sizeof(elliptic_curve_fr_t) + // e + s_v + s_i + s_e1 + s_e2 +
            sizeof(elliptic_curve_fr_t) + (attributes->num_attributes - num_disclosed_attributes) * sizeof(elliptic_curve_fr_t); // s_mr + s_mz non-disclosed attributes

    // calculate how many data transmissions are necessary
    transmissions = data_length / MAX_APDU_SEND_SIZE_T0 + (data_length % MAX_APDU_SEND_SIZE_T0 > 0 ? 1 : 0);

    offset = 0;
    le = (MAX_APDU_SEND_SIZE_T0 < data_length ? MAX_APDU_SEND_SIZE_T0 : data_length);
    for (it = 0; it < transmissions; it++)
    {
        dwSendLength = sizeof(pbSendBuffer);
        r = apdu_build_command(CASE2, CLA_APPLICATION, INS_GET_PROOF_OF_KNOWLEDGE, 0x01, transmissions, 0, NULL, le, pbSendBuffer, &dwSendLength);
        if (r < 0)
        {
            return -1;
        }

        dwRecvLength = sizeof(pbRecvBuffer);
        r = sc_transmit_data(reader, pbSendBuffer, dwSendLength, pbRecvBuffer, &dwRecvLength, &elapsed_time);
        if (r < 0)
        {
            fprintf(stderr, "Error: %s\n", sc_get_error(r));
            return r;
        }

        printf("[!] Elapsed time (communication_proof_of_knowledge) = %f\n", elapsed_time);

        // expected length
        assert(dwRecvLength == le + 2);

        // copy received data
        memcpy((void *) &data[offset], (const void *) pbRecvBuffer, dwRecvLength - 2);

        offset += le;
        data_length -= le; // subtract the amount of data to be received
        le = (data_length > MAX_APDU_SEND_SIZE_T0 ? MAX_APDU_SEND_SIZE_T0 : data_length);
    }

    /// get user credential
    data_length = 6 * sizeof(elliptic_curve_point_t); // sigma_hat, sigma_hat_e1, sigma_hat_e2, sigma_minus_e1, sigma_minus_e2, pseudonym

    // calculate how many data transmissions are necessary
    transmissions = data_length / MAX_APDU_SEND_SIZE_T0 + (data_length % MAX_APDU_SEND_SIZE_T0 > 0 ? 1 : 0);

    le = (MAX_APDU_SEND_SIZE_T0 < data_length ? MAX_APDU_SEND_SIZE_T0 : data_length);
    for (it = 0; it < transmissions; it++)
    {
        dwSendLength = sizeof(pbSendBuffer);
        r = apdu_build_command(CASE2, CLA_APPLICATION, INS_GET_PROOF_OF_KNOWLEDGE, 0x02, transmissions, 0, NULL, le, pbSendBuffer, &dwSendLength);
        if (r < 0)
        {
            return -1;
        }

        dwRecvLength = sizeof(pbRecvBuffer);
        r = sc_transmit_data(reader, pbSendBuffer, dwSendLength, pbRecvBuffer, &dwRecvLength, &elapsed_time);
        if (r < 0)
        {
            fprintf(stderr, "Error: %s\n", sc_get_error(r));
            return r;
        }

        printf("[!] Elapsed time (communication_proof_of_knowledge) = %f\n", elapsed_time);

        // expected length
        assert(dwRecvLength == le + 2);

        // copy received data
        memcpy((void *) &data[offset], (const void *) pbRecvBuffer, dwRecvLength - 2);

        offset += le;
        data_length -= le; // subtract the amount of data to be received
        le = (data_length > MAX_APDU_SEND_SIZE_T0 ? MAX_APDU_SEND_SIZE_T0 : data_length);
    }

    data_length = 0;

    /// e <-- H(...)
    memcpy(&hash[SHA_DIGEST_PADDING], &data[data_length], SHA_DIGEST_LENGTH);
    multos_Fr_to_mcl_Fr(&pi->e, hash, sizeof(elliptic_curve_fr_t));
    r = mclBnFr_isValid(&pi->e);
    if (r != 1)
    {
        return -1;
    }
    data_length += SHA_DIGEST_LENGTH;

    /// s values
    // s_v
    multos_Multiplier_to_mcl_Fr(&pi->s_v, &data[data_length], sizeof(elliptic_curve_multiplier_t));
    r = mclBnFr_isValid(&pi->s_v);
    if (r != 1)
    {
        return -1;
    }
    data_length += sizeof(elliptic_curve_multiplier_t);

    // s_i
    multos_Multiplier_to_mcl_Fr(&pi->s_i, &data[data_length], sizeof(elliptic_curve_multiplier_t));
    r = mclBnFr_isValid(&pi->s_i);
    if (r != 1)
    {
        return -1;
    }
    data_length += sizeof(elliptic_curve_multiplier_t);

    // s_e1
    multos_Fr_to_mcl_Fr(&pi->s_e1, &data[data_length], sizeof(elliptic_curve_fr_t));
    r = mclBnFr_isValid(&pi->s_e1);
    if (r != 1)
    {
        return -1;
    }
    data_length += sizeof(elliptic_curve_fr_t);

    // s_e2
    multos_Fr_to_mcl_Fr(&pi->s_e2, &data[data_length], sizeof(elliptic_curve_fr_t));
    r = mclBnFr_isValid(&pi->s_e2);
    if (r != 1)
    {
        return -1;
    }
    data_length += sizeof(elliptic_curve_fr_t);

    // s_mr
    multos_Fr_to_mcl_Fr(&pi->s_mr, &data[data_length], sizeof(elliptic_curve_fr_t));
    r = mclBnFr_isValid(&pi->s_mr);
    if (r != 1)
    {
        return -1;
    }
    data_length += sizeof(elliptic_curve_fr_t);

    // s_mz non-disclosed attributes
    for (it = 0; it < attributes->num_attributes; it++)
    {
        if (attributes->attributes[it].disclosed == false)
        {
            multos_Fr_to_mcl_Fr(&pi->s_mz[it], &data[data_length], sizeof(elliptic_curve_fr_t));
            r = mclBnFr_isValid(&pi->s_mz[it]);
            if (r != 1)
            {
                return -1;
            }
            data_length += sizeof(elliptic_curve_fr_t);
        }
    }

    /// signatures
    // sigma_hat
    multos_G1_to_mcl_G1(&credential->sigma_hat, &data[data_length], sizeof(elliptic_curve_point_t));
    r = mclBnG1_isValid(&credential->sigma_hat);
    if (r != 1)
    {
        return -1;
    }
    data_length += sizeof(elliptic_curve_point_t);

    // sigma_hat_e1
    multos_G1_to_mcl_G1(&credential->sigma_hat_e1, &data[data_length], sizeof(elliptic_curve_point_t));
    r = mclBnG1_isValid(&credential->sigma_hat_e1);
    if (r != 1)
    {
        return -1;
    }
    data_length += sizeof(elliptic_curve_point_t);

    // sigma_hat_e2
    multos_G1_to_mcl_G1(&credential->sigma_hat_e2, &data[data_length], sizeof(elliptic_curve_point_t));
    r = mclBnG1_isValid(&credential->sigma_hat_e2);
    if (r != 1)
    {
        return -1;
    }
    data_length += sizeof(elliptic_curve_point_t);

    // sigma_minus_e1
    multos_G1_to_mcl_G1(&credential->sigma_minus_e1, &data[data_length], sizeof(elliptic_curve_point_t));
    r = mclBnG1_isValid(&credential->sigma_minus_e1);
    if (r != 1)
    {
        return -1;
    }
    data_length += sizeof(elliptic_curve_point_t);

    // sigma_minus_e2
    multos_G1_to_mcl_G1(&credential->sigma_minus_e2, &data[data_length], sizeof(elliptic_curve_point_t));
    r = mclBnG1_isValid(&credential->sigma_minus_e2);
    if (r != 1)
    {
        return -1;
    }
    data_length += sizeof(elliptic_curve_point_t);

    // pseudonym
    multos_G1_to_mcl_G1(&credential->pseudonym, &data[data_length], sizeof(elliptic_curve_point_t));
    r = mclBnG1_isValid(&credential->pseudonym);
    if (r != 1)
    {
        return -1;
    }
    data_length += sizeof(elliptic_curve_point_t);

    // amount of data processed = amount of data received
    assert(data_length == offset);

    return 0;
}

/**
 * Gets and displays the proof of knowledge of the user attributes.
 *
 * @param reader the reader to be used
 * @return 0 if success else -1
 */
int ue_display_proof_of_knowledge(reader_t reader)
{
    uint8_t pbSendBuffer[MAX_APDU_LENGTH_T0] = {0};
    uint8_t pbRecvBuffer[MAX_APDU_LENGTH_T0] = {0};
    uint32_t dwSendLength;
    uint32_t dwRecvLength;

    char *proof_of_knowledge_values[11] = {
            "t_verify", "t_revoke", "t_sig", "t_sig1", "t_sig2",
            "sigma_hat", "sigma_hat_e1", "sigma_hat_e2", "sigma_minus_e1", "sigma_minus_e2",
            "pseudonym"
    };

    mclBnG1 point;

    size_t it;
    int r;

    for (it = 0; it < 0x0B; it++)
    {
        dwSendLength = sizeof(pbSendBuffer);
        r = apdu_build_command(CASE2, CLA_APPLICATION, CMD_TEST_GET_PROOF_OF_KNOWLEDGE, it + 1, 0x0B, 0, NULL, sizeof(elliptic_curve_point_t), pbSendBuffer, &dwSendLength);
        if (r < 0)
        {
            return -1;
        }

        dwRecvLength = sizeof(pbRecvBuffer);
        r = sc_transmit_data(reader, pbSendBuffer, dwSendLength, pbRecvBuffer, &dwRecvLength, NULL);
        if (r < 0)
        {
            fprintf(stderr, "Error: %s\n", sc_get_error(r));
            return r;
        }

        multos_G1_to_mcl_G1(&point, pbRecvBuffer, sizeof(elliptic_curve_point_t));
        r = mclBnG1_isValid(&point);
        if (r != 1)
        {
            fprintf(stderr, "proof_of_knowledge[%lu].%s\n", it, proof_of_knowledge_values[it]);
            return -1;
        }
        mcl_display_G1(proof_of_knowledge_values[it], point);
    }

    return 0;
}
