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

#ifndef __RKVAC_PROTOCOL_CONTROLLER_USER_H_
#define __RKVAC_PROTOCOL_CONTROLLER_USER_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <mcl/bn_c256.h>
#include <openssl/sha.h>

#include "config/config.h"

#include "models/issuer.h"
#include "models/revocation-authority.h"
#include "models/user.h"
#include "system.h"

#include "helpers/mcl_helper.h"

#include "attributes.h"

typedef void *reader_t;

/**
 * Gets the user identifier using the specified reader.
 *
 * @param reader the reader to be used
 * @param identifier the user identifier
 * @return 0 if success else -1
 */
extern int ue_get_user_identifier(reader_t reader, user_identifier_t *identifier);

/**
 * Sets the revocation authority parameters and the revocation attributes.
 *
 * @param reader the reader to be used
 * @param ra_parameters the revocation authority parameters
 * @param ra_signature the signature of the user identifier
 * @return 0 if success else -1
 */
extern int ue_set_revocation_authority_data(reader_t reader, revocation_authority_par_t ra_parameters, revocation_authority_signature_t ra_signature);

/**
 * Sets the user attributes using the specified reader.
 *
 * @param reader the reader to be used
 * @param num_attributes the number of the user attributes
 * @return 0 if success else -1
 */
extern int ue_set_user_attributes(reader_t reader, size_t num_attributes);

/**
 * Gets the user attributes and identifier using the specified reader.
 *
 * @param reader the reader to be used
 * @param attributes the user attributes
 * @param identifier the user identifier
 * @param ra_signature the signature of the user identifier
 * @return 0 if success else -1
 */
extern int ue_get_user_attributes_identifier(reader_t reader, user_attributes_t *attributes, user_identifier_t *identifier, revocation_authority_signature_t *ra_signature);

/**
 * Sets the issuer signatures of the user's attributes.
 *
 * @param reader the reader to be used
 * @param ie_parameters the issuer parameters
 * @param ie_signature the issuer signature
 * @return 0 if success else -1
 */
extern int ue_set_issuer_signatures(reader_t reader, issuer_par_t ie_parameters, issuer_signature_t ie_signature);

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
extern int ue_compute_proof_of_knowledge(reader_t reader, system_par_t sys_parameters, revocation_authority_par_t ra_parameters, revocation_authority_signature_t ra_signature,
                                         issuer_signature_t ie_signature, uint8_t I, uint8_t II, const void *nonce, size_t nonce_length, const void *epoch, size_t epoch_length,
                                         user_attributes_t *attributes, size_t num_disclosed_attributes, user_credential_t *credential, user_pi_t *pi);

/**
 * Gets and displays the proof of knowledge of the user attributes.
 *
 * @param reader the reader to be used
 * @return 0 if success else -1
 */
extern int ue_display_proof_of_knowledge(reader_t reader);

#ifdef __cplusplus
}
#endif

#endif /* __RKVAC_PROTOCOL_CONTROLLER_USER_H_ */
