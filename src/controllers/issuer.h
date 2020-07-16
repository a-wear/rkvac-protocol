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

#ifndef __RKVAC_PROTOCOL_CONTROLLER_ISSUER_H_
#define __RKVAC_PROTOCOL_CONTROLLER_ISSUER_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>
#include <string.h>
#include <assert.h>

#include <mcl/bn_c256.h>
#include <openssl/sha.h>

#include "config/config.h"

#include "models/issuer.h"
#include "models/revocation-authority.h"
#include "models/user.h"
#include "system.h"

#include "helpers/mcl_helper.h"

/**
 * Outputs the issuer parameters, generates the private keys.
 *
 * @param parameters the issuer parameters
 * @param keys the issuer private keys
 * @return 0 if success else -1
 */
extern int ie_setup(issuer_par_t parameters, issuer_keys_t *keys);

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
extern int ie_issue(system_par_t sys_parameters, issuer_par_t parameters, issuer_keys_t keys, user_identifier_t ue_identifier, user_attributes_t ue_attributes,
                    revocation_authority_public_key_t revocation_authority_public_key, revocation_authority_signature_t revocation_authority_signature,
                    issuer_signature_t *signature);

#ifdef __cplusplus
}
#endif

#endif /* __RKVAC_PROTOCOL_CONTROLLER_ISSUER_H_ */
