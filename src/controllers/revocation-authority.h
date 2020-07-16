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

#ifndef __RKVAC_PROTOCOL_CONTROLLER_REVOCATION_AUTHORITY_H_
#define __RKVAC_PROTOCOL_CONTROLLER_REVOCATION_AUTHORITY_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>
#include <assert.h>

#include <mcl/bn_c256.h>
#include <openssl/sha.h>

#include "config/config.h"

#include "models/revocation-authority.h"
#include "models/user.h"
#include "system.h"

#include "helpers/mcl_helper.h"

/**
 * Outputs the revocation authority parameters, generates the
 * private key and computes the public key.
 *
 * @param sys_parameters the system parameters
 * @param parameters the revocation authority parameters
 * @param keys the revocation authority private and public keys
 * @return 0 if success else -1
 */
extern int ra_setup(system_par_t sys_parameters, revocation_authority_par_t *parameters, revocation_authority_keys_t *keys);

/**
 * Computes the signature of the user identifier using the private key.
 *
 * @param sys_parameters the system parameters
 * @param private_key the revocation authority private key
 * @param ue_identifier the user identifier
 * @param signature the signature of the user identifier
 * @return 0 if success else -1
 */
extern int ra_mac(system_par_t sys_parameters, revocation_authority_private_key_t private_key, user_identifier_t ue_identifier, revocation_authority_signature_t *signature);

#ifdef __cplusplus
}
#endif

#endif /* __RKVAC_PROTOCOL_CONTROLLER_REVOCATION_AUTHORITY_H_ */
