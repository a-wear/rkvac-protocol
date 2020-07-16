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

#ifndef __RKVAC_PROTOCOL_MODEL_REVOCATION_AUTHORITY_H_
#define __RKVAC_PROTOCOL_MODEL_REVOCATION_AUTHORITY_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>

#include <mcl/bn_c256.h>

#include "config/config.h"

typedef struct
{
    size_t k, j;

    mclBnFr alphas[REVOCATION_AUTHORITY_VALUE_J]; // alpha_j
    mclBnG1 alphas_mul[REVOCATION_AUTHORITY_VALUE_J]; // h_j = G1 * alpha_j

    mclBnFr randomizers[REVOCATION_AUTHORITY_VALUE_K];  // e_k
    mclBnG1 randomizers_sigma[REVOCATION_AUTHORITY_VALUE_K]; // sigma_e_k
} revocation_authority_par_t;

typedef struct
{
    mclBnFr sk;
} revocation_authority_private_key_t;

typedef struct
{
    mclBnG2 pk;
} revocation_authority_public_key_t;

typedef struct
{
    revocation_authority_private_key_t private_key;
    revocation_authority_public_key_t public_key;
} revocation_authority_keys_t;

typedef struct
{
    mclBnFr mr;
    mclBnG1 sigma;
} revocation_authority_signature_t;

#ifdef __cplusplus
}
#endif

#endif /* __RKVAC_PROTOCOL_MODEL_REVOCATION_AUTHORITY_H_ */
