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

#ifndef __RKVAC_PROTOCOL_MODEL_USER_H_
#define __RKVAC_PROTOCOL_MODEL_USER_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <mcl/bn_c256.h>

#include "config/config.h"

typedef struct
{
    uint8_t buffer[USER_MAX_ID_LENGTH];
    size_t buffer_length;
} user_identifier_t;

typedef struct
{
    struct attribute_t
    {
        uint8_t value[EC_SIZE];
        bool disclosed;
    } attributes[USER_MAX_NUM_ATTRIBUTES];
    size_t num_attributes;
} user_attributes_t;

typedef struct
{
    mclBnG1 pseudonym; // C
    mclBnG1 sigma_hat;
    mclBnG1 sigma_hat_e1;
    mclBnG1 sigma_hat_e2;
    mclBnG1 sigma_minus_e1;
    mclBnG1 sigma_minus_e2;
} user_credential_t;

typedef struct
{
    mclBnFr e;
    mclBnFr s_mz[USER_MAX_NUM_ATTRIBUTES]; // s_mz non-disclosed attributes
    mclBnFr s_v;
    mclBnFr s_mr;
    mclBnFr s_i;
    mclBnFr s_e1;
    mclBnFr s_e2;
} user_pi_t;

#ifdef __cplusplus
}
#endif

#endif /* __RKVAC_PROTOCOL_MODEL_USER_H_ */
