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

#ifndef __RKVAC_PROTOCOL_HASH_HELPER_H_
#define __RKVAC_PROTOCOL_HASH_HELPER_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>
#include <string.h>

#include <mcl/bn_c256.h>

#include "helpers/mcl_helper.h"
#include "types.h"

/**
 * Gets the size of a elliptic curve point depending on the
 * platform for which the software has been compiled.
 *
 * @return the size of the point
 */
extern size_t digest_get_platform_point_size(void);

/**
 * Gets the data of a elliptic curve point depending on the
 * platform for which the software has been compiled.
 *
 * @param buffer the buffer where the point conversion will be stored
 * @param x mclBnG1 data
 * @return pointer to the buffer or NULL if error
 */
extern void *digest_get_platform_point_data(void *buffer, mclBnG1 x);

#ifdef __cplusplus
}
#endif

#endif /* __RKVAC_PROTOCOL_HASH_HELPER_H_ */
