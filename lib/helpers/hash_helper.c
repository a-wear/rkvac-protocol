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

#include "hash_helper.h"

/**
 * Gets the size of a elliptic curve point depending on the
 * platform for which the software has been compiled.
 *
 * @return the size of the point
 */
size_t digest_get_platform_point_size(void)
{
#if defined (RKVAC_PROTOCOL_MULTOS)
    return sizeof(elliptic_curve_point_t);
#else
    return sizeof(mclBnG1);
#endif
}

/**
 * Gets the data of a elliptic curve point depending on the
 * platform for which the software has been compiled.
 *
 * @param buffer the buffer where the point conversion will be stored
 * @param x mclBnG1 data
 * @return pointer to the buffer or NULL if error
 */
void *digest_get_platform_point_data(void *buffer, mclBnG1 x)
{
    int r;

    if (buffer == NULL)
    {
        return NULL;
    }

#if defined (RKVAC_PROTOCOL_MULTOS)
    r = mcl_G1_to_multos_G1(buffer, sizeof(elliptic_curve_point_t), x);
#else
    memcpy(buffer, &x, sizeof(mclBnG1));
    r = 0;
#endif

    // avoid future errors
    if (r < 0)
    {
        buffer = NULL;
    }

    return buffer;
}
