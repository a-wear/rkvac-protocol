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

#include <stdio.h>

#include <getopt.h>

#include "system.h"
#include "setup.h"

#include "controllers/issuer.h"
#include "controllers/revocation-authority.h"

#if defined (RKVAC_PROTOCOL_MULTOS)
# include "multos/apdu.h"
# include "pcsc/reader.h"
# include "controllers/multos/user.h"
#else
# include "controllers/user.h"
#endif

#include "controllers/verifier.h"

static struct option long_options[] = {
        {"attributes",           required_argument, 0, 'a'},
        {"disclosed-attributes", required_argument, 0, 'd'},
        {"help",                 no_argument,       0, 'h'},
        {0, 0, 0, 0}
};

int main(int argc, char *argv[])
{
    system_par_t sys_parameters = {0};

    revocation_authority_par_t ra_parameters = {0};
    revocation_authority_keys_t ra_keys = {0};
    revocation_authority_signature_t ra_signature = {0};

    issuer_par_t ie_parameters = {0};
    issuer_keys_t ie_keys = {0};
    issuer_signature_t ie_signature = {0};

    user_identifier_t ue_identifier = {0};
    user_attributes_t ue_attributes = {0};

    size_t num_disclosed_attributes;
    user_credential_t ue_credential = {0};
    user_pi_t ue_pi = {0};

    uint8_t nonce[NONCE_LENGTH] = {0};
    uint8_t epoch[EPOCH_LENGTH] = {0};

    int opt;
    int r;

#if defined (RKVAC_PROTOCOL_MULTOS)
    uint8_t pbRecvBuffer[MAX_APDU_LENGTH_T0] = {0};
    uint32_t dwRecvLength;
    reader_t reader;
#else
    reader_t reader = NULL;
#endif

    // default (num_attributes, num_disclosed_attributes)
    ue_attributes.num_attributes = USER_MAX_NUM_ATTRIBUTES;
    num_disclosed_attributes = 0;

    while ((opt = getopt_long(argc, argv, "a:d:h", long_options, NULL)) != -1)
    {
        switch (opt)
        {
            case 'a':
            {
                ue_attributes.num_attributes = strtol(optarg, NULL, 10);

                break;
            }
            case 'd':
            {
                num_disclosed_attributes = strtol(optarg, NULL, 10);

                break;
            }
            case 'h':
            {
                fprintf(stderr, "Usage: %s --attributes=<XX> --disclosed-attributes=<XX>\n", argv[0]);

                exit(0);
            }
            default:
            {
                break;
            }
        }
    }

    // check num_attributes
    if (ue_attributes.num_attributes == 0 || ue_attributes.num_attributes > USER_MAX_NUM_ATTRIBUTES)
    {
        fprintf(stderr, "Error: invalid number of user attributes! (1-9)\n");
        return 1;
    }
    // check num_disclosed_attributes
    if (num_disclosed_attributes > ue_attributes.num_attributes)
    {
        fprintf(stderr, "Error: the number of disclosed attributes is greater than the number of user attributes! (0-%lu)\n", ue_attributes.num_attributes);
        return 1;
    }

#if defined (RKVAC_PROTOCOL_MULTOS)
    r = sc_get_card_connection(&reader);
    if (r < 0)
    {
        fprintf(stderr, "Error: %s\n", sc_get_error(r));
        return 1;
    }

# ifndef NDEBUG
    fprintf(stdout, "[-] Command: APDU_SCARD_SELECT_APPLICATION\n");
# endif

    dwRecvLength = sizeof(pbRecvBuffer);
    r = sc_transmit_data(reader, APDU_SCARD_SELECT_APPLICATION, sizeof(APDU_SCARD_SELECT_APPLICATION), pbRecvBuffer, &dwRecvLength, NULL);
    if (r < 0)
    {
        fprintf(stderr, "Error: %s\n", sc_get_error(r));
        return 1;
    }
#endif

    printf("[!] Disclosed attributes: %lu\n", num_disclosed_attributes);
    printf("[!] Number of user attributes: %lu\n", ue_attributes.num_attributes);

    // system - setup
    r = sys_setup(&sys_parameters);
    if (r < 0)
    {
        fprintf(stderr, "Error: cannot initialize the system!\n");
        return 1;
    }

    // user - get user identifier
    r = ue_get_user_identifier(reader, &ue_identifier);
    if (r < 0)
    {
        fprintf(stderr, "Error: cannot get the user identifier!\n");
        return 1;
    }

    // revocation authority - setup
    r = ra_setup(sys_parameters, &ra_parameters, &ra_keys);
    if (r < 0)
    {
        fprintf(stderr, "Error: cannot initialize the revocation authority!\n");
        return 1;
    }

    // revocation authority - mac
    r = ra_mac(sys_parameters, ra_keys.private_key, ue_identifier, &ra_signature);
    if (r < 0)
    {
        fprintf(stderr, "Error: cannot compute the revocation authority MAC!\n");
        return 1;
    }

    // user - set revocation authority data
    r = ue_set_revocation_authority_data(reader, ra_parameters, ra_signature);
    if (r < 0)
    {
        fprintf(stderr, "Error: cannot set the revocation authority data!\n");
        return 1;
    }

    // user - set user attributes
    r = ue_set_user_attributes(reader, ue_attributes.num_attributes);
    if (r < 0)
    {
        fprintf(stderr, "Error: cannot set the user attributes!\n");
        return 1;
    }

    // user - get user attributes and identifier
    r = ue_get_user_attributes_identifier(reader, &ue_attributes, &ue_identifier, &ra_signature);
    if (r < 0)
    {
        fprintf(stderr, "Error: cannot get the user information!\n");
        return 1;
    }

    // issuer - setup
    ie_parameters.num_attributes = ue_attributes.num_attributes;
    r = ie_setup(ie_parameters, &ie_keys);
    if (r < 0)
    {
        fprintf(stderr, "Error: cannot initialize the issuer!\n");
        return 1;
    }

    // issuer - user attributes signature
    r = ie_issue(sys_parameters, ie_parameters, ie_keys, ue_identifier, ue_attributes, ra_keys.public_key, ra_signature, &ie_signature);
    if (r < 0)
    {
        fprintf(stderr, "Error: cannot compute the user attributes signature!\n");
        return 1;
    }

    // user - set issuer signature of the user's attributes
    r = ue_set_issuer_signatures(reader, ie_parameters, ie_signature);
    if (r < 0)
    {
        fprintf(stderr, "Error: cannot set the issuer signature of the user's attributes!\n");
        return 1;
    }

    // verifier - generate nonce and epoch
    r = ve_generate_nonce_epoch(nonce, sizeof(nonce), epoch, sizeof(epoch));
    if (r < 0)
    {
        fprintf(stderr, "Error: cannot generate nonce or epoch!\n");
        return 1;
    }

#ifndef NDEBUG
    fprintf(stdout, "[+] user - compute proof of knowledge\n");
#endif

    // user - compute proof of knowledge
    r = ue_compute_proof_of_knowledge(reader, sys_parameters, ra_parameters, ra_signature, ie_signature, 0, 0, nonce, sizeof(nonce), epoch, sizeof(epoch), &ue_attributes, num_disclosed_attributes, &ue_credential, &ue_pi);
    if (r < 0)
    {
        fprintf(stderr, "Error: cannot compute the user proof of knowledge!\n");
        return 1;
    }

#ifndef NDEBUG
    // user - display proof of knowledge
    r = ue_display_proof_of_knowledge(reader);
    if (r < 0)
    {
        fprintf(stderr, "Error: cannot display the user proof of knowledge!\n");
        return 1;
    }

    fprintf(stdout, "\n");
#endif

#ifndef NDEBUG
    fprintf(stdout, "[+] verifier - verify proof of knowledge\n");
#endif

    // verifier - verify proof of knowledge
    r = ve_verify_proof_of_knowledge(sys_parameters, ra_parameters, ra_keys.public_key, ie_keys, nonce, sizeof(nonce), epoch, sizeof(epoch), ue_attributes, ue_credential, ue_pi);
    if (r < 0)
    {
        fprintf(stderr, "Error: cannot verify the user proof of knowledge!\n");
        return 1;
    }

#if defined (RKVAC_PROTOCOL_MULTOS)
    sc_cleanup(reader);
#endif

    fprintf(stdout, "OK!\n");

    return 0;
}
