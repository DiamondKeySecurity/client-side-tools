// Copyright (c) 2019  Diamond Key Security, NFP
 
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2
// of the License only.
 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
 
// You should have received a copy of the GNU General Public License
// along with this program; if not, If not, see <https://www.gnu.org/licenses/>.

// Script to import CrypTech code into DKS HSM folders.
//

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <string.h>
#include <termios.h>
#include <stdbool.h>
#include <poll.h>
#include <netinet/in.h>

#include <tls.h>

#include <dks.h>

#include <hal.h>

#define hal_check(_expr_)            ((_expr_) == HAL_OK)

int main(int argc, char **argv)
{
    /*
    * Use dks tools to get the address of the HSM we need to connect to
    */
    hsm_info_t *hsm_info = NULL;
    if (HSMCONF_OK != LoadHSMInfo(&hsm_info, HSM_PORT_RPC))
    {
        printf("\nUnable to connect locate HSM configuration file\n");
        return 0;
    }

    if (!hal_check(hal_rpc_client_transport_init_ip(hsm_info->ip_addr, hsm_info->servername)))
    {
        printf("\nUnable to connect to HSM '%s' at '%s'\n", hsm_info->ip_addr, hsm_info->servername);
        return 0;
    }
    else
    {
        FreeHSMInfo(&hsm_info);
    }

    hal_rpc_client_close();
}