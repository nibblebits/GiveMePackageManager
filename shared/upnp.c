#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/miniwget.h>
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/portlistingparse.h>
#include <miniupnpc/upnperrors.h>

#include <stddef.h>
#include <stdio.h>

#include <stddef.h>
/* Test function
 * 1 - get connection type
 * 2 - get extenal ip address
 * 3 - Add port mapping
 * 4 - get this port mapping from the IGD */
static int SetRedirectAndTest(struct UPNPUrls *urls,
                              struct IGDdatas *data,
                              const char *iaddr,
                              const char *iport,
                              const char *eport,
                              const char *proto,
                              const char *leaseDuration,
                              const char *remoteHost,
                              const char *description,
                              int addAny)
{
    char externalIPAddress[40];
    char intClient[40];
    char intPort[6];
    char reservedPort[6];
    char duration[16];
    int r;

    if (!iaddr || !iport || !eport || !proto)
    {
        return -1;
    }
    if (!proto)
    {
        return -1;
    }

    r = UPNP_GetExternalIPAddress(urls->controlURL,
                                  data->first.servicetype,
                                  externalIPAddress);
    if (addAny)
    {
        r = UPNP_AddAnyPortMapping(urls->controlURL, data->first.servicetype,
                                   eport, iport, iaddr, description,
                                   proto, remoteHost, leaseDuration, reservedPort);
        if (r == UPNPCOMMAND_SUCCESS)
            eport = reservedPort;

    }
    else
    {
        r = UPNP_AddPortMapping(urls->controlURL, data->first.servicetype,
                                eport, iport, iaddr, description,
                                proto, remoteHost, leaseDuration);
        if (r != UPNPCOMMAND_SUCCESS)
        {
            return -2;
        }
    }

    r = UPNP_GetSpecificPortMappingEntry(urls->controlURL,
                                         data->first.servicetype,
                                         eport, proto, remoteHost,
                                         intClient, intPort, NULL /*desc*/,
                                         NULL /*enabled*/, duration);
    if (r != UPNPCOMMAND_SUCCESS)
    {
        return -2;
    }

    return 0;
}

int upnp_redirect(int localPort, int publicPort)
{
    int error = 0;
    struct UPNPDev *devlist = NULL;
    devlist = upnpDiscover(2000, "", "", UPNP_LOCAL_PORT_ANY, 0, 2, &error);
    if (!devlist)
    {
        // No UPNP devices were discovered, let us hope they are not behind a router
        // as they will struggle to use the network properly.
        return -1;
    }

    struct UPNPDev *device = NULL;
    for (device = devlist; device; device = device->pNext)
    {
        struct UPNPUrls urls;
        struct IGDdatas data;
        char lanaddr[64] = "unset"; /* my ip address on the LAN */

        int i = UPNP_GetValidIGD(devlist, &urls, &data, lanaddr, sizeof(lanaddr));
        if (i < 0)
        {
            break;
        }
     
        char port_l[6] = {0};
        char port_p[6] = {0};
        sprintf(port_l, "%i", localPort);
        sprintf(port_p, "%i", publicPort);

        SetRedirectAndTest(&urls, &data, lanaddr, port_l, port_p, "tcp", "14400", "", "Rhythm Network", 1);
        FreeUPNPUrls(&urls);
    }

    return 0;
}

