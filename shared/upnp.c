#include <stddef.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/netdevice.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/miniwget.h>
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/portlistingparse.h>
#include <miniupnpc/upnperrors.h>

#include "log.h"


/**
 * @brief We currently determine a valid IP address to be an IP 
 * that is starting with 192.
 * 
 * This could be done a lot better.. such as checking we are on the right network interface
 * rather than relying on checking IP addresses.
 * @param ip 
 * @return true 
 * @return false 
 */
bool upnp_ip_valid_for_forward(const char* ip)
{
    if (ip[0] == '1' && ip[1] == '2')
    {
        return false;
    }

    return ip[0] != '0';
}

int interface_my_ip_find(char *addr_out)
{
    int s;
    int res = 0;
    struct ifconf ifconf;
    struct ifreq ifr[50];
    int ifs;
    int i;

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
    {
        res = -1;
        goto out;
    }

    ifconf.ifc_buf = (char *)ifr;
    ifconf.ifc_len = sizeof ifr;

    if (ioctl(s, SIOCGIFCONF, &ifconf) == -1)
    {
        res = -1;
        goto out;
    }

    ifs = ifconf.ifc_len / sizeof(ifr[0]);
    for (i = 0; i < ifs; i++)
    {
        char ip[INET_ADDRSTRLEN];
        struct sockaddr_in *s_in = (struct sockaddr_in *)&ifr[i].ifr_addr;

        if (!inet_ntop(AF_INET, &s_in->sin_addr, ip, sizeof(ip)))
        {
            res = -1;
            goto out;
        }

        // Right now we ignore 0 and 1 starts to avoid ip such as
        // 127.0.0.1 and 0.0.0.0 .. THis is not a clever way to resolve the local IP
        // and there are better ways, but this is a fail safe in the event
        // UPNP fails on us..
        if (upnp_ip_valid_for_forward(ip))
        {
            strncpy(addr_out, ip, sizeof(ip));
            res = 0;
            break;
        }
    }

out:
    if (s)
    {
        close(s);
    }
    return res;
}

int upnp_get_my_local_ip(char *lanaddr_out)
{
    if (!lanaddr_out)
    {
        return -1;
    }

    // Not NULL? Then its already been set.
    if (lanaddr_out[0])
    {
        return 0;
    }

    // NULL bytes?? Then UPNP Local IP Lookup failed.. We are going to have to
    // find it another way
    return interface_my_ip_find(lanaddr_out);
}

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
    int res = 0;
    struct UPNPDev *devlist = NULL;
    devlist = upnpDiscover(2000, "", "", UPNP_LOCAL_PORT_ANY, 0, 2, &res);
    if (!devlist)
    {
        // No UPNP devices were discovered, let us hope they are not behind a router
        // as they will struggle to use the network properly.
        res = -1;
        goto out;
    }

    struct UPNPDev *device = NULL;
    for (device = devlist; device; device = device->pNext)
    {
        struct UPNPUrls urls;
        struct IGDdatas data;
        char lanaddr[64] = {};
        char externalIpAddress[40] = {};

        int i = UPNP_GetValidIGD(devlist, &urls, &data, lanaddr, sizeof(lanaddr));
        if (i < 0)
        {
            break;
        }

        // Let's set our LAN address based on UPNP response or alternatively
        // interface lookup if the UPNP failed..
        i = upnp_get_my_local_ip(lanaddr);
        if (i < 0)
        {
            giveme_log("%s We still failed to find our LOCAL ip address.. UPNP port forward will not be possible\n", __FUNCTION__);
            res = -1;
            goto out;
        }

        i = UPNP_GetExternalIPAddress(urls.controlURL,
	                          data.first.servicetype,
							  externalIpAddress);
        if (i < 0)
        {
            giveme_log("%s failed to find our external IP address. We can't UPNP without that\n", __FUNCTION__);
            res = -1;
            goto out;
        }


        char port_l[6] = {0};
        char port_p[6] = {0};
        sprintf(port_l, "%i", localPort);
        sprintf(port_p, "%i", publicPort);

        SetRedirectAndTest(&urls, &data, lanaddr, port_l, port_p, "tcp", "14400",externalIpAddress, "Rhythm Network", 0);
        FreeUPNPUrls(&urls);
    }

out:
    return res;
}
