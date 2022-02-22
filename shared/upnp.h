#ifndef GIVEME_UPNP_H
#define GIVEME_UPNP_H

/**
 * @brief Port forwards the public port to the local port on the router for the current local ip address
 * @param localPort 
 * @param publicPort 
 * @return int 
 */
int upnp_redirect(int localPort, int publicPort);

#endif
