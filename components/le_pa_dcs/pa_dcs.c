//--------------------------------------------------------------------------------------------------
/**
 * LWIP Data Connection Service Adapter
 * Provides adapter for linux specific functionality needed by dataConnectionService component
 *
 */
//--------------------------------------------------------------------------------------------------

#include "legato.h"
#include "interfaces.h"
#include "lwip/api.h"
#include "lwip/netif.h"
#include "lwip/dhcp.h"
#include "lwip/dns.h"
#include "lwip/netdb.h"
#include "lwip/prot/ip4_route.h"
#include "pa_dcs.h"


/**
 * TODO: This is most likely wrong - on linux
 *       side, we do not need masks when searching
 *       for routes. In LWIP, we do need masks and
 *       they are not provided by the caller
 */
#define IPV4_DEFAULT_MASK_STRING         "255.255.255.255"

/** Standard port for TIME protocol (RFC 868). */
#define TIME_PORT           37U

/** Unix Epoch in seconds since 00:00 Jan 1, 1900. */
#define TIME_OF_UNIX_EPOCH  2208988800UL

//--------------------------------------------------------------------------------------------------
/**
 * Used to set mask to /32 or /64
 *
 * @return
 *
 */
//--------------------------------------------------------------------------------------------------
static le_result_t SetMask
(
    ip_addr_t*    addressPtr,
    u8_t          type
)
{
    ip6_addr_t* ip6Ptr;
    ip4_addr_t* ip4Ptr;
    int         i;
    le_result_t retStat = LE_OK;

    memset(addressPtr, 0x00, sizeof(ip_addr_t));
    addressPtr->type = type;

    switch (addressPtr->type)
    {
    case IPADDR_TYPE_V4:
        ip4Ptr = &addressPtr->u_addr.ip4;
        ip4Ptr->addr = 0xFFFFFFFF;
        break;

    case IPADDR_TYPE_V6:
        ip6Ptr = &addressPtr->u_addr.ip6;
        for (i = 0; i < 4; i++)
        {
            ip6Ptr->addr[i] = 0xFFFFFFFF;
        }
        break;

    default:
        LE_ERROR("Invalid IP address type %d", addressPtr->type);
        retStat = LE_FAULT;
        break;
    }

    return retStat;
}

//--------------------------------------------------------------------------------------------------
/**
 * This function adds route
 *
 * @return
 *          LE_OK      succes
 *          LE_FAULT   failure
 *
 */
//--------------------------------------------------------------------------------------------------
static le_result_t AddRoute
(
    struct netif*     netifPtr,
    ip_addr_t*        destinationPtr
)
{
    le_result_t    retStat = LE_OK;
    ip_addr_t      mask;

    /**
     * Set mask depending on destination type
     */
    if (SetMask(&mask, destinationPtr->type) != LE_OK)
    {
        LE_ERROR("Failed to set the mask");
        return LE_FAULT;
    }

    switch (destinationPtr->type)
    {
    case IPADDR_TYPE_V4:
        if (ip4_add_route_entry(mask,
                                *destinationPtr,
                                netifPtr) != IP_ROUTE_OK)
        {
            retStat = LE_FAULT;
        }
        break;

    case IPADDR_TYPE_V6:
        if (ip6_add_route_entry(mask,
                                *destinationPtr,
                                netifPtr) != IP_ROUTE_OK)
        {
            retStat = LE_FAULT;
        }
        break;

    default:
        retStat = LE_FAULT;
        LE_ERROR("Invalid IP ADDR TYPE %" PRIu8, destinationPtr->type);
        break;
    }

    return retStat;
}

//--------------------------------------------------------------------------------------------------
/**
 * This function removes route
 *
 * @return
 *          LE_OK      succes
 *          LE_FAULT   failure
 *
 */
//--------------------------------------------------------------------------------------------------
static le_result_t RemoveRoute
(
    ip_addr_t*        destinationPtr
)
{
    le_result_t    retStat = LE_OK;
    ip_addr_t      mask;

    /**
     * Set proper mask depending on destination type
     */
    if (SetMask(&mask, destinationPtr->type) != LE_OK)
    {
        LE_ERROR("Failed to set the mask");
        return LE_FAULT;
    }

    switch (destinationPtr->type)
    {
    case IPADDR_TYPE_V4:
        if (ip4_remove_route_entry(mask,
                                *destinationPtr) != IP_ROUTE_OK)
        {
            retStat = LE_FAULT;
        }
        break;

    case IPADDR_TYPE_V6:
        if (ip6_remove_route_entry(mask,
                                *destinationPtr) != IP_ROUTE_OK)
        {
            retStat = LE_FAULT;
        }
        break;

    default:
        retStat = LE_FAULT;
        LE_ERROR("Invalid IP ADDR TYPE %" PRIu8, destinationPtr->type);
        break;
    }
    return retStat;
}


//--------------------------------------------------------------------------------------------------
/**
 * This function parses char address and determines
 * what type (V6 or V4) it is. The address can
 * be provided in the form of host name or legitimate
 * numeric IP address
 *
 * @return
 *          LE_OK      succes
 *          LE_FAULT   failure
 *
 */
//--------------------------------------------------------------------------------------------------
static le_result_t AddressStrToAddressStruct
(
    const char*          charAddress,     /// < [IN] address to analyze
    ip_addr_t*           retAddrInfoPtr   /// < [OUT] ret address info
)
{
    err_t stat;

    memset(retAddrInfoPtr, 0x00, sizeof(ip_addr_t));

    /**
     * See if DNS lookup is really needed, check
     * if this is legitimate numeric address first
     */
    if (ipaddr_aton(charAddress, retAddrInfoPtr) == 1)
    {
        return LE_OK;
    }

    /**
     * Have to do DNS lookup
     */
    stat = netconn_gethostbyname_addrtype(charAddress,
                                       retAddrInfoPtr,
                                       NETCONN_DNS_IPV4_IPV6,
                                       NULL);
    if (stat != ERR_OK)
    {
        LE_ERROR("Failed for charAddress=%s, stat=%d",
                 charAddress,
                 stat);
        return LE_FAULT;
    }

    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * This function converts ip_addr_t struct data to string
 * form of IP address (V4 or V6)
 *
 * @return
 *          IP address string      succes
 *          NULL                   failure
 *
 */
//--------------------------------------------------------------------------------------------------
static le_result_t  AddressStructToAddressStr
(
    ip_addr_t*       addrStructPtr,
    char*            addrBufferPtr,
    size_t           bufferLen
)
{
    le_result_t  retStat = LE_OK;

    addrBufferPtr[0] = '\0';

    switch (addrStructPtr->type)
    {
    case IPADDR_TYPE_V4:
        if (inet_ntoa_r(addrStructPtr->u_addr.ip4,
                        addrBufferPtr,
                        bufferLen) == NULL)
        {
            LE_ERROR("Failed to convert ip4 addr struct to string");
            retStat = LE_FAULT;
        }
        break;

    case IPADDR_TYPE_V6:
        if (inet6_ntoa_r(addrStructPtr->u_addr.ip6,
                         addrBufferPtr,
                         bufferLen) == NULL)
        {
            LE_ERROR("Failed to convert ip6 addr struct to string");
            retStat = LE_FAULT;
        }
        break;

    default:
        LE_ERROR("Invalid address type: %d", addrStructPtr->type);
        retStat = LE_FAULT;
        break;
    }

    LE_DEBUG("Converted address is %s", addrBufferPtr);

    return retStat;
}

//--------------------------------------------------------------------------------------------------
/**
 * Add the provided DNS configurations into /etc/resolv.conf. An empty string in any of the 2
 * input arguments means that it has no DNS address to add in that field. And this function's
 * caller should have blocked the case in having both inputs empty.
 *
 * @return
 *      LE_FAULT        Function failed
 *      LE_OK           Function succeed
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_dcs_SetDnsNameServers
(
    const char* dns1Ptr,    ///< [IN] Pointer to 1st DNS address; empty string means nothing to add
    const char* dns2Ptr,    ///< [IN] Pointer to 2nd DNS address; empty string means nothing to add
    bool* isDns1Added,      ///< [OUT] Whether the 1st DNS address is added or not
    bool* isDns2Added       ///< [OUT] Whether the 2nd DNS address is added or not
)
{
    const char*       dnsNameServerArray[2] = {dns1Ptr, dns2Ptr};
    ip_addr_t         retAddrStruct;
    le_result_t       stat;
    int               i, arrayLen;

    arrayLen = sizeof(dnsNameServerArray)/sizeof(const char*);

    for (i = 0; i < arrayLen; i++)
    {
        if('\0' != dnsNameServerArray[i][0])
        {
            stat = AddressStrToAddressStruct(dnsNameServerArray[i], &retAddrStruct);
            if (stat != LE_OK)
            {
                LE_WARN("Failed to convert address %d info for DNS Name Server: %s, state=%d", i,
                    dnsNameServerArray[i],
                    stat);
                *isDns1Added = false;
                *isDns2Added = false;
                return LE_FAULT;
            }
            else
            {
                dns_setserver(i, &retAddrStruct);
                *isDns1Added = ('\0' != dns1Ptr[0]);
                *isDns2Added = ('\0' != dns2Ptr[0]);
            }
        }
    }

    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * This function is only needed for WiFi client which is NOT part
 * for now of any LWIP based platform we use. Besides, LWIP dhcp (Altair)
 * is disabled  and we will hold of using AT client until we really need it.
 *
 *
 * @return
 *      - LE_OK     Function successful
 *      - LE_FAULT  Function failed
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_dcs_AskForIpAddress
(
    const char*    interfaceStrPtr
)
{
    LE_ERROR("Unsupported");
    return LE_FAULT;
}

//--------------------------------------------------------------------------------------------------
/**
 * Executes change route
 *
 * return
 *      LE_OK           Function succeed
 *      LE_FAULT        Function failed
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_dcs_ChangeRoute
(
    pa_dcs_RouteAction_t   routeAction,
    const char*            ipDestAddrStrPtr,
    const char*            prefixLengthPtr,
    const char*            interfaceStrPtr
)
{
    struct netif   *netIfPtr;
    le_result_t     retStat = LE_OK;
    ip_addr_t       destination;
    int             stat;

    switch (routeAction)
    {
    case PA_DCS_ROUTE_ADD:
        netIfPtr = netif_find(interfaceStrPtr);

        if (netIfPtr == NULL)
        {
            LE_ERROR("Failed to find network interface %s", interfaceStrPtr);
            retStat = LE_FAULT;
        } else {
            stat = AddressStrToAddressStruct(ipDestAddrStrPtr, &destination);
            if (stat != LE_OK)
            {
                LE_ERROR("Failed to convert destination address: %s, stat=%d",
                         ipDestAddrStrPtr,
                          stat);
                 retStat = LE_FAULT;
            } else {
                if (AddRoute(netIfPtr, &destination) != LE_OK)
                {
                    LE_ERROR("Failed to add destination=%s to netIf=%s",
                             ipDestAddrStrPtr,
                             interfaceStrPtr);
                    retStat = LE_FAULT;
                }
            }
        }
        break;

    case PA_DCS_ROUTE_DELETE:
        stat = AddressStrToAddressStruct(ipDestAddrStrPtr, &destination);

        if (stat != LE_OK)
        {
                LE_ERROR("Failed to convert destination address: %s, stat=%d",
                         ipDestAddrStrPtr,
                          stat);
                 retStat = LE_FAULT;
        } else {
            if (RemoveRoute(&destination) != LE_OK)
            {
                LE_ERROR("Failed to remove destination=%s", ipDestAddrStrPtr);
                retStat = LE_FAULT;
            }
        }
        break;

    default:
        LE_ERROR("Illegal routeAction=%d destination=%s interface=%s",
                 routeAction,
                 ipDestAddrStrPtr,
                 interfaceStrPtr);
        retStat = LE_FAULT;
        break;
    }

    return retStat;
}

//--------------------------------------------------------------------------------------------------
/**
 * Set the default gateway in the system
 *
 * return
 *      LE_OK           Function succeed
 *      LE_FAULT        Function failed
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_dcs_SetDefaultGateway
(
    const char* interfaceNamePtr,  ///< [IN] Pointer to the interface name
    const char* gatewayPtr,        ///< [IN] Pointer to the gateway name/address
    bool        isIpv6             ///< [IN] IPv6 or not
)
{
    struct netif*  netIfPtr;

    if (isIpv6)
    {
        /**
         *  TODO: Currently we have obsolete netif_set_gw()
         *        that only takes ip4_addr_t* (not ip_addr_t*)
         */
        LE_ERROR("Failed to set default gateway on interface %s, ipV6 not supported", interfaceNamePtr);

      return LE_FAULT;
    } else {
        /**
         * Just find the interface by the name
         */
        netIfPtr = netif_find(interfaceNamePtr);

        if (netIfPtr == NULL)
        {
           LE_ERROR("Failed to find network interface %s", interfaceNamePtr);
           return LE_FAULT;
        }

        /**
         *  gw has to be provided in form of ip_addr_t
         *  and we know this is IPv4
         */
        ip_addr_t gwAddr;

        inet_pton(AF_INET, gatewayPtr, &gwAddr);

        /**
         * Note: newer version of LWIP take
         *       ip_addr_t* as second argument -
         *       that way you can set IPv4 or IPv6
         *       but for now, ip4 is allwe have
         */
        netif_set_gw(netIfPtr, &gwAddr.u_addr.ip4);
    }

    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Save the default route
 */
//--------------------------------------------------------------------------------------------------
void pa_dcs_SaveDefaultGateway
(
    pa_dcs_DefaultGwBackup_t* defGwConfigBackupPtr
)
{
    char gwAddrStrBuffer[40];

    /**
     * There is no LWIP getter that gets netif_default
     * so, we need to use this extern variable
     */
    if (netif_default != NULL)
    {
        if (sizeof(netif_default->name) >=
               sizeof(defGwConfigBackupPtr->defaultV4Interface))
        {
            LE_ERROR("Insufficient size of default interface buffer: %" PRIu32 " ",
                     sizeof(defGwConfigBackupPtr->defaultV4Interface));
            return;
        }
        memset(defGwConfigBackupPtr->defaultV4Interface,
               0x00,
               sizeof(defGwConfigBackupPtr->defaultV4Interface));

        memset(defGwConfigBackupPtr->defaultV4GW,
               0x00,
               sizeof(defGwConfigBackupPtr->defaultV4GW));

        if (AddressStructToAddressStr(&(netif_default->gw),
                                      gwAddrStrBuffer,
                                      sizeof(gwAddrStrBuffer)) == LE_OK)
        {
            snprintf(defGwConfigBackupPtr->defaultV4GW,
                     sizeof(defGwConfigBackupPtr->defaultV4GW),
                     "%s",
                     gwAddrStrBuffer);
            /**
             * Interface name in struct netif is not nul terminated
             */
            memcpy(defGwConfigBackupPtr->defaultV4Interface,
                   netif_default->name,
                   sizeof(netif_default->name));
        } else {
            LE_ERROR("Failed to convert default gw address struct");
        }
    } else {
        LE_WARN("LWIP Default Gateway not set!!!");
    }
}

//--------------------------------------------------------------------------------------------------
/**
 * Used the data backup upon connection to remove DNS entries locally added
 */
//--------------------------------------------------------------------------------------------------
void pa_dcs_RestoreInitialDnsNameServers
(
    pa_dcs_DnsBackup_t* dnsConfigBackupPtr
)
{

    ip_addr_t         dnsIpAddr;
    const ip_addr_t*  currDnsPtr;
    int               i, j;
    char*             dnsNamePtr;
    char*       dnsPtrArray[4] = {
                                   dnsConfigBackupPtr->dnsIPv4[0],
                                   dnsConfigBackupPtr->dnsIPv4[1],
                                   dnsConfigBackupPtr->dnsIPv6[0],
                                   dnsConfigBackupPtr->dnsIPv6[1]
                                  };

    for (i = 0; i < sizeof(dnsPtrArray)/sizeof(char*); i++)
    {
        dnsNamePtr = dnsPtrArray[i];

        if (strlen(dnsNamePtr))
        {
            if (AddressStrToAddressStruct(dnsNamePtr, &dnsIpAddr) != LE_OK)
            {
                // Just log an error
                LE_ERROR("Failed to convert dns %s to struct", dnsNamePtr);
            } else {
                LE_INFO("Converted dns %s to struct", dnsNamePtr);

                /**
                 * Only dns Name servers at offset 0 and 1
                 * are used
                 */
                for (j = 0; j < 2; j++)
                {
                    currDnsPtr = dns_getserver(j);
                    /**
                     * ip_addr_cmp() returns 1 when identical!!!
                     */
                    if (ip_addr_cmp(&dnsIpAddr, currDnsPtr))
                    {
                        dns_setserver(j, IP_ADDR_ANY);
                        LE_INFO("Removed dns name server %s", dnsNamePtr);
                        dnsNamePtr[0] = '\0';
                        break;
                    }
                }
            }
        }
    }

    LE_INFO("Finished");
}

//--------------------------------------------------------------------------------------------------
/**
 * Retrieve time from a server using the Time Protocol.
 *
 * @return
 *      - LE_OK             Function successful
 *      - LE_BAD_PARAMETER  A parameter is incorrect
 *      - LE_FAULT          Function failed
 *      - LE_UNSUPPORTED    Function not supported by the target
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_dcs_GetTimeWithTimeProtocol
(
    const char* serverStrPtr,       ///< [IN]  Time server
    pa_dcs_TimeStruct_t* timePtr    ///< [OUT] Time structure
)
{
    ip_addr_t            addr;
    le_result_t          result = LE_FAULT;
    struct netbuf       *bufPtr = NULL;
    struct netconn      *connPtr;
    struct tm            tm;
    uint16_t             length;
    uint32_t             time;
    void                *dataPtr;

    if (serverStrPtr == NULL || timePtr == NULL || serverStrPtr[0] == '\0')
    {
        LE_ERROR("Invalid time structure or server name");
        return LE_BAD_PARAMETER;
    }

    // Resolve server name
    if (netconn_gethostbyname(serverStrPtr, &addr) != ERR_OK)
    {
        LE_ERROR("Failed to resolve TIME server '%s'", serverStrPtr);
        return LE_FAULT;
    }

    // Open TCP connection
    connPtr = netconn_new(NETCONN_TCP);
    if (connPtr == NULL || netconn_connect(connPtr, &addr, TIME_PORT) != ERR_OK)
    {
        LE_ERROR("TIME server connection failed");
        goto end;
    }

    // Read 32-bit time value
    if (netconn_recv(connPtr, &bufPtr) != ERR_OK          ||
        netbuf_data(bufPtr, &dataPtr, &length) != ERR_OK  ||
        length != sizeof(time))
    {
        LE_ERROR("TIME server response invalid");
        goto end;
    }
    memcpy(&time, dataPtr, sizeof(time));
    time = ntohl(time);

    // Format time (received value is seconds since 00:00 Jan 1, 1900)
    time -= TIME_OF_UNIX_EPOCH;
    if (gmtime_r((time_t *) &time, &tm) == NULL)
    {
        LE_ERROR("Failed to obtain UTC time");
        goto end;
    }

    timePtr->msec = 0L;
    timePtr->sec = tm.tm_sec;
    timePtr->min = tm.tm_min;
    timePtr->hour = tm.tm_hour;
    timePtr->day = tm.tm_mday;
    timePtr->mon = tm.tm_mon + 1;       // tm_mon range is 0-11, mon range is 1-12
    timePtr->year = tm.tm_year + 1900;  // tm_year is measured from 1900

    result = LE_OK;

end:
    // Clean up
    if (bufPtr != NULL)
    {
        netbuf_free(bufPtr);
    }
    if (connPtr != NULL)
    {
        netconn_close(connPtr);
        netconn_delete(connPtr);
    }
    return result;
}

//--------------------------------------------------------------------------------------------------
/**
 * Retrieve time from a server using the Network Time Protocol.
 *
 * @return
 *      - LE_OK             Function successful
 *      - LE_BAD_PARAMETER  A parameter is incorrect
 *      - LE_FAULT          Function failed
 *      - LE_UNSUPPORTED    Function not supported by the target
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_dcs_GetTimeWithNetworkTimeProtocol
(
    const char* serverStrPtr,       ///< [IN]  Time server
    pa_dcs_TimeStruct_t* timePtr    ///< [OUT] Time structure
)
{
    struct timeval  tv;
    struct tm       tm;

    // The SNTP client's servers are configured separately - there is no one-off request mechanism,
    // so here we just return the system time, which should be set from either the cellular network
    // or SNTP.
    (void) serverStrPtr;
    if (timePtr == NULL)
    {
        LE_ERROR("Invalid time structure");
        return LE_BAD_PARAMETER;
    }

    if (gettimeofday(&tv, NULL) != 0 || gmtime_r(&tv.tv_sec, &tm) == NULL)
    {
        LE_ERROR("Failed to obtain UTC time");
        return LE_FAULT;
    }

    timePtr->msec = tv.tv_usec / 1000L;
    timePtr->sec = tm.tm_sec;
    timePtr->min = tm.tm_min;
    timePtr->hour = tm.tm_hour;
    timePtr->day = tm.tm_mday;
    timePtr->mon = tm.tm_mon + 1;       // tm_mon range is 0-11, mon range is 1-12
    timePtr->year = tm.tm_year + 1900;  // tm_year is measured from 1900

    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Query for a connection's network interface state
 *
 * @return
 *      - LE_OK             Function successful
 *      - LE_BAD_PARAMETER  A parameter is incorrect
 *      - LE_FAULT          Function failed
 *      - LE_UNSUPPORTED    Function not supported by the target
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_dcs_GetInterfaceState
(
    const char *interfacePtr,  ///< [IN] network interface name
    bool *ipv4IsUpPtr,         ///< [INOUT] IPV4 is not assigned/assigned as false/true
    bool *ipv6IsUpPtr          ///< [INOUT] IPV6 is not assigned/assigned as false/true
)
{
    LE_UNUSED(interfacePtr);
    LE_UNUSED(ipv4IsUpPtr);
    LE_UNUSED(ipv6IsUpPtr);
    return LE_UNSUPPORTED;
}

//--------------------------------------------------------------------------------------------------
/**
 * Returns DHCP lease file location
 *
 * @return
 *      LE_OVERFLOW     Destination buffer too small and output will be truncated
 *      LE_UNSUPPORTED  If not supported by OS
 *      LE_FAULT        Function failed
 *      LE_OK           Function succeed
 */
//--------------------------------------------------------------------------------------------------
LE_SHARED le_result_t pa_dcs_GetDhcpLeaseFilePath
(
    const char*  interfaceStrPtr,   ///< [IN] Pointer on the interface name
    char*        pathPtr,           ///< [OUT] Output 1 pointer
    size_t       bufferSize         ///< [IN]  Size of buffer
)
{
    LE_UNUSED(interfaceStrPtr);
    LE_UNUSED(pathPtr);
    LE_UNUSED(bufferSize);
    return LE_UNSUPPORTED;
}

//--------------------------------------------------------------------------------------------------
/**
 * Get the default route
 */
//--------------------------------------------------------------------------------------------------
LE_SHARED void pa_dcs_GetDefaultGateway
(
    pa_dcs_DefaultGwBackup_t*  defGwConfigBackupPtr,
    le_result_t* v4Result,
    le_result_t* v6Result
)
{
    LE_UNUSED(defGwConfigBackupPtr);
    *v4Result = LE_UNSUPPORTED;
    *v6Result = LE_UNSUPPORTED;
}
//--------------------------------------------------------------------------------------------------
/**
 * Component initialization
 */
//--------------------------------------------------------------------------------------------------
COMPONENT_INIT
{
}
