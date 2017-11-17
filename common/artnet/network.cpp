/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * network.c
 * Network code for libartnet
 * Copyright (C) 2004-2007 Simon Newton
 *
 */

#include "stdafx.h"

#include <errno.h>

#ifndef WIN32
#include <ifaddrs.h>
#include <sys/socket.h> // socket before net/if.h for mac
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <cstddef>
#include <netdb.h>
#else
typedef int socklen_t;
#include <winsock2.h>
#include <Ws2tcpip.h>
#include <Mswsock.h>
#include <Lm.h>
#include <Iphlpapi.h>
LPFN_WSARECVMSG WSARecvMSG = NULL;
LPFN_WSASENDMSG WSASendMSG = NULL;
#endif
#include <vector>

//#include <unistd.h>

#include "private.h"

#ifdef HAVE_GETIFADDRS
#ifdef HAVE_LINUX_IF_PACKET_H
#define USE_GETIFADDRS
#endif
#endif

#ifdef USE_GETIFADDRS
#include <ifaddrs.h>
#include <linux/types.h> // required by if_packet
#include <linux/if_packet.h>
#endif

#include <algorithm>
#include <string>
#include <string.h>


enum
{
	INITIAL_IFACE_COUNT = 10
};
enum
{
	IFACE_COUNT_INC = 5
};

typedef struct iface_s
{
	sockaddr_in ip_addr;
	sockaddr_in bcast_addr;
	int8_t hw_addr[ ARTNET_MAC_SIZE ];
	char if_name[ IF_NAMESIZE ];
	uint32_t if_index;
} iface_t;

unsigned long LOOPBACK_IP = 0x7F000001;


/*
 * Add a new interface to an interface list
 * @param head pointer to the head of the list
 * @param tail pointer to the end of the list
 * @return a new iface_t or void
 */

iface_t* new_iface( std::vector< iface_t >& list )
{
	list.emplace_back();
	memset( &list.back(), 0, sizeof( iface_t ) );
	return &list.back();
}



#ifdef WIN32
int enumerateInterfaces(std::vector<iface_t>& interfaces)
{
	int ret = ARTNET_EOK;

	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pAdapter = NULL;
	DWORD dwRetVal = 0;
	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);

	pAdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
	if (pAdapterInfo == NULL)
	{
		artnet_error("%s : Error allocating memory needed to call GetAdaptersinfo", __FUNCTION__);
		return ARTNET_EMEM;
	}

	// Make an initial call to GetAdaptersInfo to get
	// the necessary size into the ulOutBufLen variable
	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW)
	{
		free(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);
		if (pAdapterInfo == NULL)
		{
			artnet_error("%s : Error allocating memory needed to call GetAdaptersinfo", __FUNCTION__);
			return ARTNET_EMEM;
		}
	}

	if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR)
	{
		pAdapter = pAdapterInfo;
		while (pAdapter)
		{
			unsigned long net, mask;

			/*
				printf("\tComboIndex: \t%5d\n", (int)pAdapter->ComboIndex);
				printf("\tAdapter Name: \t%s\n", pAdapter->AdapterName);
				printf("\tAdapter Desc: \t%s\n", pAdapter->Description);
				printf("\tAdapter Addr: \t");
				for (i = 0; i < pAdapter->AddressLength; i++) {
						if (i == (pAdapter->AddressLength - 1))
								printf("%.2X\n", (int) pAdapter->Address[i]);
						else
								printf("%.2X-", (int) pAdapter->Address[i]);
				}
				printf("\tIndex: \t%d\n", (int)pAdapter->Index);
				printf("\tType: \t");
				switch (pAdapter->Type) {
				case MIB_IF_TYPE_OTHER:
						printf("Other\n");
						break;
				case MIB_IF_TYPE_ETHERNET:
						printf("Ethernet\n");
						break;
				case MIB_IF_TYPE_TOKENRING:
						printf("Token Ring\n");
						break;
				case MIB_IF_TYPE_FDDI:
						printf("FDDI\n");
						break;
				case MIB_IF_TYPE_PPP:
						printf("PPP\n");
						break;
				case MIB_IF_TYPE_LOOPBACK:
						printf("Lookback\n");
						break;
				case MIB_IF_TYPE_SLIP:
						printf("Slip\n");
						break;
				default:
						printf("Unknown type %ld\n", (long)pAdapter->Type);
						break;
				}

				printf("\tIP Address: \t%s\n",
							 pAdapter->IpAddressList.IpAddress.String);
				printf("\tIP Mask: \t%s\n", pAdapter->IpAddressList.IpMask.String);

				printf("\tGateway: \t%s\n", pAdapter->GatewayList.IpAddress.String);
				printf("\t***\n");

				if (pAdapter->DhcpEnabled) {
						printf("\tDHCP Enabled: Yes\n");
						printf("\t  DHCP Server: \t%s\n",
									 pAdapter->DhcpServer.IpAddress.String);
			} else
						printf("\tDHCP Enabled: No\n");

				if (pAdapter->HaveWins) {
						printf("\tHave Wins: Yes\n");
						printf("\t  Primary Wins Server:    %s\n",
									 pAdapter->PrimaryWinsServer.IpAddress.String);
						printf("\t  Secondary Wins Server:  %s\n",
									 pAdapter->SecondaryWinsServer.IpAddress.String);
				} else
						printf("\tHave Wins: No\n");
				pAdapter = pAdapter->Next;
				printf("\n");
				*/

			iface_t* ift = new_iface(interfaces);
			if (ift == NULL)
			{
				artnet_error("%s : calloc error %s", __FUNCTION__, strerror(errno));
				ret = ARTNET_EMEM;
				goto nextAdapter;
			}

			net = inet_addr(pAdapter->IpAddressList.IpAddress.String);
			mask = inet_addr(pAdapter->IpAddressList.IpMask.String);

			strncpy(ift->if_name, pAdapter->AdapterName, sizeof(ift->if_name));
			if_indextoname(pAdapter->Index, ift->if_name);
			ift->if_index = pAdapter->Index;

			memcpy(ift->hw_addr, pAdapter->Address, ARTNET_MAC_SIZE);
			ift->ip_addr.sin_addr.s_addr = net;
			ift->bcast_addr.sin_addr.s_addr = ((net & mask) | (0xFFFFFFFF ^ mask));

		nextAdapter:
			pAdapter = pAdapter->Next;
		}

		//RESOLUME: Localhost loopback interface
		{
			iface_t* localhost_interface = new_iface(interfaces);
			if (localhost_interface == NULL)
			{
				artnet_error("%s : calloc error %s", __FUNCTION__, strerror(errno));
				ret = ARTNET_EMEM;
			}
			else
			{
				const char* address = "127.0.0.1";
				unsigned long net = inet_addr(address);
				unsigned long mask = inet_addr("255.0.0.0");
				unsigned long broadcast = inet_addr("127.0.0.1");
				unsigned long localHostIndex = 0;

				strncpy(localhost_interface->if_name, "Localhost", sizeof(localhost_interface->if_name));
				if_indextoname(localHostIndex, localhost_interface->if_name);
				localhost_interface->if_index = localHostIndex;

				memcpy(localhost_interface->hw_addr, address, ARTNET_MAC_SIZE);
				localhost_interface->ip_addr.sin_addr.s_addr = net;
				localhost_interface->bcast_addr.sin_addr.s_addr = broadcast;
			}
		}
	}
	else
	{
		printf("GetAdaptersInfo failed with error: %d\n", (int)dwRetVal);
	}
	if (pAdapterInfo)
		free(pAdapterInfo);

	return ret;
}

# else // not WIN32

#ifdef USE_GETIFADDRS

/*
 * Check if we are interested in this interface
 * @param ifa a pointer to a ifaddr struct
 */
static void add_iface_if_needed( iface_t **head, iface_t **tail,
	struct ifaddrs *ifa )
{

	// skip down, loopback and non inet interfaces
	if( !ifa || !ifa->ifa_addr ) return;
	if( !(ifa->ifa_flags & IFF_UP) ) return;
	if( ifa->ifa_flags & IFF_LOOPBACK ) return;
	if( ifa->ifa_addr->sa_family != AF_INET ) return;

	iface_t *iface = new_iface( head, tail );
	struct sockaddr_in *sin = (struct sockaddr_in*) ifa->ifa_addr;
	iface->ip_addr.sin_addr = sin->sin_addr;
	strncpy( iface->if_name, ifa->ifa_name, IFNAME_SIZE - 1 );
	iface->if_index = ifa->nogiets ?

		if( ifa->ifa_flags & IFF_BROADCAST )
		{
			sin = (struct sockaddr_in *) ifa->ifa_broadaddr;
			iface->bcast_addr.sin_addr = sin->sin_addr;
		}
}


/*
 * Set if_head to point to a list of iface_t structures which represent the
 * interfaces on this machine
 * @param ift_head the address of the pointer to the head of the list
 */
static int get_ifaces( iface_t **if_head )
{
	struct ifaddrs *ifa_list, *ifa_iter;
	iface_t *if_tail, *if_iter;
	struct sockaddr_ll *sll;
	char *if_name, *cptr;
	*if_head = if_tail = NULL;

	if( getifaddrs( &ifa_list ) != 0 )
	{
		artnet_error( "Error getting interfaces: %s", strerror( errno ) );
		return ARTNET_ENET;
	}

	for( ifa_iter = ifa_list; ifa_iter; ifa_iter = ifa_iter->ifa_next )
		add_iface_if_needed( if_head, &if_tail, ifa_iter );

	// Match up the interfaces with the corrosponding AF_PACKET interface
	// to fetch the hw addresses
	//
	// TODO: Will probably not work on OS X, it should
	//      return AF_LINK -type sockaddr
	for( if_iter = *if_head; if_iter; if_iter = if_iter->next )
	{
		if_name = strdup( if_iter->if_name );

		// if this is an alias, get mac of real interface
		if( (cptr = strchr( if_name, ':' )) )
			*cptr = 0;

		// Find corresponding iface_t structure
		for( ifa_iter = ifa_list; ifa_iter; ifa_iter = ifa_iter->ifa_next )
		{
			if( (!ifa_iter->ifa_addr) || ifa_iter->ifa_addr->sa_family != AF_PACKET )
				continue;

			if( strncmp( if_name, ifa_iter->ifa_name, IFNAME_SIZE ) == 0 )
			{
				// Found matching hw-address
				sll = (struct sockaddr_ll*) ifa_iter->ifa_addr;
				memcpy( if_iter->hw_addr, sll->sll_addr, ARTNET_MAC_SIZE );
				break;
			}
		}
		free( if_name );
	}
	freeifaddrs( ifa_list );
	return 0;
}

#else // no GETIFADDRS

int enumerateInterfaces( std::vector< iface_t >& interfaces )
{
	ifconf ifc;
	ifreq *ifr, ifrcopy;
	sockaddr_in *sin;
	int len, lastlen, flags;
	char *buf, *ptr;
	int ret = ARTNET_EOK;
	int sd;

	// create socket to get iface config
	sd = socket( PF_INET, SOCK_DGRAM, 0 );

	if( sd < 0 )
	{
		artnet_error( "%s : Could not create socket %s", __FUNCTION__, strerror( errno ) );
		ret = ARTNET_ENET;
		goto e_return;
	}

	// first use ioctl to get a listing of interfaces
	lastlen = 0;
	len = INITIAL_IFACE_COUNT * sizeof( ifreq );

	for( ;; )
	{
		buf = (char*)malloc( len );

		if( buf == NULL )
		{
			artnet_error_malloc();
			ret = ARTNET_EMEM;
			goto e_free;
		}

		ifc.ifc_len = len;
		ifc.ifc_buf = buf;
		if( ioctl( sd, SIOCGIFCONF, &ifc ) < 0 )
		{
			if( errno != EINVAL || lastlen != 0 )
			{
				artnet_error( "%s : ioctl error %s", __FUNCTION__, strerror( errno ) );
				ret = ARTNET_ENET;
				goto e_free;
			}
		}
		else
		{
			if( ifc.ifc_len == lastlen )
				break;
			lastlen = ifc.ifc_len;
		}
		len += IFACE_COUNT_INC * sizeof( struct ifreq );
		free( buf );
	}

	// loop through each iface
	for( ptr = buf; ptr < buf + ifc.ifc_len;)
	{
		ifr = (struct ifreq*) ptr;

		// work out length here
#ifdef HAVE_SOCKADDR_SA_LEN
		len = std::max( (std::uint8_t)sizeof( struct sockaddr ), ifr->ifr_addr.sa_len );
#else
		switch( ifr->ifr_addr.sa_family )
		{
#ifdef  IPV6
		case AF_INET6:
			len = sizeof( struct sockaddr_in6 );
			break;
#endif
		case AF_INET:
		default:
			len = sizeof( SA );
			break;
		}
#endif

		ptr += sizeof( ifr->ifr_name ) + len;

		// look for AF_INET interfaces
		if( ifr->ifr_addr.sa_family != AF_INET )
			continue;

		ifrcopy = *ifr;
		if( ioctl( sd, SIOCGIFFLAGS, &ifrcopy ) < 0 )
		{
			artnet_error( "%s : ioctl error %s", __FUNCTION__, strerror( errno ) );
			ret = ARTNET_ENET;
			goto e_free_list;
		}

		flags = ifrcopy.ifr_flags;
		if( (flags & IFF_UP) == 0 )
			continue; //skip down interfaces

		if( (flags & IFF_LOOPBACK) )
			continue; //skip lookback

		iface_t* iface = new_iface( interfaces );
		if( !iface )
			goto e_free_list;

		sin = (sockaddr_in *) &ifr->ifr_addr;
		iface->ip_addr.sin_addr = sin->sin_addr;

		strncpy( iface->if_name, ifr->ifr_name, sizeof( iface->if_name ) );
		iface->if_index = if_nametoindex( ifr->ifr_name );

		// fetch bcast address
#ifdef SIOCGIFBRDADDR
		if( flags & IFF_BROADCAST )
		{
			if( ioctl( sd, SIOCGIFBRDADDR, &ifrcopy ) < 0 )
			{
				artnet_error( "%s : ioctl error %s", __FUNCTION__, strerror( errno ) );
				ret = ARTNET_ENET;
				goto e_free_list;
			}

			sin = (struct sockaddr_in *) &ifrcopy.ifr_broadaddr;
			iface->bcast_addr.sin_addr = sin->sin_addr;
		}
#endif
		// fetch hardware address
#ifdef SIOCGIFHWADDR
		if( flags & SIOCGIFHWADDR )
		{
			if( ioctl( sd, SIOCGIFHWADDR, &ifrcopy ) < 0 )
			{
				artnet_error( "%s : ioctl error %s", __FUNCTION__, strerror( errno ) );
				ret = ARTNET_ENET;
				goto e_free_list;
			}
			memcpy( &iface->hw_addr, ifrcopy.ifr_hwaddr.sa_data, ARTNET_MAC_SIZE );
		}
#endif

		/* ok, if that all failed we should prob try and use sysctl to work out the bcast
		 * and hware addresses
		 * i'll leave that for another day
		 */
	}

	//RESOLUME: Localhost loopback interface
	{
		iface_t* localhost_interface = new_iface(interfaces);
		if (localhost_interface == NULL)
		{
			artnet_error("%s : calloc error %s", __FUNCTION__, strerror(errno));
			ret = ARTNET_EMEM;
		}
		else
		{
			const char* address = "127.0.0.1";
			unsigned long net = inet_addr(address);
			unsigned long mask = inet_addr("255.0.0.0");
			unsigned long broadcast = inet_addr("127.0.0.1");
			unsigned long localHostIndex = 0;

			strncpy(localhost_interface->if_name, "Localhost", sizeof(localhost_interface->if_name));
			if_indextoname(localHostIndex, localhost_interface->if_name);
			localhost_interface->if_index = localHostIndex;

			memcpy(localhost_interface->hw_addr, address, ARTNET_MAC_SIZE);
			localhost_interface->ip_addr.sin_addr.s_addr = net;
			localhost_interface->bcast_addr.sin_addr.s_addr = broadcast;
		}
	}

	free( buf );
	/*
	* Close socket, this line of code wasn't here in the original distribution but very important
	*/
	close( sd );
	return ARTNET_EOK;

e_free_list:

e_free:
	free( buf );
	close( sd );
e_return:
	return ret;
}

#endif // GETIFADDRS
#endif // not WIN32

bool isInputFromAdapterAllowed( uint32_t inputAdapterIndex, const char* filterAdapter )
{
	if( strlen( filterAdapter ) == 0 )
		return true;

	char nameBuffer[ IF_NAMESIZE ];
	memset( nameBuffer, 0, IF_NAMESIZE );
	if( if_indextoname( inputAdapterIndex, nameBuffer ) != nameBuffer )
		return true;

	return strcmp( nameBuffer, filterAdapter ) == 0;
}

/*
 * Scan for interfaces, and work out which one the user wanted to use.
 */
int artnet_net_init( node n, const char* filterAdapter )
{
	int found = FALSE;
	int i;
	int ret = ARTNET_EOK;

	std::vector< iface_t > interfaces;
	ret = enumerateInterfaces( interfaces );
	if( ret != ARTNET_EOK )
		goto e_return;

	if( n->state.verbose )
	{
		printf( "#### INTERFACES FOUND ####\n" );
		for( size_t index = 0; index < interfaces.size(); ++index )
		{
			printf( "IP: %s\n", inet_ntoa( interfaces[ index ].ip_addr.sin_addr ) );
			printf( "  bcast: %s\n", inet_ntoa( interfaces[ index ].bcast_addr.sin_addr ) );
			printf( "  hwaddr: " );
			for( i = 0; i < ARTNET_MAC_SIZE; i++ )
			{
				if( i )
					printf( ":" );
				printf( "%02x", (uint8_t)interfaces[ index ].hw_addr[ i ] );
			}
			printf( "\n" );
		}
		printf( "#########################\n" );
	}

	if( filterAdapter )
	{
#ifdef WIN32
		strcpy_s( n->filterAdapter, sizeof( n->filterAdapter ), filterAdapter );
#else
		strcpy( n->filterAdapter, filterAdapter );
#endif

		for( size_t index = 0; index < interfaces.size(); ++index )
		{
			if( strcmp( interfaces[ index ].if_name, filterAdapter ) == 0 )
			{
				found = TRUE;
				n->state.ip_addr = interfaces[ index ].ip_addr.sin_addr;
				n->state.bcast_addr = interfaces[ index ].bcast_addr.sin_addr;
				memcpy( &n->state.hw_addr, &interfaces[ index ].hw_addr, ARTNET_MAC_SIZE );

				break;
			}
		}
		if( !found )
		{
			artnet_error( "Cannot find adapter %s", filterAdapter );
			ret = ARTNET_ENET;
			goto e_cleanup;
		}
		/*
		// search through list of interfaces for one with the correct address
		ret = artnet_net_inet_aton( preferred_ip, &wanted_ip );
		if( ret )
			goto e_cleanup;
			*/
	}
	else
	{
		if( !interfaces.empty() )
		{
			// pick first address
			// copy ip address, bcast address and hardware address

			n->state.ip_addr = interfaces[ 0 ].ip_addr.sin_addr;
			n->state.bcast_addr = interfaces[ 0 ].bcast_addr.sin_addr;
			memcpy( &n->state.hw_addr, &interfaces[ 0 ].hw_addr, ARTNET_MAC_SIZE );
		}
		else
		{
			artnet_error( "No interfaces found!" );
			ret = ARTNET_ENET;
		}
	}

e_cleanup:

e_return:
	return ret;
}


/*
 * Start listening on the socket
 */
int artnet_net_start( node n )
{
	int sock;
	struct sockaddr_in servAddr;
	int true_flag = TRUE;
	node tmp;

	// only attempt to bind if we are the group master
	if( n->peering.master != TRUE )
		return ARTNET_EOK;

#ifdef WIN32
	// check winsock version
	WSADATA wsaData;
	WORD wVersionRequested = MAKEWORD( 2, 2 );
	if( WSAStartup( wVersionRequested, &wsaData ) != 0 )
		return (-1);
	if( wsaData.wVersion != wVersionRequested )
		return (-2);
#endif

	// create socket
	sock = socket( PF_INET, SOCK_DGRAM, 0 );

	if( sock < 0 )
	{
		artnet_error( "Could not create socket %s", artnet_net_last_error() );
		return ARTNET_ENET;
	}

#ifdef WIN32
	// ### LH - 22.08.2008
	// make it possible to reuse port, if SO_REUSEADDR
	// exists on operating system

	// NEVER USE SO_EXCLUSIVEADDRUSE, as that freezes the application
	// on WinXP, if port is in use !
	if( setsockopt( sock, SOL_SOCKET, SO_REUSEADDR, (char *)&true_flag, sizeof( true_flag ) ) < 0 )
	{

		artnet_error( "Set reuse failed", artnet_net_last_error() );
		artnet_net_close( sock );
		return ARTNET_ENET;
	}

	u_long itrue = 1;
	if( SOCKET_ERROR == ioctlsocket( sock, FIONBIO, &itrue ) )
	{

		artnet_error( "ioctlsocket", artnet_net_last_error() );
		artnet_net_close( sock );
		return ARTNET_ENET;
	}
#else
	const int optval = 1;
	setsockopt( sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof( optval ) );
	setsockopt( sock, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof( optval ) );
#endif

	memset( &servAddr, 0x00, sizeof( servAddr ) );
	servAddr.sin_family = AF_INET;
	servAddr.sin_port = htons( ARTNET_PORT );
	servAddr.sin_addr.s_addr = htonl( INADDR_ANY );
#if defined( WIN32 )
	//On windows we can bind the socket to the desired adapter and still receive broadcasts if we enable them. On osx though we no longer
	//get broadcasts, even though we enable them. For that reason we have to bind to any on osx and manually filter.
	//servAddr.sin_addr.s_addr = n->state.ip_addr.s_addr;
	//if( setsockopt( sock, IPPROTO_IP, IP_RECVIF, (char*) &true_flag, sizeof( int ) ) == -1 )
	//{
 //     artnet_error("Failed to enable dest addr retrieval %s", artnet_net_last_error());
 //     artnet_net_close(sock);
 //     return ARTNET_ENET;
	//}
	if( setsockopt( sock, IPPROTO_IP, IP_PKTINFO, (char*)&true_flag, sizeof( int ) ) == -1 )
	{
		artnet_error( "Failed to enable delivery adapter retrieval %s", artnet_net_last_error() );
		artnet_net_close( sock );
		return ARTNET_ENET;
	}
	GUID g = WSAID_WSARECVMSG;
	DWORD dwBytesReturned = 0;
	if( WSAIoctl( sock, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof( g ), &WSARecvMSG, sizeof( WSARecvMSG ), &dwBytesReturned, NULL, NULL ) != 0 )
	{
		artnet_error( "WSARecvMsg is not available %s", artnet_net_last_error() );
		artnet_net_close( sock );
		return ARTNET_ENET;
	}
	g = WSAID_WSASENDMSG;
	dwBytesReturned = 0;
	if( WSAIoctl( sock, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof( g ), &WSASendMSG, sizeof( WSASendMSG ), &dwBytesReturned, NULL, NULL ) != 0 )
	{
		artnet_error( "WSASendMSG is not available %s", artnet_net_last_error() );
		artnet_net_close( sock );
		return ARTNET_ENET;
	}
#else
	if( setsockopt( sock, IPPROTO_IP, IP_PKTINFO, (char*)&true_flag, sizeof( int ) ) == -1 )
	{
		artnet_error( "Failed to enable delivery adapter retrieval %s", artnet_net_last_error() );
		artnet_net_close( sock );
		return ARTNET_ENET;
	}
#endif

	if( n->state.verbose )
		printf( "Binding to %s \n", inet_ntoa( servAddr.sin_addr ) );

	// bind sockets
	if( bind( sock, (SA *)&servAddr, sizeof( servAddr ) ) == -1 )
	{
		artnet_error( "Failed to bind to socket: %s", artnet_net_last_error() );
		artnet_net_close( sock );
		return ARTNET_ENET;
	}

	// allow bcasting
	if( setsockopt( sock, SOL_SOCKET, SO_BROADCAST, (char*)&true_flag, sizeof( int ) ) == -1 )
	{
		artnet_error( "Failed to enable broadcast: %s", artnet_net_last_error() );
		artnet_net_close( sock );
		return ARTNET_ENET;
	}

	n->sd = sock;
	// Propagate the socket to all our peers
	for( tmp = n->peering.peer; tmp && tmp != n; tmp = tmp->peering.peer )
		tmp->sd = sock;

	return ARTNET_EOK;
}


#if defined(WIN32)
const static std::vector<struct sockaddr_in*> local_addresses = []()
{
	std::vector<sockaddr_in*> result;
	struct addrinfo* local_address_info = NULL;
	getaddrinfo("localhost", NULL, NULL, &local_address_info);
	struct addrinfo *address_it;
	for (address_it = local_address_info; address_it != NULL; address_it = address_it->ai_next)
		result.push_back((struct sockaddr_in*)address_it->ai_addr);
	return std::move(result);
}();
#else
const static std::vector<struct sockaddr_in*> local_addresses = []()
{
	std::vector<sockaddr_in*> result;
	struct ifaddrs *ifap, *ifa;
    struct sockaddr_in *sa;
    char *addr;
    getifaddrs(&ifap);
    for (ifa = ifap; ifa; ifa = ifa->ifa_next)
        if (ifa->ifa_addr->sa_family==AF_INET)
            result.push_back((struct sockaddr_in *)ifa->ifa_addr);
    freeifaddrs(ifap);
	return std::move(result);
}();
#endif

std::string toIP(sockaddr* sockAddr)
{
	char charIPAddress[NI_MAXHOST];
	sockaddr_storage* sendAddr = (sockaddr_storage*)&sockAddr;

	//IP 4 or 6?
	sendAddr->ss_family == AF_INET ?
		inet_ntop(AF_INET, &((sockaddr_in*)&sockAddr)->sin_addr, charIPAddress, NI_MAXHOST) :
		inet_ntop(AF_INET6, &((sockaddr_in6*)&sockAddr)->sin6_addr, charIPAddress, NI_MAXHOST);

	return std::string(charIPAddress);
}

/*
 * Receive a packet.
 */
int artnet_net_recv(node n, artnet_packet p, int delay)
{
	ptrdiff_t len;
	struct sockaddr_in cliAddr;
	socklen_t cliLen = sizeof(cliAddr);
	fd_set rset;
	struct timeval tv;
	int maxfdp1 = n->sd + 1;

	FD_ZERO(&rset);
	FD_SET((unsigned int)n->sd, &rset);

	tv.tv_usec = 0;
	tv.tv_sec = delay;
	p->length = 0;

	switch (select(maxfdp1, &rset, NULL, NULL, &tv))
	{
	case 0:
		// timeout
		return RECV_NO_DATA;
		break;
	case -1:
		if (errno != EINTR)
		{
			artnet_error("Select error %s", artnet_net_last_error());
			return ARTNET_ENET;
		}
		return ARTNET_EOK;
		break;
	default:
		break;
	}

	/**
	 * This is the original way the library was reading data. But we want to filter data for our interface only
	 * so i have added socket option to pass the packet info up the stack. To get this packet info we need to use
	 * the recvmsg functionality, which isn't available on windows without using WSA functions, so that is what we
	 * are doing.
	 *
	 * Original library comment:
	 * need a check here for the amount of data read
	 * should prob allow an extra byte after data, and pass the size as sizeof(Data) +1
	 * then check the size read and if equal to size(data)+1 we have an error
	 *
	len = recvfrom( n->sd, (char*) &(p->data), sizeof( p->data ), 0, (SA*)&cliAddr, &cliLen );
	 */
#if defined( WIN32 )
	WSABUF buffer;
	buffer.len = sizeof( p->data );
	buffer.buf = (CHAR*)&p->data;

	SOCKADDR_STORAGE addrbuf;
	CHAR controlBuffer[WSA_CMSG_LEN( sizeof( buffer ) )];
	WSAMSG msg;
	msg.dwFlags = 0;
	msg.name = (SA*)&cliAddr;
	msg.namelen = cliLen;
	msg.lpBuffers = &buffer;
	msg.dwBufferCount = 1;
	msg.Control.len = WSA_CMSG_LEN( sizeof( buffer ) );
	msg.Control.buf = controlBuffer;

	DWORD sizeRecvd = 0;
	int result = WSARecvMSG( n->sd, &msg, &sizeRecvd, NULL, NULL );

	const bool from_local = [&]()
	{
		if (strcmp(n->filterAdapter, "Localhost") != 0)
			return false;
		for (struct sockaddr_in* local_addr : local_addresses)
			if (cliAddr.sin_addr.s_addr == local_addr->sin_addr.s_addr)
				return true;
		if ((*reinterpret_cast<char*>(&cliAddr.sin_addr.s_addr)) == 127)
			return true;
		return false;
	}();

	if (result == 0)
	{
		WSACMSGHDR* msghdr = NULL;
		while (msghdr = WSA_CMSG_NXTHDR(&msg, msghdr))
		{
			switch (msghdr->cmsg_type)
			{
			case IP_PKTINFO:
			{
				//assert( addrbuf.ss_family == AF_INET );
				in_pktinfo* pktinfo = (in_pktinfo*)WSA_CMSG_DATA(msghdr);
				len = sizeRecvd;
				if (!isInputFromAdapterAllowed(pktinfo->ipi_ifindex, n->filterAdapter) && !from_local)
				{
					p->length = 0;
					return ARTNET_EOK;
				}
				break;
			}
			}
		}
	}
	else
	{
		int lastError = WSAGetLastError();
		len = -1;
	}
#else


	iovec iov;
	iov.iov_base = &p->data;
	iov.iov_len = sizeof( p->data );
	char controlBuffer[ 1024 ];//Should be enough to contain a cmsghdr and an in_pktinfo. But lets make it a bit bigger so it'll also fit anything extra the os decides to put in there. (ipv6 address maybe?)

	msghdr msgh;
	msgh.msg_name = &cliAddr;
	msgh.msg_namelen = cliLen;
	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;
	msgh.msg_control = controlBuffer;
	msgh.msg_controllen = sizeof( controlBuffer );
	msgh.msg_flags = 0;

	len = recvmsg( n->sd, &msgh, 0 );

	const bool from_local = [&]()
	{
		if (strcmp(n->filterAdapter, "Localhost") != 0)
			return false;
		for (struct sockaddr_in* local_addr : local_addresses)
			if (cliAddr.sin_addr.s_addr == local_addr->sin_addr.s_addr)
				return true;
		if ((*reinterpret_cast<char*>(&cliAddr.sin_addr.s_addr)) == 127)
			return true;
		return false;
	}();

	const cmsghdr* messageHeader = (const cmsghdr*)msgh.msg_control;
	//We've requested the IP_RECVPKTINFO information, but lets check if that's what we actually got from it. This piece of code limits us receiving messages on the adapter
	//we want to receive the data from. If we didnt get the right information we cannot do this filtering, thus we'll be returning data for all interfaces.
	if( messageHeader->cmsg_len == CMSG_LEN( sizeof( in_pktinfo ) ) &&
		messageHeader->cmsg_level == IPPROTO_IP &&
		messageHeader->cmsg_type == IP_RECVPKTINFO )
	{
		//We should receive the packet info after the message header.
		const in_pktinfo* packetInfo = (const in_pktinfo*)(controlBuffer + sizeof( cmsghdr ));
		if( !isInputFromAdapterAllowed( packetInfo->ipi_ifindex, n->filterAdapter ) && !from_local)
		{
			p->length = 0;
			return ARTNET_EOK;
		}
	}
#endif
	if( len < 0 )
	{
		artnet_error( "recvmsg error %s", artnet_net_last_error() );
		return ARTNET_ENET;
	}

	/**
	 * Why was this here in the original library code? It discards packets we receive from ourselves. There's nowhere in the spec
	 * saying that we should do this, in fact, the spec sais you need to reply to your own art polls which isn't done if these
	 * packets are discarded.
	if (cliAddr.sin_addr.s_addr == n->state.ip_addr.s_addr ||
		ntohl(cliAddr.sin_addr.s_addr) == LOOPBACK_IP) {
	  p->length = 0;
	  return ARTNET_EOK;
	}
	*/
	p->length = len;
	memcpy( &(p->from), &cliAddr.sin_addr, sizeof( struct in_addr ) );
	// should set to in here if we need it
	return ARTNET_EOK;
}


/*
 * Send a packet.
 */
int artnet_net_send(node n, artnet_packet p)
{
	struct sockaddr_in addr;
	int ret;

	/**
	 * We have to be resillient agains ip changes on the network interface we're using. For this reason we may have to update our
	 * node state to the new data for the interface when it changes. Since we dont have a change detector we will be using the poll
	 * message to update our node's state. The poll is sent at an interval so after a change has occurred it will only take so long
	 * for us to notice it.
	 */
	if (p->data.ap.opCode == htols(ARTNET_POLL))
	{
		std::vector< iface_t > interfaces;
		enumerateInterfaces(interfaces);

		for (size_t index = 0; index < interfaces.size(); ++index)
		{
			if (strcmp(interfaces[index].if_name, n->filterAdapter) == 0)
			{
				if (memcmp(&n->state.ip_addr, &interfaces[index].ip_addr.sin_addr, sizeof(n->state.ip_addr)) != 0 ||
					memcmp(&n->state.bcast_addr, &interfaces[index].bcast_addr.sin_addr, sizeof(n->state.bcast_addr)) != 0 ||
					memcmp(&n->state.hw_addr, &interfaces[index].hw_addr, ARTNET_MAC_SIZE) != 0)
				{
					n->state.ip_addr = interfaces[index].ip_addr.sin_addr;
					n->state.bcast_addr = interfaces[index].bcast_addr.sin_addr;
					memcpy(&n->state.hw_addr, &interfaces[index].hw_addr, ARTNET_MAC_SIZE);
					//The ip is also stored in the poll reply as callback ip so we have to rebuild the
					//reply for it to be updated with this new ip.
					artnet_tx_build_art_poll_reply(n);
				}
				break;
			}
		}
	}

	if (n->state.mode != ARTNET_ON)
		return ARTNET_EACTION;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(ARTNET_PORT);
	addr.sin_addr = p->to;
	p->from = n->state.ip_addr;

	if (n->state.verbose)
		printf("sending to %s\n", inet_ntoa(addr.sin_addr));

	const bool localhost_selected = strcmp(n->filterAdapter, "Localhost") == 0;

	const bool to_local_addr = [&]()
	{
		if (*reinterpret_cast<char*>(&addr.sin_addr.s_addr) == 127)
			return true;
		for (struct sockaddr_in* local_addr : local_addresses)
			if (addr.sin_addr.s_addr == local_addr->sin_addr.s_addr)
				return true;
		return false;
	}();

#if defined(WIN32)
	if (localhost_selected)
	{
		/*
			This is the library's original way of sending data.
			We now use this to send over localhost since we don't care
			over which adapter we send on localhost.
		*/
		if (to_local_addr)
			ret = sendto(n->sd, (char*)&p->data, p->length, 0, (SA*)&addr, sizeof(addr));
		else
			ret = -1;
	}
	else
	{
		/*
			To send data that is not purposed for local host we will be
			using a specific adapter so we need to use sendmsg and provide 
			the packet info containing which interface and ip should be 
			used to send the data.
		*/
		WSABUF buffer;
		buffer.len = p->length;
		buffer.buf = (CHAR*)&p->data;

		CHAR controlBuffer[WSA_CMSG_LEN(sizeof(buffer))];
		WSAMSG msg;
		msg.name = (SA*)&addr;
		msg.namelen = sizeof(addr);
		msg.lpBuffers = &buffer;
		msg.dwBufferCount = 1;
		msg.Control.len = WSA_CMSG_LEN(sizeof(buffer));
		msg.Control.buf = controlBuffer;
		msg.dwFlags = 0;

		WSACMSGHDR* msghdr = WSA_CMSG_FIRSTHDR(&msg);
		msghdr->cmsg_len = msg.Control.len;
		msghdr->cmsg_level = IPPROTO_IP;
		msghdr->cmsg_type = IP_PKTINFO;

		in_pktinfo* pktinfo = (in_pktinfo*)WSA_CMSG_DATA(msghdr);
		pktinfo->ipi_addr = n->state.ip_addr;
		pktinfo->ipi_ifindex = if_nametoindex(n->filterAdapter);

		DWORD sizeToSend = p->length;
		const int result = WSASendMsg(n->sd, &msg, 0, &sizeToSend, NULL, NULL);
		if (result == 0)
		{
			ret = sizeToSend;
		}
		else
		{
			int lastError = WSAGetLastError();
			ret = -1;
		}
	}
#else
	iovec iov;
	iov.iov_len = p->length;
	iov.iov_base = &p->data;

	msghdr msgh;
	char controlBuffer[ CMSG_LEN( sizeof( in_pktinfo ) ) ];
	msgh.msg_name = (SA*)&addr;
	msgh.msg_namelen = sizeof( addr );
	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;
	msgh.msg_controllen = CMSG_LEN( sizeof( in_pktinfo ) );
	msgh.msg_control = controlBuffer;
	msgh.msg_flags = 0;


	cmsghdr* messageHeader = (cmsghdr*)msgh.msg_control;
	messageHeader->cmsg_len = msgh.msg_controllen;
	messageHeader->cmsg_level = IPPROTO_IP;
	messageHeader->cmsg_type = IP_PKTINFO;


	in_pktinfo* packetInfo = (in_pktinfo*)(((char*)msgh.msg_control) + sizeof( cmsghdr ));
	packetInfo->ipi_addr = addr.sin_addr;
	packetInfo->ipi_spec_dst = n->state.ip_addr;
	packetInfo->ipi_ifindex = if_nametoindex( n->filterAdapter );

	const bool valid_target = [&](){
		if(localhost_selected)
			return to_local_addr;
		else
			return true;
	}();

	if (valid_target)
		ret = sendmsg( n->sd, &msgh, 0 );

#endif

	if (ret == -1)
	{
		artnet_error("sendmsg failed: %s", artnet_net_last_error());
		n->state.report_code = ARTNET_RCUDPFAIL;
		return ARTNET_ENET;
	}
	else if (p->length != ret)
	{
		artnet_error("failed to send full datagram");
		n->state.report_code = ARTNET_RCSOCKETWR1;
		return ARTNET_ENET;
	}

	if (n->callbacks.send.fh)
	{
		get_type(p);
		n->callbacks.send.fh(n, p, n->callbacks.send.data);
	}
	return ARTNET_EOK;
}


/*
int artnet_net_reprogram(node n) {
  iface_t *ift_head, *ift;
  int i;

  ift_head = get_ifaces(n->sd[0]);

  for (ift = ift_head;ift != NULL; ift = ift->next ) {
	printf("IP: %s\n", inet_ntoa(ift->ip_addr.sin_addr) );
	printf("  bcast: %s\n" , inet_ntoa(ift->bcast_addr.sin_addr) );
	printf("  hwaddr: ");
	  for(i = 0; i < 6; i++ ) {
		printf("%hhx:", ift->hw_addr[i] );
	  }
	printf("\n");
  }

  free_ifaces(ift_head);

}*/


int artnet_net_set_fdset( node n, fd_set *fdset )
{
	FD_SET( (unsigned int)n->sd, fdset );
	return ARTNET_EOK;
}


/*
 * Close a socket
 */
int artnet_net_close( int sock )
{
#ifdef WIN32
	shutdown( sock, SD_BOTH );
	closesocket( sock );
	//WSACancelBlockingCall();
	WSACleanup();
#else
	if( close( sock ) )
	{
		artnet_error( artnet_net_last_error() );
		return ARTNET_ENET;
	}
#endif
	return ARTNET_EOK;
}


/*
 * Convert a string to an in_addr
 */
int artnet_net_inet_aton( const char *ip_address, struct in_addr *address )
{
#ifdef HAVE_INET_ATON
	if( !inet_aton( ip_address, address ) )
	{
#else
	in_addr_t *addr = (in_addr_t*)address;
	if( (*addr = inet_addr( ip_address )) == INADDR_NONE )
	{
#endif
		artnet_error( "IP conversion from %s failed", ip_address );
		return ARTNET_EARG;
	}
	return ARTNET_EOK;
}


/*
 *
 */
const char *artnet_net_last_error()
{
#ifdef WIN32
	static char error_str[ 10 ];
	int error = WSAGetLastError();
	sprintf_s( error_str, sizeof( error_str ), "%d", error );
	return error_str;
#else
	return strerror( errno );
#endif
}

