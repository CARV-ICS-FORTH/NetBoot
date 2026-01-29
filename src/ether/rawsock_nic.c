/*
 * SPDX-FileType: SOURCE
 *
 * SPDX-FileCopyrightText: 2023 Nick Kossifidis <mick@ics.forth.gr>
 * SPDX-FileCopyrightText: 2023 ICS/FORTH
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Raw Socket NIC
 *
 * This is a pseudo ethernet NIC using a raw socket for testing/debugging the
 * stack / app before running it on hw, it runs under an os in userspace.
 * However to keep it as close to bare metal code there are a few rules:
 * 1) No dependencies on libraries other than libc, and system headers
 * 2) No dynamic allocations
 * 3) This should fit/implement the API used in bare metal so that the
 * bare metal code stays the same.
 */

#ifdef HOST_TEST

#define _GNU_SOURCE	/* For TEMP_FAILURE_RETRY */
#include <net.h>
#undef ntohs
#undef htons
#undef bswap16
#include <utils.h>	/* For console output */
#include <ifaddrs.h>	/* For getifaddrs() */
#include <sys/ioctl.h>	/* For ioctl() and related flags*/
#include <net/if.h>	/* For querying if ioctls -ifreq etc */
#include <unistd.h>	/* For open/close */
#include <string.h>	/* For memcpy/memset */
#include <linux/if_tun.h> /* For IFF_TAP/TUNSETIFF etc */
#include <fcntl.h>	/* For O_* flags */
#include <sys/epoll.h>	/* For epoll_*() */
#include <errno.h>	/* For errno and its values */
#include <arpa/inet.h>	/* For htonX/ntoX inet_ntoa/inet_aton in_addr.. etc*/
#include <linux/if_packet.h>

struct rawsock_nic {
	uint8_t	rx_buff[RX_BUFF_SIZE] __attribute__((aligned(8)));
	uint8_t	tx_buff[TX_BUFF_SIZE] __attribute__((aligned(8)));
	mac_addr_t smac_addr;
	int fd;
	int parent_ifidx;
	int istap;
};
typedef struct rawsock_nic RawSockNic;

static RawSockNic *rsnic = NULL;

/**************\
* Entry points *
\**************/

mac_addr_t*
eth_get_mac_addr(void)
{
	if (!rsnic)
		return NULL;

	return &rsnic->smac_addr;
}

uint8_t*
eth_get_tx_buff(size_t size)
{
	if (!rsnic)
		return NULL;

	if (size > TX_BUFF_SIZE) {
		ERR("[RsNIC] requested buffer size exceeds TX buffer len\n");
		return NULL;
	}
	memset(rsnic->tx_buff, 0, size);
	return rsnic->tx_buff;
}

int
eth_trigger_tx(size_t size)
{
	if (!rsnic)
		return -ENODEV;

	if (size > TX_BUFF_SIZE) {
		ERR("[RsNIC] requested frame size won't fit TX buffer\n");
		return -EMSGSIZE;
	}

	struct sockaddr_ll socket_address = {0};
	int ret = 0;

	/* RAW socket -> need to use sendto() */
	if (!rsnic->istap) {
		/* Index of the network device */
		socket_address.sll_ifindex = rsnic->parent_ifidx;
		/* Address length*/
		socket_address.sll_halen = ETH_ADDR_LEN;
		/* Destination MAC */
		socket_address.sll_addr[0] = rsnic->tx_buff[0];
		socket_address.sll_addr[1] = rsnic->tx_buff[1];
		socket_address.sll_addr[2] = rsnic->tx_buff[2];
		socket_address.sll_addr[3] = rsnic->tx_buff[3];
		socket_address.sll_addr[4] = rsnic->tx_buff[4];
		socket_address.sll_addr[5] = rsnic->tx_buff[5];

		ret = sendto(rsnic->fd, rsnic->tx_buff, size, 0,
			     (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll));
	} else {
		ret = write(rsnic->fd, rsnic->tx_buff, size);
	}

	if (ret < 0)
		return -errno;

	return ret;
}

uint8_t*
eth_wait_for_rx_buff(ssize_t *size)
{
	if (!rsnic) {
		*size = -ENODEV;
		return NULL;
	}

	struct epoll_event ev = {0};
	int epoll_fd = 0;
	int ret = 0;

	epoll_fd = epoll_create(1);
	if (epoll_fd == -1) {
		perror(BRIGHT RED "[RsNIC] Could not create epoll instance");
		*size = -errno;
		return NULL;
	}

	ev.events = EPOLLIN;
	ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, rsnic->fd, &ev);
	if (ret == -1) {
		perror(BRIGHT RED "[RsNIC] Could not add if's descriptor to epoll");
		close(epoll_fd);
		*size = -errno;
		return NULL;
	}

	ret = epoll_wait(epoll_fd, &ev, 1, RX_ETH_TIMEOUT_MSEC);
	if (ret == -1) {
		perror(BRIGHT RED "[RsNIC] epoll_wait() failed");
		close(epoll_fd);
		*size = -errno;
		return NULL;
	}

	if (!ret) {
		DBG("[RsNIC] timeout while waiting for frame\n");
		close(epoll_fd);
		*size = -ETIME;
		return NULL;
	}
	close(epoll_fd);

	ret = read(rsnic->fd, rsnic->rx_buff, RX_BUFF_SIZE);
	if (ret < 0) {
		*size = -errno;
		return NULL;
	}

	*size = ret;
	return rsnic->rx_buff;
}

int
eth_open(void)
{
	/* Already initialized */
	if (rsnic)
		return -EINVAL;

	/* Allocate NIC state */
	rsnic = malloc(sizeof(struct rawsock_nic));
	if (rsnic != NULL)
		memset(rsnic, 0, sizeof(struct rawsock_nic));
	else
		return -ENOMEM;

	struct ifreq ifr = {0};
	struct ifaddrs *ifaddr, *ifa;
	struct in_addr ll_addr;
	struct in_addr ll_mask;
	in_addr_t if_ipaddr;
	in_addr_t if_netmask;
	struct sockaddr_in *tmp_addr;
	struct sockaddr_ll bindaddr = {0};
	const char *tmp_addr_str;
	size_t ifname_len;
	int ifidx = 0;
	int temp_fd = 0;
	int ret = 0;

	temp_fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));
	if (temp_fd < 0) {
 		perror(BRIGHT RED "[RsNIC] Open failed, socket()");
		free(rsnic);
		rsnic = NULL;
		return -errno;
	}

	/* Check if there is an interface with name "rawsoc"
	 * you may create it using:
	 * ip tuntap add mode tap rawsoc
	 * ip link set dev rawsoc up */
	strncpy(ifr.ifr_name, "rawsoc", IFNAMSIZ);
	ret = ioctl(temp_fd, SIOCGIFINDEX, &ifr);
	if (!ret) {
		DBG("[RsNIC] Attaching to rawsoc interface\n");
		rsnic->parent_ifidx = ifr.ifr_ifindex;
		rsnic->istap = 1;

		/* Get a file descriptor to the device */
		temp_fd = TEMP_FAILURE_RETRY(open("/dev/net/tun", O_RDWR));
		if (temp_fd == -1) {
			perror(BRIGHT RED "[RsNIC] Could not open /dev/net/tun");
			free(rsnic);
			rsnic = NULL;
			return -errno;
		}
		memset(&ifr, 0, sizeof(struct ifreq));
		ifr.ifr_flags = IFF_TAP | IFF_NO_PI | IFF_NAPI;
		strncpy(ifr.ifr_name, "rawsoc", IFNAMSIZ);
		ret = ioctl(temp_fd, TUNSETIFF, (void *) &ifr);
		if (ret == -1) {
			perror(BRIGHT RED "[RsNIC] Could not configure tap device");
			close(temp_fd);
			free(rsnic);
			rsnic = NULL;
			return -errno;
		}
		rsnic->fd = temp_fd;
		goto found;
	}

	/* Get link local IP / Mask for IPv4 so that we
	 * can use them to filter out virtual interfaces
	 * and/or bridge members. */
	ret = inet_aton("169.254.0.0", &ll_addr);
	if (!ret) {
		close(temp_fd);
		free(rsnic);
		rsnic = NULL;
		return -EINVAL;
	}
	ret = inet_aton("255.255.0.0", &ll_mask);
	if (!ret) {
		close(temp_fd);
		free(rsnic);
		rsnic = NULL;
		return -EINVAL;
	}
	/* Walk list of active interfaces */
	ret = getifaddrs(&ifaddr);
	if (ret < 0) {
		perror(BRIGHT RED "[RsNIC] Couldn't enumerate interfaces, getifaddrs()");
		close(temp_fd);
		free(rsnic);
		rsnic = NULL;
		return -errno;
	}

	/* We didn't attach to the baremetal tap interface, use a raw
	 * socket and try to bind to the host's main nic. */
	ret = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (ret < 0) {
		perror(BRIGHT RED "[RsNIC] Could not init raw socket");
		freeifaddrs(ifaddr);
		close(temp_fd);
		free(rsnic);
		rsnic = NULL;
		return -EIO;
	}
	rsnic->fd = ret;

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {

		if (ifa->ifa_addr == NULL)
			continue;

		/* Look for interfaces that match our criteria, filter the rest */
		if (ifa->ifa_addr->sa_family != AF_INET)
			continue;

		if (!(ifa->ifa_flags & IFF_UP)||
		(ifa->ifa_flags & (IFF_LOOPBACK | IFF_NOARP | IFF_POINTOPOINT)))
			continue;

		/* Got an active AF_INET interface, grab its index */
		memset(&ifr, 0, sizeof(ifr));

		/* Get its name and NULL-terminate it */
		ifname_len = strnlen(ifa->ifa_name, IF_NAMESIZE);
		memcpy(ifr.ifr_name, ifa->ifa_name, ifname_len);
		ifr.ifr_name[ifname_len] = 0;

		/* Grab its index */
		ret = ioctl(temp_fd, SIOCGIFINDEX, &ifr);
		if (ret < 0) {
			perror(BRIGHT RED "[RsNIC] Couldn't get interface index, ioctl()");
			freeifaddrs(ifaddr);
			close(temp_fd);
			free(rsnic);
			rsnic = NULL;
			return -errno;
		}
		ifidx = ifr.ifr_ifindex;

		/* Filter out interfaces with link-local IPs */
		tmp_addr = (struct sockaddr_in*) ifa->ifa_addr;
		if_ipaddr = tmp_addr->sin_addr.s_addr;
		tmp_addr = (struct sockaddr_in*) ifa->ifa_netmask;
		if_netmask = tmp_addr->sin_addr.s_addr;
		if ((ll_addr.s_addr & ll_mask.s_addr) ==
			(if_ipaddr & if_netmask))
			continue;


		/* Gotcha ! */
		tmp_addr = (struct sockaddr_in*) ifa->ifa_addr;
		tmp_addr_str = inet_ntoa(tmp_addr->sin_addr);
		DBG("[RsNIC] Got an active interface: %s (%i) with address %s\n",
		    ifa->ifa_name,ifidx,tmp_addr_str);
		rsnic->parent_ifidx = ifidx;

		/* Bind raw socket to parent interface */
		bindaddr.sll_family = AF_PACKET;
		bindaddr.sll_protocol = htons(ETH_P_ALL);
		bindaddr.sll_ifindex = rsnic->parent_ifidx;
		bindaddr.sll_pkttype = PACKET_HOST;

		ret = bind(rsnic->fd, (struct sockaddr *)&bindaddr, sizeof(bindaddr));
		if(ret < 0) {
			perror(BRIGHT RED "[RsNIC] Couldn't bind socket to parent, bind()");
			ret = -errno;
		}
		break;
	}

	freeifaddrs(ifaddr);

	if (!rsnic->parent_ifidx) {
		ERR("[RsNIC] Could not find parent interface\n");
		close(temp_fd);
		free(rsnic);
		rsnic = NULL;
		return -EIO;
	}

 found:
	/* Use its MAC address as our own */
	ret = ioctl(temp_fd, SIOCGIFHWADDR, &ifr);
	if (ret < 0) {
		perror(BRIGHT RED "[RsNIC] Could not get parent's MAC address");
	}

	mac_set_bytes(&rsnic->smac_addr, (const uint8_t*)ifr.ifr_hwaddr.sa_data);
	/* If it's a tap interface pretend we are a different NIC behind it, also
	 * don't close temp_fd since it's rsnic->fd */
	if (rsnic->istap)
		rsnic->smac_addr.bytes[5]++;
	else
		close(temp_fd);

	DBG("[RsNIC] MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
	    rsnic->smac_addr.bytes[0], rsnic->smac_addr.bytes[1],
	    rsnic->smac_addr.bytes[2], rsnic->smac_addr.bytes[3],
	    rsnic->smac_addr.bytes[4], rsnic->smac_addr.bytes[5]);

	return 0;
}

void
eth_close(void)
{
	if (!rsnic)
		return;

	if(rsnic->fd) {
		close(rsnic->fd);
		rsnic->fd = 0;
	}

	free(rsnic);
	rsnic = NULL;
}

#endif /* HOST_TEST */
