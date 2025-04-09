#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#pragma pack(push, 1)
struct EthArpPacket final
{
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage()
{
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

////////get MAC and IP of Attacker///////////
struct s_Mac
{
	uint8_t mac[6];
};

s_Mac get_mac(char *dev)
{
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
	{
		perror("socket");
		exit(1);
	}
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
	if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0)
	{
		perror("ioctl");
		close(sock);
		exit(1);
	}
	close(sock);

	s_Mac mac;
	memcpy(mac.addr, ifr.ifr_hwaddr.sa_data, 6);
	return mac;
}

int main(int argc, char *argv[])
{
	if (argc != 2 || argc < 4) // 인자가 최소 4개여야 함
	{
		usage();
		return EXIT_FAILURE;
	}
	{
		usage();
		return EXIT_FAILURE;
	}

	char *dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (pcap == nullptr)
	{
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return EXIT_FAILURE;
	}

	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("00:00:00:00:00:00");
	packet.eth_.smac_ = Mac("00:00:00:00:00:00");
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::Size;
	packet.arp_.pln_ = Ip::Size;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac("00:00:00:00:00:00");
	packet.arp_.sip_ = htonl(Ip("0.0.0.0"));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(Ip("0.0.0.0"));

	int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char *>(&packet), sizeof(EthArpPacket));
	if (res != 0)
	{
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
	}

	pcap_close(pcap);
}
