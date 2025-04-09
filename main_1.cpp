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
#define BUFSIZE 8192

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

uint32_t get_ip(char *dev)
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
	if (ioctl(sock, SIOCGIFADDR, &ifr) < 0)
	{
		perror("ioctl");
		close(sock);
		exit(1);
	}
	close(sock);

	return ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
}

int main(int argc, char *argv[])
{
	if (argc < 4 || argc != 2) // 인자가 최소 4개여야 함
	{
		usage();
		return EXIT_FAILURE;
	}

	s_Mac attacker_mac = get_mac(argv[1]);
	uint32_t attacker_ip = get_ip(argv[1]);

	for (int i = 1; i <= (argc - 2) / 2; i++)
	{
		char attack_mac[18] = "";
		sprintf(attack_mac, "%02x:%02x:%02x:%02x:%02x:%02x", attacker_mac.addr[0], attacker_mac.addr[1], attacker_mac.addr[2], attacker_mac.addr[3], attacker_mac.addr[4], attacker_mac.addr[5]);
		pcap_t *handle = pcap_open_live(argv[1], BUFSIZE, 1, 1, errbuf);
		if (handle == nullptr)
		{
			fprintf(stderr, "couldn't open device %s(%s)\n", argv[1], errbuf);
			return EXIT_FAILURE;
		}
		EthArpPacket packet;

		// send arp request packet
		packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF"); // broadcast MAC address
		packet.eth_.smac_ = Mac(attack_mac);		  // Attacker's MAC address
		packet.eth_.type_ = htons(EthHdr::Arp);		  // ARP type
		packet.arp_.hrd_ = htons(ArpHdr::ETHER);	  // Ethernet hardware type
		packet.arp_.pro_ = htons(EthHdr::Ip4);		  // IPv4 protocol type
		packet.arp_.hln_ = Mac::Size;				  // MAC address length
		packet.arp_.pln_ = Ip::Size;				  // IP address length
		packet.arp_.op_ = htons(ArpHdr::Request);	  // ARP request operation
		packet.arp_.smac_ = Mac(attack_mac);		  // Attacker's MAC address
		packet.arp_.sip_ = htonl(Ip(attacker_ip));	  // Attacker's IP address
		packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); // Target MAC address (unknown)
		packet.arp_.tip_ = htonl(Ip(argv[2 * i]));	  // Target IP address (sender IP). argv[2*i + 2]인지 확인.

		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packet), sizeof(EthArpPacket));
		if (res != 0)
		{
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}

		//capture arp reply packet
		while(1){
			printf("waiting arp reply packet...\n");
			struct pcap_pkthdr *header;
			const u_char *packet;
			int res = pcap_next_ex(handle, &header, &packet);
			if (res == 0)
				continue; // Timeout expired, 재시도
			if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
			{
				fprintf(stderr, "pcap_next_ex return %d error=%s\n", res, pcap_geterr(handle));
				break;
			}
			printf("ARP reply packet captured\n");
			EthArpPacket *victim_packet = reinterpret_cast(const_cast<u_char *>(packet));

			if (victim_packet->arp_.sip_ == packet.arp)
		}

		pcap_close(handle);
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
