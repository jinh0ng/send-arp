#ifndef SEND_ARP_H
#define SEND_ARP_H

#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "mac.h"
#include "ip.h"

#define BUFSIZE 8192
#define MAC_SIZE 6
#define IP_SIZE 4

#pragma pack(push, 1)
struct EthArpPacket
{
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

// MAC 주소를 저장하는 구조체
typedef struct MacAddress
{
    uint8_t address[MAC_SIZE];
} s_MacAddress;

// 인터페이스 이름을 받아 해당 인터페이스의 MAC 주소를 s_MacAddress로 반환
s_MacAddress getMacAddress(char *interfaceName);

// 인터페이스 이름을 받아 해당 인터페이스의 IP 주소를 (네트워크 바이트 순서로) 반환
uint32_t getIpAddress(char *interfaceName);

void macToStrC(const s_MacAddress *mac, char *buf, size_t bufSize);

pcap_t *openPcapHandle(const char *dev);

EthArpPacket createArpRequest(const char *attackerMacStr, uint32_t attackerIp, const char *senderIp);

bool waitForArpReply(pcap_t *handle, const EthArpPacket &request, EthArpPacket &reply);

EthArpPacket createSpoofedReply(const char *attackerMacStr,
                                const char *senderIp,
                                const char *targetIp,
                                const Mac &victimMac);

#endif