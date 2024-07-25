#include "pcap.h" 
#pragma comment ( lib, "wpcap.lib")

#define ETH_ARP         0x0806     //以太网帧类型表示后面数据的类型，对于ARP请求或应答来说，该字段的值为x0806
#define ARP_HARDWARE    1          //硬件类型字段值为表示以太网地址
#define ETH_IP          0x0800     //协议类型字段表示要映射的协议地址类型值为x0800表示IP地址
#define ARP_REQUEST     1          //ARP请求
#define ARP_RESPONSE    2          //ARP应答

//14字节以太网首部
struct EthernetHeader
{
	unsigned char DestMAC[6];    //目的MAC地址 6字节
	unsigned char SourMAC[6];   //源MAC地址 6字节
	unsigned short EthType;         //上一层协议类型，如0x0800代表上一层是IP协议，0x0806为arp  2字节
};

//28字节ARP帧结构
struct ArpHeader
{
	unsigned short hdType;   //硬件类型
	unsigned short proType;   //协议类型
	unsigned char hdSize;   //硬件地址长度
	unsigned char proSize;   //协议地址长度
	unsigned short op;   //操作类型，ARP请求（1），ARP应答（2），RARP请求（3），RARP应答（4）。
	unsigned char smac[6];   //源MAC地址
	unsigned char sip[4];   //源IP地址
	unsigned char dmac[6];   //目的MAC地址
	unsigned char dip[4];   //目的IP地址
};

//定义整个arp报文包，总长度42字节
struct ArpPacket {
	EthernetHeader ed;
	ArpHeader ah;
};

pcap_if_t* alldevs;              // 适配器列表
pcap_if_t* d;                   // 选中适配器
pcap_t* adhandle;               // 适配器句柄
char errbuf[PCAP_ERRBUF_SIZE];  // 错误信息缓冲区
//ether proto protocol：如果数据包属于某些以太协议（protocol）类型, 则与此对应的条件表达式为真，协议字段可以是ARP
u_int netmask;                  //子网掩码
char packet_filter[] = "ether proto \\arp";   //要抓取的包的类型，这里是抓取ARP包；
struct bpf_program fcode;       //pcap_compile所调用的结构体
void device_init();
void sent_arp_packet();
void listen_init();
void recv_arp_packet();


int main() {

	device_init();
	sent_arp_packet();
	listen_init();
	recv_arp_packet();
	pcap_freealldevs(alldevs);
	return 0;
}

void device_init() {
	// 获得设备列表
	int inum;                       // 选中适配器的编号
	int i = 0;
	char* devname = _strdup(PCAP_SRC_IF_STRING);
	if (pcap_findalldevs_ex(devname, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	// 打印网络适配器列表
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}
	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return;
	}
	printf("Enter the interface number (1-%d):", i);
	//输入要监听的网络适配卡
	scanf("%d", &inum);
	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		pcap_freealldevs(alldevs); //释放设备列表
		return;
	}
	//跳转到已选网络适配卡
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);
	//打开网络适配卡
	if ((adhandle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n");
		pcap_freealldevs(alldevs); // 释放设备列表
		return;
	}
}

void sent_arp_packet() {
	//开始填充ARP包
	unsigned char sendbuf[42]; //arp包结构大小，42个字节
	unsigned char mac[6] = {0x28,0x7f,0xcf,0xdb,0x9c,0xc3};
	unsigned char sip[4] = {192,168,125,176};
	unsigned char dip[4] = {192,168,125,28};
	EthernetHeader eh;
	ArpHeader ah;
	//赋值MAC地址
	memset(eh.DestMAC, 0xff, 6);    //以太网首部目的MAC地址，全为广播地址
	memcpy(eh.SourMAC, mac, 6);     //以太网首部源MAC地址
	memcpy(ah.smac, mac, 6);        //ARP字段源MAC地址
	memset(ah.dmac, 0xff, 6);       //ARP字段目的MAC地址全为广播地址
	memcpy(ah.sip, sip, 4);         //ARP字段源IP地址
	memcpy(ah.dip, dip, 4);         //ARP字段目的IP地址
	eh.EthType = htons(ETH_ARP);    //htons：将主机的无符号短整形数转换成网络字节顺序
	ah.hdType = htons(ARP_HARDWARE);
	ah.proType = htons(ETH_IP);
	ah.hdSize = 6;
	ah.proSize = 4;
	ah.op = htons(ARP_REQUEST);

	//构造一个ARP请求
	memset(sendbuf, 0, sizeof(sendbuf));   //ARP清零
	memcpy(sendbuf, &eh, sizeof(eh));
	memcpy(sendbuf + sizeof(eh), &ah, sizeof(ah));
	//如果发送成功
	if (pcap_sendpacket(adhandle, sendbuf, 42) == 0) {
		printf("\nPacketSend succeed\n");
	}
	else {
		printf("PacketSendPacket in getmine Error: %d\n", GetLastError());
	}
}

void listen_init() {
	/* 检查数据链路层，为了简单，我们只考虑以太网 */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return;
	}

	if (d->addresses != NULL)
		/* 获得接口第一个地址的掩码 */
		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* 如果接口没有地址，那么我们假设一个C类的掩码 */
		netmask = 0xffffff;

	//编译过滤器
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return;
	}

	//设置过滤器
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return;
	}

	printf("\nlistening on %s...\n", d->description);

	/* 释放设备列表 */
	pcap_freealldevs(alldevs);
}

void recv_arp_packet() {
	/* 获取数据包 */
	int res;                       //抓包函数pcap_next_ex返回值，1-成功、0：获取报文超时、-1：发生错误、-2: 获取到离线记录文件的最后一个报文
	struct tm* ltime;              //和时间处理有关的变量 
	char timestr[16];              //和时间处理有关的变量
	time_t local_tv_sec;           //和时间处理有关的变量
	struct pcap_pkthdr* header;    //接收到的数据包的头部
	const u_char* pkt_data;        //接收到的数据包的内容
	int i;
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {

		if (res == 0)
			/* 超时时间到 */
			continue;

		//解析ARP包
		ArpHeader* arph = (ArpHeader*)(pkt_data + 14);

		//类型 
		printf("报文类型：");
		if (arph->op == 256)
			printf("请求报文\t");
		else
			printf("应答报文\t");

		//长度
		printf("长度(B)：%d\t", header->len);

		//时间
		/* 将时间戳转换成可识别的格式 */
		local_tv_sec = header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

		printf("时间：%s\n", timestr);


		//输出源IP
		printf("源IP：");
		for (i = 0; i < 3; i++)
		{
			printf("%d.", arph->sip[i]);
		}
		printf("%d\t", arph->sip[3]);

		//输出目的IP
		printf("目的IP：");
		for (i = 0; i < 3; i++)
		{
			printf("%d.", arph->dip[i]);

		}
		printf("%d\n", arph->dip[3]);

		//输出源MAC
		printf("源MAC：");
		for (i = 0; i < 5; i++)
		{
			printf("%02x-", arph->smac[i]);
		}
		printf("%02x\t", arph->smac[5]);

		//输出目的MAC
		printf("目的MAC：");
		for (i = 0; i < 5; i++)
		{
			printf("%02x-", *(pkt_data + i));
		}
		printf("%02x\n", *(pkt_data + 5));

		printf("------------------------------------------------------------------\n");

	}

	if (res == -1) {   //接收ARP包出错
		printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
		return;
	}
}