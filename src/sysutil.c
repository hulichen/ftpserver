/*ϵͳ����ģ��*/
#include"sysutil.h"

int tcp_server(const char *host, unsigned short port)  //����������TCP�����׽���
{
	int listenfd;
	if((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)  //�����׽���
		ERR_EXIT("sys create socket error");

    //�󶨵�ַ
	struct sockaddr_in addrSer;
	addrSer.sin_family = AF_INET;
	addrSer.sin_port = htons(port);
	addrSer.sin_addr.s_addr = inet_addr(host);

	//���õ�ַ����  man setsockopt �鿴
	int on = 1;
	if(setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
		ERR_EXIT("sys setsockopt");

	if(bind(listenfd, (struct sockaddr*)&addrSer, sizeof(addrSer)) < 0)
		ERR_EXIT("sys bind error");

	if(listen(listenfd, SOMAXCONN) < 0)
		ERR_EXIT("sys listen error");

	return listenfd;
}