/*系统工具模块*/
#include"sysutil.h"

int tcp_server(const char *host, unsigned short port)  //创建服务器TCP连接套接字
{
	int listenfd;
	if((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)  //创建套接字
		ERR_EXIT("sys create socket error");

    //绑定地址
	struct sockaddr_in addrSer;
	addrSer.sin_family = AF_INET;
	addrSer.sin_port = htons(port);
	addrSer.sin_addr.s_addr = inet_addr(host);

	//设置地址重用  man setsockopt 查看
	int on = 1;
	if(setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
		ERR_EXIT("sys setsockopt");

	if(bind(listenfd, (struct sockaddr*)&addrSer, sizeof(addrSer)) < 0)
		ERR_EXIT("sys bind error");

	if(listen(listenfd, SOMAXCONN) < 0)
		ERR_EXIT("sys listen error");

	return listenfd;
}