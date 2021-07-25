#include"sysutil.h"
#include"session.h"

int main(int argc, char *argv[])  //主进程
{
	//判断是否为root用户启动
	if(getuid() != 0)
	{
		printf("miniftp : must be started as root.\n");
		exit(EXIT_FAILURE);
	}

	//会话结构初始化
		session_t sess = 
	{
		//控制连接
		-1, -1, "", "", "",
		
		//数据连接
		NULL,

		//ftp协议状态
		1
	};
	int listenfd = tcp_server("172.17.0.4",  9100);

	int sockConn;
	struct sockaddr_in addrCli; //客户端地址
	socklen_t addrlen;
	while(1)
	{
		sockConn = accept(listenfd, (struct sockaddr*)&addrCli, &addrlen);//接收新建的套接字
		if(sockConn < 0)
		{
			perror("accept error");
			continue;
		}

		pid_t pid = fork();
		if(pid == -1)
			ERR_EXIT("fork  error");

		if(pid == 0) //子进程
		{
			close(listenfd);//关闭不用的套接字
			sess.ctrl_fd = sockConn;  //获取客户端和服务端之间通信创建的套接字
			begin_session(&sess);
			exit(EXIT_SUCCESS);
		}
		else  //父进程
		{
			close(sockConn);//关闭不用的套接字
		}
	}
	
	close(listenfd);
	return 0;
}