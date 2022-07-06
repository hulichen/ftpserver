#include"session.h"
#include"ftpproto.h"
#include"privparent.h"
#include"privsock.h"

void begin_session(session_t *sess)
{
	priv_sock_init(sess); //初始化ftp和nobody进程通信套接字


	pid_t pid = fork();//会话子进程中创建子进程
	if(pid == -1)
		ERR_EXIT("session fork");

	if(pid == 0)
	{
		
		void priv_sock_set_child_context(session_t * sess); //设置子进程环境
		//子进程 -- ftp 服务进程  主要针对客户端通信-->ftpproto模块
		handle_child(sess);
	}
	else
	{
		void priv_sock_set_parent_context(session_t * sess); //设置父进程环境
		
		//父进程 -- nobody 进程-->privparent模块
		handle_parent(sess);
	}
}