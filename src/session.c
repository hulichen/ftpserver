#include"session.h"
#include"ftpproto.h"
#include"privparent.h"

void begin_session(session_t *sess)
{
	pid_t pid = fork();//会话子进程中创建子进程
	if(pid == -1)
		ERR_EXIT("session fork");

	if(pid == 0)
	{
		//子进程 -- ftp 服务进程  主要针对客户端通信-->ftpproto模块
		handle_child(sess);
	}
	else
	{
		//父进程 -- nobody 进程-->privparent模块

		//更改nobody进程的信息
		struct passwd *pwd = getpwnam("nobody"); //获取nobody用户信息
		if(pwd == NULL)
			ERR_EXIT("getpwnam error");
		if(setegid(pwd->pw_gid) < 0)  //设置群组gid      0成功   -1失败  
			ERR_EXIT("setegid error");
		if(seteuid(pwd->pw_uid) < 0)  //设置uid        0成功   -1失败
			ERR_EXIT("seteuid error");

		handle_parent(sess);
	}
}