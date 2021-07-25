#include"session.h"
#include"ftpproto.h"
#include"privparent.h"

void begin_session(session_t *sess)
{
	pid_t pid = fork();//�Ự�ӽ����д����ӽ���
	if(pid == -1)
		ERR_EXIT("session fork");

	if(pid == 0)
	{
		//�ӽ��� -- ftp �������  ��Ҫ��Կͻ���ͨ��-->ftpprotoģ��
		handle_child(sess);
	}
	else
	{
		//������ -- nobody ����-->privparentģ��

		//����nobody���̵���Ϣ
		struct passwd *pwd = getpwnam("nobody"); //��ȡnobody�û���Ϣ
		if(pwd == NULL)
			ERR_EXIT("getpwnam error");
		if(setegid(pwd->pw_gid) < 0)  //����Ⱥ��gid      0�ɹ�   -1ʧ��  
			ERR_EXIT("setegid error");
		if(seteuid(pwd->pw_uid) < 0)  //����uid        0�ɹ�   -1ʧ��
			ERR_EXIT("seteuid error");

		handle_parent(sess);
	}
}