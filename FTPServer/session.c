#include"session.h"
#include"ftpproto.h"
#include"privparent.h"
#include"privsock.h"

void begin_session(session_t *sess)
{
	priv_sock_init(sess); //��ʼ��ftp��nobody����ͨ���׽���


	pid_t pid = fork();//�Ự�ӽ����д����ӽ���
	if(pid == -1)
		ERR_EXIT("session fork");

	if(pid == 0)
	{
		
		void priv_sock_set_child_context(session_t * sess); //�����ӽ��̻���
		//�ӽ��� -- ftp �������  ��Ҫ��Կͻ���ͨ��-->ftpprotoģ��
		handle_child(sess);
	}
	else
	{
		void priv_sock_set_parent_context(session_t * sess); //���ø����̻���
		
		//������ -- nobody ����-->privparentģ��
		handle_parent(sess);
	}
}