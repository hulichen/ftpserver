#include"sysutil.h"
#include"session.h"

int main(int argc, char *argv[])  //������
{
	//�ж��Ƿ�Ϊroot�û�����
	if(getuid() != 0)
	{
		printf("miniftp : must be started as root.\n");
		exit(EXIT_FAILURE);
	}

	//�Ự�ṹ��ʼ��
		session_t sess = 
	{
		//��������
		-1, -1, "", "", "",
		
		//��������
		NULL,

		//ftpЭ��״̬
		1
	};
	int listenfd = tcp_server("172.17.0.4",  9100);

	int sockConn;
	struct sockaddr_in addrCli; //�ͻ��˵�ַ
	socklen_t addrlen;
	while(1)
	{
		sockConn = accept(listenfd, (struct sockaddr*)&addrCli, &addrlen);//�����½����׽���
		if(sockConn < 0)
		{
			perror("accept error");
			continue;
		}

		pid_t pid = fork();
		if(pid == -1)
			ERR_EXIT("fork  error");

		if(pid == 0) //�ӽ���
		{
			close(listenfd);//�رղ��õ��׽���
			sess.ctrl_fd = sockConn;  //��ȡ�ͻ��˺ͷ����֮��ͨ�Ŵ������׽���
			begin_session(&sess);
			exit(EXIT_SUCCESS);
		}
		else  //������
		{
			close(sockConn);//�رղ��õ��׽���
		}
	}
	
	close(listenfd);
	return 0;
}