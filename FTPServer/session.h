#ifndef _SESSION_H_
#define _SESSION_H_

#include"common.h"

//�Ự�ṹ
typedef struct session
{
	//��������
  uid_t uid;
  int ctrl_fd;  //�ͻ��˺ͷ����֮��ͨ�Ŵ������׽���
	
  char cmdline[MAX_COMMOND_LINE_SIZE];  //�����н��շ���������
  char cmd[MAX_CMD_SIZE];
  char arg[MAX_ARG_SIZE];

	//��������
	struct sockaddr_in *port_addr;  //�˿ڵ�ַ�ṹ
	int  data_fd;   //���������õ��׽���
	int   pasv_listen_fd;  //���������׽���
	int    data_process;  //�ж��Ƿ�����������״̬�������������ӿ��жϿ���

	//ftpЭ��״̬
	char* rnfr_name;  //��������ļ�ʱ�ļ���ԭʼ����
	int is_ascii;
	unsigned long long restart_pos; //�ϵ�����λ��
	unsigned int  max_clients;  //���������
	unsigned int  max_per_ip;//ÿIP���������
	
	//���ӽ���ͨ��
	int parent_fd;
	int child_fd;

	//����
	unsigned long long transfer_start_sec; //������ʼʱ��-->��
	unsigned long long transfer_start_usec; //������ʼʱ��-->΢��

}session_t;

void begin_session(session_t *sess);

#endif /* _SESSION_H_ */
