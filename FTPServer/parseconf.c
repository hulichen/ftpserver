//配置文件解析模块
#include"parseconf.h"
#include"tunable.h"
#include"str.h"

//目前支持 bool int 和 str类型的配置项解析，
//如后续还有其他类型，增加其配置项和解析配置项模块即可 

//bool型配置项
static struct parseconf_bool_setting
{
	const char* p_setting_name; //配置项的名字
	int* p_variable;     //配置项的值
}
parseconf_bool_array[] =   //定义bool型配置项的初始值
{
	{"pasv_enable", &tunable_pasv_enable},//配置项-》是否开启被动模式
	{"port_enable", &tunable_port_enable}, //配置项-》是否开启主动模式
	{NULL, NULL}  //NULL为结束标记
};

//int配置项
static struct parseconf_uint_setting
{
	const char* p_setting_name;//配置项的名字
	unsigned int* p_variable;//配置项的值
}
parseconf_uint_array[] =    //定义int型配置项的初始值
{
	{"listen_port", &tunable_listen_port}, //端口
	{"max_clients", &tunable_max_clients}, //最大连接数
	{"max_per_ip" , &tunable_max_per_ip}, //每ip最大连接数
	{"accept_timeout", &tunable_accept_timeout}, //Accept连接超时时间
	{"connect_timeout", &tunable_connect_timeout}, //Connect连接超时时间
	{"idle_session_timeout", &tunable_idle_session_timeout}, //控制连接超时时间
	{"data_connection_timeout", &tunable_data_connection_timeout},//数据连接超时时间
	{"local_umask", &tunable_local_umask}, //掩码
	{"upload_max_rate", &tunable_upload_max_rate}, //最大上传速度
	{"download_max_rate", &tunable_download_max_rate},// 最大下载速度
	{NULL, NULL}
};


//str配置项
static struct parseconf_str_setting
{
	const char* p_setting_name;
	const char** p_variable;
}
parseconf_str_array[] =
{
	{"listen_address", &tunable_listen_address}, //监听地址
	{NULL, NULL}
};


void parseconf_load_file(const char* path) //加载文件
{
	FILE* fp = fopen(path, "r");  //只读打开
	if (NULL == fp)
		ERR_EXIT("parseconf_load_file");

	char setting_line[MAX_SETTING_LINE_SIZE] = { 0 };
	while (fgets(setting_line, MAX_SETTING_LINE_SIZE, fp) != NULL) //循环读取配置信息，解析
	{
		if (setting_line[0] == '\0' || setting_line[0] == '#')  //屏蔽掉空行和#开头的注释行
			continue;
		str_trim_crlf(setting_line); //去掉字符串的回车和换行

		//解析配置行
		parseconf_load_setting(setting_line);

		memset(setting_line, 0, MAX_SETTING_LINE_SIZE);
	}

	fclose(fp);
}

//listen_port=9100
void parseconf_load_setting(const char* setting)  
//配置项(setting)解析，需要保存解析到的数据，将读取到的配置文件信息保存到定义的全局变量中
{
	char key[MAX_KEY_SIZE] = { 0 };
	char value[MAX_VALUE_SIZE] = { 0 };
	str_split(setting, key, value, '=');//根据=分割配置项key=val;

	//查询str配置项
	//定义一结构体数据指针指向str配置项数组首元素
	const struct parseconf_str_setting* p_str_setting = parseconf_str_array;
	while (p_str_setting->p_setting_name != NULL)//配置项数组不空
	{
		if (strcmp(key, p_str_setting->p_setting_name) == 0)//通过配置项名字查找配置项是否存在
		{
			const char** p_cur_setting = p_str_setting->p_variable;
			if (*p_cur_setting) //释放上一次保存数据开辟的空间
				free((char*)*p_cur_setting);
			*p_cur_setting = strdup(value);//将valuek拷贝到p_cur_setting中，strdup会自动在底层malloc空间
			return;
		}
		p_str_setting++; //读取配置项数组下一行
	}

	//查询bool配置项  0/1开关类 
	const struct parseconf_bool_setting* p_bool_setting = parseconf_bool_array;
	while (p_bool_setting->p_setting_name != NULL)
	{
		if (strcmp(key, p_bool_setting->p_setting_name) == 0)
		{
			str_upper(value); //yes->YES
			int* p_cur_setting = p_bool_setting->p_variable;
			if (strcmp(value, "YES") == 0)
				*p_cur_setting = 1;
			else if (strcmp(value, "NO") == 0)
				*p_cur_setting = 0;
			else
				ERR_EXIT("parseconf_load_setting");
			return;
		}
		p_bool_setting++;
	}

	//查询int配置项  
	const struct parseconf_uint_setting* p_uint_setting = parseconf_uint_array;
	while (p_uint_setting->p_setting_name != NULL)
	{
		if (strcmp(key, p_uint_setting->p_setting_name) == 0)
		{
			unsigned int* p_cur_setting = p_uint_setting->p_variable;
			*p_cur_setting = atoi(value);//解析完的数据为一个str
			return;
		}
		p_uint_setting++;
	}
}