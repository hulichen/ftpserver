//配置文件解析
#ifndef _PARSE_CONF_H_
#define _PARSE_CONF_H_

#include"common.h"

void parseconf_load_file(const char* path); //加载配置文件
void parseconf_load_setting(const char* setting);  //将配置项加载到向应的变量


#endif /* _PARSE_CONF_H_ */