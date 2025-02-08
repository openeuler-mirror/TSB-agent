/*
 * file_protect.h
 *
 */

#ifndef TCS_FILE_PROTECT_H_
#define TCS_FILE_PROTECT_H_
#include "tcs_file_protect_def.h"

/*
 * 	��ȡ�ļ���������
 */
int tcs_get_file_protect_policy(struct file_protect_item **items, int *num, int *length);//proc ����



/*
 * 	�����ļ���������
 * 	���á����ӡ�ɾ����
 */

int tcs_update_file_protect_policy(
		struct file_protect_update *references,
		const char *uid,int auth_type,
		int auth_length,unsigned char *auth);

#endif /* TCS_FILE_PROTECT_H_ */
