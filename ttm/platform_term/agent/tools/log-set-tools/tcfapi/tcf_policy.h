/*
 * policy.h
 *
 *  Created on: 2021��1��12��
 *      Author: wangtao
 */

#ifndef TCFAPI_TCF_POLICY_H_
#define TCFAPI_TCF_POLICY_H_
#include "../tcsapi/tcs_policy_def.h"



//ͨ�ÿ��Ʋ��Թ���
/*
 * ����ȫ�ֿ��Ʋ���
 * uidΪ��ʱ��ѯ���й�����֤��
 */
int tcf_set_global_control_policy(
		struct global_control_policy_update *data,
		const char *uid,int cert_type,
		int auth_length,unsigned char *auth);//proc����������������֤

/*
 * ��ȡȫ�ֿ��Ʋ���
 */

int tcf_get_global_control_policy(struct global_control_policy *policy);//proc ����

/*
 * ��ȡ���Ա���
 * ������ǩ�ģ�
 */

int tcf_get_policy_report(struct policy_report *policy_report,uint64_t nonce);//proc ����


#endif /* TCFAPI_TCF_POLICY_H_ */
