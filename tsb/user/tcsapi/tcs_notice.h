#ifndef __TCS_NOTICE_DEF_H__
#define __TCS_NOTICE_DEF_H__

enum{
	NOTICE_BLOCK_EXIT,					//��ֹ֪ͨ����
	NOTICE_TRUSTED_STATUS_CHANGED,		//����״̬�ı�
	NOTICE_LICENSE_STATUS_CHANGED,		//License��Ȩ״̬�ı�
	NOTICE_POLICIES_VERSION_UPDATED,	//���԰汾����
	NOTICE_TNC_AGREEMENTA_FAILED,		//����Э��ʧ��
	NOTICE_TNC_CREATE_SESSION,			//�����Ự֪ͨ
	NOTICE_TNC_DELETE_SESSION,			//(����)ɾ���Ự֪ͨ
	NOTICE_TNC_SESSION_EXPIRE_ALL,		//�Ự����֪ͨ(����ɾ��)
	NOTICE_TNC_SESSION_EXPIRE_HALF,		//�Ự�������֪ͨ(˫��䵥��)
	NOTICE_POLICIES_SOURCE_UPDATED,		//������Դ����
};

#endif

