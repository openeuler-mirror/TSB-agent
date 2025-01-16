#ifndef __TCS_SM_H__
#define __TCS_SM_H__

#include <stdint.h>

/** ����SM3�㷨��ָ�����ݼ���ժҪֵ */
int tcs_sm3 (const uint8_t *input, int ilen, uint8_t *output, int *olen);

/** ����SM4-CBC�㷨��ָ�����ݽ��м��ܣ�keyΪ������Կ */
int tcs_sm4_cbc_encrypt(uint8_t *key, uint8_t *iv, uint8_t *data, uint32_t datalen, uint8_t *blob, uint32_t *bloblen);
/** ����SM4-ECB�㷨��ָ�����ݽ��м��ܣ�keyΪ������Կ */
int tcs_sm4_ecb_encrypt(uint8_t *key, uint8_t *data, uint32_t datalen, uint8_t *blob, uint32_t *bloblen);
/** ����SM4-CBC�㷨��ָ�����ݽ��н��ܣ�keyΪ������Կ */
int tcs_sm4_cbc_decrypt(uint8_t *key, uint8_t *iv,  uint8_t *data, uint32_t datalen, uint8_t *blob, uint32_t *bloblen);
/** ����SM4-ECB�㷨��ָ�����ݽ��н��ܣ�keyΪ������Կ */
int tcs_sm4_ecb_decrypt(uint8_t *key, uint8_t *data, uint32_t datalen, uint8_t *blob, uint32_t *bloblen);

/** ����SM2�㷨��ָ�����ݵ�ժҪֵ����ǩ�� */
int tcs_sm2_sign (uint8_t *privkey, uint8_t *digest, uint32_t digest_len, uint8_t *sig, uint32_t *siglen);

/** ����SM2�㷨��ָ�����ݵ�ժҪֵ������ǩ */
int tcs_sm2_verify (uint8_t *pubkey, uint8_t *digest, uint32_t digest_len, uint8_t *sig, uint32_t siglen);

/** ����SM2�㷨��ָ�����ݽ���ǩ��
	TPCM��ԭʼ�����Ƚ���ѹ������ѹ�������ݽ���ǩ�� */
int tcs_sm2_sign_e (uint8_t *privkey, uint8_t *pubkey, uint8_t *data, uint32_t datalen, uint8_t *sig, uint32_t *siglen);

/** ����SM2�㷨��ָ�����ݽ���ǩ��
	TPCM��ԭʼ�����Ƚ���ѹ������ѹ�������ݽ�����ǩ  */
int tcs_sm2_verify_e (uint8_t *pubkey, uint8_t *data, uint32_t datalen, uint8_t *sig, uint32_t siglen);


/** ��ȡ����� */
int tcs_random (uint8_t *data, uint32_t size);

#endif	/** __TCS_SM_H__ */

