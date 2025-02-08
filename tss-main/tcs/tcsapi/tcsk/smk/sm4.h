/**
 * \file sm4.h
 */
#ifndef __SM4_H__
#define __SM4_H__


#define FM_ALGMODE_ECB	0
#define FM_ALGMODE_CBC	1

/**
 * \brief          SM4 context structure
 */
typedef struct {
    unsigned long sk[32];       /*!<  SM4 subkeys       */
    unsigned char iv[16];		/*!<  SM4 iv			*/
}
sm4_context;


#ifdef __cplusplus
extern "C" {
#endif

/************************************************************************/
/* sm4_importkey				                                        */
/* \brief			����key �� iv                                       */
/* \param ctx		SM4 ������                                          */
/* \param key		SM4 ��Կ											*/
/* \param iv		SM4 CBC ģʽ��ʼ����								*/
/************************************************************************/
void httc_sm4_importkey(sm4_context *ctx, unsigned char key[16], unsigned char iv[16]);

/************************************************************************/
/* sm4_encrypt															*/
/* \brief			ʹ�� ctx �� key �� iv ����							*/
/* \param ctx		SM4 ������                                          */
/* \param mode		����ģʽ FM_ALGMODE_ECB / FM_ALGMODE_CBC			*/
/* \param input		���뻺����											*/
/* \param ilen		���뻺������С										*/
/* \param output	���������											*/
/* \param olen		�����������С										*/
/* \remark			output ���� NULL ʱ�����س��ȣ�����������㹻���ڴ�	*/
/************************************************************************/
void httc_sm4_encrypt(sm4_context *ctx, int mode, unsigned char *input, int ilen,
                 unsigned char *output, int *olen);

/************************************************************************/
/* sm4_decrypt															*/
/* \brief			ʹ�� ctx �� key �� iv ����							*/
/* \param ctx		SM4 ������                                          */
/* \param mode		����ģʽ FM_ALGMODE_ECB / FM_ALGMODE_CBC			*/
/* \param input		���뻺����											*/
/* \param ilen		���뻺������С										*/
/* \param output	���������											*/
/* \param olen		�����������С										*/
/* \remark			output �����������ͬ����С���ڴ�					*/
/************************************************************************/
void httc_sm4_decrypt(sm4_context *ctx, int mode, unsigned char *input, int ilen,
                 unsigned char *output, int *olen);

#ifdef __cplusplus
}
#endif	/** __SM4_H__ */

#endif
