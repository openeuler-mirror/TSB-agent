#include "ec.h"
#include "../SM3/sm3.h"

#define SM2_ERR_NOERR			0
#define SM2_ERR_INIT_FAILED		1
#define SM2_ERR_MALLOC_FAILED	2
#define SM2_ERR_BAD_PARAM		3
#define SM2_ERR_EC_LIB			4
#define SM2_ERR_BN_LIB			5
#define SM2_ERR_RANDOM_FAILED	6
#define SM2_ERR_BAD_SIGNATURE	7
#define SM2_ERR_PRIVATEKEY		8
#define SM2_ERR_PUBLICKEY		9
#define SM2_ERR_DECRYPT			10
#define SM2_ERR_DH_FAILED		11

#define SM2_BIGNUM_BUFSIZE		32
#define SM2_ECPOINT_BUFSIZE		65

typedef struct  
{
	unsigned int bits;
	unsigned char d[SM2_BIGNUM_BUFSIZE];
} SM2_PRIVATE_KEY;

typedef struct
{
	unsigned int bits;
	unsigned char x[SM2_BIGNUM_BUFSIZE];
	unsigned char y[SM2_BIGNUM_BUFSIZE];
} SM2_PUBLIC_KEY;

typedef struct  
{
	unsigned char r[SM2_BIGNUM_BUFSIZE];
	unsigned char s[SM2_BIGNUM_BUFSIZE];
} SM2_SIGNATURE;

#ifdef __cplusplus
extern "C" {
#endif


/************************************************************************/
/* sm2_init																*/
/* \brief			��ʼ����Բ���߲���                                  */
/* \param ecgroup	��Բ���߲���                                        */
/* \return			0 �ɹ���ʧ�ܷ�����Ӧ�������						*/
/* \remark			sm2_init_standard ������֤�����淶					*/
/************************************************************************/
int sm2_init(EC_GROUP **ecgroup);
int sm2_init_standard(EC_GROUP **ecgroup);

/************************************************************************/
/* sm2_cleanup															*/
/* \brief			�ͷ���Բ���߲���ռ�õ��ڴ�                          */
/* \param ecgroup	��Բ���߲���                                        */
/************************************************************************/
void sm2_cleanup(EC_GROUP *ecgroup);

/************************************************************************/
/* sm2_gen_keypair														*/
/* \brief			������˽Կ��	                                    */
/* \param ecgroup	��Բ���߲���                                        */
/* \param privatekey˽Կ												*/
/* \param publickey	��Կ												*/
/* \return			0 �ɹ���ʧ�ܷ�����Ӧ�������						*/
/* \remark			privatekey/publickey ���� NULL ʱ�����س��ȣ�		*/
/*					����������㹻���ڴ�								*/
/*					sm2_init_standard* ������֤�����淶					*/
/************************************************************************/
int sm2_gen_keypair(const EC_GROUP *ecgroup, SM2_PRIVATE_KEY *privatekey, SM2_PUBLIC_KEY *publickey);
int sm2_gen_keypair_standard1(const EC_GROUP *ecgroup, SM2_PRIVATE_KEY *privatekey, SM2_PUBLIC_KEY *publickey);
int sm2_gen_keypair_standard2_a(const EC_GROUP *ecgroup, SM2_PRIVATE_KEY *privatekey, SM2_PUBLIC_KEY *publickey);
int sm2_gen_keypair_standard2_b(const EC_GROUP *ecgroup, SM2_PRIVATE_KEY *privatekey, SM2_PUBLIC_KEY *publickey);
int sm2_gen_keypair_standard3(const EC_GROUP *ecgroup, SM2_PRIVATE_KEY *privatekey, SM2_PUBLIC_KEY *publickey);
int sm2_gen_keypair_standard5(const EC_GROUP *ecgroup, SM2_PRIVATE_KEY *privatekey, SM2_PUBLIC_KEY *publickey);

/************************************************************************/
/* sm2_dh_key															*/
/* \brief			���� ECC ����������Կ                               */
/* \param ecgroup	��Բ���߲���                                        */
/* \param Za		���������Ϣ										*/
/* \param Zb		���շ������Ϣ										*/
/* \param privatekey˽Կ												*/
/* \param publickey	�Է���Կ											*/
/* \param a_r		���������											*/
/* \param R_b		�Է���Բ���ߵ�										*/
/* \param keylen	��Ҫ��ȡ�Ĺ�����Կ����								*/
/* \param keylen	������Կ���������									*/
/* \return			0 �ɹ���ʧ�ܷ�����Ӧ�������						*/
/* \remark			sm2_init_standard* ������֤�����淶					*/
/************************************************************************/
int sm2_dh_key(const EC_GROUP *ecgroup, const unsigned char Za[SM3_DIGEST_SIZE], const unsigned char Zb[SM3_DIGEST_SIZE],
	const SM2_PRIVATE_KEY *a_pri_key, const SM2_PUBLIC_KEY *b_pub_key, const unsigned char a_r[SM2_BIGNUM_BUFSIZE],
	const unsigned char R_b[SM2_ECPOINT_BUFSIZE], unsigned int keylen, unsigned char *outkey);

/************************************************************************/
/* sm2_encrypt															*/
/* \brief			��Կ����		                                    */
/* \param ecgroup	��Բ���߲���                                        */
/* \param publickey	��Կ												*/
/* \param input		���뻺����											*/
/* \param ilen		���뻺��������										*/
/* \param output	���������											*/
/* \param olen		�������������										*/
/* \return			0 �ɹ���ʧ�ܷ�����Ӧ�������						*/
/* \remark			output ���� NULL ʱ�����س��ȣ�����������㹻���ڴ�	*/
/* \remark			sm2_encrypt_standard ������֤�����淶				*/
/************************************************************************/
int sm2_encrypt(const EC_GROUP *ecgroup, const SM2_PUBLIC_KEY *publickey, const unsigned char *input, unsigned int ilen,
	unsigned char *output, unsigned int *olen);
int sm2_encrypt_standard(const EC_GROUP *ecgroup, const SM2_PUBLIC_KEY *publickey, const unsigned char *input, unsigned int ilen,
	unsigned char *output, unsigned int *olen);

/************************************************************************/
/* sm2_decrypt															*/
/* \brief			˽Կ����		                                    */
/* \param ecgroup	��Բ���߲���                                        */
/* \param publickey	˽Կ												*/
/* \param input		���뻺����											*/
/* \param ilen		���뻺��������										*/
/* \param output	���������											*/
/* \param olen		�������������										*/
/* \return			0 �ɹ���ʧ�ܷ�����Ӧ�������						*/
/* \remark			output ���� NULL ʱ�����س��ȣ�����������㹻���ڴ�	*/
/************************************************************************/
int sm2_decrypt(const EC_GROUP *ecgroup, const SM2_PRIVATE_KEY *privatekey, const unsigned char *input, unsigned int ilen,
	unsigned char *output, unsigned int *olen);

/************************************************************************/
/* sm2_sign																*/
/* \brief			˽Կǩ��		                                    */
/* \param ecgroup	��Բ���߲���                                        */
/* \param privatekey˽Կ												*/
/* \param Z			ǩ���������Ϣ										*/
/* \param input		���뻺����											*/
/* \param ilen		���뻺��������										*/
/* \param output	ǩ�����											*/
/* \return			0 �ɹ���ʧ�ܷ�����Ӧ�������						*/
/* \remark			input ���ڲ�ʹ�� SM3 �㷨����ժҪ					*/
/*					sm2_sign_standard ������֤�����淶					*/
/************************************************************************/
int sm2_sign(const EC_GROUP *ecgroup, const SM2_PRIVATE_KEY *privatekey, const unsigned char Z[SM3_DIGEST_SIZE],
	const unsigned char *input, unsigned int ilen, SM2_SIGNATURE *output);
int sm2_sign_standard(const EC_GROUP *ecgroup, const SM2_PRIVATE_KEY *privatekey, const unsigned char Z[SM3_DIGEST_SIZE],
	const unsigned char *input, unsigned int ilen, SM2_SIGNATURE *output);

/************************************************************************/
/* sm2_verify															*/
/* \brief			��Կ��֤		                                    */
/* \param ecgroup	��Բ���߲���                                        */
/* \param publickey	��Կ												*/
/* \param Z			ǩ���������Ϣ										*/
/* \param input		���뻺����											*/
/* \param ilen		���뻺��������										*/
/* \param signature	ǩ������											*/
/* \return			0 �ɹ���ʧ�ܷ�����Ӧ�������						*/
/* \remark			input ���ڲ�ʹ�� SM3 �㷨����ժҪ					*/
/************************************************************************/
int sm2_verify(const EC_GROUP *ecgroup, const SM2_PUBLIC_KEY *publickey, const unsigned char Z[SM3_DIGEST_SIZE],
	const unsigned char *input, unsigned int ilen, const SM2_SIGNATURE *signature);

/************************************************************************/
/* sm_gen_random														*/
/* \brief			�����������		                                */
/* \param len		��Ҫ���������������								*/
/* \param output	���������											*/
/* \return			1 �ɹ���0 ʧ��										*/
/************************************************************************/
int sm_gen_random(unsigned int len, unsigned char *output);

/************************************************************************/
/* sm2_dh_gen_random													*/
/* \brief			��ԿЭ������������������                          */
/* \param ecgroup	��Բ���߲���                                        */
/* \param r			�����												*/
/* \param R			��Բ���ߵ�Ķ����Ʊ�ʾ								*/
/* \return			0 �ɹ���ʧ�ܷ�����Ӧ�������						*/
/*					sm2_dh_gen_random_standard* ������֤�����淶		*/
/************************************************************************/
int sm2_dh_gen_random(const EC_GROUP *ecgroup, unsigned char r[SM2_BIGNUM_BUFSIZE], unsigned char R[SM2_ECPOINT_BUFSIZE]);
int sm2_dh_gen_random_standard_a(const EC_GROUP *ecgroup, unsigned char r[SM2_BIGNUM_BUFSIZE], unsigned char R[SM2_ECPOINT_BUFSIZE]);
int sm2_dh_gen_random_standard_b(const EC_GROUP *ecgroup, unsigned char r[SM2_BIGNUM_BUFSIZE], unsigned char R[SM2_ECPOINT_BUFSIZE]);

/************************************************************************/
/* sm_kdf																*/
/* \brief			��Կ��������				                        */
/* \param share		������Կ������                                      */
/* \param sharelen	������Կ����������									*/
/* \param keylen	Ҫ��õ���Կ���ݵĳ���								*/
/* \param keylen	�����Կ������										*/
/************************************************************************/
void sm_kdf(const unsigned char *share, unsigned sharelen, unsigned keylen, unsigned char *outkey);

/************************************************************************/
/* sm2_Z																*/
/* \brief			�����û������Ϣ			                        */
/* \param ecgroup	��Բ���߲���                                        */
/* \param ID		�û� ID												*/
/* \param idlen		�û� ID	����										*/
/* \param publickey	��Կ												*/
/* \param dgst		���������											*/
/* \return			0 �ɹ���ʧ�ܷ�����Ӧ�������						*/
/************************************************************************/
int sm2_Z(const EC_GROUP *ecgroup, const unsigned char *ID, unsigned short idlen, const SM2_PUBLIC_KEY *publickey, unsigned char dgst[SM3_DIGEST_SIZE]);


#define SM2_MALLOC(size) sm2_malloc(size, __FILE__, __LINE__)
#define SM2_FREE(ptr) sm2_free(ptr, __FILE__, __LINE__)

void *sm2_malloc(size_t size,  const char *file, int line);
void sm2_free(void *ptr,  const char *file, int line);




#ifdef __cplusplus
}
#endif
