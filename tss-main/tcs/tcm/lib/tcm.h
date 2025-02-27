/********************************************************************************/
/*										*/
/*			     	TCM Utilities					*/
/*			     Written by J. Kravitz     				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: tcm.h 4633 2011-10-11 00:28:56Z stefanb $			*/
/*										*/
/* (c) Copyright IBM Corporation 2006, 2010.					*/
/*										*/
/* All rights reserved.								*/
/* 										*/
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/* 										*/
/* Redistributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/* 										*/
/* Redistributions in binary form must reproduce the above copyright		*/
/* notice, this list of conditions and the following disclaimer in the		*/
/* documentation and/or other materials provided with the distribution.		*/
/* 										*/
/* Neither the names of the IBM Corporation nor the names of its		*/
/* contributors may be used to endorse or promote products derived from		*/
/* this software without specific prior written permission.			*/
/* 										*/
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		*/
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		*/
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	*/
/* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		*/
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	*/
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/********************************************************************************/

#ifndef TCM_H
#define TCM_H

#include <string.h>
#include <stdint.h>
#ifdef TCM_POSIX
#include <netinet/in.h>
#endif
#ifdef TCM_WINDOWS
#include <winsock2.h>
#endif

#define ERR_MASK             0x80000000 /* mask to define error state */
/* keep 0x8001000 unassigned since the bash only sees the lowest byte! */
#define ERR_DUMMY            0x80001000
#define ERR_HMAC_FAIL        0x80001001 /* HMAC authorization verification failed */
#define ERR_NULL_ARG         0x80001002 /* An argument was NULL that shouldn't be */
#define ERR_BAD_ARG          0x80001003 /* An argument had an invalid value */
#define ERR_CRYPT_ERR        0x80001004 /* An error occurred in an OpenSSL library call */
#define ERR_IO               0x80001005 /* An I/O Error occurred */
#define ERR_MEM_ERR          0x80001006 /* A memory allocation error occurred */
#define ERR_BAD_FILE         0x80001007 /* File error occurred */
#define ERR_BAD_DATA         0x80001008 /* data read from a stream were bad */
#define ERR_BAD_SIZE         0x80001009 /* the size of the data to send to the TCM is too large */
#define ERR_BUFFER           0x8000100a /* the size of the buffer is too small */
#define ERR_STRUCTURE        0x8000100b /* this is not the stream for the structure to be parsed */
#define ERR_NOT_FOUND        0x8000100c /* searched item could not be found  */
#define ERR_ENV_VARIABLE     0x8000100d /* environment variable is not set */
#define ERR_NO_TRANSPORT     0x8000100e /* no transport allowed for this ordinal */
#define ERR_BADRESPONSETAG   0x8000100f /* bad response tag in message */
#define ERR_SIGNATURE        0x80001010 /* bad signature */
#define ERR_PCR_LIST_NOT_IMA 0x80001011 /* PCR values do not correspond to that in IMA */
#define ERR_CHECKSUM         0x80001012 /* Checksum not correct */
#define ERR_BAD_RESP         0x80001013 /* response from TCM not formatted correctly */
#define ERR_BAD_SESSION_TYPE 0x80001014 /* session type choice is not good */
#define ERR_BAD_FILE_CLOSE   0x80001015 /* close() or fclose() failed */
#define ERR_BAD_FILE_WRITE   0x80001016 /* write() failed */
#define ERR_BAD_FILE_READ    0x80001017 /* read() failed */
#define ERR_TTD_DEV			 0x80001018 /* tcm_ttd dev open or close fail*/	
#define ERR_LAST             0x80001019 /* keep this as the last error code !!!! */
#define TCM_MAX_BUFF_SIZE              4096
#define TCM_HASH_SIZE                  32
#define TCM_NONCE_SIZE                 32

#define TCM_U16_SIZE                   2
#define TCM_U32_SIZE                   4		

#define TCM_PARAMSIZE_OFFSET           TCM_U16_SIZE  // 2  
#define TCM_RETURN_OFFSET              ( TCM_U16_SIZE + TCM_U32_SIZE ) // 2+4=6
#define TCM_PRIVCODE_OFFSET			( TCM_RETURN_OFFSET + TCM_U32_SIZE) //2+4+4 =10
//#define TCM_DATA_OFFSET                ( TCM_PRIVCODE_OFFSET + TCM_U32_SIZE )//2+4+4+4=14
#define TCM_DATA_OFFSET                ( TCM_PRIVCODE_OFFSET )

static inline void store32(unsigned char *const buffer,
                           int offset,
                           uint32_t value)
{
    int i;
    for (i = 3; i >= 0; i--) {
        buffer[offset + i] = (value & 0xff);
        value >>= 8;
    }
}


static inline void store16(unsigned char *const buffer,
                           int offset,
                           uint16_t value)
{
    int i;
    for (i = 1; i >= 0; i--) {
        buffer[offset + i] = (value & 0xff);
        value >>= 8;
    }
}

#define STORE32(buffer,offset,value)    store32(buffer, offset, value)
#define STORE16(buffer,offset,value)    store16(buffer, offset, value)
#if __BYTE_ORDER == __LITTLE_ENDIAN
# define STORE32N(buffer,offset,value)   memcpy(&buffer[offset], &value, 4);
# define STORE16N(buffer,offset,value)   memcpy(&buffer[offset], &value, 2);
#elif __BYTE_ORDER == __BIG_ENDIAN
# define STORE32N(buffer,offset,value)   STORE32(buffer, offset, value)
# define STORE16N(buffer,offset,value)   STORE16(buffer, offset, value)
#else
# error __BYTE_ORDER not defined
#endif
#define LOAD32(buffer,offset)           load32(buffer, offset)
#define LOAD16(buffer,offset)           load16(buffer, offset)
#define LOAD32N(buffer,offset)          load32N(buffer, offset)
#define LOAD16N(buffer,offset)          load16N(buffer, offset)

#define LOAD8(buffer,offset)          (      (*(uint8_t  *)&(buffer)[(offset)]) )

//host byte order(no need use ntohs/ntohl)
static inline uint32_t load32(const unsigned char *buffer, int offset)
{
    int i;
    uint32_t res = 0;

    for (i = 0; i <= 3; i++) {
        res <<= 8;
        res |= buffer[offset + i];
    }
    return res;
}


static inline uint16_t load16(const unsigned char *buffer, int offset)
{
    int i;
    uint16_t res = 0;

    for (i = 0; i <= 1; i++) {
        res <<= 8;
        res |= buffer[offset + i];
    }
    return res;
}


static inline uint32_t load32N(const unsigned char *buffer, int offset)
{
    uint32_t res;
    memcpy(&res, &buffer[offset], sizeof(res));
    return res;
}

static inline uint16_t load16N(const unsigned char *buffer, int offset)
{
    uint16_t res;
    memcpy(&res, &buffer[offset], sizeof(res));
    return res;
}

#define TCM_CURRENT_TICKS_SIZE  (sizeof(TCM_STRUCTURE_TAG)+2*TCM_U32_SIZE+TCM_U16_SIZE+TCM_NONCE_SIZE)

struct tcm_buffer {
    uint32_t size;
    uint32_t used;
    uint32_t flags;
    unsigned char buffer[TCM_MAX_BUFF_SIZE];
};

enum {
    BUFFER_FLAG_ON_STACK = 1,
};

#define STACK_TCM_BUFFER(X)                    \
	struct tcm_buffer X = {                \
		.size = sizeof( X.buffer ),    \
		.used = 0,                     \
		.flags = BUFFER_FLAG_ON_STACK, \
		.buffer = ""};
#define RESET_TCM_BUFFER(X) \
	(X)->used = 0
#define ALLOC_TCM_BUFFER(X,S) \
	struct tcm_buffer *X = TSS_AllocTCMBuffer(S);
#define FREE_TCM_BUFFER(X) \
	TSS_FreeTCMBuffer(X)
#define SET_TCM_BUFFER(X, src, len) 					\
	do {								\
		uint32_t to_copy = (X)->size > len ? len : (X)->size; 	\
		memcpy((X)->buffer, src, to_copy);			\
		(X)->used = to_copy;					\
	} while (0);
#define IS_TCM_BUFFER_EMPTY(X) \
	((X)->used == 0)

struct tcm_buffer *TSS_AllocTCMBuffer(int len );

static inline struct tcm_buffer *clone_tcm_buffer(struct tcm_buffer *orig      )
{
    struct tcm_buffer *buf = TSS_AllocTCMBuffer(orig->used + 20          );
    if (buf) {
        SET_TCM_BUFFER(buf, orig->buffer, orig->used);
    }
    return buf;
}

#if defined (__x86_64__)
#define OUT_FORMAT(a,b) b
#else
#define OUT_FORMAT(a,b) a
#endif





#endif
