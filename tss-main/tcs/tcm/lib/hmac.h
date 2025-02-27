/********************************************************************************/
/*										*/
/*			     	TCM HMAC					*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: hmac.h 4073 2010-04-30 14:44:14Z kgoldman $			*/
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

#ifndef HMAC_H
#define HMAC_H

#include <oiaposap.h>

uint32_t TSS_authhmac1(unsigned char *digest, unsigned char *key, unsigned int keylen,
                       unsigned char *h1, unsigned char h2, ...);
uint32_t TSS_authhmac2(unsigned char *digest, unsigned char *key, unsigned int keylen,
                       unsigned char *authdata, unsigned char *h1, unsigned char h2, ...);
uint32_t TSS_checkhmac1(const struct tcm_buffer *tb, uint32_t command,
                        unsigned char *seq, unsigned char *key, unsigned int keylen, ...);

uint32_t TSS_AuthHMAC3(unsigned char *digest, const unsigned char *key, unsigned int keylen,
                       unsigned int h1len, unsigned char *h1, ...);
TCM_RESULT TSS_CheckHMAC3(TCM_BOOL *valid,
                          TCM_HMAC expect,
                          const TCM_SECRET key,
                          unsigned int h1len, unsigned char *h1, ...);
uint32_t TSS_checkhmac2(const struct tcm_buffer *tb, uint32_t command,
                        unsigned char *seq, unsigned char *entityauth, unsigned char *key, unsigned int keylen, ...);
uint32_t TSS_checkhmac3(const struct tcm_buffer *tb, uint32_t command,
                        unsigned char *seq, unsigned char *entityauth, unsigned char *key, unsigned int keylen, ...);

uint32_t TSS_checkhmac1New(const struct tcm_buffer *tb, uint32_t command,
                           unsigned char *seq, unsigned char *key, unsigned int keylen, ...);

uint32_t TSS_rawhmac(unsigned char *digest, const unsigned char *key, unsigned int keylen, ...);

#endif
