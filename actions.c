//#define ECLIPSE

#ifndef ECLIPSE
#include <pif_plugin.h>
#include <nfp/me.h>
#include <nfp/mem_atomic.h>
#include <pif_common.h>
#include <memory.h>
#endif

#include <stdint.h>
#include <string.h>

#ifdef ECLIPSE
#include <stdio.h>
#define __ctm
#define __export
#define __mem
#define __lmem
#define PIF_PLUGIN_RETURN_DROP 1
#define PIF_PLUGIN_RETURN_FORWARD 0
#define memset_mem memset
#define memmove_mem_mem memmove
#endif


#define BLOCKLEN 16 //Block length in bytes AES is 128b block only

/* Definition of static buffer size for the payload*/
#define PAYLOAD_BUFFER_SIZE 1500
#define OUT_PAYLOAD_BUFFER_SIZE (PAYLOAD_BUFFER_SIZE+BLOCKLEN)


#define TYPE_NDN_DATA 0x06
#define TYPE_NDN_SIGNATURE_INFO 0x16
#define TYPE_NDN_SIGNATURE_VALUE 0x17

#define TYPE_ENCRYPT_ME_HEADER 33000
#define TYPE_ENCRYPT_ME_HEADER_CIPHER_SUITE 33001
#define TYPE_ENCRYPT_ME_HEADER_KEY_ID 33002
#define TYPE_ENCRYPT_ME_ENCRYPTED_CONTENT 0x80eb


/* Definitions for CIpher Suite TLV*/
#define CIPHER_SUITE_NONE 0
#define CIPHER_SUITE_AES_128_CBC 0x77
#define CIPHER_SUITE_AES_192_CBC 2
#define CIPHER_SUITE_AES_256_CBC 3
/* End of definitions for CIpher Suite TLV*/

#define BUFFER_TYPE_INCREASE 3
#define BUFFER_LENGTH_INCREASE 3

/* Payload chunk size in LW (32-bit) and bytes */
#define CHUNK_LW 8
#define CHUNK_B (CHUNK_LW*4)


/****************************** SHA256 MACROS ******************************/
#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

/****************************** END SHA256 MACROS ******************************/

#define SHA256_BLOCK_SIZE 32            // SHA256 outputs a 32 byte digest


/**************************** Definitions for Signature Info and Signature Value TLVs ****************************/
#define SIG_VALUE_T_SIZE 1
#define SIG_VALUE_L_SIZE 1
#define SIG_VALUE_V_SIZE SHA256_BLOCK_SIZE
#define SIG_INFO_T_SIZE 1
#define SIG_INFO_L_SIZE 1
#define SIG_INFO_V_SIZE 3
#define SIG_INFO_SIZE (SIG_INFO_T_SIZE + SIG_INFO_L_SIZE + SIG_INFO_V_SIZE)
#define SIG_VALUE_SIZE (SIG_VALUE_T_SIZE + SIG_VALUE_L_SIZE + SIG_VALUE_V_SIZE)
#define NEW_SIGNATURE_SIZE (SIG_INFO_SIZE + SIG_VALUE_SIZE)
/**************************** End of definitions for Signature Info and Signature Value TLVs ****************************/


/**************************** DATA TYPES ****************************/


typedef unsigned char BYTE;             // 8-bit byte
typedef unsigned int  WORD;             // 32-bit word, change to "long" for 16-bit machines


typedef struct {
	BYTE data[64];
	WORD datalen;
	unsigned long long bitlen;
	WORD state[8];
} SHA256_CTX;


typedef struct {
	 uint8_t* contentTLVStartPosition;
	 uint32_t signatureStartOffset;
	 uint32_t signatureInfoAndValueTLVSize;
	 uint8_t* encryptMeHeaderStartPosition;
	 uint32_t contentTLVOffset;
	 uint32_t cipherSuite;
	 uint32_t keyId;
	 uint32_t contentTLVSize;
	 uint32_t encryptMeHeaderTLVSize;
	 uint32_t dataSize;
	 uint32_t dataTLVSize;

} encrypt_me_result;

/* ***************************  *************************** */
volatile __export __mem uint32_t pif_mu_len = 0;
static __export __ctm uint32_t count;
/****************************  ****************************/

/****************************  ****************************/
static __export __ctm uint8_t  iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f }; //goes local
static __export __ctm uint8_t packet_buffer[PAYLOAD_BUFFER_SIZE];
static __export __ctm uint8_t encrypt_input_buffer[300];
static __export __ctm uint8_t encrypt_me_tlv_buffer[PAYLOAD_BUFFER_SIZE + BLOCKLEN + BLOCKLEN + BUFFER_LENGTH_INCREASE + BUFFER_TYPE_INCREASE];
static __export __ctm uint8_t key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
static __export __mem SHA256_CTX sha_context;

#ifdef ECLIPSE
static uint8_t payload[] = {0x06, 0xfd, 0x01, 0x9f, 0x07, 0x21, 0x08, 0x03, 0x6e, 0x64, 0x6e, 0x08, 0x03, 0x65, 0x64, 0x75, 0x08, 0x03, 0x75, 0x63, 0x69, 0x08, 0x04, 0x70, 0x69, 0x6e, 0x67, 0x08, 0x0a, 0x31, 0x30, 0x36, 0x36, 0x32, 0x32, 0x37, 0x35, 0x30, 0x35, 0x14, 0x04, 0x19, 0x02, 0x03, 0xe8, 0xfd, 0x80, 0xe8, 0x0a, 0xfd, 0x80, 0xe9, 0x01, 0x77, 0xfd, 0x80, 0xea, 0x01, 0x88, 0x15, 0x16, 0x4e, 0x44, 0x4e, 0x20, 0x54, 0x4c, 0x56, 0x20, 0x50, 0x69, 0x6e, 0x67, 0x20, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x00, 0x16, 0x4a, 0x1b, 0x01, 0x01, 0x1c, 0x45, 0x07, 0x43, 0x08, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x08, 0x07, 0x64, 0x61, 0x65, 0x6d, 0x6f, 0x6e, 0x73, 0x08, 0x0c, 0x6e, 0x64, 0x6e, 0x2d, 0x74, 0x6c, 0x76, 0x2d, 0x70, 0x69, 0x6e, 0x67, 0x08, 0x03, 0x4b, 0x45, 0x59, 0x08, 0x11, 0x6b, 0x73, 0x6b, 0x2d, 0x31, 0x34, 0x30, 0x36, 0x34, 0x32, 0x31, 0x33, 0x38, 0x33, 0x36, 0x35, 0x33, 0x08, 0x07, 0x49, 0x44, 0x2d, 0x43, 0x45, 0x52, 0x54, 0x17, 0xfd, 0x01, 0x00, 0x31, 0x8b, 0x4b, 0x84, 0x50, 0xc0, 0xfa, 0x62, 0x95, 0xbb, 0x53, 0x50, 0xf7, 0xbf, 0x3d, 0xc0, 0xe5, 0xe6, 0x3d, 0x43, 0x48, 0x07, 0x30, 0x59, 0xfa, 0xd3, 0xbd, 0xad, 0x5f, 0x13, 0xc0, 0x9b, 0xb4, 0x69, 0xb0, 0x3b, 0x7c, 0xe7, 0xb2, 0xaf, 0xde, 0x3d, 0x05, 0x1f, 0xe3, 0xb9, 0xb7, 0x10, 0x92, 0x34, 0xe3, 0x82, 0x5b, 0x5f, 0x13, 0xd4, 0x18, 0xb1, 0xe6, 0xe0, 0xbf, 0x07, 0x17, 0xb0, 0x49, 0x32, 0x49, 0xaa, 0xa2, 0x3e, 0x2f, 0xde, 0x47, 0x6a, 0x3c, 0x5a, 0x7a, 0xae, 0x85, 0xa9, 0xb3, 0xd4, 0x84, 0x15, 0x78, 0x78, 0xc3, 0x9a, 0x0e, 0x80, 0xb3, 0x89, 0x85, 0x6a, 0xd9, 0x45, 0xfc, 0xf1, 0x68, 0x88, 0xdc, 0x82, 0xea, 0xe3, 0x40, 0x49, 0x8e, 0xbe, 0xb1, 0x2c, 0x31, 0xb9, 0x25, 0x0e, 0x35, 0xb5, 0x35, 0xda, 0x33, 0xd5, 0x66, 0xdd, 0x07, 0xda, 0xd5, 0x41, 0xfd, 0xf0, 0xb4, 0x07, 0x8b, 0x53, 0x77, 0x50, 0x8c, 0xfe, 0xbf, 0x22, 0xfd, 0xfd, 0xff, 0xc6, 0x50, 0xc4, 0x9a, 0xc5, 0x2b, 0x36, 0xa3, 0x5f, 0x89, 0xa8, 0xcc, 0xbd, 0x1c, 0xd7, 0x25, 0x3a, 0x6e, 0x39, 0x89, 0xf3, 0xbe, 0x73, 0xcf, 0x00, 0xb8, 0x57, 0x34, 0xe9, 0x08, 0x0d, 0x70, 0xc8
, 0x60, 0x7d, 0x8c, 0x82, 0x1b, 0x35, 0x1c, 0xf4, 0xe3, 0x65, 0xad, 0x2a, 0x51, 0x47, 0x60, 0x72, 0x8c, 0xe6, 0x28, 0xe7, 0x9c, 0x7f, 0xdd, 0x3e, 0x44, 0xd7, 0x8b, 0x3a, 0x44, 0xa1, 0x49, 0x24, 0xf1, 0x45, 0x36, 0x5e, 0x1d, 0x1c, 0x7e, 0x35, 0x12, 0x71, 0x61, 0x30, 0xf3, 0xe6, 0xb0, 0xf4, 0xd2, 0xff, 0xf3, 0x54, 0x04, 0xb6, 0xfa, 0x34, 0x17, 0x6f, 0x8b, 0xac, 0x55, 0xf5, 0xae, 0xbb, 0x11, 0xdd, 0x90, 0x05, 0xb8, 0x27, 0xe0, 0x29, 0x8e, 0x2b, 0x5e, 0x02, 0x47, 0x41, 0x70, 0xed, 0x1b, 0x62};
#endif

/* ***************************  *************************** */

/*
This is an implementation of the AES algorithm, specifically ECB and CBC mode.
Block size can be chosen in aes.h - available choices are AES128, AES192, AES256.

The implementation is verified against the test vectors in:
  National Institute of Standards and Technology Special Publication 800-38A 2001 ED

ECB-AES128
----------

  plain-text:
    6bc1bee22e409f96e93d7e117393172a
    ae2d8a571e03ac9c9eb76fac45af8e51
    30c81c46a35ce411e5fbc1191a0a52ef
    f69f2445df4f9b17ad2b417be66c3710

  key:
    2b7e151628aed2a6abf7158809cf4f3c

  resulting cipher
    3ad77bb40d7a3660a89ecaf32466ef97
    f5d3d58503b9699de785895a96fdbaaf
    43b1cd7f598ece23881b00e3ed030688
    7b0c785e27e8ad3f8223207104725dd4


NOTE:   String length must be evenly divisible by 16byte (str_len % 16 == 0)
        You should pad the end of the string with zeros if this is not the case.
        For AES192/256 the block size is proportionally larger.

*/

#define Nb 4

#if defined(AES256) && (AES256 == 1)
    #define Nk 8
    #define KEYLEN 32
    #define Nr 14
    #define keyExpSize 240
#elif defined(AES192) && (AES192 == 1)
    #define Nk 6
    #define KEYLEN 24
    #define Nr 12
    #define keyExpSize 208
#else
    #define Nk 4        // The number of 32 bit words in a key.
    #define KEYLEN 16   // Key length in bytes
    #define Nr 10       // The number of rounds in AES Cipher.
    #define keyExpSize 176
#endif

// jcallan@github points out that declaring Multiply as a function
// reduces code size considerably with the Keil ARM compiler.
// See this link for more information: https://github.com/kokke/tiny-AES128-C/pull/3
#ifndef MULTIPLY_AS_A_FUNCTION
  #define MULTIPLY_AS_A_FUNCTION 0
#endif


/*****************************************************************************/
/* Private variables:                                                        */
/*****************************************************************************/
// state - array holding the intermediate results during decryption.
typedef uint8_t state_t[4][4];
static state_t* state;

// The array that stores the round keys.
static __export __ctm uint8_t RoundKey[keyExpSize];

// The Key input to the AES Program
static const uint8_t* Key;

// Initial Vector used only for CBC mode
static __mem uint8_t* Iv;

// The lookup-tables are marked const so they can be placed in read-only storage instead of RAM
// The numbers below can be computed dynamically trading ROM for RAM -
// This can be useful in (embedded) bootloader applications, where ROM is often limited.
static __export __ctm const uint8_t sbox[256] = {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

static __export __ctm const uint8_t rsbox[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };

// The round constant word array, Rcon[i], contains the values given by
// x to th e power (i-1) being powers of x (x is denoted as {02}) in the field GF(2^8)
static __export __ctm const uint8_t Rcon[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

/**************************** VARIABLES *****************************/
static __export __ctm const WORD k[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};


/*****************************************************************************/
/* TNO functions:                                                        */
/*****************************************************************************/
#ifdef ECLIPSE
void print_buf(uint8_t* buf, size_t size){
	int i =0;
	for (i = 0; i < size ; i++) {
		if ( i % 16 == 0 ){
			printf("\n");
		}
		printf("%02x ", buf[i]);
	}
	printf("\n\n");
}

#endif

/*****************************************************************************/
/* Private functions:                                                        */
/*****************************************************************************/
static uint8_t getSBoxValue(uint8_t num)
{
  return sbox[num];
}

//static uint8_t getSBoxInvert(uint8_t num)
//{
//  return rsbox[num];
//}

// This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states.
static void KeyExpansion(void)
{
  uint32_t i, k;
  uint8_t tempa[4]; // Used for the column/row operations

  // The first round key is the key itself.
  for (i = 0; i < Nk; ++i)
  {
    RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
    RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
    RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
    RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
  }

  // All other round keys are found from the previous round keys.
  //i == Nk
  for (; i < Nb * (Nr + 1); ++i)
  {
    {
      tempa[0]=RoundKey[(i-1) * 4 + 0];
      tempa[1]=RoundKey[(i-1) * 4 + 1];
      tempa[2]=RoundKey[(i-1) * 4 + 2];
      tempa[3]=RoundKey[(i-1) * 4 + 3];
    }

    if (i % Nk == 0)
    {
      // This function shifts the 4 bytes in a word to the left once.
      // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

      // Function RotWord()
      {
        k = tempa[0];
        tempa[0] = tempa[1];
        tempa[1] = tempa[2];
        tempa[2] = tempa[3];
        tempa[3] = k;
      }

      // SubWord() is a function that takes a four-byte input word and
      // applies the S-box to each of the four bytes to produce an output word.

      // Function Subword()
      {
        tempa[0] = getSBoxValue(tempa[0]);
        tempa[1] = getSBoxValue(tempa[1]);
        tempa[2] = getSBoxValue(tempa[2]);
        tempa[3] = getSBoxValue(tempa[3]);
      }

      tempa[0] =  tempa[0] ^ Rcon[i/Nk];
    }
#if defined(AES256) && (AES256 == 1)
    if (i % Nk == 4)
    {
      // Function Subword()
      {
        tempa[0] = getSBoxValue(tempa[0]);
        tempa[1] = getSBoxValue(tempa[1]);
        tempa[2] = getSBoxValue(tempa[2]);
        tempa[3] = getSBoxValue(tempa[3]);
      }
    }
#endif
    RoundKey[i * 4 + 0] = RoundKey[(i - Nk) * 4 + 0] ^ tempa[0];
    RoundKey[i * 4 + 1] = RoundKey[(i - Nk) * 4 + 1] ^ tempa[1];
    RoundKey[i * 4 + 2] = RoundKey[(i - Nk) * 4 + 2] ^ tempa[2];
    RoundKey[i * 4 + 3] = RoundKey[(i - Nk) * 4 + 3] ^ tempa[3];
  }
}

// This function adds the round key to state.
// The round key is added to the state by an XOR function.
static void AddRoundKey(uint8_t round)
{
  uint8_t i,j;
  for (i=0;i<4;++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[i][j] ^= RoundKey[round * Nb * 4 + i * Nb + j];
    }
  }
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void SubBytes(void)
{
  uint8_t i, j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[j][i] = getSBoxValue((*state)[j][i]);
    }
  }
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
static void ShiftRows(void)
{
  uint8_t temp;

  // Rotate first row 1 columns to left
  temp           = (*state)[0][1];
  (*state)[0][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[3][1];
  (*state)[3][1] = temp;

  // Rotate second row 2 columns to left
  temp           = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;

  temp           = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;

  // Rotate third row 3 columns to left
  temp           = (*state)[0][3];
  (*state)[0][3] = (*state)[3][3];
  (*state)[3][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[1][3];
  (*state)[1][3] = temp;
}

static uint8_t xtime(uint8_t x)
{
  return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}

// MixColumns function mixes the columns of the state matrix
static void MixColumns(void)
{
  uint8_t i;
  uint8_t Tmp,Tm,t;
  for (i = 0; i < 4; ++i)
  {
    t   = (*state)[i][0];
    Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3] ;
    Tm  = (*state)[i][0] ^ (*state)[i][1] ; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][1] ^ (*state)[i][2] ; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][2] ^ (*state)[i][3] ; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][3] ^ t ;              Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp ;
  }
}

// Multiply is used to multiply numbers in the field GF(2^8)
#if MULTIPLY_AS_A_FUNCTION
static uint8_t Multiply(uint8_t x, uint8_t y)
{
  return (((y & 1) * x) ^
       ((y>>1 & 1) * xtime(x)) ^
       ((y>>2 & 1) * xtime(xtime(x))) ^
       ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^
       ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))));
  }
#else
#define Multiply(x, y)                                \
      (  ((y & 1) * x) ^                              \
      ((y>>1 & 1) * xtime(x)) ^                       \
      ((y>>2 & 1) * xtime(xtime(x))) ^                \
      ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^         \
      ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))   \

#endif

// Cipher is the main function that encrypts the PlainText.
static void Cipher(void)
{
  uint8_t round = 0;

  // Add the First round key to the state before starting the rounds.
  AddRoundKey(0);

  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr-1 rounds are executed in the loop below.
  for (round = 1; round < Nr; ++round)
  {
    SubBytes();
    ShiftRows();
    MixColumns();
    AddRoundKey(round);
  }

  // The last round is given below.
  // The MixColumns function is not here in the last round.
  SubBytes();
  ShiftRows();
  AddRoundKey(Nr);
}



/*****************************************************************************/
/* Public functions:                                                         */
/*****************************************************************************/
static void XorWithIv(__mem uint8_t* buf)
{
  uint8_t i;
  for (i = 0; i < BLOCKLEN; ++i) //WAS for(i = 0; i < KEYLEN; ++i) but the block in AES is always 128bit so 16 bytes!
  {
    buf[i] ^= Iv[i];
  }
}

void AES_CBC_encrypt_buffer(__mem uint8_t* output, __mem uint8_t* input, uint32_t length, const uint8_t* key, __mem const uint8_t* iv)
{
  uint32_t i;

  // Skip the key expansion if key is passed as 0
  if (0 != key)
  {
    Key = key;
    KeyExpansion();
  }

  if (iv != 0)
  {
    Iv = (uint8_t*)iv;
  }

  for (i = 0; i < length; i += BLOCKLEN)
  {
    XorWithIv(input);
    memmove_mem_mem(output, input, BLOCKLEN);
    state = (state_t*)output;
    Cipher();
    Iv = output;
    input += BLOCKLEN;
    output += BLOCKLEN;
  }

}


/* SHA Functions*/
void sha256_transform(__mem SHA256_CTX *ctx, __mem const BYTE data[])
{
	__mem WORD a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

	for (i = 0, j = 0; i < 16; ++i, j += 4)
		m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
	for ( ; i < 64; ++i)
		m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];
	f = ctx->state[5];
	g = ctx->state[6];
	h = ctx->state[7];

	for (i = 0; i < 64; ++i) {
		t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
		t2 = EP0(a) + MAJ(a,b,c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
	ctx->state[5] += f;
	ctx->state[6] += g;
	ctx->state[7] += h;
}

void sha256_init(__mem SHA256_CTX *ctx)
{
	ctx->datalen = 0;
	ctx->bitlen = 0;
	ctx->state[0] = 0x6a09e667;
	ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372;
	ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f;
	ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab;
	ctx->state[7] = 0x5be0cd19;
}

void sha256_update(__mem SHA256_CTX *ctx, __mem const BYTE data[], size_t len)
{
	WORD i;

	for (i = 0; i < len; ++i) {
		ctx->data[ctx->datalen] = data[i];
		ctx->datalen++;
		if (ctx->datalen == 64) {
			sha256_transform(ctx, ctx->data);
			ctx->bitlen += 512;
			ctx->datalen = 0;
		}
	}
}

void sha256_final(__mem SHA256_CTX *ctx, __mem BYTE hash[])
{
	__mem WORD i;

	i = ctx->datalen;

	// Pad whatever data is left in the buffer.
	if (ctx->datalen < 56) {
		ctx->data[i++] = 0x80;
		while (i < 56)
			ctx->data[i++] = 0x00;
	}
	else {
		ctx->data[i++] = 0x80;
		while (i < 64)
			ctx->data[i++] = 0x00;
		sha256_transform(ctx, ctx->data);
		memset_mem(ctx->data, 0, 56);
	}

	// Append to the padding the total message's length in bits and transform.
	ctx->bitlen += ctx->datalen * 8;
	ctx->data[63] = ctx->bitlen;
	ctx->data[62] = ctx->bitlen >> 8;
	ctx->data[61] = ctx->bitlen >> 16;
	ctx->data[60] = ctx->bitlen >> 24;
	ctx->data[59] = ctx->bitlen >> 32;
	ctx->data[58] = ctx->bitlen >> 40;
	ctx->data[57] = ctx->bitlen >> 48;
	ctx->data[56] = ctx->bitlen >> 56;
	sha256_transform(ctx, ctx->data);

	// Since this implementation uses little endian byte ordering and SHA uses big endian,
	// reverse all the bytes when copying the final state to the output hash.
	for (i = 0; i < 4; ++i) {
		hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
	}
}

/* End of SHA functions */

static int tlv_len_offset(uint8_t *buff, int currpos, __mem uint32_t *TLVlen, __mem uint32_t *TLVlenK){
	uint8_t len0 = buff[currpos++]; //get length and advance
	uint32_t len = 0;
	uint8_t lenK = 1;
    uint8_t i = 0;

	if (len0 < 253){
		len = len0;
	}
	else {
		//length encoded in following 2,4,or 8 octets
		switch (len0){
    		case 253 :
    			lenK = 2;
    			break;
    		case 254 :
    			lenK = 4;
    			break;
    		case 255 :
    			lenK = 8;
    			break;
    		default :
    			return -1;

		}
		for(i=0; i < lenK; i++){
			len = len * 256 + buff[currpos++];
		}
		lenK++; //account for the fact that first octet plays now indication role
	}
	*TLVlen = len;
	*TLVlenK = lenK;
	return 0;
}

uint32_t extract_value_at_position(uint8_t* buf, uint32_t length){
	int i = 0;
	uint32_t value = 0;
	for( i = 0; i < length; i++){
		value = value * 256 + buf[i];
	}
	return value;
}

int get_type(uint8_t* buf, __mem uint32_t *type, __mem uint32_t *type_size){
	return(tlv_len_offset(buf, 0, type, type_size));
}

int get_length(uint8_t* buf, uint32_t offset, __mem uint32_t *length, __mem uint32_t *length_size){
	return(tlv_len_offset(buf, offset, length, length_size));
}

int get_encrypt_me_header_content(uint8_t* buf, __mem encrypt_me_result *encrypt_me_header){
    uint32_t currentPosition = 0;
    uint32_t start_unencrypted_position = 0;
    __mem uint32_t type =0 , type_size =0  , length_size = 0, length =0;

	get_type(buf+currentPosition, &type, &type_size);

	if(type != TYPE_NDN_DATA){
		return PIF_PLUGIN_RETURN_DROP;
	}

	get_length(buf + currentPosition, type_size, &(encrypt_me_header->dataSize), &length_size);
	encrypt_me_header->dataTLVSize = type_size + length_size + encrypt_me_header->dataSize;

	currentPosition += type_size + length_size;

	for(;;){

		get_type(buf+currentPosition, &type, &type_size);
		get_length(buf+currentPosition, type_size, &length, &length_size);

		/* MetaInfo and Name TLVs are also in the packets, only check for Encrypt me type */
		/* Check if type matches encrypt me header */
		if(type == TYPE_ENCRYPT_ME_HEADER){

			/* Enter the encrypt me header */
			int encryptMeHeaderPosition = currentPosition;
			encrypt_me_header->encryptMeHeaderStartPosition = buf + encryptMeHeaderPosition;
			currentPosition += type_size + length_size + length;

			encryptMeHeaderPosition += type_size + length_size;

			encrypt_me_header->encryptMeHeaderTLVSize = type_size + length_size + length;

			// ciphersuite
			get_type(buf+encryptMeHeaderPosition, &type, &type_size);
			get_length(buf+encryptMeHeaderPosition, type_size, &length, &length_size);

			if(type == TYPE_ENCRYPT_ME_HEADER_CIPHER_SUITE){
				/* Enter the encrypt me header cipher suite */

				/* Extract the (ciphersuite) value from the value field*/
				encrypt_me_header->cipherSuite = extract_value_at_position(buf + encryptMeHeaderPosition + type_size + length_size, length);
				encryptMeHeaderPosition += type_size + length_size + length;

			} else {
				return PIF_PLUGIN_RETURN_DROP;
			}
			// End of Ciphergroup TLV

			//keyID
			get_type(buf+encryptMeHeaderPosition, &type, &type_size);
			get_length(buf+encryptMeHeaderPosition, type_size, &length, &length_size);


			if(type == TYPE_ENCRYPT_ME_HEADER_KEY_ID){
				/* Enter the encrypt me header keyID*/
				/* Extract the (keyID) value from the value field*/
				encrypt_me_header->keyId = extract_value_at_position(buf + encryptMeHeaderPosition + type_size + length_size, length);
				encryptMeHeaderPosition += type_size + length_size + length;

			} else {
				return PIF_PLUGIN_RETURN_DROP;
			}
			// End of keyID TLV

			encrypt_me_header->contentTLVStartPosition = buf + encryptMeHeaderPosition;
			start_unencrypted_position = encryptMeHeaderPosition;
			encrypt_me_header->contentTLVOffset = start_unencrypted_position;
			break; //exit for loop
		}

		currentPosition += type_size + length_size + length;

		if(currentPosition > encrypt_me_header->dataTLVSize){
			return PIF_PLUGIN_RETURN_DROP;
		}
	} // End of for loop

	for(;;){
	    //find signature field using this for loop
		get_type(buf+currentPosition, &type, &type_size);
		get_length(buf+currentPosition, type_size, &length, &length_size);

		if(type == TYPE_NDN_SIGNATURE_INFO){
			encrypt_me_header->contentTLVSize = (currentPosition - start_unencrypted_position);
			encrypt_me_header->signatureStartOffset = currentPosition;
			encrypt_me_header->signatureInfoAndValueTLVSize = encrypt_me_header->dataTLVSize - encrypt_me_header->signatureStartOffset;
		}

		currentPosition += type_size + length_size + length;

		if(currentPosition == encrypt_me_header->dataTLVSize)
			break;
		if(currentPosition > encrypt_me_header->dataTLVSize){
			return PIF_PLUGIN_RETURN_DROP;
		}
	}
	return 0;
}


#ifndef ECLIPSE
int pif_plugin_payload_scan(EXTRACTED_HEADERS_T *headers,
                            MATCH_DATA_T *match_data)
#else
	int main()
#endif

{
	#ifndef ECLIPSE
	uint32_t mu_len, ctm_len;
    __mem uint8_t *payload;
    PIF_PLUGIN_udp_T *udp;
    PIF_PLUGIN_ipv4_T *ipv4;
    short length_inc;
	#endif


    uint16_t length;

	__mem encrypt_me_result result = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	__lmem uint16_t encryptMeOffset = 0;
    int i;
    uint16_t originalDataSize = 0;
    uint16_t originalContentTLVOffset = 0;
    uint16_t amountOfPaddingBytesForEncryptedContent = 0;
    uint16_t sizeOfEncryptMeHeaderTL = 0;
    uint16_t contentIncreaseDueToEncryption = 0;
    uint16_t correctedOriginalDataSize = 0;
	uint16_t sizeOfContentTLVAfterEncryption = 0;
	uint16_t signatureTLVSize = 0;
	short signatureTLVSizeDifference = 0;
	uint16_t dataTLVValueStartOffset = 0;

#ifndef ECLIPSE
    ipv4 = pif_plugin_hdr_get_ipv4(headers);

    if(ipv4->mf_flag == 1){
        return PIF_PLUGIN_RETURN_DROP;
    }
    if(ipv4->fragOffset > 0 ){
        return PIF_PLUGIN_RETURN_DROP;
    }

    if(pif_pkt_info_global.pkt_len > (1500 - BLOCKLEN)){
         return PIF_PLUGIN_RETURN_DROP;
    }

    if (pif_pkt_info_global.split) { /* payload split to MU */
        uint32_t sop; /* start of packet offset */
        sop = PIF_PKT_SOP(pif_pkt_info_global.pkt_buf, pif_pkt_info_global.pkt_num);
        mu_len = pif_pkt_info_global.pkt_len - (256 << pif_pkt_info_global.ctm_size) + sop;
    } else /* no data in MU */
        mu_len = 0;

    /* debug info for mu_split */
    pif_mu_len = mu_len;

    /* get the ctm byte count:
     * packet length - offset to parsed headers - byte_count_in_mu
     * Note: the parsed headers are always in ctm
     */
    count = pif_pkt_info_global.pkt_len - pif_pkt_info_global.pkt_pl_off - mu_len;
    /* Get a pointer to the ctm portion */
    payload = pif_pkt_info_global.pkt_buf;
    /* point to just beyond the parsed headers */
    payload += pif_pkt_info_global.pkt_pl_off;


    for (i = 0; i < count; i++) {
           packet_buffer[i]=payload[i];
    }

    length = count; //prevent overwrite of beginning of buf

    /* same as above, but for mu. Code duplicated as a manual unroll */
    if (mu_len) {
        payload = (__addr40 void *)((uint64_t)pif_pkt_info_global.muptr << 11);
        /* Adjust payload size depending on the ctm size for the packet */
        payload += 256 << pif_pkt_info_global.ctm_size;
        count = mu_len;
        for (i = 0; i < count; i++) {
           packet_buffer[length+i]=payload[i];
        }
        length=length+count;
    }
#else
    for (i = 0; i < sizeof(payload); i++) {
             packet_buffer[i]=payload[i];
      }
    length=sizeof(payload);
#endif


    if(get_encrypt_me_header_content((uint8_t *)packet_buffer, &result) != 0){
    		return PIF_PLUGIN_RETURN_DROP;
   	}

	// Calculate the new lengths of the SignatureInfo and SignatureValue TLVs
	signatureTLVSize = NEW_SIGNATURE_SIZE;

	// Calculate the difference in length, used for shrinking/increasing the packet later on
	signatureTLVSizeDifference = signatureTLVSize - result.signatureInfoAndValueTLVSize;

	// Update the length field of the Data TLV because of the encrypt me header that is inserted
	originalDataSize = result.dataTLVSize;

	// Adjust the size of the (V) of the Data TLV and the actual size of the (L) of the Data TLV
	result.dataSize += signatureTLVSizeDifference;
	result.dataTLVSize += signatureTLVSizeDifference;

	// Calculate the amount of padding bytes for encryption, will always be divisible by BLOCKLEN, pad up until it is divisible
	amountOfPaddingBytesForEncryptedContent = (result.contentTLVSize % BLOCKLEN) == 0 ? 0 : BLOCKLEN - (result.contentTLVSize % BLOCKLEN);

	// Calculate the new size of the content after encryption
	sizeOfContentTLVAfterEncryption =  result.contentTLVSize + amountOfPaddingBytesForEncryptedContent + BLOCKLEN;

	// Set the (T)ype value to 33003 (EncryptedContentTLV)
	encrypt_me_tlv_buffer[0] = 0xfd;
	encrypt_me_tlv_buffer[1] = 0x80;
	encrypt_me_tlv_buffer[2] = 0xeb;
	encryptMeOffset += 3;

	// Determine the amount of bytes needed to encode the (L)ength part (EncryptedContent TLV)
	if(sizeOfContentTLVAfterEncryption < 253){
		encrypt_me_tlv_buffer[3] = sizeOfContentTLVAfterEncryption;
		encryptMeOffset += 1;
	} else {
		encrypt_me_tlv_buffer[3] = 0xfd;
		encrypt_me_tlv_buffer[4] = (sizeOfContentTLVAfterEncryption >> 8);
		encrypt_me_tlv_buffer[5] = (sizeOfContentTLVAfterEncryption & 0xff);
		encryptMeOffset += 3;
	}
	sizeOfContentTLVAfterEncryption += encryptMeOffset;

	sizeOfEncryptMeHeaderTL += encryptMeOffset;

	// Copy iv to the start of the output buffer
    for (i = 0; i < BLOCKLEN; i++) {
	   encrypt_me_tlv_buffer[i + encryptMeOffset] = iv[i];
    }

    // Compensate the offset for iv by adding BLOCKLEN
    encryptMeOffset += BLOCKLEN;

    // The increase of size is: the T and L part of the encrypt me header, the amount of padding bytes we added for encryption, and the IV (which is equal to BLOCKLEN)
    contentIncreaseDueToEncryption = sizeOfEncryptMeHeaderTL + amountOfPaddingBytesForEncryptedContent + BLOCKLEN;

    // Update the data TLV size with the amount we are going to add in the encryption proces
	result.dataSize += contentIncreaseDueToEncryption;
	result.dataTLVSize += contentIncreaseDueToEncryption;

	memmove_mem_mem(encrypt_input_buffer, result.contentTLVStartPosition, result.contentTLVSize);

    // Copy this state of the variable for moving over everything after the content
    correctedOriginalDataSize = originalDataSize;

    AES_CBC_encrypt_buffer((uint8_t*)(encrypt_me_tlv_buffer + encryptMeOffset),
    		(uint8_t *) encrypt_input_buffer,
    		result.contentTLVSize,
    		(uint8_t*) key,
    		(uint8_t*) iv);

    // Check value for L field of the Data TLV, if encoding is increased, do make_space
	if(result.dataSize < 253 && originalDataSize < 253){ // Size did not change after encryption
		packet_buffer[1] = result.dataSize;
		dataTLVValueStartOffset = 2;
	} else if (result.dataSize >= 253 && originalDataSize < 253) { // Size has increased after encryption, make space, 2 bytes
		result.dataTLVSize += 2;
		correctedOriginalDataSize += 2;

		packet_buffer[1] = 0xfd;
		packet_buffer[2] = (result.dataSize >> 8);
		packet_buffer[3] = (result.dataSize & 0xff);

		result.contentTLVStartPosition += 2;
		result.signatureStartOffset += 2;
		result.encryptMeHeaderStartPosition += 2;
		result.contentTLVOffset += 2;
		dataTLVValueStartOffset = 4;
		// call make space function with 2 bytes
		memmove_mem_mem(packet_buffer + 3, packet_buffer + 1, originalDataSize - 1);
	} else if (result.dataSize >= 253 && originalDataSize >= 253) { // Size was already encoded in multiple bytes, no make space necessary
		packet_buffer[1] = 0xfd;
		packet_buffer[2] = (result.dataSize >> 8);
		packet_buffer[3] = (result.dataSize & 0xff);
		dataTLVValueStartOffset = 4;
	} else { // Size of encoding has changed and became smaller, remove space from the packet, Remove space, 2 bytes, recalculate all offsets, everything is minus 2
		result.dataTLVSize -= 2;
		correctedOriginalDataSize -= 2;
		packet_buffer[1] = result.dataSize;
		result.contentTLVStartPosition -= 2;
		result.signatureStartOffset -= 2;
		result.encryptMeHeaderStartPosition -= 2;
		result.contentTLVOffset -= 2;
		dataTLVValueStartOffset = 2; // One for Type, One of Length
		memmove_mem_mem((packet_buffer + 2),(packet_buffer + 4), originalDataSize - 2); // call remove space function with 2 bytes
	}

	// call make space function with contentIncreaseDueToEncryption as size
	// make_space(result.signatureStartOffset , contentIncreaseDueToEncryption);
	originalContentTLVOffset = result.contentTLVOffset;

	// Move the signature
	memmove_mem_mem((packet_buffer + result.signatureStartOffset + contentIncreaseDueToEncryption),
			(packet_buffer + result.signatureStartOffset), correctedOriginalDataSize - result.signatureStartOffset);

	// The offset of the signature TLV changes due to creating space with contentIncreaseDueToEncryption as amount
	result.signatureStartOffset += contentIncreaseDueToEncryption;

	// Copy encrypted content into the packet buffer
	memmove_mem_mem((packet_buffer + originalContentTLVOffset), (encrypt_me_tlv_buffer), sizeOfContentTLVAfterEncryption);

	// Construct Signature Info TLV (Type=0x16, Length=0x3)
	packet_buffer[result.signatureStartOffset] = 0x16;
	packet_buffer[result.signatureStartOffset + 1] = 0x3;
	packet_buffer[result.signatureStartOffset + 2] = 0x1b;
	packet_buffer[result.signatureStartOffset + 3] = 0x1;
	packet_buffer[result.signatureStartOffset + 4] = 0x0;

	// Construct Signature Value TLV Type=0x17, Length = 0x20
	packet_buffer[result.signatureStartOffset + 5] = 0x17;
	packet_buffer[result.signatureStartOffset + 6] = 0x20;

	// Apply SHA function on the Name, MetaInfo, EncryptedContentTLV
	sha256_init(&sha_context);
	sha256_update(&sha_context, (uint8_t *) (packet_buffer + dataTLVValueStartOffset), result.dataSize - signatureTLVSize); // Start at the first byte of the (V) part of the Data TLV, dont use signature itself for calculation
	sha256_final(&sha_context, (BYTE*) &(packet_buffer[result.signatureStartOffset + 7]));



#ifndef ECLIPSE
    length_inc = result.dataTLVSize - length;
    if(length_inc > 0) {
        pif_pkt_make_space(result.signatureStartOffset, length_inc); // Make space, packet has increased in size
    } else if (length_inc < 0) {
        pif_pkt_free_space(result.signatureStartOffset, -length_inc); // Remove space, since packet has decreased in size
    }

    if (pif_pkt_info_global.split) { /* payload split to MU */
        uint32_t sop; /* start of packet offset */
        sop = PIF_PKT_SOP(pif_pkt_info_global.pkt_buf, pif_pkt_info_global.pkt_num);
        mu_len = pif_pkt_info_global.pkt_len - (256 << pif_pkt_info_global.ctm_size) + sop;
    } else /* no data in MU */
        mu_len = 0;

    /* debug info for mu_split */
    pif_mu_len = mu_len;
    count = pif_pkt_info_global.pkt_len - pif_pkt_info_global.pkt_pl_off - mu_len;
    /* Get a pointer to the ctm portion */
    payload = pif_pkt_info_global.pkt_buf;
    /* point to just beyond the parsed headers */
    payload += pif_pkt_info_global.pkt_pl_off;

    for (i = 0; i < count; i++) {
        payload[i]=packet_buffer[i];
    }

    length = count; //prevent overwrite of beginning of buf

    /* same as above, but for mu. Code duplicated as a manual unroll */
    if (mu_len) {
        payload = (__addr40 void *)((uint64_t)pif_pkt_info_global.muptr << 11);
        /* Adjust payload size depending on the ctm size for the packet */
        payload += 256 << pif_pkt_info_global.ctm_size;
        count = mu_len;
        for (i = 0; i < count; i++) {
           payload[i]=packet_buffer[length+i];
        }
    }

    ipv4->totalLen += length_inc;


    udp = pif_plugin_hdr_get_udp(headers);
    udp->len += length_inc;
#else
    print_buf(packet_buffer, sizeof(packet_buffer));
#endif
    return PIF_PLUGIN_RETURN_FORWARD;


}
