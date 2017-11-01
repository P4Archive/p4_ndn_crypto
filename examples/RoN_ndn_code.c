#include <assert.h>
#include <stdio.h>

#include <stdint.h>
#include <string.h>



#define CBC 1
/*
 * Payload scan: search the payload for a string
 */

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

#define CIPHER_SUITE_NONE 0
#define CIPHER_SUITE_AES_128_CBC 0x77
#define CIPHER_SUITE_AES_192_CBC 2
#define CIPHER_SUITE_AES_256_CBC 3

#define BUFFER_TYPE_INCREASE 3
#define BUFFER_LENGTH_INCREASE 3

#define KEY_ID 0x88


/* Payload chunk size in LW (32-bit) and bytes */
#define CHUNK_LW 8
#define CHUNK_B (CHUNK_LW*4)
#define __ctm
#define __export
#define __mem
#define PIF_PLUGIN_RETURN_DROP 1
#define PIF_PLUGIN_RETURN_FORWARD 0

volatile __export __mem uint32_t pif_mu_len = 0;

static __export __ctm uint32_t count;
static __export __ctm uint8_t  iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f }; //goes local
static __export __ctm uint8_t buf[PAYLOAD_BUFFER_SIZE];
static __export __ctm uint8_t encrypt_buf[PAYLOAD_BUFFER_SIZE];

static __export __ctm uint8_t outbuf[PAYLOAD_BUFFER_SIZE+BLOCKLEN+BLOCKLEN+BUFFER_LENGTH_INCREASE+BUFFER_TYPE_INCREASE];

static __export __ctm uint8_t key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
static __export __ctm uint8_t plain_text[64] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 };


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
static uint8_t RoundKey[keyExpSize];

// The Key input to the AES Program
static const uint8_t* Key;

#if defined(CBC) && CBC
  // Initial Vector used only for CBC mode
  static uint8_t* Iv;
#endif

// The lookup-tables are marked const so they can be placed in read-only storage instead of RAM
// The numbers below can be computed dynamically trading ROM for RAM -
// This can be useful in (embedded) bootloader applications, where ROM is often limited.
static const uint8_t sbox[256] = {
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

static const uint8_t rsbox[256] = {
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
static const uint8_t Rcon[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

/*
 * Jordan Goulder points out in PR #12 (https://github.com/kokke/tiny-AES128-C/pull/12),
 * that you can remove most of the elements in the Rcon array, because they are unused.
 *
 * From Wikipedia's article on the Rijndael key schedule @ https://en.wikipedia.org/wiki/Rijndael_key_schedule#Rcon
 *
 * "Only the first some of these constants are actually used â€“ up to rcon[10] for AES-128 (as 11 round keys are needed),
 *  up to rcon[8] for AES-192, up to rcon[7] for AES-256. rcon[0] is not used in AES algorithm."
 *
 * ... which is why the full array below has been 'disabled' below.
 */
#if 0
static const uint8_t Rcon[256] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
  0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
  0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
  0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
  0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
  0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
  0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
  0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
  0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
  0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
  0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
  0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
  0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
  0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
  0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
  0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d };
#endif



/*****************************************************************************/
/* Private functions:                                                        */
/*****************************************************************************/
static uint8_t getSBoxValue(uint8_t num)
{
  return sbox[num];
}

static uint8_t getSBoxInvert(uint8_t num)
{
  return rsbox[num];
}

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

// MixColumns function mixes the columns of the state matrix.
// The method used to multiply may be difficult to understand for the inexperienced.
// Please use the references to gain more information.
static void InvMixColumns(void)
{
  int i;
  uint8_t a, b, c, d;
  for (i = 0; i < 4; ++i)
  {
    a = (*state)[i][0];
    b = (*state)[i][1];
    c = (*state)[i][2];
    d = (*state)[i][3];

    (*state)[i][0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
    (*state)[i][1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
    (*state)[i][2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
    (*state)[i][3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
  }
}


// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void InvSubBytes(void)
{
  uint8_t i,j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[j][i] = getSBoxInvert((*state)[j][i]);
    }
  }
}

static void InvShiftRows(void)
{
  uint8_t temp;

  // Rotate first row 1 columns to right
  temp = (*state)[3][1];
  (*state)[3][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[0][1];
  (*state)[0][1] = temp;

  // Rotate second row 2 columns to right
  temp = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;

  temp = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;

  // Rotate third row 3 columns to right
  temp = (*state)[0][3];
  (*state)[0][3] = (*state)[1][3];
  (*state)[1][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[3][3];
  (*state)[3][3] = temp;
}


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

static void InvCipher(void)
{
  uint8_t round=0;

  // Add the First round key to the state before starting the rounds.
  AddRoundKey(Nr);

  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr-1 rounds are executed in the loop below.
  for (round = (Nr - 1); round > 0; --round)
  {
    InvShiftRows();
    InvSubBytes();
    AddRoundKey(round);
    InvMixColumns();
  }

  // The last round is given below.
  // The MixColumns function is not here in the last round.
  InvShiftRows();
  InvSubBytes();
  AddRoundKey(0);
}


/*****************************************************************************/
/* Public functions:                                                         */
/*****************************************************************************/
#if defined(CBC) && (CBC == 1)


static void XorWithIv(uint8_t* buf)
{
  uint8_t i;
  for (i = 0; i < BLOCKLEN; ++i) //WAS for(i = 0; i < KEYLEN; ++i) but the block in AES is always 128bit so 16 bytes!
  {
    buf[i] ^= Iv[i];
  }
}

void AES_CBC_encrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length, const uint8_t* key, const uint8_t* iv)
{
  //uintptr_t i;
  uint32_t i;
  uint8_t extra = length % BLOCKLEN; /* Remaining bytes in the last non-full block */

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
    memcpy(output, input, BLOCKLEN);
    state = (state_t*)output;
    Cipher();
    Iv = output;
    input += BLOCKLEN;
    output += BLOCKLEN;
    //printf("Step %d - %d", i/16, i);
  }

//  if (extra)
//  {
//    memcpy(output, input, extra);
//    state = (state_t*)output;
//    Cipher();
//  }
}

void AES_CBC_decrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length, const uint8_t* key, const uint8_t* iv)
{
  //uintptr_t i;
  uint32_t i;
  uint8_t extra = length % BLOCKLEN; /* Remaining bytes in the last non-full block */

  // Skip the key expansion if key is passed as 0
  if (0 != key)
  {
    Key = key;
    KeyExpansion();
  }

  // If iv is passed as 0, we continue to encrypt without re-setting the Iv
  if (iv != 0)
  {
    Iv = (uint8_t*)iv;
  }

  for (i = 0; i < length; i += BLOCKLEN)
  {
    memcpy(output, input, BLOCKLEN);
    state = (state_t*)output;
    InvCipher();
    XorWithIv(output);
    Iv = input;
    input += BLOCKLEN;
    output += BLOCKLEN;
  }

  if (extra)
  {
    memcpy(output, input, extra);
    state = (state_t*)output;
    InvCipher();
  }
}

#endif // #if defined(CBC) && (CBC == 1)

static int tlv_len_offset(uint8_t *buff, int currpos, uint32_t *TLVlen, uint32_t *TLVlenK){
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

// NDN packet without testvector
//uint8_t empayload[] = {
//0x06, 0xfd, 0x01, 0x9f, 0x07, 0x21, 0x08, 0x03, 0x6e, 0x64, 0x6e, 0x08, 0x03, 0x65, 0x64, 0x75,
//0x08, 0x03, 0x75, 0x63, 0x69, 0x08, 0x04, 0x70, 0x69, 0x6e, 0x67, 0x08, 0x0a, 0x31, 0x30, 0x36,
//0x36, 0x32, 0x32, 0x37, 0x35, 0x30, 0x35, 0x14, 0x04, 0x19, 0x02, 0x03, 0xe8, 0xfd, 0x80, 0xe8,
//0x0a, 0xfd, 0x80, 0xe9, 0x01, 0x77, 0xfd, 0x80, 0xea, 0x01, 0x88, 0x15, 0x16, 0x4e, 0x44, 0x4e,
//0x20, 0x54, 0x4c, 0x56, 0x20, 0x50, 0x69, 0x6e, 0x67, 0x20, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
//0x73, 0x65, 0x00, 0x16, 0x4a, 0x1b, 0x01, 0x01, 0x1c, 0x45, 0x07, 0x43, 0x08, 0x09, 0x6c, 0x6f,
//0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x08, 0x07, 0x64, 0x61, 0x65, 0x6d, 0x6f, 0x6e, 0x73,
//0x08, 0x0c, 0x6e, 0x64, 0x6e, 0x2d, 0x74, 0x6c, 0x76, 0x2d, 0x70, 0x69, 0x6e, 0x67, 0x08, 0x03,
//0x4b, 0x45, 0x59, 0x08, 0x11, 0x6b, 0x73, 0x6b, 0x2d, 0x31, 0x34, 0x30, 0x36, 0x34, 0x32, 0x31,
//0x33, 0x38, 0x33, 0x36, 0x35, 0x33, 0x08, 0x07, 0x49, 0x44, 0x2d, 0x43, 0x45, 0x52, 0x54, 0x17,
//0xfd, 0x01, 0x00, 0x31, 0x8b, 0x4b, 0x84, 0x50, 0xc0, 0xfa, 0x62, 0x95, 0xbb, 0x53, 0x50, 0xf7,
//0xbf, 0x3d, 0xc0, 0xe5, 0xe6, 0x3d, 0x43, 0x48, 0x07, 0x30, 0x59, 0xfa, 0xd3, 0xbd, 0xad, 0x5f,
//0x13, 0xc0, 0x9b, 0xb4, 0x69, 0xb0, 0x3b, 0x7c, 0xe7, 0xb2, 0xaf, 0xde, 0x3d, 0x05, 0x1f, 0xe3,
//0xb9, 0xb7, 0x10, 0x92, 0x34, 0xe3, 0x82, 0x5b, 0x5f, 0x13, 0xd4, 0x18, 0xb1, 0xe6, 0xe0, 0xbf,
//0x07, 0x17, 0xb0, 0x49, 0x32, 0x49, 0xaa, 0xa2, 0x3e, 0x2f, 0xde, 0x47, 0x6a, 0x3c, 0x5a, 0x7a,
//0xae, 0x85, 0xa9, 0xb3, 0xd4, 0x84, 0x15, 0x78, 0x78, 0xc3, 0x9a, 0x0e, 0x80, 0xb3, 0x89, 0x85,
//0x6a, 0xd9, 0x45, 0xfc, 0xf1, 0x68, 0x88, 0xdc, 0x82, 0xea, 0xe3, 0x40, 0x49, 0x8e, 0xbe, 0xb1,
//0x2c, 0x31, 0xb9, 0x25, 0x0e, 0x35, 0xb5, 0x35, 0xda, 0x33, 0xd5, 0x66, 0xdd, 0x07, 0xda, 0xd5,
//0x41, 0xfd, 0xf0, 0xb4, 0x07, 0x8b, 0x53, 0x77, 0x50, 0x8c, 0xfe, 0xbf, 0x22, 0xfd, 0xfd, 0xff,
//0xc6, 0x50, 0xc4, 0x9a, 0xc5, 0x2b, 0x36, 0xa3, 0x5f, 0x89, 0xa8, 0xcc, 0xbd, 0x1c, 0xd7, 0x25,
//0x3a, 0x6e, 0x39, 0x89, 0xf3, 0xbe, 0x73, 0xcf, 0x00, 0xb8, 0x57, 0x34, 0xe9, 0x08, 0x0d, 0x70,
//0xc8, 0x60, 0x7d, 0x8c, 0x82, 0x1b, 0x35, 0x1c, 0xf4, 0xe3, 0x65, 0xad, 0x2a, 0x51, 0x47, 0x60,
//0x72, 0x8c, 0xe6, 0x28, 0xe7, 0x9c, 0x7f, 0xdd, 0x3e, 0x44, 0xd7, 0x8b, 0x3a, 0x44, 0xa1, 0x49,
//0x24, 0xf1, 0x45, 0x36, 0x5e, 0x1d, 0x1c, 0x7e, 0x35, 0x12, 0x71, 0x61, 0x30, 0xf3, 0xe6, 0xb0,
//0xf4, 0xd2, 0xff, 0xf3, 0x54, 0x04, 0xb6, 0xfa, 0x34, 0x17, 0x6f, 0x8b, 0xac, 0x55, 0xf5, 0xae,
//0xbb, 0x11, 0xdd, 0x90, 0x05};

// NDN packet with testvector embedded inside the content TLV
uint8_t empayload[] = {
	0x06, 0xfd, 0x01, 0xc9, 0x07, 0x21, 0x08, 0x03, 0x6e, 0x64, 0x6e, 0x08, 0x03, 0x65, 0x64, 0x75, 0x08, 0x03,
	0x75, 0x63, 0x69, 0x08, 0x04, 0x70, 0x69, 0x6e, 0x67, 0x08, 0x0a, 0x31, 0x30, 0x36, 0x36, 0x32, 0x32, 0x37,
	0x35, 0x30, 0x35, 0x14, 0x04, 0x19, 0x02, 0x03, 0xe8, 0xfd, 0x80, 0xe8, 0x0a, 0xfd, 0x80, 0xe9, 0x01, 0x77,
	0xfd, 0x80, 0xea, 0x01, 0x88, 0x15, 0x40, 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e,
	0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45,
	0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52,
	0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,

	0x16,
	0x4a, 0x1b, 0x01, 0x01, 0x1c, 0x45, 0x07, 0x43, 0x08, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73,
	0x74, 0x08, 0x07, 0x64, 0x61, 0x65, 0x6d, 0x6f, 0x6e, 0x73, 0x08, 0x0c, 0x6e, 0x64, 0x6e, 0x2d, 0x74, 0x6c,
	0x76, 0x2d, 0x70, 0x69, 0x6e, 0x67, 0x08, 0x03, 0x4b, 0x45, 0x59, 0x08, 0x11, 0x6b, 0x73, 0x6b, 0x2d, 0x31,
	0x34, 0x30, 0x36, 0x34, 0x32, 0x31, 0x33, 0x38, 0x33, 0x36, 0x35, 0x33, 0x08, 0x07, 0x49, 0x44, 0x2d, 0x43,
	0x45, 0x52, 0x54,

	0x17, 0xfd, 0x01, 0x00, 0x31, 0x8b, 0x4b, 0x84, 0x50, 0xc0, 0xfa, 0x62, 0x95, 0xbb, 0x53,
	0x50, 0xf7, 0xbf, 0x3d, 0xc0, 0xe5, 0xe6, 0x3d, 0x43, 0x48, 0x07, 0x30, 0x59, 0xfa, 0xd3, 0xbd, 0xad, 0x5f,
	0x13, 0xc0, 0x9b, 0xb4, 0x69, 0xb0, 0x3b, 0x7c, 0xe7, 0xb2, 0xaf, 0xde, 0x3d, 0x05, 0x1f, 0xe3, 0xb9, 0xb7,
	0x10, 0x92, 0x34, 0xe3, 0x82, 0x5b, 0x5f, 0x13, 0xd4, 0x18, 0xb1, 0xe6, 0xe0, 0xbf, 0x07, 0x17, 0xb0, 0x49,
	0x32, 0x49, 0xaa, 0xa2, 0x3e, 0x2f, 0xde, 0x47, 0x6a, 0x3c, 0x5a, 0x7a, 0xae, 0x85, 0xa9, 0xb3, 0xd4, 0x84,
	0x15, 0x78, 0x78, 0xc3, 0x9a, 0x0e, 0x80, 0xb3, 0x89, 0x85, 0x6a, 0xd9, 0x45, 0xfc, 0xf1, 0x68, 0x88, 0xdc,
	0x82, 0xea, 0xe3, 0x40, 0x49, 0x8e, 0xbe, 0xb1, 0x2c, 0x31, 0xb9, 0x25, 0x0e, 0x35, 0xb5, 0x35, 0xda, 0x33,
	0xd5, 0x66, 0xdd, 0x07, 0xda, 0xd5, 0x41, 0xfd, 0xf0, 0xb4, 0x07, 0x8b, 0x53, 0x77, 0x50, 0x8c, 0xfe, 0xbf,
	0x22, 0xfd, 0xfd, 0xff, 0xc6, 0x50, 0xc4, 0x9a, 0xc5, 0x2b, 0x36, 0xa3, 0x5f, 0x89, 0xa8, 0xcc, 0xbd, 0x1c,
	0xd7, 0x25, 0x3a, 0x6e, 0x39, 0x89, 0xf3, 0xbe, 0x73, 0xcf, 0x00, 0xb8, 0x57, 0x34, 0xe9, 0x08, 0x0d, 0x70,
	0xc8, 0x60, 0x7d, 0x8c, 0x82, 0x1b, 0x35, 0x1c, 0xf4, 0xe3, 0x65, 0xad, 0x2a, 0x51, 0x47, 0x60, 0x72, 0x8c,
	0xe6, 0x28, 0xe7, 0x9c, 0x7f, 0xdd, 0x3e, 0x44, 0xd7, 0x8b, 0x3a, 0x44, 0xa1, 0x49, 0x24, 0xf1, 0x45, 0x36,
	0x5e, 0x1d, 0x1c, 0x7e, 0x35, 0x12, 0x71, 0x61, 0x30, 0xf3, 0xe6, 0xb0, 0xf4, 0xd2, 0xff, 0xf3, 0x54, 0x04,
	0xb6, 0xfa, 0x34, 0x17, 0x6f, 0x8b, 0xac, 0x55, 0xf5, 0xae, 0xbb, 0x11, 0xdd, 0x90, 0x05, 0xb8, 0x27, 0xe0,
	0x29, 0x8e, 0x2b, 0x5e, 0x02, 0x47, 0x41, 0x70, 0xed, 0x1b, 0x62
};


void mymemmove(uint8_t *to, uint8_t *from, size_t size) {
	int i;

	if(from == to){// Nothing to copy!
		return;
	}
	else if(from > to)
	{
		for(i = 0; i < size; i++) {
			to[i] = from[i];
		}
	}
	else
	{
		for(i = size-1; i >= 0; i--) {
			to[i] = from[i];
		}
	}
}

uint32_t extract_value_at_position(uint8_t* buf, uint32_t length){
	int i = 0;
	uint32_t value = 0;
	for( i = 0; i < length; i++){
		value = value * 256 + buf[i];
	}
	return value;
}

int get_type(uint8_t* buf, uint32_t *type, uint32_t *type_size){
	return(tlv_len_offset(buf, 0, type, type_size));
}

int get_length(uint8_t* buf, uint32_t offset, uint32_t *length, uint32_t *length_size){
	return(tlv_len_offset(buf, offset, length, length_size));
}

typedef struct {

	 uint8_t* contentTLVStartPosition;
	 uint32_t signatureStartOffset;
	 uint8_t* encryptMeHeaderStartPosition;
	 uint32_t contentTLVOffset;
	 uint32_t cipherSuite;
	 uint32_t keyId;
	 uint32_t contentTLVSize;
	 uint32_t encryptMeHeaderTLVSize;
	 uint32_t dataSize;
	 uint32_t dataTLVSize;


} encrypt_me_result;

/*
 * Find encrypt me header - get pointer to start
 * Find start of signature header - get pointer to start
 * Extract cipher suite and key from encrypt me header
 * Find end of encrypt me header - get pointer, this should be start of content
 * Determine the range of content ( end pointer of encrypt me + 1 -- start of signature pointer)
 * It saves these values into the encrypt_me_result struct that is passed to the method
 * */
int get_encrypt_me_header_content(uint8_t* buf, encrypt_me_result *encrypt_me_header){
    uint32_t currentPosition = 0;
    uint32_t start_unencrypted_position = 0;
    uint32_t type =0 , type_size =0 , length =0 , length_size = 0;

	get_type(buf+currentPosition, &type, &type_size);

	if(type != TYPE_NDN_DATA){
		return PIF_PLUGIN_RETURN_DROP;
	}

	get_length(buf+currentPosition, type_size, &(encrypt_me_header->dataSize), &length_size);
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

int main(){
	encrypt_me_result result;
	int i;
	int encryptMeOffset = 0;
	int originalDataSize = 0;
	int originalContentTLVOffset = 0;
	int amountOfPaddingBytesForEncryptedContent = 0;
	int sizeOfEncryptMeHeaderTL = 0;
	int contentIncreaseDueToEncryption = 0;
	int correctedOriginal = 0;
	uint32_t sizeOfContentTLVAfterEncryption = 0;

	// Initialize the values inside the struct to 0
	memset((uint8_t*) &result, 0, sizeof(result));

	// Initialize all values in the buffer to 0
    for (i = 0; i < sizeof(buf); i++) {
    	buf[i] = 0;
    }

    for (i = 0; i < sizeof(outbuf); i++) {
    	outbuf[i] = 0;
    }

    // Move the payload to the buffer
    mymemmove(buf, empayload, sizeof(empayload));

    // Obtain the encrypt_me_result struct
	if(get_encrypt_me_header_content(buf, &result) != 0){
		return PIF_PLUGIN_RETURN_DROP;
	}

	// Calculate the amount of padding bytes for encryption, will always be divisible by BLOCKLEN, pad up until it is divisible
	amountOfPaddingBytesForEncryptedContent = (result.contentTLVSize % BLOCKLEN) == 0 ? 0 : BLOCKLEN - (result.contentTLVSize % BLOCKLEN);

	// Calculate the new size of the content after encryption
	sizeOfContentTLVAfterEncryption =  result.contentTLVSize + amountOfPaddingBytesForEncryptedContent + BLOCKLEN;

	// Update the length field of the Data TLV because of the encrypt me header that is inserted
	originalDataSize = result.dataTLVSize;

	// Set the (T)ype value to 33003 (EncryptedContentTLV)
	outbuf[0] = 0xfd;
	outbuf[1] = 0x80;
	outbuf[2] = 0xeb;
	encryptMeOffset += 3;

	// Determine the amount of bytes needed to encode the (L)ength part (EncryptedContent TLV)
	if(sizeOfContentTLVAfterEncryption < 253){
		outbuf[3] = sizeOfContentTLVAfterEncryption;
		encryptMeOffset += 1;
	} else {
		outbuf[3] = 0xfd;
		outbuf[4] = (sizeOfContentTLVAfterEncryption >> 8);
		outbuf[5] = (sizeOfContentTLVAfterEncryption & 0xff);
		encryptMeOffset += 3;
	}
	sizeOfContentTLVAfterEncryption += encryptMeOffset;

	sizeOfEncryptMeHeaderTL += encryptMeOffset;

	// Copy iv to the start of the output buffer
    for (i = 0; i < BLOCKLEN; i++) {
	   outbuf[i + encryptMeOffset] = iv[i];
    }

    // Compensate the offset for iv by adding BLOCKLEN
    encryptMeOffset += BLOCKLEN;

    // The increase of size is: the T and L part of the encrypt me header, the amount of padding bytes we added for encryption, and the IV (which is equal to BLOCKLEN)
    contentIncreaseDueToEncryption = sizeOfEncryptMeHeaderTL + amountOfPaddingBytesForEncryptedContent + BLOCKLEN;

    // Update the data TLV size with the amount we are going to add in the encryption proces
	result.dataSize += contentIncreaseDueToEncryption;

	mymemmove(encrypt_buf, (uint8_t*)(result.contentTLVStartPosition), result.contentTLVSize);

    AES_CBC_encrypt_buffer((uint8_t*)(outbuf + encryptMeOffset),
    		encrypt_buf,
    		result.contentTLVSize,
    		(uint8_t*) key,
    		(uint8_t*) iv);

    // Copy this state of the variable for moving over everything after the content
    correctedOriginal = originalDataSize;

    // Check value for L field of the Data TLV, if encoding is increased, do make_space
	if(result.dataSize < 253 && originalDataSize < 253){ // Size did not change after encryption
		buf[1] = result.dataSize;
	} else if (result.dataSize >= 253 && originalDataSize < 253) { // Size has increased after encryption, make space, 2 bytes
		result.dataTLVSize += 2;
		correctedOriginal += 2;

		buf[1] = 0xfd;
		buf[2] = (result.dataSize >> 8);
		buf[3] = (result.dataSize & 0xff);

		result.contentTLVStartPosition += 2;
		result.signatureStartOffset += 2;
		result.encryptMeHeaderStartPosition += 2;
		result.contentTLVOffset += 2;
		// call make space function with 2 bytes
		mymemmove(buf + 3, buf + 1, originalDataSize - 1);
	} else if (result.dataSize >= 253 && originalDataSize >= 253) { // Size was already encoded in multiple bytes, no make space necessary
		buf[1] = 0xfd;
		buf[2] = (result.dataSize >> 8);
		buf[3] = (result.dataSize & 0xff);
	} else { // Size of encoding has changed and became smaller, remove space from the packet, Remove space, 2 bytes, recalculate all offsets, everything is minus 2
		result.dataTLVSize -= 2;
		correctedOriginal -= 2;
		buf[1] = result.dataSize;
		result.contentTLVStartPosition -= 2;
		result.signatureStartOffset -= 2;
		result.encryptMeHeaderStartPosition -= 2;
		result.contentTLVOffset -= 2;
		// call remove space function with 2 bytes
		mymemmove(buf + 1, buf + 3, originalDataSize - 1);
	}

	// call make space function with contentIncreaseDueToEncryption as size
	//	make_space(result.signatureStartOffset , contentIncreaseDueToEncryption);
	originalContentTLVOffset = result.contentTLVOffset;

	print_buf(buf, result.dataTLVSize);

	mymemmove(buf + result.signatureStartOffset + contentIncreaseDueToEncryption,
			buf + result.signatureStartOffset, correctedOriginal - result.signatureStartOffset);


	// The offset of the signature TLV changes due to creating space with contentIncreaseDueToEncryption as amount
	result.signatureStartOffset += contentIncreaseDueToEncryption;

	memcpy(buf + originalContentTLVOffset, outbuf, sizeOfContentTLVAfterEncryption);

	print_buf(buf, result.dataTLVSize + contentIncreaseDueToEncryption);

	// buf contains the entire payload
	// outbuf contains the EncryptedContentTLV

    // Pre-prend IV in the output buffer + (generate IV instead of )
    // Call encrypt function with start pointer of content, length is end encrypt me pointer - start signature pointers
    // Calculate increase of content size

    // Make space using the increase content size value after the NDN header ( end is best)
    // Done: Create EncryptedContent TLV - calculate length (original + max 2x padding)

    // Make space for T-L and the extra length of the value
    // Done: Go to end of encrypt me header pointer
    // Done: Append the Encrypted Data TLV to the Encrypt Me header from the buffer
    // Done: Update length of Encrypt me Header

    // Done: Recalculate the L field of the Data TLV
    // Check value for L field of the Data TLV, if encoding is increased, do make_space
    // Write new L value for data TLV


    // Recalculate Signature

    // Recalculate UDP length
    // Recalculate IP length
    // Recalculate UDP checksum
    // Recalculate IP checksum

	return 0;
}
