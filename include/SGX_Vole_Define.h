#ifndef _SGX_VOLE_DEFINE_H_
#define _SGX_VOLE_DEFINE_H_

//  for c++
using namespace std;

//  for time
#include <chrono>
typedef std::chrono::system_clock::time_point Timer;

//  for socket
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
/*  parameters for func listen(int sockfd, int backlog);
    the length for the ESTABLISHED_STATUS_QUEUE
    maximum is 128  */
#define DEFAULT_RECEIVER_BACKLOG 30

/* localhost是个域名，不能直接绑定套接字，必须先gethostbyname转成IP才能绑定。*/ 

// Receiver's port & addr could be designated at first
#define RECEIVER_PORT 4602
#define RECEIVER_ADDR "127.0.0.1"

// Sender's port & addr could be designated at first
#define SENDER_PORT 4602
#define SENDER_ADDR "127.0.0.1"


//  for vole
#define FIELD_B 64
#define FIELD_F 128
#define SIZE_M 1357676
#define DEFAULT_PARA_LENGTH 10

//  for openssl
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/aes.h>



//  for RSA

/*  RSA_F4 or RSA_3 unsigned long type, for public exponent
    Sender and Receiver should have the same key length, otherwise we need to adjust the transfer */
#define RSA_KEY_BIT_LENGTH 2048
#define RSA_PBULIC_EXPONENT RSA_F4  

/*  MAX Char buff size, at most is KEY_LENGTH_BIT/4 
        X-bit key length
        X/4 hex-length (0-F)
        each symbol of hex(0-F) is presented in char, which is 8 bit / 1 byte
        so the required length of CHAR_BUFF_SIZE is at most X/4
*/
#define CHAR_BUFF_SIZE (RSA_KEY_BIT_LENGTH/4)
// #define CHAR_BUFF_SIZE (RSA_KEY_BIT_LENGTH/4 + 1)    //  cause modulus = 257/129

//  parameters for RSA padding
#define PADDING_MODE RSA_PKCS1_PADDING 
#define DEFAULT_PADDING_LENGTH 11



//  for AES

//  aes key length 128/256(192 not considered here)
#define AES_KEY_LENGTH_BIT 128  
#define AES_KEY_LENGTH_BYTE AES_KEY_LENGTH_BIT/8

//  aes block size 128 bit
#define AES_BLOCK_SIZE_BIT 128
#define AES_IV_LENGTH_BIT 128
#define AES_BLOCK_SIZE_BYTE AES_BLOCK_SIZE_BIT/8
#define AES_IV_LENGTH_BYTE AES_IV_LENGTH_BIT/8




#endif