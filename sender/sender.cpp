#include <iostream>
#include <string>
#include <cmath>
#include <cstring>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <netdb.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
using namespace std;

#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/pem.h>

// RSA_F4 or RSA_3 unsigned long type, for public exponent
#define RSA_KEY_BIT_LENGTH 2048
#define RSA_PBULIC_EXPONENT RSA_F4 

// confirm buff size
#define CONFIRM_BUFF_SIZE 16

#define SENDER_PORT 4602
#define SENDER_ADDR "127.0.0.1"

#define PADDING_MODE RSA_PKCS1_PADDING 
#define DEFAULT_PADDING_LENGTH 11

//  para for VOLE
#define FIELD_B 64
#define FIELD_F 128
#define SIZE_M 1357676

//  max bytes for a single send
#define DEFAULT_MAX_SOCKET_LENGTH 

int main(int argc, char *argv[]) {


    // Sender Protocol
        // out TEE
        //   generate rsa-pk' & sk'
        //   send pk' to Receiver (we can transfer n/d/e or pk_pem)
        //   receive Encrypt(BΔ, pk') to Sender
        //   decrypt Encrypt(BΔ, pk') with sk'


    /*----------- Generate Key -----------*/
    
    cout << "--------------------------------------------------------------------" << endl;
    // cout << "Start" << endl;
    // cout << "--------------------------------------------------------------------" << endl;
    // cout << "--------------------------- Generate Key ---------------------------" << endl;
    cout << "Generating rsa pk & sk for Sender ..." << endl;
    RSA *sender_rsa = RSA_new();
    BIGNUM *sender_bne = BN_new();
    BN_set_word(sender_bne, RSA_PBULIC_EXPONENT);
    RSA_generate_key_ex(sender_rsa, RSA_KEY_BIT_LENGTH, sender_bne, NULL);
    
    RSA *sender_pk = RSAPublicKey_dup(sender_rsa);
    RSA *sender_sk = RSAPrivateKey_dup(sender_rsa);
    cout << "Generating rsa pk & sk for Sender [done]" << endl;
    cout << "--------------------------------------------------" << endl;

    //  encrypt: rsa or pk could both be used
    //  decrypt: rsa or sk could both be used


    /*----------- Socket Transfer (Send pk') -----------*/
    // cout << "--------------------------------------------------------------------" << endl;
    // cout << "/*------------------ Socket Transfer (Send pk') ------------------*/" << endl;

    cout << "Sending pk' to Receiver ..." << endl;

    //  create socket
    int sender_sockfd;
    if( (sender_sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0 )
    {
        cout << "---[Error] Create socket failed." << endl;
        return -1;
    }
    else cout << "---Create socket done." << endl;

    
    //  connect to receiver
    struct sockaddr_in sender_addr;
    memset(&sender_addr, 0, sizeof(sender_addr));
    sender_addr.sin_family = AF_INET;
    sender_addr.sin_port = htons(atoi(argv[2]));        //  Sender Port
    sender_addr.sin_addr.s_addr=inet_addr(argv[1]);     //  Sender IP
    if ( connect(sender_sockfd, (struct sockaddr *)&sender_addr, sizeof(sender_addr)) != 0 ) // Connect Request to Receiver
    { 
        cout << "---[Error] Connect to Receiver failed." << endl;
        close(sender_sockfd); 
        return -1; 
    }
    else cout << "---Connect to Receiver done." << endl;

    //  transfer pk to unsigned char buffer

    //  when re-constructing pk, only n&e are needed
    //  code for Receiver to re-construct
        //  BIGNUM *sender_n = BN_new();
        //  BIGNUM *sender_e = BN_new();
        //  BN_hex2bn(&sender_n, big_n);
        //  BN_hex2bn(&sender_e, big_e);
        //  RSA_set0_key(rsa2, modulus, privateExponent, NULL); //  must set NULL here for pk

    char *big_n = BN_bn2hex(RSA_get0_n(sender_pk));     // big_n 是一块私有空间，不允许直接访问？
    char *big_e = BN_bn2hex(RSA_get0_e(sender_pk));
    cout << "---Transfer sender's pk to char buffer done." << endl;
    // cout << "size of char_buff_n = " << strlen(big_n) << endl;
    // cout << "size of char_buff_e = " << strlen(big_e) << endl;
    

    //  send char_n & char_e to Receiver
    int iret;
    char confirm_buff[CONFIRM_BUFF_SIZE];   // only for receiver signal for n&e confirm


    //  send n and receive confirm
    if ( (iret = send(sender_sockfd, big_n, strlen(big_n), 0)) <= 0 ) // send n to server
    { 
        cout << "---[Error] Send n to Receiver failed." << endl;
        return -1;
    }
    else cout << "---Send n to Receiver done." << endl;
    // memset(confirm_buff, 0, sizeof(confirm_buff)); 
    // if ( (iret = recv(sender_sockfd, confirm_buff, sizeof(confirm_buff), 0)) <= 0 ) // receive confirm for n
    // { 
    //     cout << "---[Error] Send n to Receiver, confirm failed." << endl;
    //     return -1;
    // }
    // else cout << "---Send n to Receiver, confirm done." << endl;


    //  send e and receive confirm
    if ( (iret = send(sender_sockfd, big_e, strlen(big_e), 0)) <= 0 ) // send e to server
    { 
        cout << "---[Error] Send e to Receiver failed." << endl;
        return -1;
    }
    else cout << "---Send e to Receiver done." << endl;
    // memset(confirm_buff, 0, sizeof(confirm_buff));
    // if ( (iret = recv(sender_sockfd, confirm_buff, sizeof(confirm_buff), 0)) <= 0 ) // receive confirm for e
    // { 
    //     cout << "---[Error] Send e to Receiver, confirm failed." << endl;
    //     return -1;
    // }
    // else cout << "---Send e to Receiver, confirm done." << endl;



    cout << "Sending pk' to Receiver [done]" << endl;
    cout << "--------------------------------------------------" << endl;



    /*----------- Socket Transfer (Receive encrypted data) -----------*/
    // cout << "--------------------------------------------------------------------" << endl;
    // cout << "/*----------- Socket Transfer (Receive encrypted data) -----------*/" << endl;
    cout << "Receiving Enc(B) & Enc(Delta) from Receiver ..." << endl;

    // memset(confirm_buff, 0, sizeof(confirm_buff));
    // strcpy(confirm_buff,"request");
    // if ( (iret = send(sender_sockfd, confirm_buff, strlen(confirm_buff), 0)) <= 0 ) //  send confirm to receiver
    // { 
    //     cout << "---[Error] Send Request of Enc(B) to Receiver failed." << endl;
    //     return -1;
    // }
    // else cout << "---Send Request of Enc(B) to Receiver done." << endl;

    int byte_length_field_B = (int)(FIELD_B/8);
    int byte_length_field_F = (int)(FIELD_F/8);
    int bytes_count_B = byte_length_field_F;

    int bytes_count_B_total = SIZE_M * bytes_count_B;
    int bytes_count_Delta = byte_length_field_B;


    int sender_pk_size = RSA_size(sender_pk);       //  count in byte
    int element_B_count_per_cipher = (sender_pk_size   - DEFAULT_PADDING_LENGTH) / bytes_count_B;
    int cipher_count_B = ceil(SIZE_M *1.0/ element_B_count_per_cipher);

    int buffer_size_B = cipher_count_B * sender_pk_size;
    int buffer_size_Delta = sender_pk_size;

    unsigned char* buffer_B = (unsigned char*)malloc(buffer_size_B);
    unsigned char* buffer_Delta = (unsigned char*)malloc(buffer_size_Delta);

    unsigned char* randB = (unsigned char*)malloc(bytes_count_B_total);
    unsigned char* randDelta = (unsigned char*)malloc(bytes_count_Delta);

    memset(confirm_buff, 0, sizeof(confirm_buff));
    strcpy(confirm_buff,"confirm");

    //  receiving Enc(B) and send confirm

    int total_recv = 0;      // 已发送数据的长度
    while (total_recv < buffer_size_B) {  // 只要还有数据未发送完毕
        int recved = recv(sender_sockfd, buffer_B + total_recv, buffer_size_B - total_recv, 0);  // 接收剩余部分
        if (recved == -1) {  // 如果发送失败
            cout << "---[Error] Receiving Enc(B) from Receiver failed." << endl;
            return -1;
        }
        total_recv += (int)recved;  // 更新已发送长度
    }
    cout << "---Receiving Enc(B) from Receiver done." << endl;

    // memset(buffer_B, 0, buffer_size_B);
    // if ( (iret = recv(sender_sockfd, buffer_B, buffer_size_B, 0)) <= 0 )         //  receiving Enc(B)
    // { 
    //     cout << "---[Error] Receiving Enc(B) from Receiver failed." << endl;
    //     return -1;
    // }
    // else cout << "---Receiving Enc(B) from Receiver done." << endl;
    // cout << iret << endl;

    // size_t aa;

    // if ( (iret = send(sender_sockfd, confirm_buff, strlen(confirm_buff), 0)) <= 0 ) //  send confirm to receiver
    // { 
    //     cout << "---[Error] Send confirm of Enc(B) to Receiver failed." << endl;
    //     return -1;
    // }
    // else cout << "---Send confirm of Enc(B) to Receiver done." << endl;


    //  receiving Enc(Delta) and send confirm
    memset(buffer_Delta, 0, buffer_size_Delta);
    if ( (iret = recv(sender_sockfd, buffer_Delta, buffer_size_Delta, 0)) <= 0 )     //  receiving Enc(Delta)
    { 
        cout << "---[Error] Receiving Enc(Delta) from Receiver failed." << endl;
        return -1;
    }
    else cout << "---Receiving Enc(Delta) from Receiver done." << endl;

    // if ( (iret = send(sender_sockfd, confirm_buff, strlen(confirm_buff), 0)) <= 0 )     //  send confirm to receiver
    // { 
    //     cout << "---[Error] Send confirm of Enc(Delta) to Receiver failed." << endl;
    //     return -1;
    // }
    // else cout << "---Send confirm of Enc(Delta) to Receiver done." << endl;

    cout << "Receiving Enc(B) & Enc(Delta) from Receiver [done]" << endl;
    cout << "--------------------------------------------------" << endl;


    /*----------- Decryption -----------*/
    // cout << "--------------------------------------------------------------------" << endl;
    // cout << "/*-------------------------- Decryption --------------------------*/" << endl;
    cout << "Decrypting Enc(B) & Enc(Delta) ..." << endl;

    //  Decrypting B
    // cout << "---Decrypting B" << endl;
    // int bytes_ptr = 0;
    // for(int i=0; i<cipher_count_B; i++){
    //     // cout << i <<  endl;
    //     int res = RSA_private_decrypt(sender_pk_size, (unsigned char*)(buffer_B + i*sender_pk_size), (unsigned char*)(randB + bytes_ptr), sender_sk, PADDING_MODE);
    //     bytes_ptr += res;
    // }
    // cout << "---Decrypting B done" << endl;

    cout << "---Decrypting Delta" << endl;
    RSA_private_decrypt(sender_pk_size, buffer_Delta, randDelta, sender_sk, PADDING_MODE);
    cout << "---Decrypting Delta done" << endl;


    cout << "Decrypting Enc(B) & Enc(Delta) [done]" << endl;
    cout << "--------------------------------------------------" << endl;

    


    free(buffer_B);
    free(buffer_Delta);
    free(randB);
    free(randDelta);
    close(sender_sockfd);

    /*----------- Done -----------*/
    cout << "/*----------- Done -----------*/" << endl;
    return 0;





}



