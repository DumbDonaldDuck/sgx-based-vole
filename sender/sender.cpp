#include <iostream>
#include <string>
#include <cmath>
#include <cstring>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <netdb.h>

//  Common C++ header files
#include <SGX_Vole_Define.h>

int main(int argc, char *argv[]) {

    /*-------------------------- Sender Protocol -----------------------------        
        out TEE
                generate rsa-pk' & sk'
                send pk' to Receiver (we can transfer n/d/e or pk_pem)
                receive Encrypt(BΔ, pk') to Sender
                decrypt Encrypt(BΔ, pk') with sk'

    --------------------------------------------------------------------------*/ 
   
    std::cout << "--------------------------------------------------" << endl;
    Timer totalBegin = std::chrono::system_clock::now();
    Timer generatepkBegin = std::chrono::system_clock::now();

    std::cout << "Generate RSA-key for Sender ..." << endl;
    RSA *sender_rsa = RSA_new();
    BIGNUM *sender_bne = BN_new();
    BN_set_word(sender_bne, RSA_PBULIC_EXPONENT);
    RSA_generate_key_ex(sender_rsa, RSA_KEY_BIT_LENGTH, sender_bne, NULL);
    
    RSA *sender_pk = RSAPublicKey_dup(sender_rsa);
    RSA *sender_sk = RSAPrivateKey_dup(sender_rsa);

    Timer generatepkEnd = std::chrono::system_clock::now();
    std::cout << "Generate RSA-key for Sender done ";
    std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(generatepkEnd - generatepkBegin).count() << "ms" << std::endl;
    
    
    std::cout << "--------------------------------------------------" << endl;

    //  encrypt: rsa or pk could both be used
    //  decrypt: rsa or sk could both be used


    /*----------- Socket Transfer (Send pk') -----------*/

    std::cout << "Socket Transfer ..." << endl;
    Timer receiveresultBegin = std::chrono::system_clock::now();

    Timer sendpkBegin = std::chrono::system_clock::now();

    //  create socket
    int sender_sockfd;
    if( (sender_sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0 )
    {
        std::cout << "---[Error] Create socket failed." << endl;
        return -1;
    }
    else std::cout << "---Create socket" << endl;

    
    //  connect to receiver
    struct sockaddr_in sender_addr;
    memset(&sender_addr, 0, sizeof(sender_addr));
    sender_addr.sin_family = AF_INET;
    sender_addr.sin_port = htons(atoi(argv[2]));        //  Sender Port
    sender_addr.sin_addr.s_addr=inet_addr(argv[1]);     //  Sender IP
    if ( connect(sender_sockfd, (struct sockaddr *)&sender_addr, sizeof(sender_addr)) != 0 ) // Connect Request to Receiver
    { 
        std::cout << "---[Error] Connect to Receiver failed." << endl;
        close(sender_sockfd); 
        return -1; 
    }
    else std::cout << "---Connect to Receiver" << endl;

    //  transfer pk to unsigned char buffer

    //  when re-constructing pk, only n&e are needed
    //  code for Receiver to re-construct
        //  BIGNUM *sender_n = BN_new();
        //  BIGNUM *sender_e = BN_new();
        //  BN_hex2bn(&sender_n, big_n);
        //  BN_hex2bn(&sender_e, big_e);
        //  RSA_set0_key(rsa2, modulus, privateExponent, NULL); //  must set NULL here for pk
    
    const BIGNUM *n, *e;
    RSA_get0_key(sender_pk, &n, &e, NULL);


    char *big_n = BN_bn2hex(n);     // big_n 是一块私有空间，不允许直接访问？
    char *big_e = BN_bn2hex(e);

    //  send char_n & char_e to Receiver
    int iret;


    //  send n 
    if ( (iret = send(sender_sockfd, big_n, strlen(big_n), 0)) <= 0 ) // send n to server
    { 
        std::cout << "---[Error] Send Sender-pk(n) failed." << endl;
        return -1;
    }
    else std::cout << "---Send Sender-pk(n)" << endl;
    

    //  send e 
    if ( (iret = send(sender_sockfd, big_e, strlen(big_e), 0)) <= 0 ) // send e to server
    { 
        std::cout << "---[Error] Send Sender-pk(e) failed." << endl;
        return -1;
    }
    else std::cout << "---Send Sender-pk(e)" << endl;
    

    Timer sendpkEnd = std::chrono::system_clock::now();
    std::cout << "Socket Transfer done ";
    std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(sendpkEnd - sendpkBegin).count() << "ms" << std::endl;
    

    std::cout << "--------------------------------------------------" << endl;



    /*----------- Socket Transfer (Receive encrypted data) -----------*/
    
    std::cout << "Socket Transfer ... " << endl;

    //  Receive Protocol-Mode
    char buffer_mode[1];
    memset(buffer_mode, 0, sizeof(buffer_mode));
    if ( (iret = recv(sender_sockfd, buffer_mode, sizeof(buffer_mode), 0)) <= 0 )    
    { 
        std::cout << "---[Error] Receive Protocol-Mode failed" << endl;
        return -1;
    }
    else std::cout << "---Receive Protocol-Mode" << endl;

    int HYBRID_ENCRYPTION_ON = buffer_mode[0];


    //  Buffer & Decryption Parameters
    int byte_length_field_B = (int)(FIELD_B/8);
    int byte_length_field_F = (int)(FIELD_F/8);
    int bytes_count_B = byte_length_field_F;
    int bytes_count_Delta = byte_length_field_B;
    int bytes_count_B_total = SIZE_M * bytes_count_B;


    int sender_pk_size = RSA_size(sender_pk);       //  count in byte
    int element_B_count_per_cipher = (sender_pk_size   - DEFAULT_PADDING_LENGTH) / bytes_count_B;
    int cipher_count_B = ceil(SIZE_M *1.0/ element_B_count_per_cipher);
    int buffer_size_B = cipher_count_B * sender_pk_size;
    int buffer_size_Delta = sender_pk_size;


    if(HYBRID_ENCRYPTION_ON){
        buffer_size_B = SIZE_M * bytes_count_B;
        buffer_size_Delta = max(bytes_count_Delta, AES_BLOCK_SIZE_BYTE);
    }

    unsigned char* buffer_B = (unsigned char*)malloc(buffer_size_B);
    unsigned char* buffer_Delta = (unsigned char*)malloc(buffer_size_Delta);

    unsigned char* randB = (unsigned char*)malloc(bytes_count_B_total);
    unsigned char* randDelta = (unsigned char*)malloc(bytes_count_Delta);

    //  Receive Enc(B)
    int total_recv = 0;      // 已发送数据的长度
    while (total_recv < buffer_size_B) {  // 只要还有数据未发送完毕
        int recved = recv(sender_sockfd, buffer_B + total_recv, buffer_size_B - total_recv, 0);  // 接收剩余部分
        if (recved == -1) {  // 如果发送失败
            std::cout << "---[Error] Receive Enc(B) failed." << endl;
            return -1;
        }
        total_recv += (int)recved;  // 更新已发送长度
    }
    std::cout << "---Receive Enc(B)" << endl;

    //  Receive Enc(Delta)
    memset(buffer_Delta, 0, buffer_size_Delta);
    if ( (iret = recv(sender_sockfd, buffer_Delta, buffer_size_Delta, 0)) <= 0 )     //  receiving Enc(Delta)
    { 
        std::cout << "---[Error] Receive Enc(Delta) failed." << endl;
        return -1;
    }
    else std::cout << "---Receive Enc(Delta)" << endl;

    

    unsigned char* AES_buffer_sender = (unsigned char*)malloc(4*sender_pk_size);

    //  HYBRID_ENCRYPTION_ON = 1, Receive RSA-Enc(AES-key/ivec)
    if(HYBRID_ENCRYPTION_ON){
        
        memset(AES_buffer_sender, 0, 4*sender_pk_size);

        if ( iret = recv(sender_sockfd, AES_buffer_sender, 4*sender_pk_size, 0) <= 0 )     //  receiving AES key and iv
        { 
            std::cout << "---[Error] Receive RSA-Enc(AES-key/ivec) failed." << endl;
            return -1;
        }
        else std::cout << "---Receive RSA-Enc(AES-key/ivec)" << endl;

        
    }

    Timer receiveresultEnd = std::chrono::system_clock::now();
    std::cout << "Socket Transfer done ";
    std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(receiveresultEnd - receiveresultBegin).count() << "ms" << std::endl;
    std::cout << "--------------------------------------------------" << endl;



    /*----------- Decryption -----------*/
    std::cout << "Decrypt Enc(B/Delta) ..." << endl;
    Timer decryptBegin = std::chrono::system_clock::now();

    //  HYBRID_ENCRYPTION_ON = 1, Decrypt Enc(B/Delta) with AES
    if(HYBRID_ENCRYPTION_ON){

        AES_KEY sender_aes_key1, sender_aes_key2;
        unsigned char aes_sender_key_buffer1[AES_KEY_LENGTH_BYTE];
        unsigned char aes_sender_key_buffer2[AES_KEY_LENGTH_BYTE];
        unsigned char aes_sender_ivec1[AES_IV_LENGTH_BYTE];
        unsigned char aes_sender_ivec2[AES_IV_LENGTH_BYTE];

        memset(aes_sender_key_buffer1, 0, AES_KEY_LENGTH_BYTE);
        memset(aes_sender_key_buffer2, 0, AES_KEY_LENGTH_BYTE);
        memset(aes_sender_ivec1, 0, AES_IV_LENGTH_BYTE);
        memset(aes_sender_ivec2, 0, AES_IV_LENGTH_BYTE);
        
        //  RSA decrypt
        RSA_private_decrypt(sender_pk_size, (unsigned char*)(AES_buffer_sender + 0*sender_pk_size), aes_sender_key_buffer1, sender_sk, PADDING_MODE);
        RSA_private_decrypt(sender_pk_size, (unsigned char*)(AES_buffer_sender + 1*sender_pk_size), aes_sender_key_buffer2, sender_sk, PADDING_MODE);
        RSA_private_decrypt(sender_pk_size, (unsigned char*)(AES_buffer_sender + 2*sender_pk_size), aes_sender_ivec1, sender_sk, PADDING_MODE);
        RSA_private_decrypt(sender_pk_size, (unsigned char*)(AES_buffer_sender + 3*sender_pk_size), aes_sender_ivec2, sender_sk, PADDING_MODE);

        //  Set AES key
        AES_set_decrypt_key(aes_sender_key_buffer1, AES_KEY_LENGTH_BIT, &sender_aes_key1);
        AES_set_decrypt_key(aes_sender_key_buffer2, AES_KEY_LENGTH_BIT, &sender_aes_key2);

        //  AES decrypt

        //  Decrypt B
        AES_cbc_encrypt(buffer_B, randB, bytes_count_B_total, &sender_aes_key1, aes_sender_ivec1, AES_DECRYPT);
        std::cout << "---Decrypt B" << endl;
        //  Decrypt Delta
        AES_cbc_encrypt(buffer_Delta, randDelta, bytes_count_Delta, &sender_aes_key2, aes_sender_ivec2, AES_DECRYPT);
        std::cout << "---Decrypt Delta" << endl;
    }

    //  HYBRID_ENCRYPTION_ON = 0, Decrypt Enc(B/Delta) with RSA
    else{

        int bytes_ptr = 0;

        //  Decrypt B
        for(int i=0; i<cipher_count_B; i++){
            int res = RSA_private_decrypt(  sender_pk_size, 
                                            (unsigned char*)(buffer_B + i*sender_pk_size), 
                                            (unsigned char*)(randB + bytes_ptr), sender_sk, PADDING_MODE);
            bytes_ptr += res;
        }
        std::cout << "---Decrypt B" << endl;

        //  Decrypt Delta
        RSA_private_decrypt(sender_pk_size, buffer_Delta, randDelta, sender_sk, PADDING_MODE);
        std::cout << "---Decrypt Delta" << endl;
    }


    Timer decryptEnd = std::chrono::system_clock::now();
    std::cout << "Decrypt Enc(B/Delta) done ";
    std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(decryptEnd - decryptBegin).count() << "ms" << std::endl;
    

    
    std::cout << "--------------------------------------------------" << endl;

    // free all heap space
    free(buffer_B);
    free(buffer_Delta);
    free(randB);
    free(randDelta);
    free(AES_buffer_sender);
    
    //  close socket
    close(sender_sockfd);

    Timer totalEnd = std::chrono::system_clock::now();
    std::cout << "Total time: ";
    std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(totalEnd - totalBegin).count() << "ms" << std::endl;
    


    /*----------- Done -----------*/

    return 0;

}

