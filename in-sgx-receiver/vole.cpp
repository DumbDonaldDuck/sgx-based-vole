

#include <iostream>
#include <vector>
#include <ctime>
#include <cmath>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/time.h>

#include <chrono>
typedef std::chrono::system_clock::time_point Timer;

using namespace std;

#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/aes.h>

#define PADDING_MODE RSA_PKCS1_PADDING 
#define DEFAULT_PADDING_LENGTH 11

//  aes key length 128/256(192 not considered here)
#define AES_KEY_LENGTH_BIT 128  
#define AES_KEY_LENGTH_BYTE AES_KEY_LENGTH_BIT/8

//  aes block size 128 bit
#define AES_BLOCK_SIZE_BIT 128
#define AES_IV_LENGTH_BIT 128
#define AES_BLOCK_SIZE_BYTE AES_BLOCK_SIZE_BIT/8
#define AES_IV_LENGTH_BYTE AES_IV_LENGTH_BIT/8

// typedef int type_size;
// typedef long type_B;
// typedef long long int type_F;

int main(int argc, char *argv[]){

    // VOLE-in-SGX Protocol
        //  Parse arguments (m, F, B, pk, pk')
        // 
        //  Generate A/B/C/Δ
        //      
        //  Encryption    
        //  
        //  Store the result in shared memory
    Timer sgxBegin = std::chrono::system_clock::now();

    std::cout << "--------------------------------------------------" << endl;
    std::cout << "Interact with TEE ..." << endl;

    /*----------- Parse arguments -----------*/
    Timer parseBegin = std::chrono::system_clock::now();

    std::cout << "---[In SGX] Parse parameters ";

    if (argc < 14) {
        std::cout << "---[In SGX] ---[Error] Parameters missing in VOLE Generation" << endl;
        return EXIT_FAILURE;
    }
    // else std::cout << "---[In SGX] ---Parameters enough in VOLE Generation" << endl;
                                                                        //  str->unsigned long
    int OVERALL_PROTOCOL_MODE = (int) strtoul(argv[1], NULL, 10);               //  MODE 0/1
    int field_B  = (int) strtoul(argv[2], NULL, 10);                    //  B, unsigned long  
    int field_F  = (int) strtoul(argv[3], NULL, 10);                    //  F, unsigned long  
    int size_m   = (int) strtoul(argv[4], NULL, 10);                    //  m, unsigned long
    RSA* sender_pk  = (RSA *) strtoul(argv[5], NULL, 10);               //  pk'

    unsigned char *share_buf_B_ptr = (unsigned char *) strtoul(argv[6], NULL, 10);      //  shared_buff_ptr
    size_t share_buf_B_size = (size_t) strtoul(argv[7], NULL, 10);                      //  shared_buff_size
    unsigned char *share_buf_Delta_ptr = (unsigned char *) strtoul(argv[8], NULL, 10);  //  shared_buff_ptr
    size_t share_buf_Delta_size = (size_t) strtoul(argv[9], NULL, 10);                  //  shared_buff_size

    unsigned char *share_buf_A_ptr = (unsigned char *) strtoul(argv[10], NULL, 10);     //  shared_buff_ptr
    size_t share_buf_A_size = (size_t) strtoul(argv[11], NULL, 10);                     //  shared_buff_size
    unsigned char *share_buf_C_ptr = (unsigned char *) strtoul(argv[12], NULL, 10);     //  shared_buff_ptr
    size_t share_buf_C_size = (size_t) strtoul(argv[13], NULL, 10);                     //  shared_buff_size

    int PROTOCOL_MODE = OVERALL_PROTOCOL_MODE % 2;
    int HYBRID_ENCRYPTION_ON = OVERALL_PROTOCOL_MODE / 2;
    // int OVERALL_PROTOCOL_MODE = 2*HYBRID_ENCRYPTION_ON + PROTOCOL_MODE;
    //      HYBRID_ENCRYPTION_ON    PROTOCOL_MODE
    //  0       0                          0
    //  1       0                          1
    //  2       1                          0
    //  3       1                          1
    // std::cout << "PROTOCOL_MODE: " << PROTOCOL_MODE << endl;
    // std::cout << "HYBRID_ENCRYPTION_ON: " << HYBRID_ENCRYPTION_ON << endl;

    RSA* receiver_pk;
    unsigned char *AES_buffer_sender_ptr;
    unsigned char *AES_buffer_receiver_ptr;
    size_t AES_buffer_sender_size, AES_buffer_receiver_size;


    //  must need receiver_pk
    if(PROTOCOL_MODE){

        receiver_pk = (RSA *) strtoul(argv[14], NULL, 10);             //  receiver_pk

        //  A/B/C/Delta need to encrypt, so need AES_buffer_receiver & AES_buffer_sender
        if(HYBRID_ENCRYPTION_ON){
            AES_buffer_sender_ptr = (unsigned char *) strtoul(argv[15], NULL, 10);     //  AES_buffer_sender_ptr
            AES_buffer_sender_size = (size_t) strtoul(argv[16], NULL, 10);             //  AES_buffer_sender_size
            AES_buffer_receiver_ptr = (unsigned char *) strtoul(argv[17], NULL, 10);   //  AES_buffer_receiver_ptr
            AES_buffer_receiver_size = (size_t) strtoul(argv[18], NULL, 10);           //  AES_buffer_receiver_size
        }

    }

    // do not need receiver_pk
    else{
        if(HYBRID_ENCRYPTION_ON){
            AES_buffer_sender_ptr = (unsigned char *) strtoul(argv[14], NULL, 10);     //  AES_buffer_sender_ptr
            AES_buffer_sender_size = (size_t) strtoul(argv[15], NULL, 10);             //  AES_buffer_sender_size
        }
    }
       


    if (share_buf_A_ptr == NULL || share_buf_A_size == 0 || share_buf_B_ptr == NULL || share_buf_B_size == 0 || \
        share_buf_C_ptr == NULL || share_buf_C_size == 0 || share_buf_Delta_ptr == NULL || share_buf_Delta_size == 0 || \
        field_B == 0 || field_F == 0 || size_m == 0 || sender_pk == NULL || \
        (PROTOCOL_MODE == 1 &&  receiver_pk == NULL) || \

        (PROTOCOL_MODE == 1 && HYBRID_ENCRYPTION_ON == 1 && (AES_buffer_sender_ptr == NULL || AES_buffer_sender_size == 0 || \
                                                            AES_buffer_receiver_ptr == NULL || AES_buffer_receiver_size == 0)) || \

        (PROTOCOL_MODE == 0 && HYBRID_ENCRYPTION_ON == 1 && (AES_buffer_sender_ptr == NULL || AES_buffer_sender_size == 0)) ){
            
        std::cout << "---[In SGX] ---[Error] Parameters illegal in VOLE Generation" << endl;
        return EXIT_FAILURE;
    }
    // else std::cout << "---[In SGX] ---Parameters legal in VOLE Generation" << endl;

    // RSA_print_fp(stdout, sender_pk, 0);
    // RSA_print_fp(stdout, receiver_pk, 0);

    

    // std::cout << "size_m = " << size_m << endl;
    // std::cout << "field_F = " << field_F << endl;
    // std::cout << "field_B = " << field_B << endl;
    // std::cout << sender_pk_size << endl;
    Timer parseEnd = std::chrono::system_clock::now();
    // std::cout << "---[Time] Interact with TEE process: ";
    std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(parseEnd - parseBegin).count() << "ms" << std::endl;
    
    // std::cout << "---[In SGX] Parse parameters [done]" << endl;


    /*----------- Generate A/B/C/Δ -----------*/
 
        //  each element in field_B/F:  128 bit <==> 16 Byte
        //  
        //  for security, padding 11Bytes
        //  
        //  2048-bit key  ==>  256 Bytes  ==>  245 Bytes available
        //  
        //  every 240 Bytes(15 elements)
        //  
        //  (3m+1) elements
        //  (3m+1) / 15  *256 Bytes total needed (about 70MB)


    //  type for paras
        //  RSA                 unsigned char* -> unsigned char*
        //  random generator    unsigned char*(RAND_bytes)
        //  BIGNUM memory   

        //  A       field B     -> receiver
        //  C       field F     -> receiver
        //  B       field F     -> sender
        //  Δ       field B     -> sender
    std::cout << "---[In SGX] Generate A/B/C/Delta ";
    Timer generateBegin = std::chrono::system_clock::now();




    int byte_length_field_B = (int)(field_B/8);
    int byte_length_field_F = (int)(field_F/8);

    
    int bytes_count_A = byte_length_field_B;
    int bytes_count_B = byte_length_field_F;
    int bytes_count_C = byte_length_field_F;    

    int bytes_count_A_total = size_m * bytes_count_A;
    int bytes_count_B_total = size_m * bytes_count_B;
    int bytes_count_C_total = size_m * bytes_count_C;
    int bytes_count_Delta = byte_length_field_B;


    unsigned char *randA = (unsigned char *)malloc(bytes_count_A_total);
    unsigned char *randB = (unsigned char *)malloc(bytes_count_B_total);
    unsigned char *randC = (unsigned char *)malloc(bytes_count_C_total);
    unsigned char *randDelta = (unsigned char *)malloc(bytes_count_Delta);

    int rand_res_1 = RAND_bytes(randA,bytes_count_A_total);
    int rand_res_2 = RAND_bytes(randB,bytes_count_B_total);
    int rand_res_3 = RAND_bytes(randDelta,bytes_count_Delta);

    if(rand_res_1 == 0 || rand_res_2 == 0 || rand_res_3 == 0){
        std::cout << "---[In SGX] ---[Error] Randomness malloc generation failure" << endl;
        return EXIT_FAILURE;
    }
    // else std::cout << "---[In SGX] ---Randomness malloc generation success" << endl;

    // std::cout << rand_res_1 << " " << rand_res_2 << " " << rand_res_3 << endl;
    
    BIGNUM *Delta = BN_new();
    Delta = BN_bin2bn(randDelta, bytes_count_Delta, NULL);


    // char *p = BN_bn2hex (Delta); 
    // if (p)
    // {
    // printf ("number is 0x%s\n", p);
    // OPENSSL_free (p);
    // }

    BIGNUM *tmpA = BN_new();
    BIGNUM *tmpB = BN_new();
    // BIGNUM *tmpADelta = BN_new();
    BIGNUM *tmpC = BN_new();
    unsigned char tmpC2store[bytes_count_C + 1];
    for (int i = 0; i< size_m; i++){
        tmpA = BN_bin2bn((unsigned char*)(randA + (int)(i*bytes_count_A)), bytes_count_A, NULL);   
        tmpB = BN_bin2bn((unsigned char*)(randB + (int)(i*bytes_count_B)), bytes_count_B, NULL);    
        BN_CTX *ctx = BN_CTX_new();
        BN_mul(tmpC, tmpA, Delta, ctx);
        BN_add(tmpC, tmpC, tmpB);
        BN_bn2bin(tmpC, tmpC2store);
        // std::cout << "generate res:" << res << " i = " << i <<  endl;
        memcpy((unsigned char*)(randC + (int)(i*bytes_count_C)), tmpC2store, bytes_count_C);
        BN_CTX_free (ctx);
    }

    // std::cout << "---[In SGX] Generate A/B/C/Delta [done]" << endl;
    Timer generateEnd = std::chrono::system_clock::now();
    // std::cout << "---[In SGX] ---[Time] Generate A/B/C/Delta: ";
    std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(generateEnd - generateBegin).count() << "ms" << std::endl;
    
    
    
    /*----------- Encryption -----------*/
    if(PROTOCOL_MODE) std::cout << "---[In SGX] Encrypt A/B/C/Delta ..." << endl;
    else std::cout << "---[In SGX] Encrypt B/Delta ";

    Timer encryptBDeltaBegin = std::chrono::system_clock::now();


    int sender_pk_size = RSA_size(sender_pk);       //  count in byte
    
    //  Encrypt B/Delta
        //  each cipher text contains (element_B_count_per_cipher) elements B
        //  plaintext   in  randB/Delta/A/C
        //  ciphertext  in  buffer_B/Delta(A/C)

    // std::cout << "size_m = " << size_m << endl;
    // std::cout << "bytes_count_B = " << bytes_count_B << endl;
    // std::cout << "element_B_count_per_cipher = " << element_B_count_per_cipher << endl;
    // std::cout << "cipher_count_B = " << cipher_count_B << endl;
    
    
    //  sender_pk must be inside the sgx, so we create a new RSA object
    RSA *sender_pk_inside = RSA_new();
    const BIGNUM *n, *e;
    RSA_get0_key(sender_pk, &n, &e, NULL);
    RSA_set0_key(sender_pk_inside, BN_dup(n), BN_dup(e), NULL);

    // //  buffer for rsa encryption for aes-key&ivec for sender
    // unsigned char *buffer_sender_enc_aes_key;
    // unsigned char *buffer_sender_enc_aes_ivec;

    //  Hybrid Encryption for B/Delta
    if(HYBRID_ENCRYPTION_ON){
        //  Hybrid encryption
        //  RSA + AES
        //  RSA:    encrypt AES key
        //  AES:    encrypt data
        //  AES key:   AES_KEY_LENGTH bit
        //  AES data:  A/B/C/Delta
        //  RSA key:   KEY_LENGTH bit
        //  RSA data:  aes key & ivec


        // //  buffer for rsa encryption for aes-key&ivec for sender
        // buffer_sender_enc_aes_key = (unsigned char *)malloc(sender_pk_size);
        // buffer_sender_enc_aes_ivec = (unsigned char *)malloc(sender_pk_size);

        //  AES key & ivec generation
        unsigned char *aes_sender_key_buffer1 = (unsigned char *)malloc(AES_KEY_LENGTH_BYTE);
        unsigned char *aes_sender_key_buffer2 = (unsigned char *)malloc(AES_KEY_LENGTH_BYTE);
        unsigned char *aes_sender_ivec1 = (unsigned char *)malloc(AES_IV_LENGTH_BYTE);
        unsigned char *aes_sender_ivec2 = (unsigned char *)malloc(AES_IV_LENGTH_BYTE);

        //  加密/解密过程中 ivec 会发生变化，因此每次加密选择新的 ivec & key

        int rand_res_4 = RAND_bytes(aes_sender_key_buffer1,AES_KEY_LENGTH_BYTE);
        int rand_res_5 = RAND_bytes(aes_sender_key_buffer2,AES_KEY_LENGTH_BYTE);
        int rand_res_6 = RAND_bytes(aes_sender_ivec1,AES_IV_LENGTH_BYTE);
        int rand_res_7 = RAND_bytes(aes_sender_ivec2,AES_IV_LENGTH_BYTE);
        if(rand_res_4 == 0 || rand_res_5 == 0 || rand_res_6 == 0 || rand_res_7 == 0) std::cout << "---[In SGX] ---[Error] AES key generation for Sender failure" << endl;
        // else std::cout << "---[In SGX] ---AES key generation for Sender success" << endl;
        

        // //  display key * ivec
        // std::cout << "AES stuff in sender vole: " << endl;
        // for(int i = 0; i < AES_KEY_LENGTH_BYTE; i++){
        //     printf("%02x ", aes_sender_key_buffer1[i]);
        // }
        // printf("\n");
        // for(int i = 0; i < AES_KEY_LENGTH_BYTE; i++){
        //     printf("%02x ", aes_sender_key_buffer2[i]);
        // }
        // printf("\n");
        // for(int i = 0; i < AES_IV_LENGTH_BYTE; i++){
        //     printf("%02x ", aes_sender_ivec1[i]);
        // }   
        // printf("\n");
        // for(int i = 0; i < AES_IV_LENGTH_BYTE; i++){
        //     printf("%02x ", aes_sender_ivec2[i]);
        // }
        // printf("\n");


        //  Encrypt AES key & ivec
        //  iv 应该保存 加密之前的部分，这样才可以反向解密
        RSA_public_encrypt(AES_KEY_LENGTH_BYTE, aes_sender_key_buffer1, (unsigned char*)(AES_buffer_sender_ptr + 0*sender_pk_size), sender_pk_inside, PADDING_MODE);
        RSA_public_encrypt(AES_KEY_LENGTH_BYTE, aes_sender_key_buffer2, (unsigned char*)(AES_buffer_sender_ptr + 1*sender_pk_size), sender_pk_inside, PADDING_MODE);
        RSA_public_encrypt(AES_IV_LENGTH_BYTE, aes_sender_ivec1,        (unsigned char*)(AES_buffer_sender_ptr + 2*sender_pk_size), sender_pk_inside, PADDING_MODE);
        RSA_public_encrypt(AES_IV_LENGTH_BYTE, aes_sender_ivec2,        (unsigned char*)(AES_buffer_sender_ptr + 3*sender_pk_size), sender_pk_inside, PADDING_MODE);
        // std::cout << "---[In SGX] ---Encrypt AES key & ivec for [Sender] done " << endl;



        // for(int i = 0; i < 4*sender_pk_size; i++){
        //     printf("%02x ", AES_buffer_sender_ptr[i]);
        // }
        // printf("\n");


        AES_KEY sender_aes_encrypt_key1, sender_aes_encrypt_key2;
        AES_set_encrypt_key(aes_sender_key_buffer1, AES_KEY_LENGTH_BIT, &sender_aes_encrypt_key1);
        AES_set_encrypt_key(aes_sender_key_buffer2, AES_KEY_LENGTH_BIT, &sender_aes_encrypt_key2);


        
        //  Encrypt B
        AES_cbc_encrypt(randB, share_buf_B_ptr, bytes_count_B_total, &sender_aes_encrypt_key1, aes_sender_ivec1, AES_ENCRYPT);
        // std::cout << "---[In SGX] ---Encrypt B done" << endl;

        //  Encrypt Delta
        AES_cbc_encrypt(randDelta, share_buf_Delta_ptr, bytes_count_Delta, &sender_aes_encrypt_key2, aes_sender_ivec2, AES_ENCRYPT);
        // std::cout << "---[In SGX] ---Encrypt Delta done" << endl;

        

    }
    else{
        //  Encrypt B
        int element_B_count_per_cipher = (sender_pk_size   - DEFAULT_PADDING_LENGTH) / bytes_count_B;
        int cipher_count_B = ceil(size_m *1.0/ element_B_count_per_cipher);

        int real_element_in_cipher_count_B = element_B_count_per_cipher;
        int iter;
        for(iter = 0; iter < cipher_count_B - 1; iter ++){
            RSA_public_encrypt(real_element_in_cipher_count_B * bytes_count_B, \
            (unsigned char*)(randB + (iter * bytes_count_B * element_B_count_per_cipher)), \
            (unsigned char*)(share_buf_B_ptr + (iter * sender_pk_size)) , \
            sender_pk_inside, PADDING_MODE);
            
        }
        real_element_in_cipher_count_B = size_m - iter * element_B_count_per_cipher;
        RSA_public_encrypt(real_element_in_cipher_count_B, \
        (const unsigned char*)(randB + (iter * bytes_count_B * element_B_count_per_cipher)), \
        (unsigned char*)(share_buf_B_ptr + (iter * sender_pk_size)) , \
        sender_pk_inside, PADDING_MODE);
        std::cout << "---[In SGX] ---Encrypt B done" << endl;

        //  Encrypt Delta
        RSA_public_encrypt(bytes_count_Delta, randDelta, share_buf_Delta_ptr, sender_pk_inside, PADDING_MODE);
        std::cout << "---[In SGX] ---Encrypt Delta done" << endl;
    }
    
    
    
    Timer encryptBDeltaEnd = std::chrono::system_clock::now();

    if(PROTOCOL_MODE) std::cout << "---[In SGX] ---Encrypt B/Delta " << std::chrono::duration_cast<std::chrono::milliseconds>(encryptBDeltaEnd - encryptBDeltaBegin).count() << "ms" << std::endl;
    else     std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(encryptBDeltaEnd - encryptBDeltaBegin).count() << "ms" << std::endl;

    // std::cout << "---[In SGX] ---[Time] Encrypt B/Delta: ";
    // std::cout << 
    
    // int tmp_start = 100;
    // int tmp_end = 200;
    // for(int i = tmp_start;i<tmp_end;i++) printf("%02x ",randA[i]);
    // printf("\n");
    // for(int i = tmp_start;i<tmp_end;i++) printf("%02x ",randB[i]);
    // printf("\n");
    // for(int i = tmp_start;i<tmp_end;i++) printf("%02x ",randC[i]);
    // printf("\n");


    // std::cout << "bytes_count_Delta = " << bytes_count_Delta << endl;

    // unsigned char plain[512]="This is the plaintext to encrypt!";
    // unsigned char cipper[512]={0};
    // unsigned char newplain[512]={0};

    // // std::cout << "Enc error" << endl;
    // // RSA_print_fp(stdout, sender_pk, 11);
    // // RSA_print_fp(stdout, receiver_pk, 11);
    
    // int out1 = RSA_private_encrypt(strlen((char*)plain), plain, cipper, receiver_pk, PADDING_MODE);
    // int out2 = RSA_public_decrypt(out1,cipper,newplain,receiver_pk,PADDING_MODE);

    // std::cout << out1 << endl;
    // std::cout << out2 << endl;

    // printf("-----------------\n%s\n", newplain);
    // for(int i =0;i<out2;i++) {
    //     printf("%02x ",newplain[i]);
    // }
    // printf("\n");



    //  Encrypt A/C (Optional)     

    // //  Encrypt AES key & ivec with rsa-receiver-pk (Optional)
    // unsigned char *buffer_receiver_enc_aes_key;
    // unsigned char *buffer_receiver_enc_aes_ivec;

    if(PROTOCOL_MODE){  //  need to encrypt
        Timer encryptACBegin = std::chrono::system_clock::now();

        RSA *receiver_pk_inside = RSA_new();
        const BIGNUM *n, *e;
        RSA_get0_key(receiver_pk, &n, &e, NULL);
        RSA_set0_key(receiver_pk_inside, BN_dup(n), BN_dup(e), NULL);
        int receiver_pk_size = RSA_size(receiver_pk);   //  count in byte

        //  Hybrid encryption for receiver
        if(HYBRID_ENCRYPTION_ON){

            // //  buffer for rsa encryption for aes-key&ivec for sender
            // buffer_receiver_enc_aes_key = (unsigned char *)malloc(receiver_pk_size);
            // buffer_receiver_enc_aes_ivec = (unsigned char *)malloc(receiver_pk_size);


            //  AES key & ivec generation
            unsigned char aes_receiver_key_buffer1[AES_KEY_LENGTH_BYTE];
            unsigned char aes_receiver_key_buffer2[AES_KEY_LENGTH_BYTE];
            unsigned char aes_receiver_ivec1[AES_IV_LENGTH_BYTE];
            unsigned char aes_receiver_ivec2[AES_IV_LENGTH_BYTE];


            int rand_res_4 = RAND_bytes(aes_receiver_key_buffer1,AES_KEY_LENGTH_BYTE);
            int rand_res_5 = RAND_bytes(aes_receiver_key_buffer1,AES_KEY_LENGTH_BYTE);
            int rand_res_6 = RAND_bytes(aes_receiver_ivec1,AES_IV_LENGTH_BYTE);
            int rand_res_7 = RAND_bytes(aes_receiver_ivec2,AES_IV_LENGTH_BYTE);
            if(rand_res_4 == 0 || rand_res_5 == 0 || rand_res_6 == 0 || rand_res_7 == 0) std::cout << "---[In SGX] ---[Error] AES key generation for Receiver failure" << endl;
            // else std::cout << "---[In SGX] ---AES key generation for Receiver success" << endl;
            
            //  Encrypt AES key & ivec
            //  iv 应该保存 加密之前的部分，这样才可以反向解密
            RSA_public_encrypt(AES_KEY_LENGTH_BYTE, aes_receiver_key_buffer1, (unsigned char*)(AES_buffer_receiver_ptr + 0*receiver_pk_size), receiver_pk_inside, PADDING_MODE);
            RSA_public_encrypt(AES_KEY_LENGTH_BYTE, aes_receiver_key_buffer2, (unsigned char*)(AES_buffer_receiver_ptr + 1*receiver_pk_size), receiver_pk_inside, PADDING_MODE);
            RSA_public_encrypt(AES_IV_LENGTH_BYTE, aes_receiver_ivec1,        (unsigned char*)(AES_buffer_receiver_ptr + 2*receiver_pk_size), receiver_pk_inside, PADDING_MODE);
            RSA_public_encrypt(AES_IV_LENGTH_BYTE, aes_receiver_ivec2,        (unsigned char*)(AES_buffer_receiver_ptr + 3*receiver_pk_size), receiver_pk_inside, PADDING_MODE);
            // std::cout << "---[In SGX] ---Encrypt AES key & ivec for [Receiver] done " << endl;
            

            // std::cout << "AES stuff in receiver vole: " << endl;
            // for(int i = 0; i < AES_KEY_LENGTH_BYTE; i++){
            //     printf("%02x ", aes_receiver_key_buffer1[i]);
            // }
            // printf("\n");
            // for(int i = 0; i < AES_KEY_LENGTH_BYTE; i++){
            //     printf("%02x ", aes_receiver_key_buffer2[i]);
            // }
            // printf("\n");
            // for(int i = 0; i < AES_IV_LENGTH_BYTE; i++){
            //     printf("%02x ", aes_receiver_ivec1[i]);
            // }   
            // printf("\n");
            // for(int i = 0; i < AES_IV_LENGTH_BYTE; i++){
            //     printf("%02x ", aes_receiver_ivec2[i]);
            // }
            // printf("\n");


            AES_KEY receiver_aes_encrypt_key1, receiver_aes_encrypt_key2;
            AES_set_encrypt_key(aes_receiver_key_buffer1, AES_KEY_LENGTH_BIT, &receiver_aes_encrypt_key1);
            AES_set_encrypt_key(aes_receiver_key_buffer2, AES_KEY_LENGTH_BIT, &receiver_aes_encrypt_key2);


            

            //  Encrypt A
            AES_cbc_encrypt(randA, share_buf_A_ptr, bytes_count_A_total, &receiver_aes_encrypt_key1, aes_receiver_ivec1, AES_ENCRYPT);
            // std::cout << "---[In SGX] ---Encrypt A done" << endl;

            //  Encrypt C
            AES_cbc_encrypt(randC, share_buf_C_ptr, bytes_count_C_total, &receiver_aes_encrypt_key2, aes_receiver_ivec2, AES_ENCRYPT);
            // std::cout << "---[In SGX] ---Encrypt C done" << endl;

            // for(int i = 0; i < 100; i++){
            //     printf("%02x ", randA[i]);
            // }
            // printf("\n");
            
        }
        else{
            int element_A_count_per_cipher = (receiver_pk_size - DEFAULT_PADDING_LENGTH) / bytes_count_A;
            int element_C_count_per_cipher = (receiver_pk_size - DEFAULT_PADDING_LENGTH) / bytes_count_C;
            int cipher_count_A = ceil(size_m *1.0/ element_A_count_per_cipher);
            int cipher_count_C = ceil(size_m *1.0/ element_C_count_per_cipher);


            // std::cout << "sender_pk_size = " << RSA_size(sender_pk) << endl;
            // std::cout << "sender_pk_size_inside = " << RSA_size(sender_pk_inside) << endl;

            // std::cout << "receiver_pk_size = " << RSA_size(receiver_pk) << endl;
            // std::cout << "receiver_pk_size_inside = " << RSA_size(receiver_pk_inside) << endl;
            int iter;

            //  Encrypt A
            int real_element_in_cipher_count_A = element_A_count_per_cipher;
            for(iter = 0; iter < cipher_count_A - 1; iter ++){
                RSA_public_encrypt(real_element_in_cipher_count_A * bytes_count_A, \
                (unsigned char*)(randA + (iter * bytes_count_A * element_A_count_per_cipher)), \
                (unsigned char*)(share_buf_A_ptr + (iter * receiver_pk_size)) , \
                receiver_pk_inside, PADDING_MODE);
                // std::cout << iter << endl;
            }
            real_element_in_cipher_count_A = size_m - iter * element_A_count_per_cipher;
            RSA_public_encrypt(real_element_in_cipher_count_A, \
            (const unsigned char*)(randA + (iter * bytes_count_A * element_A_count_per_cipher)), \
            (unsigned char*)(share_buf_A_ptr + (iter * receiver_pk_size)) , \
            receiver_pk_inside, PADDING_MODE);
            // std::cout << "---[In SGX] ---Encrypt A done" << endl;

            //  Encrypt C
            int real_element_in_cipher_count_C = element_C_count_per_cipher;
            for(iter = 0; iter < cipher_count_C - 1; iter ++){
                RSA_public_encrypt(real_element_in_cipher_count_C * bytes_count_C, \
                (unsigned char*)(randC + (iter * bytes_count_C * element_C_count_per_cipher)), \
                (unsigned char*)(share_buf_C_ptr + (iter * receiver_pk_size)) , \
                receiver_pk_inside, PADDING_MODE);
                
            }

            real_element_in_cipher_count_C = size_m - iter * element_C_count_per_cipher;
            RSA_public_encrypt(real_element_in_cipher_count_C, \
            (const unsigned char*)(randC + (iter * bytes_count_C * element_C_count_per_cipher)), \
            (unsigned char*)(share_buf_C_ptr + (iter * receiver_pk_size)) , \
            receiver_pk_inside, PADDING_MODE);
            // std::cout << "---[In SGX] ---Encrypt C done" << endl;
        }


        Timer encryptACEnd = std::chrono::system_clock::now();
        std::cout << "---[In SGX] ---Encrypt A/C ";
        std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(encryptACEnd - encryptACBegin).count() << "ms" << std::endl;

        std::cout << "---[In SGX] Encrypt A/B/C/Delta done" << endl;

    }
    else{
        memcpy(share_buf_A_ptr, randA, bytes_count_A_total);
        memcpy(share_buf_C_ptr, randC, bytes_count_C_total);
    }

    // Timer decryptBegin, decryptEnd;

    // AES_KEY receiver_aes_key;
    // unsigned char* aes_receiver_key_buffer = (unsigned char*)malloc(AES_KEY_LENGTH_BYTE);
    // unsigned char* aes_receiver_ivec = (unsigned char*)malloc(AES_IV_LENGTH_BYTE);
    // memset(aes_receiver_key_buffer, 0, AES_KEY_LENGTH_BYTE);
    // memset(aes_receiver_ivec, 0, AES_IV_LENGTH_BYTE);
    
    // //  RSA decrypt
    // AES_set_decrypt_key(aes_receiver_key_buffer, aes_key_length_receiver, &receiver_aes_key);

    // //  AES decrypt

    // //  Decrypting A
    // std::cout << "---Decrypting A" << endl;
    // decryptBegin = std::chrono::system_clock::now();

    
    // AES_cbc_encrypt(buffer_A, randA, bytes_count_A_total, &receiver_aes_key, aes_receiver_ivec, AES_DECRYPT);
    // decryptEnd = std::chrono::system_clock::now();
    // std::cout << "---[Time] Decrypting Enc(A): ";
    // std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(decryptEnd - decryptBegin).count() << "ms" << std::endl;

    // //  Decrypting C
    // std::cout << "---Decrypting C" << endl;
    // decryptBegin = std::chrono::system_clock::now();
    // AES_cbc_encrypt(buffer_C, randC, bytes_count_C_total, &receiver_aes_key, aes_receiver_ivec, AES_DECRYPT);
    // decryptEnd = std::chrono::system_clock::now();
    // std::cout << "---[Time] Decrypting Enc(C): ";
    // std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(decryptEnd - decryptBegin).count() << "ms" << std::endl;


    // if(PROTOCOL_MODE) std::cout << "---[In SGX] Encrypt A/B/C/Delta [done]" << endl;
    // else std::cout << "---[In SGX] Encrypt B/Delta [done]" << endl;


    // for(int i = 0; i < 200; i++){
    //     printf("%02x ", randB[i]);
    // }
    // printf("\n");

    Timer sgxEnd = std::chrono::system_clock::now();
    std::cout << "Interact with TEE done ";
    std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(sgxEnd - sgxBegin).count() << "ms" << std::endl;
    
    std::cout << "--------------------------------------------------" << endl;

    return EXIT_SUCCESS;

}