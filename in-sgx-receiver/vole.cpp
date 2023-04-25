#include <iostream>
#include <vector>
#include <ctime>
#include <cmath>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/time.h>

using namespace std;

#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/pem.h>

#define PADDING_MODE RSA_PKCS1_PADDING 
#define DEFAULT_PADDING_LENGTH 11


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


    /*----------- Parse arguments -----------*/

    cout << "---[In SGX] Parsing parameters ..." << endl;

    if (argc < 14) {
        cout << "---[In SGX] ---[Error] Parameters missing in VOLE Generation" << endl;
        return EXIT_FAILURE;
    }
    else cout << "---[In SGX] ---Parameters enough in VOLE Generation" << endl;
                                                                        //  str->unsigned long
    int PROTOCOL_MODE = (int) strtoul(argv[1], NULL, 10);               //  MODE 0/1
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


    RSA* receiver_pk;
    if(PROTOCOL_MODE){
        receiver_pk = (RSA *) strtoul(argv[14], NULL, 10);             //  pk
    }  
    

    if (share_buf_A_ptr == NULL || share_buf_A_size == 0 || share_buf_B_ptr == NULL || share_buf_B_size == 0 || \
        share_buf_C_ptr == NULL || share_buf_C_size == 0 || share_buf_Delta_ptr == NULL || share_buf_Delta_size == 0 || \
        field_B == 0 || field_F == 0 || size_m == 0 || sender_pk == NULL || \
        (PROTOCOL_MODE == 1 &&  receiver_pk == NULL)) {
        cout << "---[In SGX] ---[Error] Parameters illegal in VOLE Generation" << endl;
        return EXIT_FAILURE;
    }
    else cout << "---[In SGX] ---Parameters legal in VOLE Generation" << endl;

    // RSA_print_fp(stdout, sender_pk, 0);
    // RSA_print_fp(stdout, receiver_pk, 0);

    

    // cout << "size_m = " << size_m << endl;
    // cout << "field_F = " << field_F << endl;
    // cout << "field_B = " << field_B << endl;
    // cout << sender_pk_size << endl;
    cout << "---[In SGX] Parsing parameters [done]" << endl;


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
    cout << "---[In SGX] Generating A/B/C/Delta ..." << endl;




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
        cout << "---[In SGX] ---[Error] Randomness malloc generation failure" << endl;
        return EXIT_FAILURE;
    }
    else cout << "---[In SGX] ---Randomness malloc generation success" << endl;

    // cout << rand_res_1 << " " << rand_res_2 << " " << rand_res_3 << endl;
    
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
        // cout << "generate res:" << res << " i = " << i <<  endl;
        memcpy((unsigned char*)(randC + (int)(i*bytes_count_C)), tmpC2store, bytes_count_C);
        BN_CTX_free (ctx);
    }

    cout << "---[In SGX] Generating A/B/C/Delta [done]" << endl;

    
    
    /*----------- Encryption -----------*/
    if(PROTOCOL_MODE) cout << "---[In SGX] Encrypting A/B/C/Delta ..." << endl;
    else cout << "---[In SGX] Encrypting B/Delta ..." << endl;

    int sender_pk_size = RSA_size(sender_pk);       //  count in byte
    int element_B_count_per_cipher = (sender_pk_size   - DEFAULT_PADDING_LENGTH) / bytes_count_B;
    int cipher_count_B = ceil(size_m *1.0/ element_B_count_per_cipher);



    

    
    //  Encrypting B/Delta
        //  each cipher text contains (element_B_count_per_cipher) elements B
        //  plaintext   in  randB/Delta/A/C
        //  ciphertext  in  buffer_B/Delta(A/C)

    // cout << "size_m = " << size_m << endl;
    // cout << "bytes_count_B = " << bytes_count_B << endl;
    // cout << "element_B_count_per_cipher = " << element_B_count_per_cipher << endl;
    // cout << "cipher_count_B = " << cipher_count_B << endl;
    
    
    //  sender_pk must be inside the sgx, so we create a new RSA object
    RSA *sender_pk_inside = RSA_new();
    const BIGNUM *n, *e;
    RSA_get0_key(sender_pk, &n, &e, NULL);
    RSA_set0_key(sender_pk_inside, BN_dup(n), BN_dup(e), NULL);
    
    //  Encrypting B
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
    cout << "---[In SGX] ---Encrypting B done" << endl;

    //  Encrypting Delta
    RSA_public_encrypt(bytes_count_Delta, randDelta, share_buf_Delta_ptr, sender_pk_inside, PADDING_MODE);
    cout << "---[In SGX] ---Encrypting Delta done" << endl;


    // cout << "bytes_count_Delta = " << bytes_count_Delta << endl;

    // unsigned char plain[512]="This is the plaintext to encrypt!";
    // unsigned char cipper[512]={0};
    // unsigned char newplain[512]={0};

    // // cout << "Enc error" << endl;
    // // RSA_print_fp(stdout, sender_pk, 11);
    // // RSA_print_fp(stdout, receiver_pk, 11);
    
    // int out1 = RSA_private_encrypt(strlen((char*)plain), plain, cipper, receiver_pk, PADDING_MODE);
    // int out2 = RSA_public_decrypt(out1,cipper,newplain,receiver_pk,PADDING_MODE);

    // cout << out1 << endl;
    // cout << out2 << endl;

    // printf("-----------------\n%s\n", newplain);
    // for(int i =0;i<out2;i++) {
    //     printf("%02x ",newplain[i]);
    // }
    // printf("\n");



    //  Encrypting A/C (Optional)       

    if(PROTOCOL_MODE){  //  need to encrypt
        RSA *receiver_pk_inside = RSA_new();
        const BIGNUM *n, *e;
        RSA_get0_key(receiver_pk, &n, &e, NULL);
        RSA_set0_key(receiver_pk_inside, BN_dup(n), BN_dup(e), NULL);

        int receiver_pk_size = RSA_size(receiver_pk);   //  count in byte
        int element_A_count_per_cipher = (receiver_pk_size - DEFAULT_PADDING_LENGTH) / bytes_count_A;
        int element_C_count_per_cipher = (receiver_pk_size - DEFAULT_PADDING_LENGTH) / bytes_count_C;
        int cipher_count_A = ceil(size_m *1.0/ element_A_count_per_cipher);
        int cipher_count_C = ceil(size_m *1.0/ element_C_count_per_cipher);

        //  Encrypting A
        int real_element_in_cipher_count_A = element_A_count_per_cipher;
        for(iter = 0; iter < cipher_count_A - 1; iter ++){
            RSA_public_encrypt(real_element_in_cipher_count_A * bytes_count_A, \
            (unsigned char*)(randA + (iter * bytes_count_A * element_A_count_per_cipher)), \
            (unsigned char*)(share_buf_A_ptr + (iter * sender_pk_size)) , \
            receiver_pk_inside, PADDING_MODE);
            
        }
        real_element_in_cipher_count_A = size_m - iter * element_A_count_per_cipher;
        RSA_public_encrypt(real_element_in_cipher_count_A, \
        (const unsigned char*)(randA + (iter * bytes_count_A * element_A_count_per_cipher)), \
        (unsigned char*)(share_buf_A_ptr + (iter * sender_pk_size)) , \
        receiver_pk_inside, PADDING_MODE);
        cout << "---[In SGX] ---Encrypting A done" << endl;

        //  Encrypting C
        int real_element_in_cipher_count_C = element_C_count_per_cipher;
        for(iter = 0; iter < cipher_count_C - 1; iter ++){
            RSA_public_encrypt(real_element_in_cipher_count_C * bytes_count_C, \
            (unsigned char*)(randC + (iter * bytes_count_C * element_C_count_per_cipher)), \
            (unsigned char*)(share_buf_C_ptr + (iter * sender_pk_size)) , \
            receiver_pk_inside, PADDING_MODE);
            
        }

        real_element_in_cipher_count_C = size_m - iter * element_C_count_per_cipher;
        RSA_public_encrypt(real_element_in_cipher_count_C, \
        (const unsigned char*)(randC + (iter * bytes_count_C * element_C_count_per_cipher)), \
        (unsigned char*)(share_buf_C_ptr + (iter * sender_pk_size)) , \
        receiver_pk_inside, PADDING_MODE);
        cout << "---[In SGX] ---Encrypting C done" << endl;

    }
    else{
        memcpy(share_buf_A_ptr, randA, bytes_count_A_total);
        memcpy(share_buf_C_ptr, randC, bytes_count_C_total);
    }


    if(PROTOCOL_MODE) cout << "---[In SGX] Encrypting A/B/C/Delta [done]" << endl;
    else cout << "---[In SGX] Encrypting B/Delta [done]" << endl;



    return EXIT_SUCCESS;



    // srand(time(nullptr));

    // type_size m = 100;
    // type_F F_MAX = rand();
    // type_B B_MAX = sqrt(F_MAX);
    
    // // type_F delta;

    
    // type_F delta = rand()%F_MAX;
    // vector<type_B> A;
    // vector<type_F> B, C;

    // for(int i=0; i< m; i++){
    //     type_B tmpa = rand()%B_MAX;
    //     type_F tmpb = rand()%F_MAX;
    //     A.push_back(tmpa);
    //     B.push_back(tmpb);
    //     C.push_back(tmpa * delta + tmpb);
    // }

    // for(int i=0; i< m; i++){
    //     cout << A[i] << "   "  << B[i] << "    " << C[i] << endl;
    // }


    // printf("vole generation done\n");
    // return 0;
}