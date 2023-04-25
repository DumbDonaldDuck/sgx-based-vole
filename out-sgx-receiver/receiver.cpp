#include <iostream>
#include <string>
// here is something wrong

#include <cmath>
#include <cstring>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <netdb.h>
#include <occlum_pal_api.h>
#include <linux/limits.h>

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

// MAX Char buff size, at most is KEY_LENGTH_BIT/4 
    //  X-bit key length
    //  X/4 hex-length (0-F)
    //  each symbol of hex(0-F) is presented in char, which is 8 bit / 1 byte
    //  so the required length of CHAR_BUFF_SIZE is at most X/4
#define CHAR_BUFF_SIZE (RSA_KEY_BIT_LENGTH/4 + 1)

// confirm buff size
#define CONFIRM_BUFF_SIZE 16

// Receiver's port & addr could be designated at first
#define RECEIVER_PORT 4602
#define RECEIVER_ADDR "127.0.0.1"

//  parameters for func listen(int sockfd, int backlog);
//  the length for the ESTABLISHED_STATUS_QUEUE
//  maximum is 128
#define DEFAULT_RECEIVER_BACKLOG 5

//  para for RSA padding
#define PADDING_MODE RSA_PKCS1_PADDING 
#define DEFAULT_PADDING_LENGTH 11

//  para for VOLE
#define FIELD_B 64
#define FIELD_F 128
#define SIZE_M 1357676
#define DEFAULT_PARA_LENGTH 10

//  max bytes for a single send
#define DEFAULT_MAX_SOCKET_LENGTH 

int main(int argc, char *argv[]) {


    // // Receiver Protocol
    //     // out TEE
    //     //   generate rsa-pk & sk
    //     //   receiver pk' from Sender (we can transfer n/d/e or pk_pem)
    //     // in TEE
    //     //      --given m,F,B,pk,pk', 
    //     //      --run VOLE
    //     //      --Encrypt(AC, pk)       **(might omit)
    //     //      --Encrypt(BΔ, pk')
    //     //  out TEE
    //     //   decrypt Encrypt(AC, pk)    **(might omit)
    //     //   send Encrypt(BΔ, pk') to Sender


    int PROTOCOL_MODE  = (int) strtoul(argv[1], NULL, 10);
    //  PROTOCOL_MODE := 1
        // # =0	A/C are not needed to encrypt
        // # =1	A/C are needed to encrypt

    

    
    cout << "--------------------------------------------------------------------" << endl;
    // cout << "Start" << endl;

    /*----------- Generate Key -----------*/
    // cout << "/*----------- Generate Key -----------*/" << endl;
    RSA *receiver_rsa;
    BIGNUM *receiver_bne;
    RSA *receiver_pk;

    if (PROTOCOL_MODE){

        cout << "Generating rsa pk & sk for Receiver ..." << endl;
        receiver_rsa = RSA_new();
        receiver_bne = BN_new();
        BN_set_word(receiver_bne, RSA_PBULIC_EXPONENT);
        RSA_generate_key_ex(receiver_rsa, RSA_KEY_BIT_LENGTH, receiver_bne, NULL);
        
        // RSAPrivateKey ::= SEQUENCE {
        //     version           Version,
        //     modulus           INTEGER,  -- n
        //     publicExponent    INTEGER,  -- e
        //     privateExponent   INTEGER,  -- d
        //     prime1            INTEGER,  -- p
        //     prime2            INTEGER,  -- q
        //     exponent1         INTEGER,  -- d mod (p-1)
        //     exponent2         INTEGER,  -- d mod (q-1)
        //     coefficient       INTEGER,  -- (inverse of q) mod p
        //     otherPrimeInfos   OtherPrimeInfos OPTIONAL
        // }

        receiver_pk = RSAPublicKey_dup(receiver_rsa);
        // RSA *receiver_sk = RSAPrivateKey_dup(receiver_rsa);
        cout << "Generating rsa pk & sk for Receiver done" << endl;
        cout << "--------------------------------------------------" << endl;


        //  encrypt: rsa or pk could both be used
        //  decrypt: rsa or sk could both be used
    }

    /*----------- Socket Transfer -----------*/
    // cout << "/*----------- Socket Transfer -----------*/" << endl;

    cout << "Receiving pk' from Receiver ..." << endl;

    //  create socket
    int receiver_sockfd;
    if( (receiver_sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1 )
    {
        cout << "---[Error] Create socket failed." << endl;
        return -1;
    }
    else cout << "---Create socket done." << endl;

    //  bind receiver's port & addr to socket
    struct sockaddr_in receiver_addr;
    memset(&receiver_addr, 0, sizeof(receiver_addr));
    receiver_addr.sin_family = AF_INET;
    receiver_addr.sin_port = htons((int)RECEIVER_PORT);        //  Sender Port
    receiver_addr.sin_addr.s_addr = inet_addr(RECEIVER_ADDR);     //  Sender IP

    if( bind(receiver_sockfd, (struct sockaddr *)&receiver_addr, sizeof(receiver_addr)) != 0 )
    {
        cout << "---[Error] Bind socket failed." << endl;
        return -1;
    }
    else cout << "---Bind socket done." << endl;

    //  listen: transfer this default-"sender-like" socket to a "listener-like" socket
    if( listen(receiver_sockfd, DEFAULT_RECEIVER_BACKLOG) != 0 )
    {
        cout << "---[Error] Listen failed." << endl;
        close(receiver_sockfd);
        return -1;
    }
    else cout << "---Listen done." << endl;


    //  wating for the connection from the Sender

    socklen_t socklen=sizeof(struct sockaddr_in);
    struct sockaddr_in sender_addr;
    int sender_sockfd = accept(receiver_sockfd, (struct sockaddr*)&sender_addr, (socklen_t *)&socklen);
    if(sender_sockfd < 0) cout << "---[Error] Connect from Sender failed." << endl;
    else cout << "---Connect from Sender " << inet_ntoa(sender_addr.sin_addr) << " done." << endl;


    //  receiver n&e from the Sender
        //  send buffer strlen(buff)
        //  recv buffer sizeof(buff)

    char confirm_buff[CONFIRM_BUFF_SIZE];
    // cout << sizeof(confirm_buff) << endl;
    // memset(confirm_buff, 0, sizeof(confirm_buff));
    // cout << sizeof(confirm_buff) << endl;
    strcpy(confirm_buff, "confirm");
    // cout << sizeof(confirm_buff) << endl;


    // unsigned char* tmpptr = (unsigned char*)malloc(4096);
    // cout << sizeof(tmpptr) << endl;
    // memset(tmpptr, 0, sizeof(tmpptr));
    // cout << sizeof(tmpptr) << endl;

    int iret;

    //  re-construct n&e from the recv-buffer
        //  we have char_buff_n & char_buff_e sequencial in the memory
        //  so the strlen(char_buff_n) will count (char_buff_e) in
        //  only need one buffer to receive


    BIGNUM *sender_n = BN_new();
    BIGNUM *sender_e = BN_new();
    char char_buff_exclusive[CHAR_BUFF_SIZE];
    
    //  receive n and send confirm
    memset(char_buff_exclusive, 0, sizeof(char_buff_exclusive));
    if ( (iret = recv(sender_sockfd, char_buff_exclusive, sizeof(char_buff_exclusive), 0)) <= 0 ) // receive n from Sender
    { 
        cout << "---[Error] Receive n from Sender failed." << endl;
        return -1;
    }
    else cout << "---Receive n from Sender done." << endl;
    BN_hex2bn(&sender_n, char_buff_exclusive);
    // if ( (iret = send(sender_sockfd, confirm_buff, strlen(confirm_buff), 0)) <= 0 ) // send confirm of n to Sender
    // { 
    //     cout << "---[Error] Send confirm of n to Sender failed." << endl;
    //     return -1;
    // }
    // else cout << "---Send confirm of n to Sender done." << endl;


    //  receive e and send confirm
    memset(char_buff_exclusive, 0, sizeof(char_buff_exclusive));
    if ( (iret = recv(sender_sockfd, char_buff_exclusive, sizeof(char_buff_exclusive), 0)) <= 0 ) // receive e from Sender
    { 
        cout << "---[Error] Receive e from Sender failed." << endl;
        return -1;
    }
    else cout << "---Receive e from Sender done." << endl;
    BN_hex2bn(&sender_e, char_buff_exclusive);

    // if ( (iret = send(sender_sockfd, confirm_buff, strlen(confirm_buff), 0)) <= 0 ) // send confirm of e to Sender
    // { 
    //     cout << "---[Error] Send confirm of e to Sender failed." << endl;
    //     return -1;
    // }
    // else cout << "---Send confirm of e to Sender done." << endl;


    //  re-construct sender_pk from n&e
    RSA *sender_pk = RSA_new();
    RSA_set0_key(sender_pk, sender_n, sender_e, NULL); //  must set NULL here for pk

    cout << "Receiving pk' from Sender [done]" << endl;
    cout << "--------------------------------------------------" << endl;

    // RSA_print_fp(stdout, sender_pk, 0);
 




    /*----------- Connect with TEE process -----------*/
    // cout << "/*----------- Connect with TEE process -----------*/" << endl;


    // Init Occlum PAL
    occlum_pal_attr_t pal_attr = OCCLUM_PAL_ATTR_INITVAL;
    pal_attr.instance_dir = "occlum_instance";
    pal_attr.log_level = "off";
    if (occlum_pal_init(&pal_attr) < 0) {
        return EXIT_FAILURE;
    }

    
    // Prepare cmd path and arguments
    /*
        cmd_path,
        protocol_mode       //  Protocol mode
        B,                  //  VOLE-para B
        F,                  //  VOLE-para F
        m                   //  VOLE-para m
        
        sender_pk,              //  sender_pk 
        share_buf_B,            //  shared_buf_ptr
        share_buf_B,            //  shared_buf_size
        share_buf_Delta,        //  shared_buf_ptr
        share_buf_Delta,        //  shared_buf_size

        share_buf_A,            //  shared_buf_ptr
        share_buf_A,            //  shared_buf_size
        share_buf_C,            //  shared_buf_ptr
        share_buf_C,            //  shared_buf_size

        (Optional)
        receiver_pk,            //  receiver_pk

    */


    //  cmd_path   
    const char *cmd_path = "/bin/vole";     //  in-sgx app name

    //  B F m protocol_mode
    char space_for_field_B[DEFAULT_PARA_LENGTH];
    char space_for_field_F[DEFAULT_PARA_LENGTH];
    char space_for_size_m[DEFAULT_PARA_LENGTH];
    char space_for_proto_mode[DEFAULT_PARA_LENGTH];

    
    sprintf(space_for_field_B, "%d",(int)FIELD_B);
    sprintf(space_for_field_F, "%d",(int)FIELD_F);
    sprintf(space_for_size_m, "%d",(int)SIZE_M);
    sprintf(space_for_proto_mode, "%d", PROTOCOL_MODE);

    const char *field_B_str = (const char*)space_for_field_B;   //  unsigned long   use BIGNUM* to present the big type
    const char *field_F_str = (const char*)space_for_field_F;   //  unsigned long
    const char *size_m_str = (const char*)space_for_size_m;     //  unsigned long   here is for the n = 1000000
    const char *protocol_mode_str = (const char*)space_for_proto_mode;

    //  sender-pk
    char sender_pk_str[32] = {0};               //  RSA*
    snprintf(sender_pk_str, sizeof (sender_pk_str), "%lu", (unsigned long)sender_pk);

    //  buffer A/B/C/Delta Common Paras
    // The buffer shared between the outside and inside the enclave
    // the data encrypted in the enclave could be stored in shared_buff
    int byte_length_field_B = (int)(FIELD_B/8);
    int byte_length_field_F = (int)(FIELD_F/8);
    int bytes_count_B = byte_length_field_F;


    //  buffer B/Delta  -> ptr & size
    int sender_pk_size = RSA_size(sender_pk);       //  count in byte
    int element_B_count_per_cipher = (sender_pk_size   - DEFAULT_PADDING_LENGTH) / bytes_count_B;
    int cipher_count_B = ceil(SIZE_M *1.0/ element_B_count_per_cipher);
    
    int buffer_size_B = cipher_count_B * sender_pk_size;
    unsigned char *buffer_B = (unsigned char*)malloc(buffer_size_B);

    // cout << "sender_pk_size = " << sender_pk_size << endl;
    // cout << "element_B_count_per_cipher = " << element_B_count_per_cipher << endl;
    // cout << "cipher_count_B = " << cipher_count_B << endl;
    // cout << "buffer_size_B = " << buffer_size_B << endl;

    char share_buf_B_ptr_str[32] = {0};
    char share_buf_B_size_str[32] = {0};
    snprintf(share_buf_B_ptr_str, sizeof(share_buf_B_ptr_str), "%lu", (unsigned long) buffer_B);
    snprintf(share_buf_B_size_str, sizeof(share_buf_B_size_str), "%lu", sizeof(buffer_B));


    int buffer_size_Delta = sender_pk_size;
    unsigned char *buffer_Delta = (unsigned char*)malloc(buffer_size_Delta);
    char share_buf_Delta_ptr_str[32] = {0};
    char share_buf_Delta_size_str[32] = {0};
    snprintf(share_buf_Delta_ptr_str, sizeof(share_buf_Delta_ptr_str), "%lu", (unsigned long) buffer_Delta);
    snprintf(share_buf_Delta_size_str, sizeof(share_buf_Delta_size_str), "%lu", sizeof(buffer_Delta));


    //  buffer A/C      -> ptr & size               //  different mode, different size

    int bytes_count_A = byte_length_field_B;
    int bytes_count_C = byte_length_field_F;    

    int buffer_size_A = SIZE_M * bytes_count_A;    //  default mode-0  plaintext transfer between receiver & enclave
    int buffer_size_C = SIZE_M * bytes_count_C;


    //  for mode-1
    char receiver_pk_str[32] = {0};             //  RSA*
    int receiver_pk_size;   //  count in byte
    int element_A_count_per_cipher;
    int element_C_count_per_cipher;
    int cipher_count_A;
    int cipher_count_C;


    if (PROTOCOL_MODE){
        receiver_pk_size = RSA_size(receiver_pk);   //  count in byte
        element_A_count_per_cipher = (receiver_pk_size - DEFAULT_PADDING_LENGTH) / bytes_count_A;
        element_C_count_per_cipher = (receiver_pk_size - DEFAULT_PADDING_LENGTH) / bytes_count_C;
        cipher_count_A = ceil(SIZE_M *1.0/ element_A_count_per_cipher);
        cipher_count_C = ceil(SIZE_M *1.0/ element_C_count_per_cipher);
        buffer_size_A = cipher_count_A * receiver_pk_size;
        buffer_size_C = cipher_count_C * receiver_pk_size;

        //  receiver-pk
        snprintf(receiver_pk_str, sizeof (receiver_pk_str), "%lu", (unsigned long)receiver_pk);
    }


    unsigned char *buffer_A = (unsigned char*)malloc(buffer_size_A);
    unsigned char *buffer_C = (unsigned char*)malloc(buffer_size_C);


    char share_buf_A_ptr_str[32] = {0};
    char share_buf_A_size_str[32] = {0};
    snprintf(share_buf_A_ptr_str, sizeof(share_buf_A_ptr_str), "%lu", (unsigned long) buffer_A);
    snprintf(share_buf_A_size_str, sizeof(share_buf_A_size_str), "%lu", sizeof(buffer_A));

    char share_buf_C_ptr_str[32] = {0};
    char share_buf_C_size_str[32] = {0};
    snprintf(share_buf_C_ptr_str, sizeof(share_buf_C_ptr_str), "%lu", (unsigned long) buffer_C);
    snprintf(share_buf_C_size_str, sizeof(share_buf_C_size_str), "%lu", sizeof(buffer_C));



    const char *cmd_args0[] = {  //  an array of type (const char*)  
                                //  both the ptr and the memory are const 
        cmd_path,
        protocol_mode_str,  //  Protocol mode
        field_B_str,        //  VOLE-para B
        field_F_str,        //  VOLE-para F
        size_m_str,         //  VOLE-para m
        
        sender_pk_str,      //  sender_pk 
        share_buf_B_ptr_str,            //  shared_buf_ptr
        share_buf_B_size_str,           //  shared_buf_size
        share_buf_Delta_ptr_str,        //  shared_buf_ptr
        share_buf_Delta_size_str,       //  shared_buf_size


        
        share_buf_A_ptr_str,            //  shared_buf_ptr
        share_buf_A_size_str,           //  shared_buf_size
        share_buf_C_ptr_str,        //  shared_buf_ptr
        share_buf_C_size_str,       //  shared_buf_size

        NULL
    };


    // RSA *receiver_sk = RSAPrivateKey_dup(receiver_rsa);
    // char receiver_sk_str[32] = {0};             //  RSA*
    // snprintf(receiver_sk_str, sizeof (receiver_sk_str), "%lu", (unsigned long)receiver_sk);

    // RSA_print_fp(stdout, receiver_sk, 0);


    const char *cmd_args1[] = {  //  an array of type (const char*)  
                                //  both the ptr and the memory are const 
        cmd_path,
        protocol_mode_str,  //  Protocol mode
        field_B_str,        //  VOLE-para B
        field_F_str,        //  VOLE-para F
        size_m_str,         //  VOLE-para m
        
        sender_pk_str,      //  sender_pk
        // receiver_pk_str,      //  receiver  //  for debug 
        share_buf_B_ptr_str,            //  shared_buf_ptr
        share_buf_B_size_str,           //  shared_buf_size
        share_buf_Delta_ptr_str,        //  shared_buf_ptr
        share_buf_Delta_size_str,       //  shared_buf_size


        
        share_buf_A_ptr_str,            //  shared_buf_ptr
        share_buf_A_size_str,           //  shared_buf_size
        share_buf_C_ptr_str,        //  shared_buf_ptr
        share_buf_C_size_str,       //  shared_buf_size

        receiver_pk_str,    //  receiver_pk
        // receiver_sk_str,        //  receiver_sk//  for debug 

        NULL
    };



    struct occlum_stdio_fds io_fds = {
        .stdin_fd = STDIN_FILENO,
        .stdout_fd = STDOUT_FILENO,
        .stderr_fd = STDERR_FILENO,
    };

    // Use Occlum PAL to create new process
    int libos_tid = 0;
    struct occlum_pal_create_process_args create_process_args = {
        .path = cmd_path,
        .argv = PROTOCOL_MODE == 0 ? cmd_args0 : cmd_args1,
        .env = NULL,
        .stdio = (const struct occlum_stdio_fds *) &io_fds,
        .pid = &libos_tid,
    };

    if (occlum_pal_create_process(&create_process_args) < 0) {
        return EXIT_FAILURE;
    }

    // Use Occlum PAL to execute the cmd
    int exit_status = 0;
    struct occlum_pal_exec_args exec_args = {
        .pid = libos_tid,
        .exit_value = &exit_status,
    };
    if (occlum_pal_exec(&exec_args) < 0) {
        return EXIT_FAILURE;
    }


    cout << "--------------------------------------------------" << endl;




    // for(int i=0;i<12;i++){
    //     printf("%d ", i*i);
    // }
    // printf("\n");
    

    /*----------- Sending Enc(B/Delta) to Sender -----------*/
    cout << "Sending Enc(B/Delta) to Sender ..." << endl;

    int bytes_count_A_total = SIZE_M * bytes_count_A;
    int bytes_count_C_total = SIZE_M * bytes_count_C;


    unsigned char *randA = (unsigned char *)malloc(bytes_count_A_total);
    unsigned char *randC = (unsigned char *)malloc(bytes_count_C_total);

    if(PROTOCOL_MODE){  //  need to decrypt

        cout << "Decrypting A/C ..." << endl;
        RSA* receiver_sk = RSAPrivateKey_dup(receiver_rsa);
        int bytes_ptr;

        //  Decrypting A
        bytes_ptr = 0;
        cout << "---Decrypting A" << endl;
        for(int i=0; i<cipher_count_A; i++){
            int res = RSA_private_decrypt(receiver_pk_size, (unsigned char*)(buffer_A + i*receiver_pk_size), (unsigned char*)(randA + bytes_ptr), receiver_sk, PADDING_MODE);
            bytes_ptr += res;
            // cout << i << endl;
        }
        cout << bytes_ptr << endl;
        cout << "---Decrypting C" << endl;
        //  Decrypting C
        bytes_ptr = 0;
        for(int i=0; i<cipher_count_A; i++){
            int res = RSA_private_decrypt(receiver_pk_size, (unsigned char*)(buffer_C + i*receiver_pk_size), (unsigned char*)(randC + bytes_ptr), receiver_sk, PADDING_MODE);
            bytes_ptr += res;
        }
        cout << "Decrypting A/C [done]" << endl;

    }
    else{   //  直接copy
        memcpy(randA, buffer_A, bytes_count_A_total);
        memcpy(randC, buffer_C, bytes_count_C_total);
    }



    /*----------- Sending Enc(B/Delta) to Sender -----------*/

    // cout << "/*----------- Sending Enc(B/Delta) to Sender -----------*/" << endl;
    // cout << "Sending Enc(B/Delta) to Sender ..." << endl;

    // memset(confirm_buff, 0, sizeof(confirm_buff));
    // if ( (iret = recv(sender_sockfd, confirm_buff, sizeof(confirm_buff), 0)) <= 0 ) // receive n from Sender
    // { 
    //     cout << "---[Error] Receive Request of Enc(B) from Sender failed." << endl;
    //     return -1;
    // }
    // else cout << "---Receive Request of Enc(B) from Sender done." << endl;



    //  sending Enc(B) and receive confirm



    int total_sent = 0;      // 已发送数据的长度
    while (total_sent < buffer_size_B) {  // 只要还有数据未发送完毕
        int sent = send(sender_sockfd, buffer_B + total_sent, buffer_size_B - total_sent, 0);  // 发送剩余部分
        if (sent == -1) {  // 如果发送失败
            cout << "---[Error] Send Enc(B) to Sender failed." << endl;
            return -1;
        }
        total_sent += (int)sent;  // 更新已发送长度
    }
    cout << "---Send Enc(B) to Sender done." << endl;

    // if ( (iret = send(sender_sockfd, buffer_B, buffer_size_B, 0)) <= 0 )    // send Enc(B) to Sender
    // { 
    //     cout << "---[Error] Send Enc(B) to Sender failed." << endl;
    //     return -1;
    // }
    // else cout << "---Send Enc(B) to Sender done." << endl;
    // cout << buffer_size_B << endl;
    // cout << iret << endl;

    // memset(confirm_buff, 0, sizeof(confirm_buff));
    // if ( (iret = recv(sender_sockfd, confirm_buff, sizeof(confirm_buff), 0)) <= 0 ) // receive n from Sender
    // { 
    //     cout << "---[Error] Send Enc(B) to Sender, confirm failed." << endl;
    //     return -1;
    // }
    // else cout << "---Send Enc(B) to Sender, confirm done." << endl;
    

    //  sending Enc(Delta) and receive confirm

    if ( (iret = send(sender_sockfd, buffer_Delta, buffer_size_Delta, 0)) <= 0 )    // send Enc(B) to Sender
    { 
        cout << "---[Error] Send Enc(Delta) to Sender failed." << endl;
        return -1;
    }
    else cout << "---Send Enc(Delta) to Sender done." << endl;

    // memset(confirm_buff, 0, sizeof(confirm_buff));
    // if ( (iret = recv(sender_sockfd, confirm_buff, sizeof(confirm_buff), 0)) <= 0 ) // receive n from Sender
    // { 
    //     cout << "---[Error] Send Enc(Delta) to Sender, confirm failed." << endl;
    //     return -1;
    // }
    // else cout << "---Send Enc(Delta) to Sender, confirm done." << endl;
    cout << "Sending Enc(B/Delta) to Sender [done]" << endl;

    cout << "--------------------------------------------------" << endl;


    // Destroy Occlum PAL
    occlum_pal_destroy();







    free(buffer_A);
    free(buffer_B);
    free(buffer_C);
    free(buffer_Delta);





    close(receiver_sockfd);
    close(sender_sockfd);

    /*----------- Done -----------*/
    // cout << "/*----------- Done -----------*/" << endl;
    
    
    // cout << "sgx return result = " << exit_status << endl;
    return exit_status;     //  according to occlum-exec result to return
}