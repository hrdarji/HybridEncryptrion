#include <stdio.h> 
#include <string.h> 
#include <time.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <openssl/md5.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define KEYBIT_LEN	1024    
unsigned char msg[16];

#define BLOCK_SIZE 16
#define FREAD_COUNT 4096
#define KEY_BIT 256
#define IV_SIZE 16
#define RW_SIZE 1
#define SUCC 0
#define FAIL -1

 
AES_KEY aes_ks3;
unsigned char iv[IV_SIZE];
unsigned char key[16];
unsigned char MD5_sender[16];
unsigned char MD5_receiver[16];
FILE *inFile;
FILE *md5sender;
FILE *md5receiver;
time_t rawtime;
struct tm * timeinfo;

static void
printHex(const char *title, const unsigned char *s, int len)
{
	int     n;
	printf("%s:", title);
	for (n = 0; n < len; ++n) {
		if ((n % 16) == 0) {
			printf("\n%04x", n);
		}
		printf(" %02x", s[n]);
	}
	printf("\n");
}

 // To encrypt the plain text using AES
int fs_encrypt_aes(char *in_file,char *out_file,char key1[])
{
    
    int i=0;
    int len=0;
    int padding_len=0;
    char buf[FREAD_COUNT+BLOCK_SIZE];
	
for(i=0;i<16;i++)
        {
          key[i]=key1[i];
        }
	// To generate the random key using the Random function
    //RAND_bytes(key,sizeof (key));
 
    FILE *fp=fopen(in_file,"rb");
    if( fp == NULL ){
        fprintf(stderr,"[ERROR] %d can not fopen('%s')\n",__LINE__,in_file);
        return FAIL;
    }
 
    FILE *wfp=fopen(out_file,"wb");
    if( wfp == NULL ){
        fprintf(stderr,"[ERROR] %d can not fopen('%s')\n",__LINE__,out_file);
        return FAIL;
    }
 
    memset(iv,0,sizeof(iv)); // init iv
	// SET the AES Key to 256 bit
    AES_set_encrypt_key(key ,KEY_BIT ,&aes_ks3);
    while( len = fread( buf ,RW_SIZE ,FREAD_COUNT, fp) ){
        if( FREAD_COUNT != len ){
            break;
        }
 
        AES_cbc_encrypt(buf ,buf ,len ,&aes_ks3 ,iv ,AES_ENCRYPT);
        fwrite(buf ,RW_SIZE ,len ,wfp);
    }
 
 
    //
    padding_len=BLOCK_SIZE - len % BLOCK_SIZE;
    //printf("enc padding len:%d\n",padding_len);
    memset(buf+len, padding_len, padding_len);
/**
    for(i=len; i < len+padding_len ;i++){
        buf[i]=padding_len;
    }
**/
    AES_cbc_encrypt(buf ,buf ,len+padding_len ,&aes_ks3, iv,AES_ENCRYPT);
    fwrite(buf ,RW_SIZE ,len+padding_len ,wfp);
 
    fclose(wfp);
    fclose(fp);
 
    return SUCC;
}


 // This function will take the encrypted Text and will decrypt it into the plain text using AES
int fs_decrypt_aes(char *in_file,char *out_file, char key1[])
{
    char buf[FREAD_COUNT+BLOCK_SIZE];
    int len=0;
    int total_size=0;
    int save_len=0;
    int w_len=0;
int i;
for(i=0;i<16;i++)
        {
          key[i]=key1[i];
        }
 
    FILE *fp=fopen(in_file,"rb");
    if( fp == NULL ){
        fprintf(stderr,"[ERROR] %d can not fopen('%s')\n",__LINE__,in_file);
        return FAIL;
    }
 
    FILE *wfp=fopen(out_file,"wb");
    if( wfp == NULL ){
        fprintf(stderr,"[ERROR] %d can not fopen('%s')\n",__LINE__,out_file);
        return FAIL;
    }
 
    memset(iv,0,sizeof(iv)); // the same iv
    AES_set_decrypt_key(key ,KEY_BIT ,&aes_ks3);
 
    fseek(fp ,0 ,SEEK_END);
    total_size=ftell(fp);
    fseek(fp ,0 ,SEEK_SET);
    //printf("total_size %d\n",total_size);
 
    while( len = fread( buf ,RW_SIZE ,FREAD_COUNT ,fp) ){
        if( FREAD_COUNT == 0 ){
            break;
        }
        save_len+=len;
        w_len=len;
 
        AES_cbc_encrypt(buf ,buf ,len ,&aes_ks3 ,iv ,AES_DECRYPT);
        if( save_len == total_size ){ // check last block
            w_len=len - buf[len-1];
            //printf("dec padding size %d\n" ,buf[len-1]);
        }
 
        fwrite(buf ,RW_SIZE ,w_len ,wfp);
	
    }
 //printf("Nandish");
    fclose(wfp);
    fclose(fp);
 
    return SUCC;
}



// Digital Signature and certificate Sign and Verify //

int
doSign(RSA *prikey, RSA *pubkey, unsigned char *data, int dataLen)
{
	unsigned char hash[SHA256_DIGEST_LENGTH];
	unsigned char sign[256];
	unsigned int signLen;
	int     ret;


	// USING THE SHA FUNCTION TO CREATE THE HASH
	SHA256(data, dataLen, hash);

	/* Sign the certificate and write to keycertificate.txt*/
	ret = RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, sign,
				   &signLen, prikey);
	printHex("SIGN", sign, signLen);
	//printf("Signature length = %d\n", signLen);
	printf("RSA_sign: %s\n", (ret == 1) ? "OK" : "NG");

	// WRITING THE CERTIFICATE TO FILE keycertificate.txt" //
	FILE *keycertificate = fopen("keycertificate.txt","w");
	fwrite(sign, RW_SIZE, signLen, keycertificate);
	fclose(keycertificate);

	// Verify the certficate using the publickey, hash and keycertificate.txt//
	ret = RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, sign,
					 signLen, pubkey);
	printf("RSA_Verify: %s\n", (ret == 1) ? "true" : "false");
	
	//unsigned char signverify[1];
        printf("Value of ret: %d",ret);
        char *finalstring= "Yes\0";
	if(ret==1)
	{
         FILE *yesno = fopen("yesno_output.txt","a");
	 fwrite(finalstring,RW_SIZE,strlen(finalstring),yesno);
	 fclose(yesno);
	}


	/* If the Sign is verified then 1/is true written to the file yesno_output.txt" */

	//FILE *yesno = fopen("yesno_output.txt","w");
	//fwrite(signverify, RW_SIZE, 1, yesno);
	//fclose(yesno);

	return ret;
}



int main(int argc, char *args[])
{
    
   clock_t start_t, end_t, total_t;
   int i;

   start_t = clock();
 //  printf("Starting of the program, start_t = %ld\n", start_t);



    if( argc != 2 ){
        printf("[Usage] %s fs_src_file\n",args[0]);
        return FAIL;
    }
    
    FILE *fp=fopen(args[1],"a+b");
    time ( &rawtime );
    timeinfo = localtime ( &rawtime );
    printf ( "\nsending local time and date: %s \n", asctime (timeinfo));
    fprintf(fp, "%s\n", asctime(timeinfo));
    fclose(fp);


	// Creating the Symetric Key for AES
	RAND_bytes(msg,sizeof (msg));
 


//******************* HYBRID ENCRYPTION USING OAEP-RSA *********************//

	int     ret;
	RSA    *prikey, *pubkey;
	//unsigned char *data;
	unsigned int dataLen;
	dataLen = strlen(msg); 
	char   *p, *q, *n, *e, *d;
	char    errbuf[1024];
	FILE   *priKeyFile;


	ERR_load_crypto_strings();

	/* generate private key & public key */
	//printf("< RSA Key Generation >\n");
	prikey = RSA_generate_key(KEYBIT_LEN, RSA_F4, NULL, NULL);
	if (prikey == NULL) {
		printf("RSA_generate_key: err = %s\n",
			   ERR_error_string(ERR_get_error(), errbuf));
		return 1;
	}
	priKeyFile = fopen("Privatekey.pem", "w");
	if (priKeyFile == NULL)	{
		perror("failed to fopen");
		return 1;
	}

	// Print this to know the value of p,q,n,e,d //

	p = BN_bn2hex(prikey->p);
	q = BN_bn2hex(prikey->q);
	n = BN_bn2hex(prikey->n);
	e = BN_bn2hex(prikey->e);
	d = BN_bn2hex(prikey->d);
/*	printf("p = 0x%s\n", p);
	printf("q = 0x%s\n", q);
	printf("n = 0x%s\n", n);
	printf("e = 0x%s\n", e);
	printf("d = 0x%s\n", d); */


	/* writing private key to file (PEM format) */
	if (PEM_write_RSAPrivateKey(priKeyFile, prikey, NULL, NULL, 0,
								NULL, NULL) != 1) {
		printf("PEM_write_RSAPrivateKey: err = %s\n",
			   ERR_error_string(ERR_get_error(), errbuf));
		return 1;
	}

	/* copy public keys */
	pubkey = RSA_new();

	FILE *publickey1= fopen("Publickey.pem","w");
	if (PEM_write_RSAPublicKey(publickey1, pubkey) != 1) {
		printf("PEM_write_RSAPublicKey: err = %s\n",
			   ERR_error_string(ERR_get_error(), errbuf));
		return 1;
	}
        //fwrite(pubkey,1,strlen(pubkey),publickey1);
        fclose(publickey1);
       // printf("\nThe Private key is written to file Privatekey.txt");

	BN_hex2bn(&(pubkey->e), e);
	BN_hex2bn(&(pubkey->n), n);

	/* encrypt & decrypt */
	//printf("\n< RSA Encrypt/Decrypt >\n");
	//printHex("PLAIN", msg, dataLen);

	int     i1;
	int     encryptLen, decryptLen;
	unsigned char encrypt[1024], decrypt[1024];

	/* encrypt */
	encryptLen = RSA_public_encrypt(dataLen, msg, encrypt, pubkey,
									RSA_PKCS1_OAEP_PADDING);
	/* print data */
	//printHex("ENCRYPT", encrypt, encryptLen);
	//printf("Encrypt length = %d\n", encryptLen);
	

	FILE *out = fopen("rsa.bin", "w");
        fwrite(encrypt, sizeof(*encrypt),  encryptLen, out);
        fclose(out);
        //printf("Encrypted message written to file.\n");	


        fs_encrypt_aes(args[1],"fs_in.file",msg);


	FILE *in = fopen("rsa.bin","r");
	
	long publicsize;
	fseek(in, 0, SEEK_END);
	publicsize = ftell(in);
	fseek(in, 0, SEEK_SET);

	char data1[1024];
	//data1 = malloc(publicsize);
	fread(data1, RW_SIZE, publicsize, in);
	//printf("The Public key is %s",data1);
	/* decrypt */

	decryptLen = RSA_private_decrypt(encryptLen, data1, decrypt, prikey,
									 RSA_PKCS1_OAEP_PADDING);
	//printf("The Decrypted text is%s",decrypt);
	//printHex("DECRYPT", decrypt, decryptLen);
	if (dataLen != decryptLen) {
		return 1;
	}
	for (i1 = 0; i1 < decryptLen; i1++) {
		if (msg[i1] != decrypt[i1]) {
			return 1;
		}
	}




//******************* Digital Signature ****************************//



FILE *public1 = fopen("Publickey.txt","r");
FILE *validityparam = fopen("validityparameters.txt","r");

long publicsize1;
fseek(public1, 0, SEEK_END);
publicsize1 = ftell(public1);
fseek(public1, 0, SEEK_SET);
//printf("Size of Public key%ld",publicsize1);

long val;
fseek(validityparam, 0, SEEK_END);
val = ftell(validityparam);
fseek(validityparam, 0, SEEK_SET);
//printf("Size of Validity Param%ld",val);

long max;
max = publicsize1 + val;
char *publickeydata = NULL;
char *data2= NULL;
char *destination= NULL;

publickeydata = malloc(publicsize1);
data2=malloc(val);
fread(data1, RW_SIZE, publicsize1, public1);
fread(data2, RW_SIZE, val, validityparam);
//printf("\nThe message in data1 is:%s",data1);
//printf("\nThe message in data2 is:%s",data2);

destination= malloc(max);
strcpy(destination,publickeydata);
strcat(destination,data2);

//printf("\nThe String after Concatenation is :%s",destination);


	printf("\n< RSA Sign/verify >\n");
	ret = doSign(prikey, pubkey, destination, max);
	if (ret != 1) {
		printf("Sign/Verify Error.\n");
		return ret;
	}

	RSA_free(prikey);
	RSA_free(pubkey);
	OPENSSL_free(p);
	OPENSSL_free(q);
	OPENSSL_free(n);
	OPENSSL_free(e);
	OPENSSL_free(d);
	fclose(priKeyFile);

//******************************** Digital Signature Ends here *******************************************//



// *************Calling the AES Decrypt Function for decryption of Encrypted text with the decrypted key from RSA**********//
 fs_decrypt_aes("fs_in.file","fs_out.file",decrypt);

  

//********************* MD5 generation sender side   ********************************//

    unsigned char c[MD5_DIGEST_LENGTH];
    inFile = fopen ("fs_in.file", "rb");
    int bytes;
    char mdString[33];
    fseek(inFile, 0, SEEK_END); 
    long fsize = ftell(inFile);
    long inputfilelength=0;
    unsigned char digest[16];
    fseek(inFile, 0, SEEK_SET); 
    while (fgetc(inFile) != EOF)
    {
        inputfilelength++;
        //printf("inputfilelength inside loop : %d\n",inputfilelength );
    }
   
    char *data = malloc(inputfilelength + 1);
    
    fseek(inFile, 0, SEEK_SET); 
    //printf("inputfilelength : %d\n",inputfilelength);
    fgets(data, inputfilelength, inFile);
    //printf("\bsender side data: %s\n",data);
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, data, inputfilelength);
    MD5_Final(digest, &ctx);
    md5sender = fopen ("md5sender.txt", "w");
    for(i = 0; i < 16; i++)
    {
        //printf("%.02x",digest[i]);
        MD5_sender[i]=digest[i];
        fprintf(md5sender, "%.02x", digest[i]);
    }
    fclose(md5sender);
    fclose (inFile);
    
    // MD5 receiver side
    inFile = fopen ("fs_in.file", "r");
    fseek(inFile, 0, SEEK_END); 
    fsize = ftell(inFile);
    inputfilelength=0;
    fseek(inFile, 0, SEEK_SET);
    while (fgetc(inFile) != EOF)
    {
        inputfilelength++;
    }
   
    //char *data = malloc(inputfilelength + 1);
    
    fseek(inFile, 0, SEEK_SET); 
    fgets(data, inputfilelength, inFile);
    //MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, data, inputfilelength);
    MD5_Final(digest, &ctx);
    md5receiver = fopen ("md5receiver.txt", "w");
    for(i = 0; i < 16; i++)
    {
        //printf("%.02x",digest[i]);
        MD5_receiver[i]=digest[i];
        fprintf(md5receiver, "%.02x", digest[i]);
    }
    fclose(md5receiver);
    fclose (inFile);

    end_t = clock();
   //printf ("%f cpu sec\n", ((double)end_t - (double)start_t)*1000000);
  //  printf("Exiting of the program...\n");
    int flag=0;

    for(i = 0; i < 16; i++)
    {
        
        if(MD5_sender[i]!=MD5_receiver[i])
        {
            flag=1;
        }
        
    }


    // fetch receiver side time from decrypted text :
    FILE *source;
    source = fopen("fs_out.file","r+");
    fseek(source, 0, SEEK_END);
    int filesize = ftell(source); 
    fseek(source, 0, SEEK_SET);

    long a = filesize -25;

    fseek(source,a-1,SEEK_SET); // Set the new position at 10. 
    int j=0;
    unsigned char buffer[25];
    printf("Sender Time Recieved: ");
    if (source != NULL) 
    { 
        for (i = a; i < filesize; i++) 
        { 
           char c = fgetc(source); // Get character 
            buffer[j] = c; 
	    printf("%c",buffer[j]);
            j++;
        }
    }

 // Getting Reciever side Time

  time_t rawtime1;
  struct tm * timeinfo1;
  time ( &rawtime1 );
  timeinfo1 = localtime ( &rawtime1 );
  printf ( "\nCurrent local time and date on reciever side: %s", asctime (timeinfo1) );

 
 long timeend= (int)*asctime(timeinfo1);
 long timestart= (int)*asctime(timeinfo);

if((timeend-timestart)<0)
  {
   printf("Time integrity Failed");
}
 else
  {
    printf("Time integrity Verified");
}

    if(flag==0)
    {
        printf("\n\nMessage integrity verified\n\n\n");
    }

    //int a = 
    //receiver side  time stamp
 
    return 0;
}
