// todo header, license and stuff
// author: Ralph Ankele (ralph.ankele.2015@live.rhul.ac.uk)
// modified by bg nerilex (bg@nerilex.org)

#include <stdio.h>
#include <stdlib.h>

#include "crypto_aead.h"

#include "api.h"

int main(int argc, char** argv){
	printf("Start testing\n");
	
	unsigned char ciphertext[4096];
	unsigned char plaintext[4096], plaintext2[4096];
	unsigned char ad[4096];
	unsigned char key[16];
	unsigned char npub[16];
	unsigned char nsec[16];
	unsigned char mac[16];
	unsigned long long  msglen, adlen, clen;    // msg, adlen, clen in bytes.
	
	int i = 0;
	int retval = 0;
	
	for (i = 0; i < 16; i++) key[i] = 0;
	for (i = 0; i < 16; i++) npub[i] = 0;
	for (i = 0; i < 16; i++) nsec[i] = 0;
	
	for (i = 0; i < 4096; i++) plaintext[i]  = i%256;
	for (i = 0; i < 4096; i++) plaintext2[i]  = 0;
	for (i = 0; i < 4096; i++) ciphertext[i] = 0;
	for (i = 0; i < 4096; i++) ad[i] = i%7;
	
	msglen = 1003;
	adlen = 1003;
	
	
	retval = crypto_aead_encrypt(
								 ciphertext , &clen,
								 plaintext, msglen,
								 ad, adlen,
								 nsec,
								 npub,
								 key
								 );
	printf("%d\n", retval);
	
	retval = crypto_aead_decrypt(
								 plaintext2, &msglen,
								 nsec,
								 ciphertext,clen,
								 ad,adlen,
								 npub,
								 key
								 );
	
	printf("plaintext1: \n");
	for( i = 0; i < msglen; i++) printf("%2x", plaintext[i]);
	printf("\nplaintext2: \n");
	for( i = 0; i < msglen; i++) printf("%2x", plaintext2[i]);
	
	printf("\n%d\n", retval);
	
	printf("The tag is: ");
	for( i = 0; i < 16; i++) printf("%2x", ciphertext[msglen+i]);
	
	
	return 0;
}



