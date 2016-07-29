#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "crypto_aead.h"

#define STR(s) #s
#define XSTR(s) STR(s)

#define FILENAME "log_" XSTR(CAESAR_CIPHER) "_" XSTR(CAESAR_OPT) ".txt"

#include "api.h"

#define MEASUREMENT_CNT 200
#define MEAN_CNT 91

#define AD_MAX_ENTRIES 100
#define MSG_MAX_ENTRIES 100

//variables
struct parameters {
    int testcase_id;
    int ad[AD_MAX_ENTRIES];
    int ad_size;
    int msg[MSG_MAX_ENTRIES];
    int msg_size;
};
struct parameters p;

int varnonce = 0;
int varkey = 0;

//prototypes
long int getTimeStampCounterFrequency();
void writeHeader();
int comp (const void * elem1, const void * elem2);
void prettyPrint(double cyle_per_byte, uint64_t adlen, uint64_t mlen);
extern inline uint64_t rdtscp();


// This benchmark checks the key setup time of the primitives
// Message = constant
// Key = variable
// Nonce = variable
int benchAEAD(){
	unsigned char key[CRYPTO_KEYBYTES];
	unsigned char npub[CRYPTO_NPUBBYTES];
	unsigned char nsec[CRYPTO_NSECBYTES];
	
	long long unsigned int clen, mlen, adlen;
	
	unsigned char *ciphertext = NULL;
	unsigned char *plaintext = NULL;
	unsigned char *ad = NULL;
	
	memset(npub, 0x00, sizeof(unsigned char) * CRYPTO_NPUBBYTES);
	memset(nsec, 0x00, sizeof(unsigned char) * CRYPTO_NSECBYTES);
    memset(key, 0x42, sizeof(unsigned char) * CRYPTO_KEYBYTES);
	
	writeHeader();
	
	unsigned long long x[MEASUREMENT_CNT];
	unsigned long long y[MEASUREMENT_CNT];
	double time_diff[MEAN_CNT];
	
	printf("start measurement\n");
	
	int count = 0; //counter for nonce

    int ac = 0;
	for (; ac < p.ad_size; ac++){
        adlen = p.ad[ac];
    
		ad = malloc(adlen*sizeof(unsigned char));
		memset(ad, 'B', adlen);
		
        int jc = 0;
		for (; jc < p.msg_size; jc++){
            mlen = p.msg[jc];
            
			plaintext = malloc(mlen*sizeof(unsigned char));
			ciphertext = malloc((mlen+CRYPTO_ABYTES)*sizeof(unsigned char)); // ciphertext = ciphertext+tag
			memset(plaintext, 'A', mlen);
			memset(ciphertext, 0x0, (mlen+CRYPTO_ABYTES));
			
            if(varkey){
                //generate random key
                memset(key, (rand() % 256), sizeof(unsigned char) * CRYPTO_KEYBYTES);
            }
			
            if(varnonce){
                int c = 0;
                for(; c < CRYPTO_NPUBBYTES; c++){
                    npub[c] = (count >> (c*8)) & 0xff;
                }
                count++;
            }
      
			
			uint64_t i = 0;
			for (; i < MEAN_CNT; i++){
				uint64_t o = 0;
				for(; o < MEASUREMENT_CNT; o++){
        
        

        
					x[o] = 0; y[o] = 0;
					x[o] = rdtscp();
					crypto_aead_encrypt(ciphertext,&clen,plaintext,mlen,ad,adlen,nsec,npub,key);
					y[o] = rdtscp();
				}
				
				time_diff[i] = 0;
				for(o = 0; o < MEASUREMENT_CNT; o++){
					time_diff[i] += (y[o] - x[o]);
				}
				time_diff[i] /= MEASUREMENT_CNT;
			}
			
			double cyle_per_byte[MEAN_CNT];
			for(i = 0; i < MEAN_CNT; i++){
				cyle_per_byte[i] = (time_diff[i])/(mlen + adlen);
				// printf("%02f\n", cyle_per_byte[i]);
			}
			
			qsort(cyle_per_byte, sizeof(cyle_per_byte)/sizeof(*cyle_per_byte), sizeof(*cyle_per_byte), comp);
			prettyPrint(cyle_per_byte[MEAN_CNT/2], adlen, mlen);
			
			free(plaintext);
			free(ciphertext);
			plaintext = NULL;
			ciphertext = NULL;
		}
		free(ad);
		ad = NULL;
	}
	
	return 0;
}

inline uint64_t rdtscp() {
    uint32_t lo, hi;
    __asm__ __volatile__ ("rdtscp\n" : "=a" (lo), "=d" (hi));
    return (uint64_t)hi << 32 | lo;
}

long int getTimeStampCounterFrequency(){
    FILE *fp = NULL;
    char file_type[40];
    char test[11];
	
    fp = popen("sysctl -a machdep.tsc.frequency", "r");
    while (fgets(file_type, sizeof(file_type), fp) != NULL);
    pclose(fp);
    
    strncpy(test, file_type+23, 10);
    
    return atol(test);
}

void writeHeader(){
    FILE *log = fopen(FILENAME, "a");
    fprintf(log, "TESTCASE_ID=%d;AD_ENTRIES=%d;MSG_ENTRIES=%d;\n", p.testcase_id, p.ad_size, p.msg_size);
    fprintf(log, "implementation;cyle_per_byte;message_length;ad_length\n");
    fclose(log);
}

int comp (const void *elem1, const void *elem2){
    double f = *((double*)elem1);
    double s = *((double*)elem2);
    if (f > s) return  1;
    if (f < s) return -1;
    return 0;
}

void prettyPrint(double cyle_per_byte, uint64_t adlen, uint64_t mlen){
    
    FILE *log = fopen(FILENAME, "a");
  
    fprintf(log, "%s;", XSTR(CAESAR_OPT));
    fprintf(log, "%.2f;", cyle_per_byte);
    fprintf(log, "%llu;", mlen);
    fprintf(log, "%llu;\n", adlen);
    fclose(log);
}

//##############################################################################

#define NR_OF_TESTCASES 2

int main(int argc, char** argv)
{

    /* settings for the measurement process */
    FILE *log = fopen(FILENAME, "a");
    fprintf(log, "NR_OF_TESTCASES=%d\n", NR_OF_TESTCASES);
    fclose(log);
  
  
    // Measurements with variable length's
    /*int ad = 0;
    for (; ad <= 2048; ad+=128) {
        p.ad[ad/128] = ad;
    }
    p.ad_size = (2048/128)+1;*/
  
    p.ad[0] = 0;
    p.ad_size = 1;
    
    int msg = 0;
    for (; msg <= 2048; msg+=128) {
        p.msg[msg/128] = msg;
    }
    p.msg_size = (2048/128)+1;
  
   /* p.testcase_id = 1;
    benchAEAD();*/
  
    varnonce = 1;
    p.testcase_id = 2;
    benchAEAD();
  
    /*varnonce = 1;
    varkey = 1;
    p.testcase_id = 3;
    benchAEAD();*/
    
    
    /*
     Measurements with fixed length's
     
     + same message, key constant, nonce changes every time
     - message size:  16 bytes, associated data: 5bytes, small payload
     - message size: 557 bytes, associated data: 5bytes, average ip packet
     - message size:  16 KB,    associated data: 5bytes, large payload (max TCP paket)
     - message size:   1 MB,    associated data: 5bytes, HUGE payload (fileupload)
     
     + same message, key/nonce changes every time (key setup)
     - as above
     
     + same message, key/nonce constant (nonce-missuse)
     - as above
     
         // 1 byte = 1 key stroke (SSH)
         // 1.5kB = ethernet frame (TLS)
     */
  
    varnonce = 0;
    varkey = 0;
  
    p.ad[0] = 5;
    p.ad_size = 1;
  
    p.msg[0] = 1;
    p.msg[1] = 16;
    p.msg[2] = 557;
    p.msg[3] = 1500;
    p.msg[4] = 16000;
    p.msg[5] = 1000000;
    p.msg_size = 6;
    
    /*p.testcase_id = 1;
    benchAEAD();*/
    
    varnonce = 1;
    p.testcase_id = 2;
    benchAEAD();
    
    /*varkey = 1;
    p.testcase_id = 3;
    benchAEAD();*/
  

  
    /*varnonce = 0;
    varkey = 0;
  
    p.ad[0] = 5;
    p.ad_size = 1;
    
    p.msg[0] = 1;
    p.msg[1] = 1500;
    p.msg_size = 2;
    
    p.testcase_id = 1;
    varnonce = 1;
    benchAEAD();*/
    
	return 0;
}




