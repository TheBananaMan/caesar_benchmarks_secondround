/* LS-cipher implementation */

#include "crypto_uint16.h"
#include "crypto_uint8.h"

#include "sbox.h"
#include "lbox.h"
#include "params.h"


#include <stdio.h>
#define PrintStateDetailed 0

void print_detail(crypto_uint16 input[8]){
    crypto_uint16 i;
    
    for(i = 0; i < 8; i++)
        printf("%04X ", input[i]);
    printf("\n");
    
    return;
}

void LS_encrypt(const crypto_uint8 input[16], const crypto_uint8 key[16], const crypto_uint8 tweak[16],
		crypto_uint8 output[16]) {
  crypto_uint16 data[8];
  crypto_uint16 k[8];
  crypto_uint16 t[8];
  int i,j;

  for (i=0; i<8; i++) {
    data[i] = ((crypto_uint16)input[2*i+1]<<8) + input[2*i];
    k[i] = ((crypto_uint16)  key[2*i+1]<<8) +   key[2*i];
    t[i] = ((crypto_uint16)tweak[2*i+1]<<8) + tweak[2*i];
  }
    
  /* Initial key + tweak addition */
  for (j=0; j<8; j++) data[j] ^= k[j] ^ t[j];
    
  /* ---------------- Step Function ---------------- */
  for (i=0; i<nSteps; i++) {
        
    /* ---------------- First Round ---------------- */
#if PrintStateDetailed
      printf("Round %i\n", 2*i+1);
#endif
      
      /* SBox layer (bitsliced) */
      SBOX(data);
#if PrintStateDetailed
      printf("S-box\t\t: ");
      print_detail(data);
#endif
      
      /* First round constant */
      data[0] ^= ((2199*(2*i)) % 65536);
#if PrintStateDetailed
      printf("AddConstant\t: ");
      print_detail(data);
#endif
      
      /* LBox layer (tables) */
      for (j=0; j<8; j++)
          data[j] = LBox2[data[j]>>8] ^ LBox1[data[j]&0xff];
#if PrintStateDetailed
      printf("Linear-Layer\t: ");
      print_detail(data);
#endif
      
    /* ---------------- Second Round -------------- */
#if PrintStateDetailed
      printf("Round %i\n", 2*i+2);
#endif
      
      /* SBox layer (bitsliced) */
      SBOX(data);
#if PrintStateDetailed
      printf("S-box\t\t: ");
      print_detail(data);
#endif
      
      /* Round constant */
      data[0] ^= ((2199*(2*i+1)) % 65536);
#if PrintStateDetailed
      printf("AddConstant\t: ");
      print_detail(data);
#endif
      
      /* LBox layer (tables) */
      for (j=0; j<8; j++)
          data[j] = LBox2[data[j]>>8] ^ LBox1[data[j]&0xff];
#if PrintStateDetailed
      printf("Linear-Layer\t: ");
      print_detail(data);
#endif
      
    /* Tweak schedule */
    for (j=0; j<4; j++) {
      t[j]   ^= t[j+4];
      t[j+4] ^= t[j];
    }
    /* ----------- Key + Tweak Addition ---------- */
    for (j=0; j<8; j++) data[j] ^= k[j] ^ t[j];
  }

  /* ----------- Restore initial tweak --------- */
  for (i=nSteps%3; i<3; i++) {
    for (j=0; j<4; j++) {
      t[j]   ^= t[j+4];
      t[j+4] ^= t[j];
    }
  }
    
  for (i=0; i<8; i++) {
    output[2*i]   = data[i];
    output[2*i+1] = data[i]>>8;
  }
#if PrintStateDetailed
    printf("\n");
#endif
}


void LS_decrypt(const crypto_uint8 input[16], const crypto_uint8 key[16], const crypto_uint8 tweak[16],
		crypto_uint8 output[16]) {
  crypto_uint16 data[8];
  crypto_uint16 k[8];
  crypto_uint16 t[8];
  int i,j;

  for (i=0; i<8; i++) {
    data[i] = ((crypto_uint16)input[2*i+1]<<8) + input[2*i];
    k[i] = ((crypto_uint16)  key[2*i+1]<<8) +   key[2*i];
    t[i] = ((crypto_uint16)tweak[2*i+1]<<8) + tweak[2*i];
  }

  /* ---------------- Step Function ---------------- */
  for (i=nSteps-1; i>=0; i--) {
    /* ----------- Key + Tweak Addition ---------- */
    for (j=0; j<8; j++) data[j] ^= k[j];
    switch(i%3) {
    case     0:
      for (j=0; j<4; j++) data[j] ^= t[j] ^ t[j+4];
      for (j=4; j<8; j++) data[j] ^= t[j-4];
      break;
    case     1:
      for (j=0; j<4; j++) data[j] ^= t[j+4];
      for (j=4; j<8; j++) data[j] ^= t[j] ^ t[j-4];
      break;
    case     2:
      for (j=0; j<8; j++) data[j] ^= t[j] ;
      break;
    }

    /* ---------------- Second Round -------------- */
    /* LBox layer (tables) */
    for (j=0; j<8; j++)
      data[j] = LBoxInv2[data[j]>>8] ^ LBoxInv1[data[j]&0xff];
    /* Round constant */
    data[0] ^= ((2199*(2*i+1)) % 65536);
    /* SBox layer (bitsliced) */
    SBOX_Inv(data);
        
    /* ---------------- First Round ---------------- */
    /* LBox layer (tables) */
    for (j=0; j<8; j++)
      data[j] = LBoxInv2[data[j]>>8] ^ LBoxInv1[data[j]&0xff];
    /* First round constant */
    data[0] ^= ((2199*(2*i)) % 65536);
    /* SBox layer (bitsliced) */
    SBOX_Inv(data);
  }

  /* Final key + tweak addition */
  for (j=0; j<8; j++) data[j] ^= k[j] ^ t[j];
    
  for (i=0; i<8; i++) {
    output[2*i]   = data[i];
    output[2*i+1] = data[i]>>8;
  }
}
