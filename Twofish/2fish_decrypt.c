/*
 ============================================================================
 Name        : 2fish_decrypt.c
 Author      : Vasileios Leivadas
 Version     :
 Copyright   : Your copyright notice
 Description : Hello World in C, Ansi-style
 ============================================================================
 */

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

//typedef unsigned __int128 uint128_t;

//Prototypes
uint32_t ROL32 (uint32_t value, int count);
uint32_t ROR32 (uint32_t value, int count);
uint8_t ROR8 (uint8_t value, int count);
uint8_t ROL8 (uint8_t value, int count);
unsigned int ROR4(unsigned int value, int count);
uint8_t q_perm0(uint8_t qin0);
uint8_t q_perm1(uint8_t qin1);
uint32_t Gen_S0(void);
uint32_t Gen_S1(void);
uint32_t MDS(uint8_t y0, uint8_t y1, uint8_t y2, uint8_t y3);
uint32_t g_func(uint32_t X, uint32_t Key1, uint32_t Key2);
void h_func(void);
void F_func(uint32_t Fin0, uint32_t Fin1);

//Key Array
uint32_t K[40];

//Fout
uint32_t F[2];

//Round Number
int r;

//Plaintext
uint64_t Plaintext[2] = {0,0};

//User-Supplied M_key
uint32_t M_key[16][1]= {
						{0x53},
						{0x81},
						{0xAE},
						{0x19},
						{0xDC},
						{0x87},
						{0x7F},
						{0xAD},
						{0x69},
						{0x01},
						{0x03},
						{0x7D},
						{0x81},
						{0x65},
						{0x20},
						{0x1A}
							};

//RS-Matrix
uint8_t RS[4][8] = {
						{0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E},
						{0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5},
						{0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19},
						{0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03}
																	};


int main(void){
	//Generate Keys
	h_func();

	//Input Cipher Text
	uint64_t Ciph0, Ciph1;
	Ciph0 = 0xD6CBDD0F522DFFA2;
	Ciph1 = 0x78EE89E8054FC74D;

	uint32_t R0,R1,R2,R3,R4,R5,R6,R7,C2,C3,Temp1,Temp2;

	//Break It down
	R3 = Ciph1 & (0x00000000FFFFFFFF);
	R2 = (Ciph1 & (0xFFFFFFFF00000000)) >> 32;
	R1 = Ciph0 & (0x00000000FFFFFFFF);
	R0 = (Ciph0 & (0xFFFFFFFF00000000)) >> 32;
	printf("R3 = %u,R2 = %u,R1 = %u,R0 = %u\n",R3,R2,R1,R0);
	
	//Input Whitening
	R0 ^= K[39];
	R1 ^= K[38];
	R2 ^= K[37];
	R3 ^= K[36];
	printf("After Whitening: R3 = %u,R2 = %u,R1 = %u,R0 = %u\n",R3,R2,R1,R0);
	for (r=0;r<16;r++){
		//Main Iteration
		printf("Iteration %i\n",r);
		F_func(R0,R1);
		R2 = ROL32(R2,1);
		printf("R2 = %u\n",R2);
		C2 = F[0]^R2;
		C3 = F[1]^R3;
		printf("C3 = %u\n",C3);
		C3 = ROR32(C3,1);
		printf("C3 = %u\n",C3);

		//Swap R0/C2/R2
		Temp1 = R0;
		R0 = C2;
		R2 = Temp1;

		//Swap R1/C3/R3
		Temp2 = R1;
		R1 = C3;
		R3 = Temp2;
	}

	//Undo last Swap for R0 and R1
	R0 = Temp1;
	R1 = Temp2;

	//Output Whitening
	R4 = C2^K[35];
	R5 = C3^K[34];
	R6 = R0^K[33];
	R7 = R1^K[32];

	//Plaintext
	Plaintext[0] |= R4;
	Plaintext[0] = (Plaintext[0] << 32) | R5;
	Plaintext[1] |= R6;
	Plaintext[1] = (Plaintext[1] << 32) | R7;

	printf("P0 = %I64u\nP1 = %I64u", Plaintext[0],Plaintext[1]);

	return(0);
}

//Rotation Functions
int ROR4(unsigned int value, int count){
	    value |= ((value & ((1<<count)-1) ) << 4);
	    value >>= count;
	    return value;
}

uint32_t ROL32 (uint32_t value, int count) {
	uint32_t value_32 = ( value<<count | value>>(32-count) );
    return value_32;
}

uint32_t ROR32 (uint32_t value, int count) {
	uint32_t value_32 = ( value>>count | value<<(32-count) );
    return value_32;
}

uint8_t ROR8 (uint8_t value, int count) {
	uint8_t value_8 = ( value>>count | value<<(8-count) );
    return value_8;
}

uint8_t ROL8 (uint8_t value, int count) {
	uint8_t value_8 = ( value<<count | value>>(8-count) );
    return value_8;
}

//*****Key Schedule*****//

uint32_t Gen_S0(void){
	int i,j = 0,k;
	uint32_t S0 = 0;
	uint8_t temp0;
	for (i=0;i<4;i++){
		temp0 = 0;
		for (k=0;k<8;k++){
			temp0 += RS[i][k]*M_key[k][j];
		}
		S0 |= temp0;
		S0 <<= 8;
	}
	printf("S0 = %u\n",S0);
	return (S0);
}

uint32_t Gen_S1(void){
	int i,j = 0,k;
	uint32_t S1 = 0;
	uint8_t temp1;
	for (i=0;i<4;i++){
		temp1 = 0;
		for (k=0;k<8;k++){
			temp1 += RS[i][k]*M_key[k+8][j];
		}
		S1 |= temp1;
		S1 <<= 8;
	}
	printf("S1 = %u\n",S1);
	return (S1);
}

void h_func(void){
	int i;
	uint32_t M0=0,M1=0,M2=0,M3=0, a, b, aout, bout;
	uint32_t rho = 0x01010101;
	M3 = ( (M_key[12][0] << 24) | (M_key[13][0] << 16) | (M_key[14][0] << 8) | M_key[15][0]);
	M2 = ( (M_key[8][0] << 24) | (M_key[9][0] << 16) | (M_key[10][0] << 8) | M_key[11][0]);
	M1 = ( (M_key[4][0] << 24) | (M_key[5][0] << 16) | (M_key[6][0] << 8) | M_key[7][0]);
	M0 = ( (M_key[0][0] << 24) | (M_key[1][0] << 16) | (M_key[2][0] << 8) | M_key[3][0]);
	printf("M3 = %u,M2 = %u,M1 = %u,M0 = %u\n",M3,M2,M1,M0);
	for (i=0; i<20; i++){
		printf("Keys for i = %i\n",i);
		a = g_func(2*i*rho, M2, M0);
		b = g_func((2*i+1)*rho, M3, M1);
		b = ROL32(b,8);
		aout = ((a+b)%(0x100000000));
		bout = ((b+aout)%(0x100000000));
		K[2*i] = aout;
		K[2*i+1] = ROL32(bout,9);
		printf("K%i = %u, K%i = %u\n",2*i,K[2*i],2*i+1,K[2*i+1]);
	}
}


//Main Part - G/F

uint32_t MDS(uint8_t y0, uint8_t y1, uint8_t y2, uint8_t y3){
	uint8_t MDSmtrx[4][4] = {
								{0x01, 0xEF, 0x5B, 0x5B},
								{0x5B, 0xEF, 0xEF, 0x01},
								{0xEF, 0x5B, 0x01, 0xEF},
								{0xEF, 0x01, 0xEF, 0x5B}
												};
	uint8_t Ymtrx[4][1] = {
							{y0},
							{y1},
							{y2},
							{y3}
							};
	int i,j = 0,k;
	uint32_t T = 0;
	uint32_t temp;
	for (i=0;i<4;i++){
		temp = 0;
		for (k=0;k<4;k++){
			temp += MDSmtrx[i][k]*Ymtrx[k][j];
		}
		temp <<= 8*i;
		T |= temp;
	}
	return (T);
}


uint8_t q_perm0(uint8_t qin0){
	unsigned int a0, b0, a1, b1, a2, b2, a3, b3, a4, b4;
	uint8_t y0;
	 a0 = qin0 >> 4;
	 b0 = qin0 & 0x0F;
	 a1 = a0 ^ b0;
	 b1 = (a0 ^ ROR4(b0,1) ^ ((8*a0)%16));
	 switch(a1){
		case 0x0 : a2 = 0x8; break;
		case 0x1 : a2 = 0x1; break;
		case 0x2 : a2 = 0x7; break;
		case 0x3 : a2 = 0xD; break;
		case 0x4 : a2 = 0x6; break;
		case 0x5 : a2 = 0xF; break;
		case 0x6 : a2 = 0x3; break;
		case 0x7 : a2 = 0x2; break;
		case 0x8 : a2 = 0x0; break;
		case 0x9 : a2 = 0xB; break;
		case 0xA : a2 = 0x5; break;
		case 0xB : a2 = 0x9; break;
		case 0xC : a2 = 0xE; break;
		case 0xD : a2 = 0xC; break;
		case 0xE : a2 = 0xA; break;
		case 0xF : a2 = 0x4; break;
	 }
	 switch(b1){
		case 0x0 : b2 = 0xE; break;
		case 0x1 : b2 = 0xC; break;
		case 0x2 : b2 = 0xB; break;
		case 0x3 : b2 = 0x8; break;
		case 0x4 : b2 = 0x1; break;
		case 0x5 : b2 = 0x2; break;
		case 0x6 : b2 = 0x3; break;
		case 0x7 : b2 = 0x5; break;
		case 0x8 : b2 = 0xF; break;
		case 0x9 : b2 = 0x4; break;
		case 0xA : b2 = 0xA; break;
		case 0xB : b2 = 0x6; break;
		case 0xC : b2 = 0x7; break;
		case 0xD : b2 = 0x0; break;
		case 0xE : b2 = 0x9; break;
		case 0xF : b2 = 0xD; break;
	 }
	 a3 = a2 ^ b2;
	 b3 = (a2 ^ ROR4(b2,1) ^ ((8*a2)%16));
	 switch(a3){
		case 0x0 : a4 = 0xB; break;
		case 0x1 : a4 = 0xA; break;
		case 0x2 : a4 = 0x5; break;
		case 0x3 : a4 = 0xE; break;
		case 0x4 : a4 = 0x6; break;
		case 0x5 : a4 = 0xD; break;
		case 0x6 : a4 = 0x9; break;
		case 0x7 : a4 = 0x0; break;
		case 0x8 : a4 = 0xC; break;
		case 0x9 : a4 = 0x8; break;
		case 0xA : a4 = 0xF; break;
		case 0xB : a4 = 0x3; break;
		case 0xC : a4 = 0x2; break;
		case 0xD : a4 = 0x4; break;
		case 0xE : a4 = 0x7; break;
		case 0xF : a4 = 0x1; break;
	 }
	 switch(b3){
		case 0x0 : b4 = 0xD; break;
		case 0x1 : b4 = 0x7; break;
		case 0x2 : b4 = 0xF; break;
		case 0x3 : b4 = 0x4; break;
		case 0x4 : b4 = 0x1; break;
		case 0x5 : b4 = 0x2; break;
		case 0x6 : b4 = 0x6; break;
		case 0x7 : b4 = 0xE; break;
		case 0x8 : b4 = 0x9; break;
		case 0x9 : b4 = 0xB; break;
		case 0xA : b4 = 0x3; break;
		case 0xB : b4 = 0x0; break;
		case 0xC : b4 = 0x8; break;
		case 0xD : b4 = 0x5; break;
		case 0xE : b4 = 0xC; break;
		case 0xF : b4 = 0xA; break;
	 }
	 y0 = 16*b4 + a4;
	 return y0;
}

uint8_t q_perm1(uint8_t qin1){
	unsigned int a0, b0, a1, b1, a2, b2, a3, b3, a4, b4;
	uint8_t y1;
	 a0 = qin1 >> 4;
	 b0 = qin1 & 0x0F;
	 a1 = a0 ^ b0;
	 b1 = (a0 ^ ROR4(b0,1) ^ ((8*a0)%16));
	 switch(a1){
		case 0x0 : a2 = 0x2; break;
		case 0x1 : a2 = 0x8; break;
		case 0x2 : a2 = 0xB; break;
		case 0x3 : a2 = 0xD; break;
		case 0x4 : a2 = 0xF; break;
		case 0x5 : a2 = 0x7; break;
		case 0x6 : a2 = 0x6; break;
		case 0x7 : a2 = 0xE; break;
		case 0x8 : a2 = 0x3; break;
		case 0x9 : a2 = 0x1; break;
		case 0xA : a2 = 0x9; break;
		case 0xB : a2 = 0x4; break;
		case 0xC : a2 = 0x0; break;
		case 0xD : a2 = 0xA; break;
		case 0xE : a2 = 0xC; break;
		case 0xF : a2 = 0x5; break;
	 }
	 switch(b1){
		case 0x0 : b2 = 0x1; break;
		case 0x1 : b2 = 0xE; break;
		case 0x2 : b2 = 0x2; break;
		case 0x3 : b2 = 0xB; break;
		case 0x4 : b2 = 0x4; break;
		case 0x5 : b2 = 0xC; break;
		case 0x6 : b2 = 0x3; break;
		case 0x7 : b2 = 0x7; break;
		case 0x8 : b2 = 0x6; break;
		case 0x9 : b2 = 0xD; break;
		case 0xA : b2 = 0xA; break;
		case 0xB : b2 = 0x5; break;
		case 0xC : b2 = 0xF; break;
		case 0xD : b2 = 0x9; break;
		case 0xE : b2 = 0x0; break;
		case 0xF : b2 = 0x8; break;
	 }
	 a3 = a2 ^ b2;
	 b3 = (a2 ^ ROR4(b2,1) ^ ((8*a2)%16));
	 switch(a3){
		case 0x0 : a4 = 0x4; break;
		case 0x1 : a4 = 0xC; break;
		case 0x2 : a4 = 0x7; break;
		case 0x3 : a4 = 0x5; break;
		case 0x4 : a4 = 0x1; break;
		case 0x5 : a4 = 0x6; break;
		case 0x6 : a4 = 0x9; break;
		case 0x7 : a4 = 0xA; break;
		case 0x8 : a4 = 0x0; break;
		case 0x9 : a4 = 0xE; break;
		case 0xA : a4 = 0xD; break;
		case 0xB : a4 = 0x8; break;
		case 0xC : a4 = 0x2; break;
		case 0xD : a4 = 0xB; break;
		case 0xE : a4 = 0x3; break;
		case 0xF : a4 = 0xF; break;
	 }
	 switch(b3){
		case 0x0 : b4 = 0xB; break;
		case 0x1 : b4 = 0x9; break;
		case 0x2 : b4 = 0x5; break;
		case 0x3 : b4 = 0x1; break;
		case 0x4 : b4 = 0xC; break;
		case 0x5 : b4 = 0x3; break;
		case 0x6 : b4 = 0xD; break;
		case 0x7 : b4 = 0xE; break;
		case 0x8 : b4 = 0x6; break;
		case 0x9 : b4 = 0x4; break;
		case 0xA : b4 = 0x7; break;
		case 0xB : b4 = 0xF; break;
		case 0xC : b4 = 0x2; break;
		case 0xD : b4 = 0x0; break;
		case 0xE : b4 = 0x8; break;
		case 0xF : b4 = 0xA; break;
	 }
	 y1 = 16*b4 + a4;
	 return y1;
}


uint32_t g_func(uint32_t X, uint32_t Key1, uint32_t Key2){
	uint8_t X0, X1, X2, X3;
	uint32_t T;
	printf("X  = %u\n",X);
	
	// 1st permutation
	X0 = X & (0x000000FF);
	X1 = (X & (0x0000FF00)) >> 8;
	X2 = (X & (0x00FF0000)) >> 16;
	X3 = (X & (0xFF000000)) >> 24;
	printf("X3 = %u,X2  = %u,X1 = %u, X0 = %u\n",X3,X2,X1,X0);
	X0 = q_perm0(X0);
	X1 = q_perm1(X1);
	X2 = q_perm0(X2);
	X3 = q_perm1(X3);
	uint32_t tempXi = 0;
	tempXi |= X3;
	tempXi = (tempXi << 8) | X2;
	tempXi = (tempXi << 8) | X1;
	tempXi = (tempXi << 8) | X0;
	tempXi ^= Key1;
	printf("Xi  = %u\n",tempXi);

	// 2nd permutation
	X0 = tempXi & (0x000000FF);
	X1 = (tempXi & (0x0000FF00)) >> 8;
	X2 = (tempXi & (0x00FF0000)) >> 16;
	X3 = (tempXi & (0xFF000000)) >> 24;
	X0 = q_perm0(X0);
	X1 = q_perm0(X1);
	X2 = q_perm1(X2);
	X3 = q_perm1(X3);
	uint32_t tempXii = 0;
	tempXii |= X3;
	tempXii = (tempXi << 8) | X2;
	tempXii = (tempXi << 8) | X1;
	tempXii = (tempXi << 8) | X0;
	tempXii ^= Key2;

	// 3rd permutation
	X0 = tempXii & (0x000000FF);
	X1 = (tempXii & (0x0000FF00)) >> 8;
	X2 = (tempXii & (0x00FF0000)) >> 16;
	X3 = (tempXii & (0xFF000000)) >> 24;
	X0 = q_perm1(X0);
	X1 = q_perm0(X1);
	X2 = q_perm1(X2);
	X3 = q_perm0(X3);

	//MDS call
	T = MDS(X0,X1,X2,X3);

	return(T);
}


void F_func(uint32_t Fin0, uint32_t Fin1){
	uint32_t T0,T1,c,d,S0,S1;
	S0 = Gen_S0();
	S1 = Gen_S1();
	T0 = g_func(Fin0, S0, S1);
	Fin1 = ROL32(Fin1, 8);
	T1 = g_func(Fin1, S0, S1);
	c = ((T0+T1)%(0x100000000));
	d = ((T1+c)%(0x100000000));
	printf("T0  = %u, T1 = %u, c = %u, d = %u\n",T0,T1,c,d);
	F[0] = ((c+K[31-2*r])%(0x100000000));
	F[1] = ((d+K[30-2*r])%(0x100000000));
	printf("F0 = %u, F1 = %u\n",F[0],F[1]);
}

