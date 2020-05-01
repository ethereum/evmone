

#if !WASM
#include <stdint.h>
#else
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
typedef unsigned __int128 uint128_t;
#endif

#define uint128_t __uint128_t

/*
This library requires two parameters:
BIGINT_BITS - the number of bits of the big integer
LIMB_BITS - the number of bits in each limb, must correspond to a uint*_t type
LIMB_BITS_OVERFLOW - the number of bits output by multiplication, i.e. 2*LIMB_BITS, must correspond to a uint*_t type

To use this library, define a limb size and include it:
  #define BIGINT_BITS 256
  #define LIMB_BITS 64
  #define LIMB_BITS_OVERFLOW 128
  #include "bigint.h"
  #undef BIGINT_BITS
  #undef LIMB_BITS
  #undef LIMB_BITS_OVERFLOW

  #define BIGINT_BITS 512
  #define LIMB_BITS 32
  #define LIMB_BITS_OVERFLOW 64
  #include "bigint.h"
  #undef BIGINT_BITS
  #undef LIMB_BITS
  #undef LIMB_BITS_OVERFLOW

Now you can use functions like:
  montmul256_64bitlimbs(x,y,m,inv,out);
  subtract512_32bitlimbs(a,b,out);

Warning: LIMB_BITS corresponds to the uint*_t type, and multiplication requires double the bits, for example 64 bit limbs require type uint128_t.

*/


// Define constants used in this file:

// define types UINT and UNT2, where UINT2 is for overflow of operations on UINT; for multiplication should be double the number of bits
// UINT is the limb type, uint*_t where * is the number of bits per limb
// UINT2 is also needed for multiplication UINTxUINT->UINT2, e.g. uint32_txuint32_t->uint64_t or uint64_txuint64_t->uint128_t
#define TYPE_(num) uint##num##_t
#define TYPE(num) TYPE_(num)
#define UINT TYPE(LIMB_BITS)
#define UINT2 TYPE(LIMB_BITS_OVERFLOW)

// define NUM_LIMBS to be the number of limbs
// eg UINT=uint32_t with NUM_LIMBS=8 limbs is for 256-bit
// eg UINT=uint64_t with NUM_LIMBS=8 limbs is for 512-bit
#define NUM_LIMBS (BIGINT_BITS/LIMB_BITS)

// define the function name, use concatenation
// eg BIGINT_BITS=256, LIMB_BITS=64: FUNCNAME(myname) is replaced with myname256_64bitlimbs
#define FUNCNAME__(name,A,B) name##A##_##B##bitlimbs
#define FUNCNAME_(name,A,B) FUNCNAME__(name,A,B)
#define FUNCNAME(name) FUNCNAME_(name,BIGINT_BITS,LIMB_BITS)


// add two numbers modulo the precision of NUM_LIMBS limbs
// algorithm 14.7, Handbook of Applied Cryptography, http://cacr.uwaterloo.ca/hac/about/chap14.pdf
//   except we ignore the final carry in step 3 since we assume that there is no extra limb
void FUNCNAME(add)(UINT* const out, const UINT* const x, const UINT* const y){
  UINT carry=0;
  #pragma unroll
  for (int i=0; i<NUM_LIMBS;i++){
    UINT2 temp = (UINT2)(x[i])+y[i]+carry;
    carry = temp >> LIMB_BITS; 
    out[i] = (UINT)temp;
  }
  // this had errors, keep for analysis now because above is slower
  //for (int i=0; i<NUM_LIMBS;i++){
  //  uint64_t temp = x[i]+y[i]+carry;
  //  carry = x[i] > temp ? 1:0;
  //  out[i]=temp;
  //}
}

// compute x-y for x>=y
// algorithm 14.9, Handbook of Applied Cryptography, http://cacr.uwaterloo.ca/hac/about/chap14.pdf
// but algorithm 14.9 uses negative numbers, which we don't support, so we modify it, needs review
void FUNCNAME(subtract)(UINT* const out, const UINT* const x, const UINT* const y){
  UINT carry=0;
  #pragma unroll
  for (int i=0; i<NUM_LIMBS; i++){
    UINT temp = x[i]-carry;
    carry = (temp<y[i] || x[i]<carry) ? 1:0;
    out[i] = temp-y[i];

    // casey's algorithm:
    //UINT out_temp = x[i]-y[i]-carry;
    //carry = (x[i]<y[i] || y[i]<carry) ? 1:0;
    //out[i] = out_temp;
  }
}

// checks whether x<y
// TODO: reference spec of this algorithm
uint8_t FUNCNAME(less_than)(const UINT* const x, const UINT* const y){
  for (int i=NUM_LIMBS-1;i>=0;i--){
    if (x[i]>y[i])
      return 0;
    else if (x[i]<y[i])
      return 1;
  }
  // they are equal
  return 0;
}

// checks whether x<=y
// NUM_LIMBS is number of limbs
// TODO: reference spec of this algorithm
uint8_t FUNCNAME(less_than_or_equal)(const UINT* const x, const UINT* const y){
  for (int i=NUM_LIMBS-1;i>=0;i--){
    if (x[i]>y[i])
      return 0;
    else if (x[i]<y[i])
      return 1;
  }
  // they are equal
  return 1;
}

#if 0
// algorithm 14.20, Handbook of Applied Cryptography, http://cacr.uwaterloo.ca/hac/about/chap14.pdf
// but assume they both have the same number of limbs, this is naive
void FUNCNAME(div)(UINT* const outq, UINT* const outr, const UINT* const x, const UINT* const y){
  UINT q[NUM_LIMBS];
  UINT one[NUM_LIMBS];
  for (int i=0; i<NUM_LIMBS; i++){
    q[i]=0;
    one[i]=0;
  }
  one[0]=1;
  while (FUNCNAME(less_than_or_equal)(y,x)){
    FUNCNAME(add)(q,q,one);
    FUNCNAME(subtract)(x,x,y);
  }
  for (int i=0; i<NUM_LIMBS; i++){
    outr[i]=x[i];
    outr[i]=q[i];
  }
}
#endif

// algorithm 14.12, Handbook of Applied Cryptography, http://cacr.uwaterloo.ca/hac/about/chap14.pdf
// but assume they both have the same number of limbs, this can be changed
// out should have double the limbs of inputs
// num_limbs corresponds to n+1 in the book
void FUNCNAME(mul)(UINT* const out, const UINT* const x, const UINT* const y){
  UINT* w = out;
  for (int i=0; i<2*NUM_LIMBS; i++)
    w[i]=0;
  for (int i=0; i<NUM_LIMBS; i++){
    UINT c = 0;
    for (int j=0; j<NUM_LIMBS; j++){
      UINT2 uv = (UINT2)w[i+j] + (UINT2)x[j]*y[i];
      uv += c;
      UINT2 u = uv >> LIMB_BITS;
      UINT v = (UINT)uv;
      w[i+j] = v;
      c = (UINT)u;
    }
    w[i+NUM_LIMBS] = c;
  }
  //for (int i=0; i< 2*NUM_LIMBS; i++)
  //  out[i]=w[i];
}

// algorithm 14.16, Handbook of Applied Cryptography, http://cacr.uwaterloo.ca/hac/about/chap14.pdf
// NUM_LIMBS is t (number of limbs) in the book, and the base is UINT*, usually uint32_t or uint64_t
// output out should have double the limbs of input x
void FUNCNAME(square)(UINT* const out, const UINT* const x){
  UINT w[NUM_LIMBS*2];
  for (int i=0; i< 2*NUM_LIMBS; i++)
    w[i]=0;
  for (int i=0; i<NUM_LIMBS; i++){
    UINT2 uv = (UINT2)(x[i])*x[i] + w[2*i];
    UINT u = uv >> LIMB_BITS; // / base
    UINT v = (UINT)uv; // % base
    w[2*i] = v;
    UINT c = u;
    for (int j=i+1; j<NUM_LIMBS; j++){
      UINT2 xixj = (UINT2)(x[i])*x[j];
      UINT2 partial_sum = xixj + c + w[i+j];
      uv = xixj + partial_sum;
      u = uv >> LIMB_BITS; // / base
      v = (UINT)uv; // % base
      w[i+j] = v;
      c = u;
      // may have more overflow, so keep carrying
      // this passes sume tests, but needs review
      if (uv<partial_sum){
        int k=2;
        while ( i+j+k<NUM_LIMBS*2 && w[i+j+k]==(UINT)0-1 ){ // note 0-1 is 0xffffffff
          w[i+j+k]=0;
          k++;
        }
        if (i+j+k<NUM_LIMBS*2)
          w[i+j+k]+=1;
      }
    }
    // this passes some tests, but not sure if += is correct
    w[i+NUM_LIMBS] += u;
  }
  for (int i=0; i< 2*NUM_LIMBS; i++)
    out[i]=w[i];
}



////////////////////////
// Modular arithmetic //
////////////////////////


// add two numbers modulo another number, a+b (mod m)
// algorithm 14.27, Handbook of Applied Cryptography, http://cacr.uwaterloo.ca/hac/about/chap14.pdf
void FUNCNAME(addmod)(UINT* const out, const UINT* const x, const UINT* const y, const UINT* const m){
  UINT carry=0;
  #pragma unroll
  for (int i=0; i<NUM_LIMBS;i++){
    UINT2 temp = (UINT2)(x[i])+y[i]+carry;
    carry = temp >> LIMB_BITS; 
    out[i] = (UINT)temp;
  }

  if (carry){
    FUNCNAME(subtract)(out, out, m);
    return;
  }

  for (int i=NUM_LIMBS-1;i>=0;i--){
    if (m[i]>out[i])
      return;
    else if (m[i]<out[i])
      FUNCNAME(subtract)(out, out, m);
      return;
  }
  return;

  if (carry || FUNCNAME(less_than_or_equal)(m,out)){
    FUNCNAME(subtract)(out, out, m);
  }
}

// compute x-y (mod m) for x>=y
// algorithm 14.27, Handbook of Applied Cryptography, http://cacr.uwaterloo.ca/hac/about/chap14.pdf
void FUNCNAME(subtractmod)(UINT* const out, const UINT* const x, const UINT* const y, const UINT* const m){
  (void)m;
  // the book referenced says that this is the same as submod
  FUNCNAME(subtract)(out, x, y);
}

// algorithm 14.32, Handbook of Applied Cryptography, http://cacr.uwaterloo.ca/hac/about/chap14.pdf
// T has 2*NUM_LIMBS limbs, otherwise pad most significant bits with zeros
void FUNCNAME(montreduce)(UINT* const out, UINT* const T, const UINT* const m, UINT const minv){

  UINT A[NUM_LIMBS*2+1];
  for (int i=0; i<2*NUM_LIMBS; i++)
    A[i] = T[i];
  A[NUM_LIMBS*2]=0;
  //for (int i=NUM_LIMBS; i<2*NUM_LIMBS; i++)
  //  A[i] = 0;
  for (int i=0; i<NUM_LIMBS; i++){
    UINT ui = A[i]*minv;
    UINT carry=0;
    int j;
    // add ui*m*b^i to A in a loop, since m is NUM_LIMBS long
    for (j=0; j<NUM_LIMBS; j++){
      UINT2 sum = (UINT2)ui*m[j] + A[i+j] + carry;
      A[i+j] = (UINT)sum; // % b;
      carry = sum >> LIMB_BITS; // / b
    }
    // carry may be nonzero, so keep carrying
    int k=0;
    while (carry && i+j+k<2*NUM_LIMBS+1){
      //printf("carry %d\n",i+j+k);
      UINT2 sum = (UINT2)(A[i+j+k])+carry;
      A[i+j+k] = (UINT)sum; // % b
      carry = sum >> LIMB_BITS; // / b
      k+=1;
    }
  }

  // instead of right shift, we just get the correct values
  //#pragma unroll
  for (int i=0; i<NUM_LIMBS; i++)
    out[i] = A[i+NUM_LIMBS];

  // final subtraction, first see if necessary
  if (A[NUM_LIMBS*2] || FUNCNAME(less_than_or_equal)(m,out)){
    FUNCNAME(subtract)(out, out, m);
  }
}

// algorithm 14.16 followed by 14.32
// this might be faster than algorithm 14.36, as described in remark 14.40
void FUNCNAME(montsquare)(UINT* const out, const UINT* const x, const UINT* const m, UINT const inv){
  UINT out_internal[NUM_LIMBS*2];
  FUNCNAME(square)(out_internal, x);
  FUNCNAME(montreduce)(out, out_internal, m, inv);
}

// algorithm 14.12 followed by 14.32
// this might be slower than algorithm 14.36, which interleaves these steps
void FUNCNAME(montmul_noninterleaved)(UINT* const out, const UINT* const x, const UINT* const y, const UINT* const m, UINT const inv){
  UINT out_internal[NUM_LIMBS*2];
  FUNCNAME(mul)(out_internal, x, y);
  FUNCNAME(montreduce)(out, out_internal, m, inv);
}

// algorithm 14.36, Handbook of Applied Cryptography, http://cacr.uwaterloo.ca/hac/about/chap14.pdf
void FUNCNAME(montmul)(UINT* const out, const UINT* const x, const UINT* const y, const UINT* const m, UINT const inv){
  UINT A[NUM_LIMBS*2+1];
  for (int i=0;i<NUM_LIMBS*2+1;i++)
    A[i]=0;
  //#pragma unroll	// this unroll increases binary size by a lot
  for (int i=0; i<NUM_LIMBS; i++){
    UINT ui = (A[i]+x[i]*y[0])*inv;
    UINT carry = 0;
    #pragma unroll
    for (int j=0; j<NUM_LIMBS; j++){
      UINT2 xiyj = (UINT2)x[i]*y[j];
      UINT2 uimj = (UINT2)ui*m[j];
//uint128_t partial_sum = xiyj+carry;
//uint128_t sum = uimj+A[i+j]+partial_sum;
      UINT2 partial_sum = xiyj+carry;
      UINT2 sum = uimj+A[i+j]+partial_sum;
      //UINT2 partial_sum = xiyj+carry+A[i+j];
      //UINT2 sum = uimj+partial_sum;
      A[i+j] = (UINT)sum;
      carry = sum>>LIMB_BITS;
      // if there was overflow in the sum beyond the carry:
      if (sum<partial_sum){
        int k=2;
        while ( i+j+k<NUM_LIMBS*2 && A[i+j+k]==(UINT)0-1 ){ // note 0-1 is 0xffffffff
	  // this is rare, need limb to be all 1's
          A[i+j+k]=0;
          k++;
	  //printf("rare case 0!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
        }
        if (i+j+k<NUM_LIMBS*2+1){
          A[i+j+k]+=1;
	  //printf("rare case 1 limb %d\n",i+j+k);
	}
      }
      //printf("%d %d %llu %llu %llu %llu %llu %llu %llu %llu %llu\n",i,j,x[i],x[i]*y[0],ui,xiyj,uimj,partial_sum,sum,A[i+j],carry);
    }
    A[i+NUM_LIMBS]+=carry;
  }

  // instead of right shift, we just get the correct values
  //#pragma unroll
  for (int i=0; i<NUM_LIMBS;i++)
    out[i] = A[i+NUM_LIMBS];

  // final subtraction, first see if necessary
  if (A[NUM_LIMBS*2]>0 || FUNCNAME(less_than_or_equal)(m,out))
      FUNCNAME(subtract)(out, out, m);
}

// like montmul, but with two of the args hard-coded
void FUNCNAME(montmul_3args_)(UINT* const out, const UINT* const x, const UINT* const y){
  UINT* m = (UINT*)4444444;    // hard-code m or address to m here
  UINT inv = 6666666;  // hard-code inv here
  FUNCNAME(montmul)(out, x, y, m, inv);
}


