#include "blake.h"

void blake256_compress( state256 *S, const uint8_t *block )
{
  uint32_t v[16], m[16], i;
#define ROT(x,n) (((x)<<(32-n))|( (x)>>(n)))
#define G(a,b,c,d,e)          \
  v[a] += (m[sigma[i][e]] ^ u256[sigma[i][e+1]]) + v[b]; \
  v[d] = ROT( v[d] ^ v[a],16);        \
  v[c] += v[d];           \
  v[b] = ROT( v[b] ^ v[c],12);        \
  v[a] += (m[sigma[i][e+1]] ^ u256[sigma[i][e]])+v[b]; \
  v[d] = ROT( v[d] ^ v[a], 8);        \
  v[c] += v[d];           \
  v[b] = ROT( v[b] ^ v[c], 7);

  for( i = 0; i < 16; ++i )  m[i] = U8TO32_BIG( block + i * 4 );

  for( i = 0; i < 8; ++i )  v[i] = S->h[i];

  v[ 8] = S->s[0] ^ u256[0];
  v[ 9] = S->s[1] ^ u256[1];
  v[10] = S->s[2] ^ u256[2];
  v[11] = S->s[3] ^ u256[3];
  v[12] = u256[4];
  v[13] = u256[5];
  v[14] = u256[6];
  v[15] = u256[7];

  /* don't xor t when the block is only padding */
  if ( !S->nullt )
  {
    v[12] ^= S->t[0];
    v[13] ^= S->t[0];
    v[14] ^= S->t[1];
    v[15] ^= S->t[1];
  }

  for( i = 0; i < 14; ++i )
  {
    /* column step */
    G( 0,  4,  8, 12,  0 );
    G( 1,  5,  9, 13,  2 );
    G( 2,  6, 10, 14,  4 );
    G( 3,  7, 11, 15,  6 );
    /* diagonal step */
    G( 0,  5, 10, 15,  8 );
    G( 1,  6, 11, 12, 10 );
    G( 2,  7,  8, 13, 12 );
    G( 3,  4,  9, 14, 14 );
  }

  for( i = 0; i < 16; ++i )  S->h[i % 8] ^= v[i];

  for( i = 0; i < 8 ; ++i )  S->h[i] ^= S->s[i % 4];
}


void blake256_init( state256 *S )
{
  S->h[0] = 0x6a09e667;
  S->h[1] = 0xbb67ae85;
  S->h[2] = 0x3c6ef372;
  S->h[3] = 0xa54ff53a;
  S->h[4] = 0x510e527f;
  S->h[5] = 0x9b05688c;
  S->h[6] = 0x1f83d9ab;
  S->h[7] = 0x5be0cd19;
  S->t[0] = S->t[1] = S->buflen = S->nullt = 0;
  S->s[0] = S->s[1] = S->s[2] = S->s[3] = 0;
}


void blake256_update( state256 *S, const uint8_t *in, uint64_t inlen )
{
  int left = S->buflen;
  int fill = 64 - left;

  /* data left and data received fill a block  */
  if( left && ( inlen >= fill ) )
  {
    memcpy( ( void * ) ( S->buf + left ), ( void * ) in, fill );
    S->t[0] += 512;

    if ( S->t[0] == 0 ) S->t[1]++;

    blake256_compress( S, S->buf );
    in += fill;
    inlen  -= fill;
    left = 0;
  }

  /* compress blocks of data received */
  while( inlen >= 64 )
  {
    S->t[0] += 512;

    if ( S->t[0] == 0 ) S->t[1]++;

    blake256_compress( S, in );
    in += 64;
    inlen -= 64;
  }

  /* store any data left */
  if( inlen > 0 )
  {
    memcpy( ( void * ) ( S->buf + left ), ( void * ) in, ( size_t ) inlen );
    S->buflen = left + ( int )inlen;
  }
  else S->buflen = 0;
}


void blake256_final( state256 *S, uint8_t *out )
{
  uint8_t msglen[8], zo = 0x01, oo = 0x81;
  uint32_t lo = S->t[0] + ( S->buflen << 3 ), hi = S->t[1];

  /* support for hashing more than 2^32 bits */
  if ( lo < ( S->buflen << 3 ) ) hi++;

  U32TO8_BIG(  msglen + 0, hi );
  U32TO8_BIG(  msglen + 4, lo );

  if ( S->buflen == 55 )   /* one padding byte */
  {
    S->t[0] -= 8;
    blake256_update( S, &oo, 1 );
  }
  else
  {
    if ( S->buflen < 55 )   /* enough space to fill the block  */
    {
      if ( !S->buflen ) S->nullt = 1;

      S->t[0] -= 440 - ( S->buflen << 3 );
      blake256_update( S, padding, 55 - S->buflen );
    }
    else   /* need 2 compressions */
    {
      S->t[0] -= 512 - ( S->buflen << 3 );
      blake256_update( S, padding, 64 - S->buflen );
      S->t[0] -= 440;
      blake256_update( S, padding + 1, 55 );
      S->nullt = 1;
    }

    blake256_update( S, &zo, 1 );
    S->t[0] -= 8;
  }

  S->t[0] -= 64;
  blake256_update( S, msglen, 8 );
  U32TO8_BIG( out + 0, S->h[0] );
  U32TO8_BIG( out + 4, S->h[1] );
  U32TO8_BIG( out + 8, S->h[2] );
  U32TO8_BIG( out + 12, S->h[3] );
  U32TO8_BIG( out + 16, S->h[4] );
  U32TO8_BIG( out + 20, S->h[5] );
  U32TO8_BIG( out + 24, S->h[6] );
  U32TO8_BIG( out + 28, S->h[7] );
}


void blake256_hash( uint8_t *out, const uint8_t *in, uint64_t inlen )
{
  state256 S;
  blake256_init( &S );
  blake256_update( &S, in, inlen );
  blake256_final( &S, out );
}
