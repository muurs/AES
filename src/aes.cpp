#include <array>
#include <cassert>
#include <iostream>
#include <vector>
#include "aes.hpp"
#include "utility.hpp"

using std::cout;

void print(const std::array<unsigned char, 16> &arr)
{
    cout << std::hex;
    for ( size_t i = 0; i < 4; ++i )
    {
        for ( size_t j = 0; j < 4; ++j )
        {
            unsigned x = arr[4*i + j];
            if ( x <= 0xf )
                cout << "0";
            cout << x << " ";
        }
        cout << "\n";
    }
    cout << std::dec;
}

// AES S-Box (see Figure 7, FIPS 197)
static const unsigned char s[16][16] = 
{
   {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
   {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
   {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
   {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
   {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
   {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
   {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
   {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
   {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
   {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
   {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
   {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
   {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
   {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
   {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
   {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}
};

void add_round_key(Block &state, const Block &rk)
{
    for ( size_t i = 0; i < 4; ++i )
    {
        for ( size_t j = 0; j < 4; ++j )
        {
            state(i,j) = state(i,j) ^ rk(i,j); 
        }
    }
}


template <typename RandIter>
Block to_block(RandIter beg, RandIter end)
{
    Block b;
    for ( size_t i = 0; i < 4; ++i )
    {
       for ( size_t j = 0; j < 4; ++j )
       {
            b(j,i) = beg[i][3-j];
       } 
    }

    return b;
}

void sub_bytes(Block &state)
{
    for ( size_t i = 0; i < 4; ++i )
    {
        for ( size_t j = 0; j < 4; ++j )
        {
            unsigned r = state(i,j) >> 4;
            unsigned c = state(i,j) & 0x0f;
            state(i,j) = s[r][c];
        }
    }
}

/*
 * Implementation of xtime() (see Section 4.2.1, FIPS 197)
 */
static unsigned char xtime(unsigned char x)
{
    return (x << 1) ^ ((x & 0x80) ? 0x1B : 0x00);
}



void shift_rows(Block &state)
{
    unsigned char tmp;
    
    // Shift row 1
    tmp = state(1,0);
    state(1, 0) = state(1, 1);
    state(1, 1) = state(1, 2);
    state(1, 2) = state(1, 3);
    state(1, 3) = tmp;

    // Shift row 2
    // todo: fix error here
    tmp = state(2, 0);
    state(2, 0) = state(2, 2);
    state(2, 2) = tmp;
    tmp = state(2, 1);
    state(2, 1) = state(2, 3);
    state(2, 3) = tmp;

    // Shift row 3
    tmp = state(3, 3);
    state(3, 3) = state(3, 2);
    state(3, 2) = state(3, 1);
    state(3, 1) = state(3, 0);
    state(3, 0) = tmp;
}

void mix_columns(Block &state)
{
    Block ss(state);
    for ( unsigned c = 0; c < 4; ++c )
    {
        state(0, c) = xtime(ss(0,c)) ^ ss(1,c) ^ xtime(ss(1,c)) ^ ss(2,c) ^ ss(3,c);
        state(1, c) = ss(0,c) ^ xtime(ss(1,c)) ^ ss(2,c) ^ xtime(ss(2,c)) ^ ss(3,c);
        state(2, c) = ss(0,c) ^ ss(1,c) ^ xtime(ss(2,c)) ^ ss(3,c) ^ xtime(ss(3,c));
        state(3, c) = ss(0,c) ^ xtime(ss(0,c)) ^ ss(1,c) ^ ss(2,c) ^ xtime(ss(3,c));
    }
}

std::array<unsigned char, 16> aes_cipher(const std::array<unsigned char, 16> &in, const std::vector<Word> &w, unsigned Nb,
                                         unsigned Nr)
{
    Block state(in);
    Block round_key = to_block(w.cbegin(), w.cbegin() + Nb);

    add_round_key(state, round_key);

    for ( unsigned round = 1; round < Nr; ++round )
    {
       sub_bytes(state);
       shift_rows(state);
       mix_columns(state);
       round_key = to_block(w.cbegin() + round * Nb, w.cbegin() + (round + 1) * Nb);
       add_round_key(state, round_key);
    }

    sub_bytes(state);
    shift_rows(state);
    round_key = to_block(w.cbegin() + Nr * Nb, w.cbegin() + (Nr+1) * Nb);
    add_round_key(state, round_key);

    cout << "\nOutput:\n";
    cout << state << "\n";

    std::array<unsigned char, 16> output; 
    for ( size_t i = 0; i < 4; ++i )
        for ( size_t j = 0; j < 4; ++j )
            output[4*j + i] = state(i,j);
    return output;
}

/*
 * Implemention of RotWord() (see Section 5.2, FIPS 197)
 */
static Word rot_word(const Word &w)
{
    return { w.b2, w.b1, w.b0, w.b3 };
}

/*
 * Implements SubWord() (see Section 5.1.1 and Fig. 7, FIPS 197)
 */
static Word sub_word(const Word &w)
{
    Word res;
    for ( size_t i = 0; i < 4; ++i )
    {
        unsigned r = w[i] >> 4;
        unsigned c = w[i] & 0x0f;
        res[i] = s[r][c];
    }

    return res;   
}

/*
 * Computes Rcon[i] (see Section 5.2, FIPS 197)
 */
static Word round_con(unsigned i)
{
    Word rcon(1, 0, 0, 0);
    for ( size_t k = 0; k < i; ++k )
        rcon.b3 = xtime(rcon.b3);

    return rcon;
}

/*
 * Implements Key Expansion (see Section 5.2 and Figure 11, FIPS 197)
 */
static std::vector<Word> key_expansion(const std::vector<unsigned char> &k, unsigned Nb, unsigned Nk, unsigned Nr)
{
    std::vector<Word> w(Nb * (Nr + 1));

    unsigned i = 0;
    for ( i = 0; i < Nk; ++i )
        w[i] = Word( k[4*i], k[4*i+1], k[4*i+2], k[4*i+3] );

    Word rcon(1, 0, 0, 0);
    for ( ; i < Nb * (Nr + 1); ++i )
    {
        Word tmp = w[i-1];    
        if ( i % Nk == 0 )
            tmp = sub_word(rot_word(tmp)) ^ rcon; 
        else if ( Nk > 6 && i % Nk == 4 )
            tmp = sub_word(tmp);

        w[i] = w[i-Nk] ^ tmp;
        rcon = round_con(i / Nk);
    }

    return w;
}

std::array<unsigned char, 16> aes_encrypt_block(const std::array<unsigned char, 16> &input, const std::vector<unsigned char> &key, unsigned Nk)
{
    unsigned Nr;
    if ( Nk == 4 )
        Nr = 10;
    else if ( Nk == 6 )
        Nr = 12;
    else
        Nr = 14;

    const unsigned Nb = 4;
    auto key_expanded = key_expansion(key, Nb, Nk, Nr);
    return aes_cipher(input, key_expanded, Nb, Nr); 
}

void test_cipher()
{
    std::array<unsigned char, 16> input { 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 };
    std::vector<unsigned char> key { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };

    const unsigned Nb = 4;
    const unsigned Nk = 4;
    const unsigned Nr = 10;
    auto key_expanded = key_expansion(key, Nb, Nk, Nr);

    std::array<unsigned char, 16> output = aes_cipher(input, key_expanded, Nb, Nr);
    cout << std::hex;
    for ( auto i : output )
        cout << (unsigned) i << " ";
    cout << std::dec << "\n";
}

void testC1()
{

}

void testA1() 
{
    const std::vector<unsigned char> k { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
                                         0x09, 0xcf, 0x4f, 0x3c };
    const unsigned Nb = 4;
    const unsigned Nk = 4;
    const unsigned Nr = 10;

    auto k_exp = key_expansion(k, Nb, Nk, Nr);
    for ( auto w : k_exp )
        cout << w << "\n";
}

void testA2()
{
    const std::vector<unsigned char> k { 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b,
                                         0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b };
    const unsigned Nb = 4;
    const unsigned Nk = 6;
    const unsigned Nr = 12;

    auto k_exp = key_expansion(k, Nb, Nk, Nr);
    for ( auto w : k_exp )
        cout << w << "\n"; 
}

void testA3()
{
    const std::vector<unsigned char> k { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                                         0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};    
    const unsigned Nb = 4;
    const unsigned Nk = 8; 
    const unsigned Nr = 14;

    auto k_exp = key_expansion(k, Nb, Nk, Nr);
    for ( auto w : k_exp )
        cout << w << "\n"; 
}
