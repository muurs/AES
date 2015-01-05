#include <cassert>
#include "utility.hpp"

unsigned char &Word::operator[](size_t i)
{
    assert( 0 <= i && i < 4 );
    switch ( i )
    {
    case 0: return b0;
    case 1: return b1;
    case 2: return b2;
    case 3: return b3;
    default: assert( false );
    }    
}

const unsigned char &Word::operator[](size_t i) const
{
    assert( 0 <= i && i < 4 );
    switch ( i )
    {
    case 0: return b0;
    case 1: return b1;
    case 2: return b2;
    case 3: return b3;
    default: assert( false );
    } 
}

Word operator^(const Word &lhs, const Word &rhs)
{
    return Word(lhs.b3 ^ rhs.b3, lhs.b2 ^ rhs.b2 , lhs.b1 ^ rhs.b1, lhs.b0 ^ rhs.b0);
}

std::ostream &operator<<(std::ostream &os, const Word &w)
{
    os << std::hex;
    for ( size_t i = 4; i > 0 ; --i )
    {
        if ( w[i-1] <= 0xf )
            os << "0";
        os << (unsigned) w[i-1] << ' ';
    }
    return os << std::dec;
}


std::ostream &operator<<(std::ostream &os, const Block &b)
{
    os << std::hex;
    for ( size_t i = 0; i < 4; ++i )
    {
        for ( size_t j = 0; j < 4; ++j )
        {
            os << (unsigned )b(i,j) << " ";
        }
        os << "\n";
    }
    return os << std::dec;
}
