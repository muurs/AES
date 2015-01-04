#ifndef AES_HPP
#define AES_HPP

#include <ostream>
#include <vector>

struct Word
{
    Word() { }

    Word(unsigned char a3, unsigned char a2, unsigned char a1, unsigned char a0)
        : b3(a3), b2(a2), b1(a1), b0(a0)
    { }

    unsigned char b3;
    unsigned char b2;
    unsigned char b1;
    unsigned char b0;
};

Word operator^(const Word &lhs, const Word &rhs);

std::ostream &operator<<(std::ostream &os, const Word &w);

void test();

#endif
