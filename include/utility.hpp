
#ifndef UTILITY_HPP
#define UTILITY_HPP

#include <algorithm>
#include <array>
#include <ostream>

/*
 * Word stores a 32 bit number b = b_3 b_2 b_1 b_0.
 */
struct Word
{
    Word() { }

    Word(unsigned char a3, unsigned char a2, unsigned char a1, unsigned char a0)
        : b3(a3), b2(a2), b1(a1), b0(a0)
    { }

    unsigned char &operator[](size_t i);
    const unsigned char &operator[](size_t i) const;

    unsigned char b3;
    unsigned char b2;
    unsigned char b1;
    unsigned char b0;
};

/*
 * Returns the bytewise XOR of lhs and rhs, i.e., for lhs = a_3 a_2 a_1 a_0 and
 * rhs = b_3 b_2 b_1 b_2, the Word (a3 XOR b3) (a2 XOR b2) ... (a0 XOR b0) is
 * returned. 
 */
Word operator^(const Word &lhs, const Word &rhs);

/*
 * Writes the Word <w> to <os> of the form b3 b2 b1 b0 in hex.
 */
std::ostream &operator<<(std::ostream &os, const Word &w);

class Block
{
public:
    Block()
    { }

    Block(const std::array<unsigned char, 16> &b)
        : block(b)
    { } 

    template <typename ForwardIter>
    Block(ForwardIter beg, ForwardIter end)
    {
        std::copy(beg, end, block.begin());
    }

    unsigned char &operator()(size_t i, size_t j) { return block[4*j + i]; }
    const unsigned char &operator()(size_t i, size_t j) const { return block[4*j + i]; } 
private:
    std::array<unsigned char, 16> block;
};

std::ostream &operator<<(std::ostream &os, const Block &b);
#endif
