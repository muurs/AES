#ifndef AES_HPP
#define AES_HPP

#include <array>
#include <vector>

std::array<unsigned char, 16> aes_encrypt_block(const std::array<unsigned char, 16> &input, const std::vector<unsigned char> &key, unsigned Nk);

void testA1();
void testA2();
void testA3();

void testB();

#endif
