//! @file aes.h
//! @brief This is an implementation of the AES128 algorithm, specifically ECB and CBC mode.
//! @details
//! The implementation is verified against the test vectors in:
//!     National Institute of Standards and Technology Special Publication 800-38A 2001 ED
//! 
//! ECB-AES128
//! ----------
//! 
//!     plain-text:
//!         6bc1bee22e409f96e93d7e117393172a
//!         ae2d8a571e03ac9c9eb76fac45af8e51
//!         30c81c46a35ce411e5fbc1191a0a52ef
//!         f69f2445df4f9b17ad2b417be66c3710
//! 
//!     key:
//!         2b7e151628aed2a6abf7158809cf4f3c
//! 
//!     resulting cipher
//!         3ad77bb40d7a3660a89ecaf32466ef97 
//!         f5d3d58503b9699de785895a96fdbaaf 
//!         43b1cd7f598ece23881b00e3ed030688 
//!         7b0c785e27e8ad3f8223207104725dd4 
//! 
//! 
//! @note     String length must be evenly divisible by 16byte (str_len % 16 == 0)
//!                 You should pad the end of the string with zeros if this is not the case.
#ifndef AES_H
#define AES_H

#include <stdint.h>


// #define the macros below to 1/0 to enable/disable the mode of operation.
//
// CBC enables AES128 encryption in CBC-mode of operation and handles 0-padding.
// ECB enables the basic ECB 16-byte block algorithm. Both can be enabled simultaneously.

// The #ifndef-guard allows it to be configured before #include'ing or at compile time.
#ifndef CBC
#define CBC 1
#endif

#ifndef ECB
#define ECB 1
#endif



#if defined(ECB) && ECB

void AES128_ECB_encrypt(uint8_t* input, const uint8_t* key, uint8_t* output);
void AES128_ECB_decrypt(uint8_t* input, const uint8_t* key, uint8_t* output);

#endif // #if defined(ECB) && ECB


#if defined(CBC) && CBC

void AES128_CBC_encrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length, const uint8_t* key, const uint8_t* iv);
void AES128_CBC_decrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length, const uint8_t* key, const uint8_t* iv);

#endif // #if defined(CBC) && CBC



#endif
