#include "pch.h"
#include "BinHex.h"
#include "SecureMemory.h"

#include <cassert>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#ifdef _WINDOWS_
//#define USE_DPAPI
#include <dpapi.h>
#include <memoryapi.h>
#endif

static const size_t KEY_SIZE_BITS = 256;
static const size_t IV_SIZE_BITS = 128;

static const size_t KEY_SIZE_BYTES = KEY_SIZE_BITS / 8;
static const size_t IV_SIZE_BYTES = IV_SIZE_BITS / 8;

#ifdef USE_DPAPI
static const int SECUREMEMORY_BLOCK_SIZE = CRYPTPROTECTMEMORY_BLOCK_SIZE;
#else
static const EVP_CIPHER * SECUREMEMORY_CIPHER = EVP_aes_256_cbc();
static const int SECUREMEMORY_BLOCK_SIZE = EVP_CIPHER_block_size(SECUREMEMORY_CIPHER);
#endif
static const int SECUREMEMORY_MAX_BLOCKS = INT_MAX / SECUREMEMORY_BLOCK_SIZE;

SecureMemory::SecureMemory(std::unique_ptr<byte[]> plaintextData, const int plaintextDataLen) : mKey(nullptr), mPlaintextLength(plaintextDataLen), mDataSize(0), mProtected(false)
{
	mData = CryptoAlign(plaintextData.release(), plaintextDataLen, &mDataSize);
	plaintextData = nullptr;

#ifdef _WINDOWS_
	VirtualLock(mData, mDataSize);
#else
	mlock(mData, mDataSize);
#endif

	Init();
}

void SecureMemory::Init()
{
#ifndef USE_DPAPI
	std::cout << "Generating new key for memory data encryption.\n";
	mKey = OPENSSL_malloc(KEY_SIZE_BYTES);
	mIV = OPENSSL_malloc(IV_SIZE_BYTES);
#ifdef LINUX
	mlock(mKey, KEY_SIZE_BYTES);
	mlock(mIV, IV_SIZE_BYTES);
#else
	VirtualLock(mKey, KEY_SIZE_BYTES);
	VirtualLock(mIV, IV_SIZE_BYTES);
#endif
	RAND_bytes((byte *)mKey, KEY_SIZE_BYTES);
	RAND_bytes((byte *)mIV, IV_SIZE_BYTES);

	const size_t keyHexLen = KEY_SIZE_BYTES * 2 + 1;
	char keyHexBuf[keyHexLen];
	BinHex::BinToHex((byte *)mKey, KEY_SIZE_BYTES, keyHexBuf, keyHexLen);
	std::cout << "Key: " << keyHexBuf << std::endl;
	const size_t ivHexLen = IV_SIZE_BYTES * 2 + 1;
	char ivHexBuf[ivHexLen];
	BinHex::BinToHex((byte *)mKey, IV_SIZE_BYTES, ivHexBuf, ivHexLen);
	std::cout << "IV: " << ivHexBuf << std::endl;
#endif
}

SecureMemory::~SecureMemory()
{
	if (mKey)
	{
		OPENSSL_cleanse(mKey, KEY_SIZE_BYTES);
		OPENSSL_free(mKey);
	}
	if (mData)
	{
		Protect();
		Zeroize();
		mData = nullptr;
	}
}

void SecureMemory::Zeroize()
{
#ifdef _WINDOWS_
	SecureZeroMemory(mData, (DWORD)mDataSize);
#else
	OPENSSL_cleanse(mData.get(), mDataSize);
#endif
}

void SecureMemory::Zeroize(byte * buf, size_t bufsz)
{
#ifdef _WINDOWS_
	SecureZeroMemory(buf, (DWORD)bufsz);
#else
	OPENSSL_cleanse(buf, bufsz);
#endif
}

int GetCryptoBlockAlignedSize(size_t inMinSize)
{
	size_t numBlocks = (inMinSize / SECUREMEMORY_BLOCK_SIZE);
	if (inMinSize >= numBlocks * SECUREMEMORY_BLOCK_SIZE)
	{
		numBlocks++;
	}
	if (numBlocks > SECUREMEMORY_MAX_BLOCKS)
	{
		// TODO: report error
		numBlocks = SECUREMEMORY_MAX_BLOCKS;
	}
	return (int)numBlocks * SECUREMEMORY_BLOCK_SIZE;
}

byte * SecureMemory::CryptoNew(int inMinSize, int * outSize)
{
	byte * newBuf = nullptr;

	if (inMinSize > 0)
	{
		*outSize = GetCryptoBlockAlignedSize(inMinSize);

		if ((newBuf = (byte *)OPENSSL_malloc(*outSize)) == nullptr)
		{
			*outSize = 0;
			//handleErrors();
		}
		else
		{
			memset(newBuf, 0, *outSize);
		}
	}

	return newBuf;
}

byte * SecureMemory::CryptoAlign(byte * inBuf, int inSize, int * outSize)
{
	byte * newBuf = nullptr;

	if (inBuf && inSize > 0)
	{
		*outSize = GetCryptoBlockAlignedSize(inSize);

		if ((newBuf = (byte *)OPENSSL_realloc_clean(inBuf, inSize, *outSize)) == nullptr)
		{
			*outSize = 0;
			//handleErrors();
		}
		else
		{
			if (*outSize > inSize)
			{
				memset((newBuf + inSize), 0, *outSize - inSize);
			}
		}
	}

	return newBuf;
}

void handleErrors(void)
{
	ERR_print_errors_fp(stderr);
	abort();
}

void SecureMemory::Protect()
{
	if (mData && !mProtected)
	{
#ifdef USE_DPAPI
		if (!CryptProtectMemory((LPVOID *)mData, (DWORD)mDataSize, CRYPTPROTECTMEMORY_SAME_PROCESS))
		{
			wprintf(L"CryptProtectMemory failed: %d\n", GetLastError());
			Zeroize();
			mData = nullptr;
			return;
		}
#else
		EVP_CIPHER_CTX *ctx;

		if (!(ctx = EVP_CIPHER_CTX_new()))
		{
			Zeroize();
			handleErrors();
		}

		// Use counter mode so encrypted length is same as plain length.
		if (1 != EVP_EncryptInit_ex(ctx, SECUREMEMORY_CIPHER, NULL, (byte *)mKey, (byte *)mIV))
		{
			Zeroize();
			handleErrors();
		}

		int len;
		int ciphertext_len;
		byte * ciphertext = (byte *)OPENSSL_malloc(mDataSize);
		if (!ciphertext)
		{
			Zeroize();
			handleErrors();
		}
		memset(ciphertext, 0, mDataSize);

		if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, mData, mPlaintextLength))
		{
			Zeroize();
			handleErrors();
		}
		ciphertext_len = len;

		if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
		{
			Zeroize();
			handleErrors();
		}
		ciphertext_len += len;

		memcpy(mData, ciphertext, mDataSize);
		Zeroize(ciphertext, ciphertext_len);
		OPENSSL_free(ciphertext);

		/* Clean up */
		EVP_CIPHER_CTX_free(ctx);
#endif
		mProtected = true;
	}
}

void SecureMemory::UnProtect()
{
	if (mData && mProtected)
	{
#ifdef USE_DPAPI
		if (!CryptUnprotectMemory((LPVOID *)mData, (DWORD)mDataSize, CRYPTPROTECTMEMORY_SAME_PROCESS))
		{
			wprintf(L"CryptUnprotectMemory failed: %d\n", GetLastError());
			Zeroize();
			mData = nullptr;
			return;
		}
#else
		EVP_CIPHER_CTX *ctx;

		if (!(ctx = EVP_CIPHER_CTX_new()))
		{
			Zeroize();
			handleErrors();
		}

		// Use counter mode so decrypted length is same as ciphertext length.
		if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (byte *)mKey, (byte *)mIV))
		{
			Zeroize();
			handleErrors();
		}

		int len;
		int plaintext_len;
		byte * plaintext = (byte *)OPENSSL_malloc(mDataSize);
		if (!plaintext)
		{
			Zeroize();
			handleErrors();
		}
		memset(plaintext, 0, mDataSize);

		if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, mData, mDataSize))
		{
			Zeroize();
			handleErrors();
		}
		plaintext_len = len;

		if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
		{
			Zeroize();
			handleErrors();
		}
		plaintext_len += len;

		memcpy(mData, plaintext, mDataSize);
		Zeroize(plaintext, plaintext_len);
		OPENSSL_free(plaintext);

		/* Clean up */
		EVP_CIPHER_CTX_free(ctx);
#endif
		mProtected = false;
	}
}
