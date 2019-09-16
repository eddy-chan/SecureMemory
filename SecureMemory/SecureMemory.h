#pragma once

#include "BinHex.h"

#include <memory>

class SecureMemory
{
public:
	SecureMemory(std::unique_ptr<byte[]>  plaintextData, int plaintextDataLen);
	~SecureMemory();

	void Protect();
	void UnProtect();
	void Zeroize();

	byte * GetData()
	{
		return mData;
	}

	const size_t GetSize() const
	{
		return mDataSize;
	}

	const size_t GetLength() const
	{
		return mPlaintextLength;
	}

public:
	static void Zeroize(byte * buf, size_t bufsz);
	static byte * CryptoNew(int inMinSize, int * outSize);
	static byte * CryptoAlign(byte * inBuf, int inSize, int * outSize);

private:
	void * mKey;
	void * mIV;
	byte * mData;
	const int mPlaintextLength;
	int mDataSize;
	bool mProtected;

private:
	SecureMemory(const SecureMemory & rhs);
	SecureMemory& operator=(const SecureMemory & rhs) { return *this; }
	void Init();
};

