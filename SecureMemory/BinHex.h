#pragma once

typedef unsigned char byte;

class BinHex
{
public:
	static void BinToHex(const byte * ibuf, size_t ibufsz, char * obuf, size_t obufsz);

private:
	BinHex();
	~BinHex();
};

