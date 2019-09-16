#include "pch.h"
#include "BinHex.h"

#include <memory>

void BinHex::BinToHex(const byte * ibuf, size_t ibufsz, char * obuf, size_t obufsz)
{
	if (obuf)
	{
		memset(obuf, 0, obufsz);
		if (ibuf)
		{
			for (auto i = 0; i < ibufsz; i++)
			{
				char hex[3];
				memset(hex, 0, sizeof(hex));
				snprintf(hex, sizeof(hex), "%02X", ibuf[i]);

				auto o = i * 2;
				if (o < obufsz - 1)
				{
					obuf[o] = hex[0];
				}
				else
				{
					break;
				}
				o++;
				if (o < obufsz - 1)
				{
					obuf[o] = hex[1];
				}
				else
				{
					break;
				}
			}
		}
	}
}

BinHex::BinHex()
{
}


BinHex::~BinHex()
{
}
