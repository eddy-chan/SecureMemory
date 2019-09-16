

#include "pch.h"
#include <iostream>
#include <memory>

#include <openssl/engine.h>
#include "BinHex.h"
#include "SecureMemory.h"

int main()
{
	std::cout << "Loading RDRAND engine.\n";
	ENGINE *engine;

	ENGINE_load_rdrand();

	engine = ENGINE_by_id("rdrand");
	if (engine == NULL) {
		fprintf(stderr, "ENGINE_load_rdrand returned %lu\n", ERR_get_error());
		exit(1);
	}
	if (!ENGINE_init(engine)) {
		fprintf(stderr, "ENGINE_init returned %lu\n", ERR_get_error());
		exit(1);

	}

	if (!ENGINE_set_default(engine, ENGINE_METHOD_RAND)) {
		fprintf(stderr, "ENGINE_set_default returned %lu\n", ERR_get_error());
		exit(1);
	}


	const char secret[] = "Soylent Green Is People!";
	int secretLen = (int)strlen(secret);
	byte * pData = (byte *)OPENSSL_malloc(secretLen);
	memcpy(pData, secret, secretLen);
	SecureMemory::Zeroize((byte *)secret, secretLen);

	std::unique_ptr<byte []> bufptr = std::unique_ptr<byte []>(pData);
	SecureMemory * mem = new SecureMemory(std::move(bufptr), secretLen);

	mem->Protect();
	mem->UnProtect();
	mem->Protect();

	std::cout << "Hello World!\n";

	delete mem;

	std::cout << "Cleaning up crypto engine.\n";
	ENGINE_finish(engine);
	ENGINE_free(engine);
	ENGINE_cleanup();

}
