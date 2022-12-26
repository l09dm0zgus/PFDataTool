#include "LZ4Algorithm.h"
#include <cstring>
#include "lz4.h"
#include <iterator>

PFE::typ::u32 PFE::arc::LZ4Algorithm::compress(const typ::ByteArray &dataToCompress, typ::ByteArray  &compressedData)
{
    typ::u32 compressedDataSize = 0;
    const typ::u32 dataToCompressSize = dataToCompress.size();
    const typ::u32 maximumSizeOfCompressedData = LZ4_compressBound(dataToCompressSize);
	char* buffer = new char[maximumSizeOfCompressedData];
    compressedDataSize = LZ4_compress_default((char*)&dataToCompress[0], buffer, dataToCompressSize, maximumSizeOfCompressedData);
	if (compressedDataSize <= 0)
	{
		throw "Failed to compress file!";
		return compressedDataSize;
	}
	std::copy(&buffer[0], &buffer[compressedDataSize], std::back_inserter(compressedData));
	delete[] buffer;
	return compressedDataSize;
}

PFE::typ::u32 PFE::arc::LZ4Algorithm::decompress(typ::u32 originalDataSize,const typ::ByteArray& dataToDecompress, typ::ByteArray& decompressedData)
{
    typ::u32 decompressedDataSize = 0;
    const typ::u32 compressedDataSize = dataToDecompress.size();
    char* buffer = new char[originalDataSize];
    decompressedDataSize = LZ4_decompress_safe((char*)&dataToDecompress[0], buffer, compressedDataSize, originalDataSize);
    if (decompressedDataSize < 0)
    {
        throw "Failed to decompress file!";
        return decompressedDataSize;
    }
    if (decompressedDataSize != originalDataSize)
    {
        throw "Decompressed data is different from original!\n";
        return decompressedDataSize;
    }
    std::copy(&buffer[0], &buffer[decompressedDataSize], std::back_inserter(decompressedData));
    delete[] buffer;
    return decompressedDataSize;
}
