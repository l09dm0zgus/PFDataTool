#include "NoCompression.h"

PFE::typ::u32 PFE::arc::NoCompression::compress(const typ::ByteArray &dataToCompress, typ::ByteArray &compressedData)
{
    compressedData.assign(dataToCompress.begin(),dataToCompress.end());
    return compressedData.size();
}

PFE::typ::u32 PFE::arc::NoCompression::decompress(typ::u32 originalDataSize, const typ::ByteArray &dataToDecompress, typ::ByteArray &decompressedData)
{
    decompressedData.assign(dataToDecompress.begin(),dataToDecompress.end());
    return decompressedData.size();
}
