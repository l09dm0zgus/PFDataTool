#ifndef IENCRYPTIONALGORITHM_H
#define IENCRYPTIONALGORITHM_H
#include "types/Types.h"
namespace PFE
{
    namespace crypt
    {
        class IEncryptionAlgorithm
        {
            public:
                virtual ~IEncryptionAlgorithm(){};
                virtual typ::ByteArray::size_type encrypt(const typ::ByteArray& key, const typ::ByteArray& plain, typ::ByteArray& encrypted) = 0;
                virtual typ::ByteArray::size_type decrypt(const typ::ByteArray& key, const typ::ByteArray& encrypted, typ::ByteArray& plain) = 0;
                virtual typ::ByteArray::size_type encrypt(const typ::ByteArray&& key, const typ::ByteArray& plain, typ::ByteArray& encrypted) = 0;
                virtual typ::ByteArray::size_type decrypt(const typ::ByteArray&& key, const typ::ByteArray& encrypted, typ::ByteArray& plain) = 0;
        };
    }
}

#endif // IENCRYPTIONALGORITHM_H
