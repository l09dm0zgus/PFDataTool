#ifndef NOENCRYPTION_H
#define NOENCRYPTION_H
#include "IEncryptionAlgorithm.h"

namespace PFE
{
    namespace crypt
    {
        class NoEncryption : public IEncryptionAlgorithm
        {
            public:
            typ::ByteArray::size_type encrypt(const typ::ByteArray& key, const typ::ByteArray& plain, typ::ByteArray& encrypted) override;
            typ::ByteArray::size_type decrypt(const typ::ByteArray& key, const typ::ByteArray& encrypted, typ::ByteArray& plain) override;
            typ::ByteArray::size_type encrypt(const typ::ByteArray&& key, const typ::ByteArray& plain, typ::ByteArray& encrypted) override;
            typ::ByteArray::size_type decrypt(const typ::ByteArray&& key, const typ::ByteArray& encrypted, typ::ByteArray& plain) override;
        };

    }
}

#endif // NOENCRYPTION_H
