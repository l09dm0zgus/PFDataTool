#include "NoEncryption.h"


PFE::typ::ByteArray::size_type PFE::crypt::NoEncryption::encrypt(const typ::ByteArray &key, const typ::ByteArray &plain, typ::ByteArray &encrypted)
{
    encrypted.assign(plain.begin(),plain.end());
    return encrypted.size();
}

PFE::typ::ByteArray::size_type PFE::crypt::NoEncryption::decrypt(const typ::ByteArray &key, const typ::ByteArray &encrypted, typ::ByteArray &plain)
{
    plain.assign(encrypted.begin(),encrypted.end());
    return plain.size();
}

PFE::typ::ByteArray::size_type PFE::crypt::NoEncryption::encrypt(const typ::ByteArray &&key, const typ::ByteArray &plain, typ::ByteArray &encrypted)
{
    encrypted.assign(plain.begin(),plain.end());
    return encrypted.size();
}

PFE::typ::ByteArray::size_type PFE::crypt::NoEncryption::decrypt(const typ::ByteArray &&key, const typ::ByteArray &encrypted, typ::ByteArray &plain)
{
    plain.assign(encrypted.begin(),encrypted.end());
    return plain.size();
}
