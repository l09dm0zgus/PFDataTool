/*
 * aes256.hpp
 *
 * Copyright (c) 2014, Danilo Treffiletti <urban82@gmail.com>
 * Copyright (c) 2022 cx9ps3 cx9ps3@gmail.com
 * All rights reserved.
 *
 *     This file is part of Aes256.
 *
 *     Aes256 is free software: you can redistribute it and/or modify
 *     it under the terms of the GNU Lesser General Public License as
 *     published by the Free Software Foundation, either version 2.1
 *     of the License, or (at your option) any later version.
 *
 *     Aes256 is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *     GNU Lesser General Public License for more details.
 *
 *     You should have received a copy of the GNU Lesser General Public
 *     License along with Aes256.
 *     If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef AES256_H
#define AES256_H

#define BLOCK_SIZE 16
#include "IEncryptionAlgorithm.h"
namespace PFE
{
    namespace crypt
    {
        class AES256 : public IEncryptionAlgorithm
        {

            public:

                typ::ByteArray::size_type encrypt(const typ::ByteArray& key, const typ::ByteArray& plain, typ::ByteArray& encrypted) override;
                typ::ByteArray::size_type decrypt(const typ::ByteArray& key, const typ::ByteArray& encrypted, typ::ByteArray& plain) override;
                typ::ByteArray::size_type encrypt(const typ::ByteArray&& key, const typ::ByteArray& plain, typ::ByteArray& encrypted) override;
                typ::ByteArray::size_type decrypt(const typ::ByteArray&& key, const typ::ByteArray& encrypted, typ::ByteArray& plain) override;
            private:
                typ::ByteArray key;
                typ::ByteArray salt;
                typ::ByteArray rKey;

                typ::u8 buffer[3 * BLOCK_SIZE];
                typ::u8 bufferPosition{0};
                typ::ByteArray::size_type remainingLength{0};

                typ::ByteArray::size_type encryptStart(const typ::ByteArray::size_type plain_length, typ::ByteArray& encrypted);
                typ::ByteArray::size_type encryptContinue(const typ::ByteArray& plain, typ::ByteArray& encrypted);
                typ::ByteArray::size_type encryptEnd(typ::ByteArray& encrypted);

                typ::ByteArray::size_type decryptStart(const typ::ByteArray::size_type encrypted_length);
                typ::ByteArray::size_type decryptContinue(const typ::ByteArray& encrypted, typ::ByteArray& plain);
                typ::ByteArray::size_type decryptEnd(typ::ByteArray& plain);

                bool isDecryptInitialized{false};

                void assignVectors(const typ::ByteArray &key);

                void checkAndEncryptBuffer(typ::ByteArray& encrypted);
                void checkAndDecryptBuffer(typ::ByteArray& plain);

                void encrypt(typ::u8 *buffer);
                void decrypt(typ::u8 *buffer);

                void expandEncKey(typ::u8 *rc);
                void expandDecKey(typ::u8 *rc);

                void subBytes(typ::u8 *buffer);
                void subBytesInv(typ::u8 *buffer);

                void copyKey();

                void addRoundKey(typ::u8 *buffer, const typ::u8 round);

                void shiftRows(typ::u8 *buffer);
                void shiftRowsInv(typ::u8 *buffer);

                void mixColumns(typ::u8 *buffer);
                void mixColumnsInv(typ::u8 *buffer);
        };
    }
}


#endif // AES256_H
