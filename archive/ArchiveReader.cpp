#include "ArchiveReader.h"
#include <algorithm>
#include <filesystem>
#include <iterator>

PFE::arc::ArchiveReader::ArchiveReader(const std::string &path ,const std::string &password):path(path),password(password)
{
    archiveFile.exceptions(std::fstream::badbit);
    try
    {
         archiveFile.open(path,std::ios::in | std::ios::binary);
    }
    catch (const std::ifstream::failure& exception)
    {
        std::cout << "Error: Failed to open " << path << ".What:" << exception.what() << std::endl;
        exit(-1488);
    }
    readHeader();
    readTableHeader();
    readFileEntrys();
    setCompressAlgorithm();
    setEncryptAlgorithm();
    std::cout << "Password entered :" << password << "\n";
    checkPasswordWithHash();

}

PFE::arc::ArchiveReader::~ArchiveReader()
{
    delete compressionAlgorithm;
    compressionAlgorithm = nullptr;

    delete encryptionAlgorithm;
    encryptionAlgorithm = nullptr;
}

PFE::typ::ByteArray PFE::arc::ArchiveReader::getFile(const std::string &path)
{
    std::cout << "Searching " << path << " in archive...\n";
    auto result = std::find_if(fileEntrys.begin(),fileEntrys.end(),[&path](const PFPackFileEntry &fileEntry){
        std::string p(fileEntry.pathToFile);
        return p == path;
    });
    if(result != fileEntrys.end())
    {
        return  decryptFile(decompressFile(result->size,getFile(*result)));
    }
    else
    {
        std::cout << "File with path : "<< path << " does not exist in archive!" << std::endl;
        exit(-1488);
    }
}

void PFE::arc::ArchiveReader::readHeader()
{
    std::cout << "Reading file header...\n";
    archiveFile.read((char *)&header,sizeof(header));
    std::cout << header;
}

void PFE::arc::ArchiveReader::readTableHeader()
{
    std::cout << "Reading table header...\n";
    archiveFile.read((char *)&tableHeader,sizeof(tableHeader));
    std::cout << tableHeader;
}

void PFE::arc::ArchiveReader::readFileEntrys()
{
    std::cout << "Reading file entrys...\n";
    fileEntrys.reserve(tableHeader.numberOfFiles);
    for(typ::u32 i = 0;i<tableHeader.numberOfFiles;i++)
    {
        fileEntrys.push_back(readFileEntry());
    }
}

PFE::arc::PFPackFileEntry PFE::arc::ArchiveReader::readFileEntry()
{
    PFPackFileEntry fileEntry;
    archiveFile.read((char *)&fileEntry,sizeof(fileEntry));
    std::cout << fileEntry;
    return fileEntry;
}

void PFE::arc::ArchiveReader::setCompressAlgorithm()
{
    switch (header.compression)
    {
    case NO_COMPRESSION:
        compressionAlgorithm = new NoCompression();
        break;
    case LZ4:
        compressionAlgorithm = new LZ4Algorithm();
        break;
    default:
        compressionAlgorithm = nullptr;
        break;
    }
}

void PFE::arc::ArchiveReader::setEncryptAlgorithm()
{
    switch (header.encryption)
    {
    case NO_ENCRYPTION:
        encryptionAlgorithm = new crypt::NoEncryption();
        break;
    case AES256:
        encryptionAlgorithm = new crypt::AES256();
        break;
    default:
        encryptionAlgorithm = nullptr;
        break;
    }
}

PFE::typ::ByteArray PFE::arc::ArchiveReader::getFile(const PFPackFileEntry &fileEntry)
{
    std::cout << "Getting " << fileEntry.pathToFile << " from archive...\n";
    char compressedFileData[fileEntry.compressedSize];
    archiveFile.seekg(0,std::ios::beg);
    archiveFile.seekg(fileEntry.offset,std::ios::beg);
    archiveFile.read(compressedFileData,fileEntry.compressedSize);
    typ::ByteArray compressedFileDataInVector(compressedFileData,compressedFileData + sizeof(compressedFileData)/sizeof(compressedFileData[0]));
    return compressedFileDataInVector;
}

void PFE::arc::ArchiveReader::extractAllFiles(const std::string &pathToExtract)
{
   for(auto fileEntry : fileEntrys)
   {
       std::string path(fileEntry.pathToFile);
       std::cout << "Extracting file : " << path << "\n";
       std::string pathToExtractedFile = pathToExtract + "/" + getFolder(path);
       std::filesystem::create_directories(pathToExtractedFile);
       writeExtractedFile(path,pathToExtract);
   }

}

std::string PFE::arc::ArchiveReader::getFolder(const std::string &path)
{
    typ::u32 found{0};
    found = path.find_last_of("/");
    return path.substr(0,found);
}

std::string PFE::arc::ArchiveReader::getFileName(const std::string &path)
{
    typ::u32 found{0};
    found = path.find_last_of("/");
    return path.substr(found+1);
}

void PFE::arc::ArchiveReader::writeExtractedFile(const std::string &filePathInEntry, const std::string &pathToExctractedFile)
{
    std::fstream exctractedFile;
    exctractedFile.exceptions(std::fstream::badbit);
    try
    {
        exctractedFile.open(pathToExctractedFile + "/" + filePathInEntry,std::ios::out | std::ios::binary);
        typ::ByteArray bytes = getFile(filePathInEntry);
        exctractedFile.write((char*)bytes.data(),bytes.size());
    }
    catch (const std::ifstream::failure& exception)
    {
        std::cout << "Error: Failed to open  " << pathToExctractedFile + "/" +  filePathInEntry << ".What:" << exception.what() << std::endl;
        exit(-1488);
    }

}

PFE::typ::ByteArray PFE::arc::ArchiveReader::decompressFile(typ::u32 size, const typ::ByteArray &compressedFileData)
{
    std::cout << "Decompressing file data...\n";
    typ::ByteArray decompressedFileData;
    try
    {
        compressionAlgorithm->decompress(size, compressedFileData, decompressedFileData);
    }
    catch (const char* exception)
    {
        std::cout << "Error: " << exception << "\n";
        exit(-1488);
    }
    return decompressedFileData;
}

PFE::typ::ByteArray PFE::arc::ArchiveReader::decryptFile(const typ::ByteArray &encryptedFileData)
{
    std::cout << "Decrypting file data...\n";
    typ::ByteArray decryptedFileData;
    encryptionAlgorithm->decrypt(typ::ByteArray(password.begin(),password.end()),encryptedFileData,decryptedFileData);
    return decryptedFileData;
}

void PFE::arc::ArchiveReader::checkPasswordWithHash()
{
    if(header.passwordHash != crypt::hashString(password) && header.passwordHash != 0)
    {
        std::cout << "Wrong or empty password! Hash: "<< crypt::hashString(password) << std::endl;
        exit(-1488);
    }
}

