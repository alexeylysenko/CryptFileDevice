#include "cryptfiledevice.h"

#include <openssl/err.h>
#include <openssl/aes.h>

#include <QFileDevice>
#include <QFile>

#include <QCryptographicHash>

static int const kHeaderLength = 128;

CryptFileDevice::CryptFileDevice(QObject *parent) :
    QIODevice(parent)
{
}

CryptFileDevice::CryptFileDevice(QFileDevice *device, QObject *parent) :
    QIODevice(parent),
    m_device(device),
    m_deviceOwner(false)
{
}

CryptFileDevice::CryptFileDevice(QFileDevice *device,
                                 const QByteArray &password,
                                 const QByteArray &salt,
                                 QObject *parent) :
    QIODevice(parent),
    m_device(device),
    m_deviceOwner(false),
    m_password(password),
    m_salt(salt.mid(0, 8))
{
}

CryptFileDevice::CryptFileDevice(const QString &fileName,
                                 const QByteArray &password,
                                 const QByteArray &salt,
                                 QObject *parent) :
    QIODevice(parent),
    m_device(new QFile(fileName)),
    m_deviceOwner(true),
    m_password(password),
    m_salt(salt.mid(0, 8))
{
}

CryptFileDevice::~CryptFileDevice()
{
    close();
}

void CryptFileDevice::setPassword(const QByteArray &password)
{
    m_password = password;
}

void CryptFileDevice::setSalt(const QByteArray &salt)
{
    m_salt = salt.mid(0, 8);
}

void CryptFileDevice::setKeyLength(AesKeyLength keyLength)
{
    m_aesKeyLength = keyLength;
}

void CryptFileDevice::setNumRounds(int numRounds)
{
    m_numRounds = numRounds;
}

bool CryptFileDevice::open(OpenMode mode)
{
    if (m_device == nullptr)
        return false;

    if (isOpen())
        return false;

    if (mode & WriteOnly)
        mode |= ReadOnly;

    if (mode & Append)
        mode |= ReadWrite;

    OpenMode deviceOpenMode;
    if (mode == ReadOnly)
        deviceOpenMode = ReadOnly;
    else
        deviceOpenMode = ReadWrite;

    if (mode & Truncate)
        deviceOpenMode |= Truncate;

    bool ok;
    if (m_device->isOpen())
        ok = (m_device->openMode() == deviceOpenMode);
    else
        ok = m_device->open(deviceOpenMode);

    if (!ok)
        return false;

    if (m_password.isEmpty())
    {
        setOpenMode(mode);
        return true;
    }

    if (!initCipher())
        return false;

    m_wasFlushed = false;
    m_blockFlush = false;
    m_wasSought = false;
    m_encrypted = true;
    setOpenMode(mode);
    m_size = -1;

    qint64 size = m_device->size();
    if (size == 0 && mode != ReadOnly)
        insertHeader();

    if (size > 0)
    {
        if (!tryParseHeader())
        {
            m_encrypted = false;
            return false;
        }
    }

    if (mode & Append)
    {
        qint64 size = m_device->size() - kHeaderLength;
        if (size < AES_BLOCK_SIZE)
            return true;

        m_wasFlushed = true;
    }

    return true;
}

void CryptFileDevice::insertHeader()
{
    QByteArray header;
    header.append(0xcd); // cryptdevice byte
    header.append(0x01); // version
    header.append((char *)&m_aesKeyLength, 4); // aes key length
    header.append((char *)&m_numRounds, 4); // iteration count to use
    QByteArray passwordHash = QCryptographicHash::hash(m_password, QCryptographicHash::Sha3_256);
    header.append(passwordHash);
    QByteArray saltHash = QCryptographicHash::hash(m_salt, QCryptographicHash::Sha3_256);
    header.append(saltHash);
    QByteArray padding(kHeaderLength - header.length(), 0xcd);
    header.append(padding);
    m_device->write(header);
}

bool CryptFileDevice::tryParseHeader()
{
    QByteArray header = m_device->read(kHeaderLength);
    if (header.length() != kHeaderLength)
        return false;

    if (header.at(0) != (char)0xcd)
        return false;

    //int version = header.at(1);

    int aesKeyLength = *(int *)header.mid(2, 4).data();
    if (aesKeyLength != m_aesKeyLength)
        return false;

    int numRounds = *(int *)header.mid(6, 4).data();
    if (numRounds != m_numRounds)
        return false;

    QByteArray passwordHash = header.mid(10, 32);
    QByteArray expectedPasswordHash = QCryptographicHash::hash(m_password, QCryptographicHash::Sha3_256);
    if (passwordHash != expectedPasswordHash)
        return false;

    QByteArray saltHash = header.mid(42, 32);
    QByteArray expectedSaltHash = QCryptographicHash::hash(m_salt, QCryptographicHash::Sha3_256);
    if (saltHash != expectedSaltHash)
        return false;

    QByteArray padding = header.mid(74);
    QByteArray expectedPadding(padding.length(), 0xcd);

    return padding == expectedPadding;
}

void CryptFileDevice::close()
{
    if (!isOpen())
        return;

    if ((openMode() & WriteOnly) || (openMode() & Append))
        flush();

    seek(0);
    m_device->close();
    setOpenMode(NotOpen);

    if (m_encrypted)
    {
        EVP_CIPHER_CTX_cleanup(&m_encCtx);
        EVP_CIPHER_CTX_cleanup(&m_decCtx);
        m_encrypted = false;
    }
}

void CryptFileDevice::setFileName(const QString &fileName)
{
    if (m_device)
    {
        m_device->close();
        if (m_deviceOwner)
            delete m_device;
    }
    m_device = new QFile(fileName);
    m_deviceOwner = true;
}

QString CryptFileDevice::fileName() const
{
    if (m_device != nullptr)
        return m_device->fileName();
    return QString();
}

void CryptFileDevice::setFileDevice(QFileDevice *device)
{
    if (m_device)
    {
        m_device->close();
        if (m_deviceOwner)
            delete m_device;
    }
    m_device = device;
    m_deviceOwner = false;
}

bool CryptFileDevice::flush()
{
    if (!m_encrypted)
        return false;

    if (m_wasFlushed)
        return true;

    if (m_buffer.isEmpty())
        return false;

    m_wasFlushed = true;

    int len = m_buffer.length();
    int maxCipherLen = len + AES_BLOCK_SIZE - (len % AES_BLOCK_SIZE) + AES_BLOCK_SIZE;
    int finalLen = 0;
    unsigned char *cipherText = new unsigned char[maxCipherLen];

    EVP_EncryptInit_ex(&m_encCtx, NULL, NULL, NULL, NULL);
    EVP_EncryptUpdate(&m_encCtx, cipherText, &maxCipherLen, (unsigned char *)m_buffer.data(), len);
    EVP_EncryptFinal_ex(&m_encCtx, &cipherText[maxCipherLen], &finalLen);

    len = maxCipherLen;
    if (m_device->pos() >= m_device->size())
        len += finalLen;

    m_device->write((char *)cipherText, len);
    delete[] cipherText;

    m_blockFlush = true;
    seek(pos() + m_buffer.length());
    m_blockFlush = false;
    m_wasSought = false;

    m_buffer.clear();

    return true;
}

bool CryptFileDevice::isEncrypted() const
{
    return m_encrypted;
}

qint64 CryptFileDevice::readBlock(qint64 len, QByteArray &ba)
{
    int length = ba.length();
    int readBytes = 0;
    do {
        qint64 fileRead = m_device->read(ba.data() + ba.length(), len - readBytes);
        if (fileRead <= 0)
            break;

        readBytes += fileRead;
    } while(readBytes < len);

    if (readBytes == 0)
        return 0;

    int size = readBytes;

    char * plaintext = decrypt(ba.data() + length, &size);
    ba.truncate(length);

    if (size == 0)
    {
        delete[] plaintext;
        m_device->seek(m_device->pos() - readBytes);
        return 0;
    }

    ba.append(plaintext, size);
    delete[] plaintext;

    int rereadBytes = readBytes - size;
    m_device->seek(m_device->pos() - rereadBytes);

    return size;
}

qint64 CryptFileDevice::readData(char *data, qint64 len)
{
    if (!m_encrypted)
    {
        qint64 fileRead = m_device->read(data, len);
        return fileRead;
    }

    if (len == 0)
        return m_device->read(data, len);

    int skip = pos() % AES_BLOCK_SIZE;
    len += skip;

    QByteArray ba;
    ba.reserve(len + 2 * AES_BLOCK_SIZE);
    do {
        int maxSize = len - ba.length();
        maxSize += AES_BLOCK_SIZE - (maxSize % AES_BLOCK_SIZE) + AES_BLOCK_SIZE;

        int size = readBlock(maxSize, ba);

        if (size == 0)
            break;
    } while (ba.length() < len);

    if (ba.isEmpty())
        return 0;

    int back = 0;
    int length = ba.length();
    if (length > len)
    {
        back = length - len;
        qint64 devicePos = m_device->pos() - back;
        int newDevicePos = devicePos - (devicePos % AES_BLOCK_SIZE);
        m_device->seek(newDevicePos);
    }

    memcpy(data, ba.data() + skip, length - skip - back);

    return length - skip - back;
}

qint64 CryptFileDevice::writeData(const char *data, qint64 len)
{
    if (!m_encrypted)
        return m_device->write(data, len);

    qint64 newSize = pos() + len;

    if (m_wasFlushed)
    {
        m_blockFlush = true;
        qint64 devicePos = m_device->size() - kHeaderLength;
        seek(devicePos - AES_BLOCK_SIZE);
        m_buffer = read(AES_BLOCK_SIZE);
        seek(devicePos - AES_BLOCK_SIZE);
        m_blockFlush = false;
        m_wasFlushed = false;
        m_wasSought = false;

        if (len < AES_BLOCK_SIZE)
        {
            m_device->resize(devicePos + kHeaderLength - AES_BLOCK_SIZE);
            newSize = pos() + len;
        }
    }

    if (m_wasSought)
    {
        m_blockFlush = true;
        qint64 devicePos = m_device->pos() - kHeaderLength;
        int back = pos() % AES_BLOCK_SIZE;
        if (back != 0)
        {
            seek(devicePos);
            m_buffer = read(back);
            seek(devicePos);
            Q_ASSERT(m_buffer.size() == back);
        }

        qint64 newPos = devicePos + back + len;
        qint64 deviceSize = size();

        m_buffer.append(data, len);

        if (newPos <= deviceSize)
        {
            seek(newPos);
            int needReadBytes = AES_BLOCK_SIZE - ((len + back) % AES_BLOCK_SIZE);
            QByteArray additionalData = read(needReadBytes);

            if (needReadBytes != additionalData.length())
            {
                m_device->resize(devicePos + kHeaderLength);
                newSize = newPos;
            }

            m_buffer.append(additionalData);
            seek(devicePos);
        }
        else
        {
            m_device->resize(devicePos + kHeaderLength);
            newSize = newPos;
        }

        m_wasSought = false;
        m_blockFlush = false;
    }
    else
    {
        m_buffer.append(data, len);
    }

    int size = m_buffer.length();

    if (size > len)
        size = len;

    size = size - (size % AES_BLOCK_SIZE);
    QByteArray ba(m_buffer.left(size));
    m_buffer.remove(0, size);
    char *cipherText = encrypt(ba.data(), &size);
    m_device->write(cipherText, size);
    delete[] cipherText;

    if (newSize > m_size)
        m_size = newSize;

    return len;
}

bool CryptFileDevice::initCipher()
{
    const EVP_CIPHER *cipher = EVP_enc_null();
    if (m_aesKeyLength == kAesKeyLength128)
        cipher = EVP_aes_128_ecb();
    else if (m_aesKeyLength == kAesKeyLength192)
        cipher = EVP_aes_192_ecb();
    else if (m_aesKeyLength == kAesKeyLength256)
        cipher = EVP_aes_256_ecb();
    else
        Q_ASSERT_X(false, Q_FUNC_INFO, "Unknown value of AesKeyLength");

    EVP_CIPHER_CTX_init(&m_encCtx);
    EVP_EncryptInit_ex(&m_encCtx, cipher, NULL, NULL, NULL);
    int keyLength = EVP_CIPHER_CTX_key_length(&m_encCtx);
    int ivLength = EVP_CIPHER_CTX_iv_length(&m_encCtx);

    unsigned char key[keyLength];
    unsigned char iv[ivLength];

    int ok = EVP_BytesToKey(cipher,
                            EVP_sha256(),
                            m_salt.isEmpty() ? NULL : (unsigned char *)m_salt.data(),
                            (unsigned char *)m_password.data(),
                            m_password.length(),
                            m_numRounds,
                            key,
                            iv);

    if (ok == 0)
        return false;

    EVP_CIPHER_CTX_init(&m_encCtx);
    EVP_EncryptInit_ex(&m_encCtx, cipher, NULL, key, iv);
    EVP_CIPHER_CTX_init(&m_decCtx);
    EVP_DecryptInit_ex(&m_decCtx, cipher, NULL, key, iv);

    return true;
}

char * CryptFileDevice::encrypt(const char *plainText, int *len)
{
    int maxCipherLen = *len;
    int finalLen = 0;
    unsigned char *cipherText = new unsigned char[maxCipherLen + AES_BLOCK_SIZE];

    EVP_EncryptInit_ex(&m_encCtx, NULL, NULL, NULL, NULL);
    EVP_EncryptUpdate(&m_encCtx, cipherText, &maxCipherLen, (unsigned char *)plainText, *len);
    EVP_EncryptFinal_ex(&m_encCtx, &cipherText[maxCipherLen], &finalLen);

    *len = maxCipherLen;
    return (char *)cipherText;
}

char * CryptFileDevice::decrypt(char *cipherText, int *len)
{
    int maxPlainLen = *len;
    int finalLen = 0;
    unsigned char *plainText = new unsigned char[maxPlainLen + AES_BLOCK_SIZE];

    EVP_DecryptInit_ex(&m_decCtx, NULL, NULL, NULL, NULL);
    EVP_DecryptUpdate(&m_decCtx, plainText, &maxPlainLen, (unsigned char *)cipherText, *len);
    EVP_DecryptFinal_ex(&m_decCtx, plainText + maxPlainLen, &finalLen);

    *len = maxPlainLen + finalLen;
    return (char *)plainText;
}

bool CryptFileDevice::atEnd() const
{
    return QIODevice::atEnd();
}

qint64 CryptFileDevice::bytesAvailable() const
{
    return QIODevice::bytesAvailable();
}

qint64 CryptFileDevice::pos() const
{
    return QIODevice::pos();
}

bool CryptFileDevice::seek(qint64 pos)
{
    if (m_encrypted)
    {
        if (!m_blockFlush && !m_buffer.isEmpty())
        {
            flush();
            m_wasFlushed = false;
        }

        qint64 devicePos = pos - (pos % AES_BLOCK_SIZE);
        m_device->seek(kHeaderLength + devicePos);
        m_wasSought = true;
    }
    else
    {
        m_device->seek(pos);
    }

    return QIODevice::seek(pos);
}

qint64 CryptFileDevice::size() const
{
    if (!isOpen())
        return 0;

    if (!m_encrypted)
        return m_device->size();

    if (m_size != -1)
        return m_size;

    CryptFileDevice *cfd = const_cast<CryptFileDevice*>(this);

    return cfd->calculateSize();
}

qint64 CryptFileDevice::calculateSize()
{
    bool oldValueWasSought = m_wasSought;
    bool oldValueWasFlushed = m_wasFlushed;
    bool oldValueBlockFlushed = m_blockFlush;

    m_wasFlushed = false;
    m_blockFlush = true;

    m_size = calculateSizeHelper();

    m_wasSought = oldValueWasSought;
    m_blockFlush = oldValueBlockFlushed;
    m_wasFlushed = oldValueWasFlushed;

    return m_size;
}

qint64 CryptFileDevice::calculateSizeHelper()
{
    qint64 position = m_device->pos() - kHeaderLength + (pos() % AES_BLOCK_SIZE);
    qint64 deviceSize = m_device->size();

    QByteArray oldBuffer = m_buffer;
    if (openMode() != QIODevice::ReadOnly)
        flush();

    qint64 size = m_device->size() - kHeaderLength;
    if (size < AES_BLOCK_SIZE)
    {
        seek(position);
        return size;
    }

    seek(size - AES_BLOCK_SIZE);
    QByteArray buffer = read(AES_BLOCK_SIZE);
    m_device->resize(deviceSize);
    seek(position);

    if (m_buffer != oldBuffer)
        m_buffer = oldBuffer;

    qint64 result = size + buffer.length() - AES_BLOCK_SIZE;

    return result;
}
