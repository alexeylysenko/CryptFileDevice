#ifndef CRYPTFILEDEVICE_H
#define CRYPTFILEDEVICE_H

#include <QIODevice>

#include <openssl/aes.h>

class QFileDevice;

struct CtrState
{
    unsigned char ivec[AES_BLOCK_SIZE];
    unsigned int num;
    unsigned char ecount[AES_BLOCK_SIZE];
};

class CryptFileDevice : public QIODevice
{
    Q_OBJECT
    Q_DISABLE_COPY(CryptFileDevice)
public:
    enum AesKeyLength
    {
        kAesKeyLength128,
        kAesKeyLength192,
        kAesKeyLength256
    };

    explicit CryptFileDevice(QObject *parent = 0);
    explicit CryptFileDevice(QFileDevice *device, QObject *parent = 0);
    explicit CryptFileDevice(QFileDevice *device,
                             const QByteArray &password,
                             const QByteArray &salt,
                             QObject *parent = 0);
    explicit CryptFileDevice(const QString &fileName,
                             const QByteArray &password,
                             const QByteArray &salt,
                             QObject *parent = 0);
    ~CryptFileDevice();

    bool open(OpenMode flags);
    void close();

    void setFileName(const QString &fileName);
    QString fileName() const;

    void setFileDevice(QFileDevice *device);

    void setPassword(const QByteArray &password);
    void setSalt(const QByteArray &salt);
    void setKeyLength(AesKeyLength keyLength);
    void setNumRounds(int numRounds);

    bool isEncrypted() const;
    qint64 size() const;

    bool atEnd() const;
    qint64 bytesAvailable() const;
    qint64 pos() const;
    bool seek(qint64 pos);
    bool flush();
    bool remove();

protected:
    qint64 readData(char *data, qint64 len);
    qint64 writeData(const char *data, qint64 len);

    qint64 readBlock(qint64 len, QByteArray &ba);

private:
    bool initCipher();
    void initCtr(CtrState *state, const unsigned char *iv);
    char * encrypt(const char *plainText, qint64 len);
    char * decrypt(char *cipherText, qint64 len);

    void insertHeader();
    bool tryParseHeader();

    QFileDevice *m_device = nullptr;
    bool m_deviceOwner = false;
    bool m_encrypted = false;

    QByteArray m_password;
    QByteArray m_salt;
    AesKeyLength m_aesKeyLength = kAesKeyLength256;
    int m_numRounds = 5;

    CtrState m_ctrState;
    AES_KEY m_aesKey;
};

#endif // CRYPTFILEDEVICE_H
