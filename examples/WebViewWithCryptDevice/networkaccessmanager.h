#ifndef NETWORKACCESSMANAGER_H
#define NETWORKACCESSMANAGER_H

#include <QNetworkAccessManager>
#include <QNetworkReply>

class CryptFileDevice;

class NetworkAccessManager : public QNetworkAccessManager
{
    Q_OBJECT
public:
    explicit NetworkAccessManager(QObject *parent = 0);

protected:
    QNetworkReply *createRequest(Operation op, const QNetworkRequest &req, QIODevice *outgoingData);
};

class NetworkReply : public QNetworkReply
{
    Q_OBJECT
public:
    explicit NetworkReply(QObject *parent = 0);
    ~NetworkReply();

    qint64 bytesAvailable() const;
    bool isSequential() const;
    void abort();

    void setRequestInfo(QNetworkAccessManager::Operation op, const QNetworkRequest &req);

protected:
    qint64 readData(char *data, qint64 maxlen);

private:
    void closeFile();

    CryptFileDevice *m_cryptFileDevice = nullptr;
};

#endif // NETWORKACCESSMANAGER_H
