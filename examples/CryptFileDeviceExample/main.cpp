#include <QCoreApplication>

#include "cryptfiledevice.h"

#include <QFile>
#include <QDebug>
#include <QDateTime>
#include <QDataStream>

#define PRINT_STATE(ok) { qDebug() << (ok ? "..Done" : "..Failed"); }

QByteArray generateRandomData(int size)
{
    QByteArray data;
    while (data.size() < size)
    {
        data += char(qrand() % 256);
    }
    return data;
}

bool compare(const QString &pathToEnc, const QString &pathToPlain)
{
    // Create files
    QFile plainFile(pathToPlain);

    QFile encryptedFile(pathToEnc);
    CryptFileDevice cryptFileDevice(&encryptedFile,
                                    "01234567890123456789012345678901",
                                    "0123456789012345");

    if (!plainFile.open(QIODevice::ReadOnly))
    {
        return false;
    }

    if (!cryptFileDevice.open(QIODevice::ReadOnly))
    {
        plainFile.close();
        return false;
    }

    QByteArray plainData = plainFile.readAll();
    QByteArray decryptData = cryptFileDevice.readAll();

    bool result = (plainData == decryptData);

    plainFile.close();
    cryptFileDevice.close();

    return result;
}

QByteArray calculateXor(const QByteArray &data, const QByteArray &key)
{
    if (key.isEmpty())
        return data;

    QByteArray result;
    for(int i = 0 , j = 0; i < data.length(); ++i , ++j)
    {
        if(j == key.length())
            j = 0;// repeat the key if key.length() < data.length()
        result.append(data.at(i) ^ key.at(j));
    }
    return result;
}

bool openDevicePair(QIODevice *device1, QIODevice *device2, QIODevice::OpenMode mode)
{
    if (device1->isOpen())
        device1->close();
    if (device2->isOpen())
        device2->close();

    if (!device1->open(mode))
    {
        Q_ASSERT_X(false, Q_FUNC_INFO, "Cannot create test file");
        return false;
    }

    if (!device2->open(mode))
    {
        Q_ASSERT_X(false, Q_FUNC_INFO, "Cannot create test file");
        return false;
    }
    return true;
}

void testCryptFileDevice()
{
    bool ok;

    // Create files
    QFile plainFile(qApp->applicationDirPath() + "/testfile.plain");

    QFile encryptedFile(qApp->applicationDirPath() + "/testfile.encrypted");
    CryptFileDevice cryptFileDevice(&encryptedFile,
                                    "01234567890123456789012345678901",
                                    "0123456789012345");


    // Creating (rewriting files)
    /// ----------------------------------------------------------------------
    qDebug() << "Creating test files";
    if (!openDevicePair(&plainFile, &cryptFileDevice, QIODevice::WriteOnly | QIODevice::Truncate))
        return;
    PRINT_STATE(true);

    qDebug() << "Writing random content";
    for (int i = 0; i < 200; i++)
    {
        QByteArray data = generateRandomData(qrand() % 256).toBase64() + "\r\n";
        plainFile.write(data);
        cryptFileDevice.write(data);
    }
    plainFile.close();
    cryptFileDevice.close();
    PRINT_STATE(true);

    /// ----------------------------------------------------------------------
    qDebug() << "Comparing content (should be the same)";
    {
        ok = compare(encryptedFile.fileName(), plainFile.fileName());
        PRINT_STATE(ok);
        Q_ASSERT_X(ok, Q_FUNC_INFO, "Content is different");
    }

    /// ----------------------------------------------------------------------
    qDebug() << "Comparing files's size (sould be the same)";
    {
        if (!openDevicePair(&plainFile, &cryptFileDevice, QIODevice::ReadOnly))
            return;

        ok = (cryptFileDevice.size() == plainFile.size());

        PRINT_STATE(ok);
        Q_ASSERT_X(ok, Q_FUNC_INFO, "Size is different");
    }

    /// ----------------------------------------------------------------------
    qDebug() << "Reading from random position";
    {
        if (!openDevicePair(&plainFile, &cryptFileDevice, QIODevice::ReadOnly))
            return;
        ok = true;
        for (int i = 0; i < 200; i++)
        {
            qint64 pos = qrand() % plainFile.size(); // size is the same
            qint64 maxlen = qrand() % 256;

            cryptFileDevice.seek(pos);
            Q_ASSERT(cryptFileDevice.pos() == pos);
            plainFile.seek(pos);
            Q_ASSERT(plainFile.pos() == pos);

            QByteArray data1 = plainFile.read(maxlen);
            QByteArray data2 = cryptFileDevice.read(maxlen);

            if (data1 != data2)
            {
                ok = false;
                break;
            }
        }
        PRINT_STATE(ok);
        Q_ASSERT_X(ok, Q_FUNC_INFO, "Random read content is different");
    }

    /// ----------------------------------------------------------------------
    qDebug() << "Reading line by line";
    {
        if (!openDevicePair(&plainFile, &cryptFileDevice, QIODevice::ReadOnly))
            return;

        Q_ASSERT(plainFile.pos() == 0);
        Q_ASSERT(cryptFileDevice.pos() == 0);

        ok = true;
        QByteArray seed = generateRandomData(300);
        QByteArray chk1 = seed, chk2 = seed;

        while (!plainFile.atEnd())
        {
            QByteArray line = plainFile.readLine();
            if (line.isEmpty())
                break;
            chk1 = calculateXor(chk1, line);
        }

        while (!cryptFileDevice.atEnd())
        {
            QByteArray line = cryptFileDevice.readLine();
            if (line.isEmpty())
                break;
            chk2 = calculateXor(chk2, line);
        }

        ok = (chk1 == chk2);
        PRINT_STATE(ok);
        Q_ASSERT_X(ok, Q_FUNC_INFO, "Reading lines is failed");
    }

    /// ----------------------------------------------------------------------
    qDebug() << "Appending data";
    {
        if (!openDevicePair(&plainFile, &cryptFileDevice, QIODevice::Append))
            return;

        for (int i = 0; i < 200; i++)
        {
            QByteArray data = generateRandomData(qrand() % 256).toBase64() + "\r\n";
            qint64 plainBytesWritten = plainFile.write(data);
            Q_ASSERT(plainBytesWritten == data.size());
            qint64 cryptBytesWritten = cryptFileDevice.write(data);
            Q_ASSERT(cryptBytesWritten == data.size());
        }
        plainFile.close();
        cryptFileDevice.close();

        ok = compare(encryptedFile.fileName(), plainFile.fileName());
        PRINT_STATE(ok);

        Q_ASSERT_X(ok, Q_FUNC_INFO, "Content is different");
    }

    /// ----------------------------------------------------------------------
    {
        qDebug() << "Rewriting file (truncate)";
        if (!openDevicePair(&plainFile, &cryptFileDevice, QIODevice::WriteOnly | QIODevice::Truncate))
            return;
        for (int i = 0; i < 200; i++)
        {
            QByteArray data = generateRandomData(qrand() % 256).toBase64() + "\r\n";
            plainFile.write(data);
            cryptFileDevice.write(data);
        }
        plainFile.close();
        cryptFileDevice.close();
        ok = compare(encryptedFile.fileName(), plainFile.fileName());
        PRINT_STATE(ok);
        Q_ASSERT_X(ok, Q_FUNC_INFO, "Content is different");
    }

    /// ----------------------------------------------------------------------
    qDebug() << "Flushing";
    {
        qDebug() << "Rewriting file (truncate)";
        if (!openDevicePair(&plainFile, &cryptFileDevice, QIODevice::WriteOnly | QIODevice::Truncate))
            return;

        for (int i = 0; i < 200; i++)
        {
            QByteArray data = generateRandomData(qrand() % 256).toBase64() + "\r\n";
            plainFile.write(data);
            plainFile.flush();
            cryptFileDevice.write(data);
            cryptFileDevice.flush();
        }

        plainFile.close();
        cryptFileDevice.close();
        ok = compare(encryptedFile.fileName(), plainFile.fileName());
        PRINT_STATE(ok);
        Q_ASSERT_X(ok, Q_FUNC_INFO, "Content is different");
    }

    /// ----------------------------------------------------------------------
    qDebug() << "Sizing Flushing";
    {
        qDebug() << "Rewriting file (truncate)";
        if (!openDevicePair(&plainFile, &cryptFileDevice, QIODevice::WriteOnly | QIODevice::Truncate))
            return;

        for (int i = 0; i < 200; i++)
        {
            QByteArray data = generateRandomData(qrand() % 256).toBase64() + "\r\n";
            plainFile.write(data);
            qint64 plainSize = plainFile.size();
            cryptFileDevice.write(data);
            qint64 cryptSize = cryptFileDevice.size();
            Q_ASSERT(plainSize == cryptSize);
        }

        plainFile.close();
        cryptFileDevice.close();
        ok = compare(encryptedFile.fileName(), plainFile.fileName());
        PRINT_STATE(ok);
        Q_ASSERT_X(ok, Q_FUNC_INFO, "Content is different");
    }

    /// ----------------------------------------------------------------------
    qDebug() << "Rewriting random data in file";
    {
        ok = false;
        if (!openDevicePair(&plainFile, &cryptFileDevice, QIODevice::WriteOnly | QIODevice::Truncate))
            return;
        for (int i = 0; i < 200; i++)
        {
            QByteArray data = generateRandomData(qrand() % 256).toBase64() + "\r\n";
            plainFile.write(data);
            cryptFileDevice.write(data);
        }
        plainFile.close();
        cryptFileDevice.close();
        if (compare(encryptedFile.fileName(), plainFile.fileName()))
        {
            if (!openDevicePair(&plainFile, &cryptFileDevice, QIODevice::ReadWrite))
                return;

            for (int i = 0; i < 200; i++)
            {
                qint64 pos = qrand() % plainFile.size(); // size is the same

                cryptFileDevice.seek(pos);
                Q_ASSERT(cryptFileDevice.pos() == pos);
                plainFile.seek(pos);
                Q_ASSERT(plainFile.pos() == pos);

                QByteArray data = generateRandomData(qrand() % 256).toBase64() + "\r\n";
                plainFile.write(data);
                cryptFileDevice.write(data);
            }
        }
        plainFile.close();
        cryptFileDevice.close();
        ok = compare(encryptedFile.fileName(), plainFile.fileName());

        PRINT_STATE(ok);
        Q_ASSERT_X(ok, Q_FUNC_INFO, "Content is different");
    }

    /// ----------------------------------------------------------------------
    qDebug() << "Writing using QDataStream (operator <<)";
    {
        ok = false;
        if (!openDevicePair(&plainFile, &cryptFileDevice, QIODevice::WriteOnly | QIODevice::Truncate))
            return;

        QDataStream plainStream(&plainFile);
        QDataStream cryptStream(&cryptFileDevice);
        for (int i = 0; i < 200; i++)
        {
            QByteArray data = generateRandomData(qrand() % 256).toBase64() + "\r\n";

            plainStream << data;
            cryptStream << data;
        }
        plainFile.close();
        cryptFileDevice.close();
        ok = compare(encryptedFile.fileName(), plainFile.fileName());
        PRINT_STATE(ok);
        Q_ASSERT_X(ok, Q_FUNC_INFO, "Content is different");
    }

    /// ----------------------------------------------------------------------
    qDebug() << "Writing using QDataStream (writeRawData)";
    {
        ok = false;
        if (!openDevicePair(&plainFile, &cryptFileDevice, QIODevice::WriteOnly | QIODevice::Truncate))
            return;

        QDataStream plainStream(&plainFile);
        QDataStream cryptStream(&cryptFileDevice);
        for (int i = 0; i < 200; i++)
        {
            QByteArray data = generateRandomData(qrand() % 256).toBase64() + "\r\n";

            int plainBytesWritten = plainStream.writeRawData(data.constData(), data.length());
            int cryptBytesWritten = cryptStream.writeRawData(data.constData(), data.length());
            Q_ASSERT(plainBytesWritten == cryptBytesWritten);
        }
        plainFile.close();
        cryptFileDevice.close();
        ok = compare(encryptedFile.fileName(), plainFile.fileName());
        PRINT_STATE(ok);
        Q_ASSERT_X(ok, Q_FUNC_INFO, "Content is different");
    }

    // ----------------------------------------------------------------------
    qDebug() << "Reading using QDataStream (operator >>)";
    {
        ok = false;
        if (!openDevicePair(&plainFile, &cryptFileDevice, QIODevice::ReadOnly))
            return;

        QDataStream plainStream(&plainFile);
        QDataStream cryptStream(&cryptFileDevice);

        QByteArray dataFromPlainFile;
        QByteArray dataFromCryptDevice;
        plainStream >> dataFromPlainFile;
        cryptStream >> dataFromCryptDevice;
        plainFile.close();
        cryptFileDevice.close();
        ok = (dataFromPlainFile == dataFromCryptDevice);
        PRINT_STATE(ok);
        Q_ASSERT_X(ok, Q_FUNC_INFO, "Content is different");
    }

    // ----------------------------------------------------------------------
    qDebug() << "Reading using QDataStream (readRawData)";
    {
        ok = true;
        if (!openDevicePair(&plainFile, &cryptFileDevice, QIODevice::ReadOnly))
            return;

        QDataStream plainStream(&plainFile);
        QDataStream cryptStream(&cryptFileDevice);

        for (int i = 0; i < 200; ++i)
        {
            int size = qrand() % 256;
            QByteArray dataFromPlainFile(size, ' ');
            QByteArray dataFromCryptDevice(size, ' ');

            int plainBytesRead = plainStream.readRawData(dataFromPlainFile.data(), size);
            int cryptBytesRead = cryptStream.readRawData(dataFromCryptDevice.data(), size);
            Q_ASSERT(plainBytesRead == cryptBytesRead);

            if (dataFromPlainFile != dataFromCryptDevice)
            {
                ok = false;
                break;
            }
        }
        plainFile.close();
        cryptFileDevice.close();

        PRINT_STATE(ok);
        Q_ASSERT_X(ok, Q_FUNC_INFO, "Content is different");
    }

    // ----------------------------------------------------------------------
    qDebug() << "Reading from random position using QTextStream";
    {
        ok = true;
        if (!openDevicePair(&plainFile, &cryptFileDevice, QIODevice::ReadOnly))
            return;

        QTextStream plainStream(&plainFile);
        QTextStream cryptStream(&cryptFileDevice);

        for (int i = 0; i < 200; ++i)
        {
            int pos = qrand() % plainFile.size();
            int size = qrand() % 256;

            plainStream.seek(pos);
            Q_ASSERT(plainStream.pos() == pos);
            cryptStream.seek(pos);
            Q_ASSERT(cryptStream.pos() == pos);

            QString plainData = plainStream.read(size);
            QString cryptData = cryptStream.read(size);

            if (plainData != cryptData)
            {
                ok = false;
                break;
            }
        }
        plainFile.close();
        cryptFileDevice.close();

        PRINT_STATE(ok);
        Q_ASSERT_X(ok, Q_FUNC_INFO, "Content is different");
    }

    // ----------------------------------------------------------------------
    qDebug() << "Reading line by line using QTextStream";
    {
        if (!openDevicePair(&plainFile, &cryptFileDevice, QIODevice::ReadOnly))
            return;

        QTextStream plainStream(&plainFile);
        QTextStream cryptStream(&cryptFileDevice);

        ok = true;
        QByteArray seed = generateRandomData(300);
        QByteArray chk1 = seed, chk2 = seed;

        while (!plainStream.atEnd())
        {
            QString line = plainStream.readLine();
            if (line.isEmpty())
                break;
            chk1 = calculateXor(chk1, line.toUtf8());
        }

        while (!cryptStream.atEnd())
        {
            QString line = cryptStream.readLine();
            if (line.isEmpty())
                break;
            chk2 = calculateXor(chk2, line.toUtf8());
        }

        plainFile.close();
        cryptFileDevice.close();

        ok = (chk1 == chk2);
        PRINT_STATE(ok);
        Q_ASSERT_X(ok, Q_FUNC_INFO, "Reading lines is failed");
    }

    // ----------------------------------------------------------------------
    qDebug() << "Open CryptFileDevice with wrong password";
    {
        ok = false;
        CryptFileDevice cryptFileDevice(&encryptedFile,
                                        "1234567890123456789012",
                                        "123456789012");

        if (!cryptFileDevice.open(QIODevice::ReadOnly))
        {
            ok = true;
        }

        PRINT_STATE(ok);
        Q_ASSERT_X(ok, Q_FUNC_INFO, "Open CryptFileDevice with wrong password is failed");
    }

    /// ----------------------------------------------------------------------
    qDebug() << "Removing";
    {
        ok = cryptFileDevice.remove() && !encryptedFile.exists();
        PRINT_STATE(ok);
        Q_ASSERT_X(ok, Q_FUNC_INFO, "Cannot remove file");
    }
}

QMap<QString, int> testQFilePerformance(const QString &pathToTestData)
{
    QString fileName = qApp->applicationDirPath() + "/test_qfile";
    QMap<QString, int> result;

    if (QFile::exists(fileName))
    {
        if (!QFile::remove(fileName))
        {
            Q_ASSERT_X(false, Q_FUNC_INFO, "Cannot remove file");
            return result;
        }
    }

    QFile testDataFile(pathToTestData);
    if (!testDataFile.open(QIODevice::ReadOnly))
    {
        Q_ASSERT_X(false, Q_FUNC_INFO, "Cannot open file");
        return result;
    }

    QFile testFile(fileName);
    bool ok = true;

    QTime timer;
    int time;
    QByteArray chunk;
    chunk.reserve(100000);

    // Writing data
    qDebug() << "Writing data";
    timer.start();

    ok = testFile.open(QIODevice::WriteOnly);
    PRINT_STATE(ok);
    Q_ASSERT_X(ok, Q_FUNC_INFO, "Opening file is failed");
    if (!ok) return result;


    testDataFile.seek(0);
    while (!testDataFile.atEnd())
    {
        chunk = testDataFile.read(99991); // max prime number < 100000
        testFile.write(chunk);
    }

    testFile.close();
    time = timer.elapsed();
    result.insert("writing", time);
    qDebug() << "Time:" << time;

    // Reading data
    qDebug() << "Reading data";

    ok = testFile.open(QIODevice::ReadOnly);
    PRINT_STATE(ok);
    Q_ASSERT_X(ok, Q_FUNC_INFO, "Opening file is failed");
    if (!ok) return result;

    timer.start();
    testFile.seek(0);
    while (!testFile.atEnd())
    {
        chunk = testFile.read(99991); // max prime number < 100000
    }

    testFile.close();
    time = timer.elapsed();
    result.insert("reading", time);
    qDebug() << "Time:" << timer.elapsed();

    // Writing data
    qDebug() << "Writing data with size";
    timer.start();

    ok = testFile.open(QIODevice::WriteOnly);
    PRINT_STATE(ok);
    Q_ASSERT_X(ok, Q_FUNC_INFO, "Opening file is failed");
    if (!ok) return result;

    testDataFile.seek(0);
    while (!testDataFile.atEnd())
    {
        chunk = testDataFile.read(99991); // max prime number < 100000
        testFile.write(chunk);
        testFile.size();
    }

    testFile.close();
    time = timer.elapsed();
    result.insert("writing_with_size", time);
    qDebug() << "Time:" << timer.elapsed();

    return result;
}

QMap<QString, int> testCryptFilePerformance(const QString &pathToTestData)
{
    QString fileName = qApp->applicationDirPath() + "/test_qfile";
    QMap<QString, int> result;

    if (QFile::exists(fileName))
    {
        if (!QFile::remove(fileName))
        {
            Q_ASSERT_X(false, Q_FUNC_INFO, "Cannot remove file");
            return result;
        }
    }

    QFile testDataFile(pathToTestData);
    if (!testDataFile.open(QIODevice::ReadOnly))
    {
        Q_ASSERT_X(false, Q_FUNC_INFO, "Cannot open file");
        return result;
    }

    QFile testFileDevice(fileName);
    CryptFileDevice  testFile(&testFileDevice, "14rewffsdfsdfsagfdgsd", "gfdgfdsgfdgfdgfdgfds");
    bool ok = true;

    QTime timer;
    int time;
    QByteArray chunk;
    chunk.reserve(100000);

    // Writing data
    qDebug() << "Writing data";
    timer.start();

    ok = testFile.open(QIODevice::WriteOnly);
    PRINT_STATE(ok);
    Q_ASSERT_X(ok, Q_FUNC_INFO, "Opening file is failed");
    if (!ok) return result;


    testDataFile.seek(0);
    while (!testDataFile.atEnd())
    {
        chunk = testDataFile.read(99991); // max prime number < 100000
        testFile.write(chunk);
    }

    testFile.close();
    time = timer.elapsed();
    result.insert("writing", time);
    qDebug() << "Time:" << time;

    // Reading data
    qDebug() << "Reading data";

    ok = testFile.open(QIODevice::ReadOnly);
    PRINT_STATE(ok);
    Q_ASSERT_X(ok, Q_FUNC_INFO, "Opening file is failed");
    if (!ok) return result;

    timer.start();
    testFile.seek(0);
    while (!testFile.atEnd())
    {
        chunk = testFile.read(99991); // max prime number < 100000
    }

    testFile.close();
    time = timer.elapsed();
    result.insert("reading", time);
    qDebug() << "Time:" << timer.elapsed();

    // Writing data
    qDebug() << "Writing data with size";
    timer.start();

    ok = testFile.open(QIODevice::WriteOnly);
    PRINT_STATE(ok);
    Q_ASSERT_X(ok, Q_FUNC_INFO, "Opening file is failed");
    if (!ok) return result;

    testDataFile.seek(0);
    while (!testDataFile.atEnd())
    {
        chunk = testDataFile.read(99991); // max prime number < 100000
        testFile.write(chunk);
        testFile.size();
    }

    testFile.close();
    time = timer.elapsed();
    result.insert("writing_with_size", time);
    qDebug() << "Time:" << timer.elapsed();

    return result;
}

void testPerformance()
{
    // Preparing test file
    QFile testFile(qApp->applicationDirPath() + "/testdata");
    if (!testFile.open(QIODevice::WriteOnly | QIODevice::Truncate))
    {
        Q_ASSERT_X(false, Q_FUNC_INFO, "Cannot open file");
        return;
    }

    for (int i = 0; i < 1000; i++) // How much MB
    {
        QByteArray data = generateRandomData(1024*1024); // 1MB

        testFile.write(data);
    }

    testFile.close();

    QMap<QString, int> result1 = testQFilePerformance(testFile.fileName());
    qDebug() << "Result:" << result1;
    QMap<QString, int> result2 = testCryptFilePerformance(testFile.fileName());
    qDebug() << "Result:" << result2;
    QMap<QString, int> result3 = testQFilePerformance(testFile.fileName());
    qDebug() << "Result:" << result3;
    QMap<QString, int> result4 = testCryptFilePerformance(testFile.fileName());
    qDebug() << "Result:" << result4;
    QMap<QString, int> result5 = testQFilePerformance(testFile.fileName());
    qDebug() << "Result:" << result5;
    QMap<QString, int> result6 = testCryptFilePerformance(testFile.fileName());
    qDebug() << "Result:" << result6;
}

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    int seed = QDateTime::currentDateTime().toTime_t();
    qDebug() << "Seed:" << seed;
    qsrand(seed);

    QTime timer;
    for (int i = 0; i < 200; i++)
    {
        qDebug() << i << " times";
        timer.restart();
        testCryptFileDevice();
        qDebug() << "test duration: " << timer.elapsed() << " ms";
    }

    //testPerformance();

    return 0;
}
