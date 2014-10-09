#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "cryptfiledevice.h"
#include "networkaccessmanager.h"

#include <QFileDialog>

#include <QMessageBox>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    ui->webView->page()->setNetworkAccessManager(new NetworkAccessManager);

    connect(ui->browseToolBtn, &QToolButton::clicked,
            this, &MainWindow::browseImage);
    connect(ui->encryptAndShowBtn, &QPushButton::clicked,
            this, &MainWindow::encryptAndShow);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::browseImage()
{
    QString filePath = QFileDialog::getOpenFileName(this,
                                                    tr("Select Image File"),
                                                    QString(),
                                                    tr("Images (*.png)"));
    ui->filePathLineEdit->setText(filePath);

    ui->encryptAndShowBtn->setDisabled(filePath.isEmpty());
}

void MainWindow::encryptAndShow()
{
    QString filePath = ui->filePathLineEdit->text();
    int fileIndex = filePath.lastIndexOf("/") + 1;
    QString dirPath = filePath.mid(0, fileIndex);
    QString fileName = filePath.mid(fileIndex);
    QString encFileName = fileName.append(".enc");
    QString html("<html><head></head><body><img src=\"%1\"/></body></html>");
    html = html.arg(encFileName);
    QUrl url = QUrl::fromLocalFile(dirPath);

    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly))
    {
        QMessageBox::warning(this, qApp->applicationName(), tr("Cannot open selected file"));
        return;
    }

    CryptFileDevice cryptFileDevice;
    cryptFileDevice.setFileName(filePath + ".enc");
    cryptFileDevice.setPassword("alex_password");
    cryptFileDevice.setSalt("alex_salt");
    if (!cryptFileDevice.open(QIODevice::WriteOnly | QIODevice::Truncate))
    {
        QMessageBox::warning(this, qApp->applicationName(), tr("Cannot encrypt selected file"));
        file.close();
        return;
    }

    cryptFileDevice.write(file.readAll());

    file.close();
    cryptFileDevice.close();

    ui->webView->setHtml(html, url);
}
