#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QFileDialog>

#include <QMessageBox>

#include "cryptfiledevice.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

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
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly))
    {
        QMessageBox::warning(this, qApp->applicationName(), tr("Cannot open selected file"));
        return;
    }

    CryptFileDevice cryptFileDevice;
    cryptFileDevice.setFileName(filePath + ".enc");
    cryptFileDevice.setPassword(QByteArrayLiteral("alex_password"));
    cryptFileDevice.setSalt(QByteArrayLiteral("alex_salt"));
    if (!cryptFileDevice.open(QIODevice::WriteOnly | QIODevice::Truncate))
    {
        QMessageBox::warning(this, qApp->applicationName(), tr("Cannot encrypt selected file"));
        file.close();
        return;
    }

    cryptFileDevice.write(file.readAll());

    file.close();
    cryptFileDevice.close();

    QString html = QStringLiteral("<html><head></head><body><img src=\"cd://%1.enc\"/></body></html>").arg(filePath);
    ui->webView->setHtml(html, QUrl("cd://"));
}
