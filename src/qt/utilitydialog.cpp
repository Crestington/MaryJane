// Copyright (c) 2011-2020 The Bitcoin Core developers
// Copyright (c) 2014-2023 The MaryJane Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <qt/utilitydialog.h>

#include <qt/forms/ui_helpmessagedialog.h>

#include <qt/guiutil.h>
#include <qt/networkstyle.h>

#include <clientversion.h>
#include <init.h>
#include <rpc/server.h>
#include <univalue.h>
#include <util/system.h>
#include <util/strencodings.h>

#include <stdio.h>

#include <QCloseEvent>
#include <QLabel>
#include <QMainWindow>
#include <QRegExp>
#include <QTextCursor>
#include <QTextTable>
#include <QVBoxLayout>

/** "Help message" or "About" dialog box */
HelpMessageDialog::HelpMessageDialog(QWidget *parent, const NetworkStyle* networkStyle, bool about, bool checkUpdates) :
    QDialog(parent, GUIUtil::dialog_flags),
    ui(new Ui::HelpMessageDialog)
{
    ui->setupUi(this);

    QString version = QString{PACKAGE_NAME} + " " + tr("version") + " " + QString::fromStdString(FormatFullVersion());

    if (about || checkUpdates)
    {
        // Make URLs clickable
        QRegExp uri("<(.*)>", Qt::CaseSensitive, QRegExp::RegExp2);
        uri.setMinimal(true); // use non-greedy matching

        ui->aboutMessage->setTextFormat(Qt::RichText);
        ui->scrollArea->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        ui->aboutMessage->setWordWrap(true);
        ui->helpMessage->setVisible(false);
        if(networkStyle) {
            const QSize requiredSize(1024,1024);
            QPixmap icon(networkStyle->getAppIcon().pixmap(requiredSize));
            ui->aboutLogo->setPixmap(icon);
        }

        if (about) {
            resize(780, 400);
            setWindowTitle(tr("About %1").arg(PACKAGE_NAME));

            std::string licenseInfo = LicenseInfo();
            /// HTML-format the license message from the core
            QString licenseInfoHTML = QString::fromStdString(LicenseInfo());
            licenseInfoHTML.replace(uri, "<a href=\"\\1\">\\1</a>");
            // Replace newlines with HTML breaks
            licenseInfoHTML.replace("\n", "<br>");

            text = version + "\n" + QString::fromStdString(FormatParagraph(licenseInfo));
            ui->aboutMessage->setText(version + "<br><br>" + licenseInfoHTML);

        } else {
            resize(780, 240);

            setWindowTitle(tr("Check for updates"));
            text = "Checking for updates. Please wait...";
            ui->aboutMessage->setText(text);

            // Get checkforupdatesinfo from rpc server
            UniValue result(UniValue::VOBJ);
            checkforupdatesinfo(result);

            //json_spirit::Object jsonObject = result.get_obj();
            QString localversion = "";
            QString remoteversion = "";
            QString message = "";
            QString warning = "";
            QString officialDownloadLink = "";
            QString errors = "";

            if (result.exists("localversion")) {
                localversion = QString::fromStdString(result["localversion"].get_str());
            }
            if (result.exists("remoteversion")) {
                remoteversion = QString::fromStdString(result["remoteversion"].get_str());
            }
            if (result.exists("message")) {
                message = QString::fromStdString(result["message"].get_str());
            }
            if (result.exists("warning")) {
                warning = QString::fromStdString(result["warning"].get_str());
            }
            if (result.exists("officialDownloadLink")) {
                officialDownloadLink = QString::fromStdString(result["officialDownloadLink"].get_str());
            }
            if (result.exists("error")) {
                errors = QString::fromStdString(result["error"].get_str());
            }

            if (!errors.isEmpty()) {
                text = "<font color = 'red'>Error: </font>";
                text += errors;
            } else if (localversion == remoteversion) {
                text = "Installed version: <b>" + localversion  + "</b><br>";
                text += message;
            } else {
                QString url = "<a href=\""+ officialDownloadLink +"\">"+ officialDownloadLink +"</a>";

                text = "Installed version: <b>" + localversion  + "</b><br>";
                text += "Latest repository version: <b>" + remoteversion + "</b><br><br>";
                text += "Please download the latest version from our official website <br>(" + url + ").";
            }

            ui->aboutMessage->setText(text);

        }


    } else {
        resize(780, 400);
        setWindowTitle(tr("Command-line options"));
        QString header = "Usage:  maryjane-qt [command-line options]                     \n";
        QTextCursor cursor(ui->helpMessage->document());
        cursor.insertText(version);
        cursor.insertBlock();
        cursor.insertText(header);
        cursor.insertBlock();

        std::string strUsage = gArgs.GetHelpMessage();
        QString coreOptions = QString::fromStdString(strUsage);
        text = version + "\n\n" + header + "\n" + coreOptions;

        QTextTableFormat tf;
        tf.setBorderStyle(QTextFrameFormat::BorderStyle_None);
        tf.setCellPadding(2);
        QVector<QTextLength> widths;
        widths << QTextLength(QTextLength::PercentageLength, 35);
        widths << QTextLength(QTextLength::PercentageLength, 65);
        tf.setColumnWidthConstraints(widths);

        QTextCharFormat bold;
        bold.setFontWeight(QFont::Bold);

        for (const QString &line : coreOptions.split("\n")) {
            if (line.startsWith("  -"))
            {
                cursor.currentTable()->appendRows(1);
                cursor.movePosition(QTextCursor::PreviousCell);
                cursor.movePosition(QTextCursor::NextRow);
                cursor.insertText(line.trimmed());
                cursor.movePosition(QTextCursor::NextCell);
            } else if (line.startsWith("   ")) {
                cursor.insertText(line.trimmed()+' ');
            } else if (line.size() > 0) {
                //Title of a group
                if (cursor.currentTable())
                    cursor.currentTable()->appendRows(1);
                cursor.movePosition(QTextCursor::Down);
                cursor.insertText(line.trimmed(), bold);
                cursor.insertTable(1, 2, tf);
            }
        }

        ui->helpMessage->moveCursor(QTextCursor::Start);
        ui->scrollArea->setVisible(false);
        ui->aboutLogo->setVisible(false);
    }

    GUIUtil::handleCloseWindowShortcut(this);
}

HelpMessageDialog::~HelpMessageDialog()
{
    delete ui;
}

void HelpMessageDialog::printToConsole()
{
    // On other operating systems, the expected action is to print the message to the console.
    tfm::format(std::cout, "%s\n", qPrintable(text));
}

void HelpMessageDialog::showOrPrint()
{
#if defined(WIN32)
    // On Windows, show a message box, as there is no stderr/stdout in windowed applications
    exec();
#else
    // On other operating systems, print help text to console
    printToConsole();
#endif
}

void HelpMessageDialog::on_okButton_accepted()
{
    close();
}


/** "Shutdown" window */
ShutdownWindow::ShutdownWindow(QWidget *parent, Qt::WindowFlags f):
    QWidget(parent, f)
{
    QVBoxLayout *layout = new QVBoxLayout();
    layout->addWidget(new QLabel(
        tr("%1 is shutting down…").arg(PACKAGE_NAME) + "<br /><br />" +
        tr("Do not shut down the computer until this window disappears.")));
    setLayout(layout);

    GUIUtil::handleCloseWindowShortcut(this);
}

QWidget* ShutdownWindow::showShutdownWindow(QMainWindow* window)
{
    assert(window != nullptr);

    // Show a simple window indicating shutdown status
    QWidget *shutdownWindow = new ShutdownWindow();
    shutdownWindow->setWindowTitle(window->windowTitle());

    // Center shutdown window at where main window was
    const QPoint global = window->mapToGlobal(window->rect().center());
    shutdownWindow->move(global.x() - shutdownWindow->width() / 2, global.y() - shutdownWindow->height() / 2);
    shutdownWindow->show();
    return shutdownWindow;
}

void ShutdownWindow::closeEvent(QCloseEvent *event)
{
    event->ignore();
}
