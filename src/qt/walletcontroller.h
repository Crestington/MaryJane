// Copyright (c) 2019-2020 The Bitcoin Core developers
// Copyright (c) 2019-2023 The MaryJane Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_WALLETCONTROLLER_H
#define BITCOIN_QT_WALLETCONTROLLER_H

#include <qt/sendcoinsrecipient.h>
#include <support/allocators/secure.h>
#include <sync.h>
#include <util/translation.h>

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <QMessageBox>
#include <QMutex>
#include <QProgressDialog>
#include <QString>
#include <QThread>
#include <QTimer>

class ClientModel;
class OptionsModel;
class PlatformStyle;
class WalletModel;

namespace interfaces {
class Handler;
class Node;
class Wallet;
} // namespace interfaces

class AskPassphraseDialog;
class CreateWalletActivity;
class CreateWalletDialog;
class CreateWalletWizard;
class OpenWalletActivity;
class WalletControllerActivity;

/**
 * Controller between interfaces::Node, WalletModel instances and the GUI.
 */
class WalletController : public QObject
{
    Q_OBJECT

    void removeAndDeleteWallet(WalletModel* wallet_model);

public:
    WalletController(ClientModel& client_model, const PlatformStyle* platform_style, QObject* parent);
    ~WalletController();

    //! Returns wallet models currently open.
    std::vector<WalletModel*> getOpenWallets() const;

    WalletModel* getOrCreateWallet(std::unique_ptr<interfaces::Wallet> wallet);

    //! Returns all wallet names in the wallet dir mapped to whether the wallet
    //! is loaded.
    std::map<std::string, bool> listWalletDir() const;

    void closeWallet(WalletModel* wallet_model, QWidget* parent = nullptr);
    void closeAllWallets(QWidget* parent = nullptr);

Q_SIGNALS:
    void walletAdded(WalletModel* wallet_model);
    void walletRemoved(WalletModel* wallet_model);

    void coinsSent(WalletModel* wallet_model, SendCoinsRecipient recipient, QByteArray transaction);

private:
    QThread* const m_activity_thread;
    QObject* const m_activity_worker;
    ClientModel& m_client_model;
    interfaces::Node& m_node;
    const PlatformStyle* const m_platform_style;
    OptionsModel* const m_options_model;
    mutable QMutex m_mutex;
    std::vector<WalletModel*> m_wallets;
    std::unique_ptr<interfaces::Handler> m_handler_load_wallet;

    friend class WalletControllerActivity;
};

class WalletControllerActivity : public QObject
{
    Q_OBJECT

public:
    WalletControllerActivity(WalletController* wallet_controller, QWidget* parent_widget);
    virtual ~WalletControllerActivity();

Q_SIGNALS:
    void finished();

protected:
    interfaces::Node& node() const { return m_wallet_controller->m_node; }
    QObject* worker() const { return m_wallet_controller->m_activity_worker; }

    void showProgressDialog(const QString& label_text);
    void destroyProgressDialog();

    WalletController* const m_wallet_controller;
    QWidget* const m_parent_widget;
    QProgressDialog* m_progress_dialog{nullptr};
    WalletModel* m_wallet_model{nullptr};
    bilingual_str m_error_message;
    std::vector<bilingual_str> m_warning_message;
};


class CreateWalletActivity : public WalletControllerActivity
{
    Q_OBJECT

public:
    CreateWalletActivity(WalletController* wallet_controller, QWidget* parent_widget);
    virtual ~CreateWalletActivity();

    void create();

Q_SIGNALS:
    void created(WalletModel* wallet_model);

private:
    void askPassphrase();
    void createWallet();
    void finish();

    int m_walletType;
    bool m_importing;
    SecureString m_passphrase;
    SecureString m_ssMnemonic;
    SecureString m_ssMnemonicPassphrase;
    SecureString m_ssMasterKey;
    CreateWalletDialog* m_create_wallet_dialog{nullptr};
    AskPassphraseDialog* m_passphrase_dialog{nullptr};
};

class CreateWalletWizardActivity : public WalletControllerActivity
{
    Q_OBJECT

public:
    CreateWalletWizardActivity(WalletController* wallet_controller, QWidget* parent_widget);
    virtual ~CreateWalletWizardActivity();

    void create();

Q_SIGNALS:
    void created(WalletModel* wallet_model);

private:
    void askPassphrase();
    void createWallet();
    void finish();

    int m_walletType;
    bool m_importing;
    SecureString m_passphrase;
    SecureString m_ssMnemonic;
    SecureString m_ssMnemonicPassphrase;
    SecureString m_ssMasterKey;
    CreateWalletWizard* m_create_wallet_wizard{nullptr};
    AskPassphraseDialog* m_passphrase_dialog{nullptr};
};

class OpenWalletActivity : public WalletControllerActivity
{
    Q_OBJECT

public:
    OpenWalletActivity(WalletController* wallet_controller, QWidget* parent_widget);

    void open(const std::string& path);

Q_SIGNALS:
    void opened(WalletModel* wallet_model);

private:
    void finish();
};

#endif // BITCOIN_QT_WALLETCONTROLLER_H
