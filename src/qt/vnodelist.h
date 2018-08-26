#ifndef VNODELIST_H
#define VNODELIST_H

#include "vnode.h"
#include "platformstyle.h"
#include "sync.h"
#include "util.h"

#include <QMenu>
#include <QTimer>
#include <QWidget>

#define MY_VNODELIST_UPDATE_SECONDS 60
#define VNODELIST_UPDATE_SECONDS 15
#define VNODELIST_FILTER_COOLDOWN_SECONDS 3

namespace Ui
{
class VnodeList;
}

class ClientModel;
class WalletModel;

QT_BEGIN_NAMESPACE
class QModelIndex;
QT_END_NAMESPACE

/** Vnode Manager page widget */
class VnodeList : public QWidget
{
    Q_OBJECT

public:
    explicit VnodeList(QWidget* parent = 0);
    ~VnodeList();

    void setClientModel(ClientModel* clientModel);
    void setWalletModel(WalletModel* walletModel);
    void StartAlias(std::string strAlias);
    void StartAll(std::string strCommand = "start-all");

private:
    QMenu* contextMenu;
    int64_t nTimeFilterUpdated;
    bool fFilterUpdated;

public Q_SLOTS:
    void updateMyVnodeInfo(QString strAlias, QString strAddr, CVnode* pmn);
    void updateMyNodeList(bool fForce = false);
    void updateNodeList();
Q_SIGNALS:

private:
    QTimer* timer;
    Ui::VnodeList* ui;
    ClientModel* clientModel;
    WalletModel* walletModel;
    CCriticalSection cs_mnlistupdate;
    QString strCurrentFilter;

private Q_SLOTS:
    void showContextMenu(const QPoint&);
    void on_filterLineEdit_textChanged(const QString& strFilterIn);
    void on_startButton_clicked();
    void on_startAllButton_clicked();
    void on_startMissingButton_clicked();
    void on_tableWidgetMyVnodes_itemSelectionChanged();
    void on_UpdateButton_clicked();
};
#endif // VNODELIST_H
