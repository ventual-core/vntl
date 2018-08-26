#include "vnodelist.h"
#include "ui_vnodelist.h"

#include "activevnode.h"
#include "clientmodel.h"
#include "guiutil.h"
#include "init.h"
#include "vnode-sync.h"
#include "vnodeconfig.h"
#include "vnodeman.h"
#include "sync.h"
#include "wallet.h"
#include "walletmodel.h"

#include <QMessageBox>
#include <QTimer>

CCriticalSection cs_vnodes;

VnodeList::VnodeList(QWidget* parent) : QWidget(parent),
                                                  ui(new Ui::VnodeList),
                                                  clientModel(0),
                                                  walletModel(0)
{
    ui->setupUi(this);

    ui->startButton->setEnabled(false);

    int columnAliasWidth = 100;
    int columnAddressWidth = 200;
    int columnProtocolWidth = 60;
    int columnStatusWidth = 80;
    int columnActiveWidth = 130;
    int columnLastSeenWidth = 130;

    ui->tableWidgetMyVnodes->setColumnWidth(0, columnAliasWidth);
    ui->tableWidgetMyVnodes->setColumnWidth(1, columnAddressWidth);
    ui->tableWidgetMyVnodes->setColumnWidth(2, columnProtocolWidth);
    ui->tableWidgetMyVnodes->setColumnWidth(3, columnStatusWidth);
    ui->tableWidgetMyVnodes->setColumnWidth(4, columnActiveWidth);
    ui->tableWidgetMyVnodes->setColumnWidth(5, columnLastSeenWidth);

    ui->tableWidgetVnodes->setColumnWidth(0, columnAddressWidth);
    ui->tableWidgetVnodes->setColumnWidth(1, columnProtocolWidth);
    ui->tableWidgetVnodes->setColumnWidth(2, columnStatusWidth);
    ui->tableWidgetVnodes->setColumnWidth(3, columnActiveWidth);
    ui->tableWidgetVnodes->setColumnWidth(4, columnLastSeenWidth);

    ui->tableWidgetMyVnodes->setContextMenuPolicy(Qt::CustomContextMenu);

    QAction* startAliasAction = new QAction(tr("Start alias"), this);
    contextMenu = new QMenu();
    contextMenu->addAction(startAliasAction);
    connect(ui->tableWidgetMyVnodes, SIGNAL(customContextMenuRequested(const QPoint&)), this, SLOT(showContextMenu(const QPoint&)));
    connect(startAliasAction, SIGNAL(triggered()), this, SLOT(on_startButton_clicked()));

    timer = new QTimer(this);
    connect(timer, SIGNAL(timeout()), this, SLOT(updateNodeList()));
    connect(timer, SIGNAL(timeout()), this, SLOT(updateMyNodeList()));
    timer->start(1000);

    // Fill MN list
    fFilterUpdated = true;
    nTimeFilterUpdated = GetTime();
    updateNodeList();
}

VnodeList::~VnodeList()
{
    delete ui;
}

void VnodeList::setClientModel(ClientModel* model)
{
    this->clientModel = model;
}

void VnodeList::setWalletModel(WalletModel* model)
{
    this->walletModel = model;
}

void VnodeList::showContextMenu(const QPoint& point)
{
    QTableWidgetItem* item = ui->tableWidgetMyVnodes->itemAt(point);
    if (item) contextMenu->exec(QCursor::pos());
}

void VnodeList::StartAlias(std::string strAlias)
{
    std::string strStatusHtml;
    strStatusHtml += "<center>Alias: " + strAlias;

    BOOST_FOREACH (CVnodeConfig::CVnodeEntry mne, vnodeConfig.getEntries()) {
        if (mne.getAlias() == strAlias) {
            std::string strError;
            CVnodeBroadcast mnb;

            bool fSuccess = CVnodeBroadcast::Create(mne.getIp(), mne.getPrivKey(), mne.getTxHash(), mne.getOutputIndex(), strError, mnb);

            if (fSuccess) {
                strStatusHtml += "<br>Successfully started vnode.";
                mnodeman.UpdateVnodeList(mnb);
                mnb.Relay();
            } else {
                strStatusHtml += "<br>Failed to start vnode.<br>Error: " + strError;
            }
            break;
        }
    }
    strStatusHtml += "</center>";

    QMessageBox msg;
    msg.setText(QString::fromStdString(strStatusHtml));
    msg.exec();

    updateMyNodeList(true);
}

void VnodeList::StartAll(std::string strCommand)
{
    int nCountSuccessful = 0;
    int nCountFailed = 0;
    std::string strFailedHtml;

    BOOST_FOREACH (CVnodeConfig::CVnodeEntry mne, vnodeConfig.getEntries()) {
        std::string strError;
        CVnodeBroadcast mnb;

        int nIndex;
        if(!mne.castOutputIndex(nIndex))
            continue;

        CTxIn txin = CTxIn(uint256S(mne.getTxHash()), uint32_t(nIndex));
        CVnode* pmn = mnodeman.Find(txin);

        if (strCommand == "start-missing" && pmn) continue;

        bool fSuccess = CVnodeBroadcast::Create(mne.getIp(), mne.getPrivKey(), mne.getTxHash(), mne.getOutputIndex(), strError, mnb);

        if (fSuccess) {
            nCountSuccessful++;
            mnodeman.UpdateVnodeList(mnb);
            mnb.Relay();
        } else {
            nCountFailed++;
            strFailedHtml += "\nFailed to start " + mne.getAlias() + ". Error: " + strError;
        }
    }
    pwalletMain->Lock();

    std::string returnObj;
    returnObj = strprintf("Successfully started %d vnodes, failed to start %d, total %d", nCountSuccessful, nCountFailed, nCountFailed + nCountSuccessful);
    if (nCountFailed > 0) {
        returnObj += strFailedHtml;
    }

    QMessageBox msg;
    msg.setText(QString::fromStdString(returnObj));
    msg.exec();

    updateMyNodeList(true);
}

void VnodeList::updateMyVnodeInfo(QString strAlias, QString strAddr, CVnode* pmn)
{
    LOCK(cs_mnlistupdate);
    bool fOldRowFound = false;
    int nNewRow = 0;

    for (int i = 0; i < ui->tableWidgetMyVnodes->rowCount(); i++) {
        if (ui->tableWidgetMyVnodes->item(i, 0)->text() == strAlias) {
            fOldRowFound = true;
            nNewRow = i;
            break;
        }
    }

    if (nNewRow == 0 && !fOldRowFound) {
        nNewRow = ui->tableWidgetMyVnodes->rowCount();
        ui->tableWidgetMyVnodes->insertRow(nNewRow);
    }

    QTableWidgetItem* aliasItem = new QTableWidgetItem(strAlias);
    QTableWidgetItem* addrItem = new QTableWidgetItem(pmn ? QString::fromStdString(pmn->addr.ToString()) : strAddr);
    QTableWidgetItem* protocolItem = new QTableWidgetItem(QString::number(pmn ? pmn->protocolVersion : -1));
    QTableWidgetItem* statusItem = new QTableWidgetItem(QString::fromStdString(pmn ? pmn->GetStatus() : "MISSING"));
    GUIUtil::DHMSTableWidgetItem* activeSecondsItem = new GUIUtil::DHMSTableWidgetItem(pmn ? (pmn->lastPing.sigTime - pmn->sigTime) : 0);
    QTableWidgetItem* lastSeenItem = new QTableWidgetItem(QString::fromStdString(DateTimeStrFormat("%Y-%m-%d %H:%M", pmn ? pmn->lastPing.sigTime : 0)));
    QTableWidgetItem* pubkeyItem = new QTableWidgetItem(QString::fromStdString(pmn ? CBitcoinAddress(pmn->pubKeyCollateralAddress.GetID()).ToString() : ""));

    ui->tableWidgetMyVnodes->setItem(nNewRow, 0, aliasItem);
    ui->tableWidgetMyVnodes->setItem(nNewRow, 1, addrItem);
    ui->tableWidgetMyVnodes->setItem(nNewRow, 2, protocolItem);
    ui->tableWidgetMyVnodes->setItem(nNewRow, 3, statusItem);
    ui->tableWidgetMyVnodes->setItem(nNewRow, 4, activeSecondsItem);
    ui->tableWidgetMyVnodes->setItem(nNewRow, 5, lastSeenItem);
    ui->tableWidgetMyVnodes->setItem(nNewRow, 6, pubkeyItem);
}

void VnodeList::updateMyNodeList(bool fForce)
{
    static int64_t nTimeMyListUpdated = 0;

    // automatically update my vnode list only once in MY_VNODELIST_UPDATE_SECONDS seconds,
    // this update still can be triggered manually at any time via button click
    int64_t nSecondsTillUpdate = nTimeMyListUpdated + MY_VNODELIST_UPDATE_SECONDS - GetTime();
    ui->secondsLabel->setText(QString::number(nSecondsTillUpdate));

    if (nSecondsTillUpdate > 0 && !fForce) return;
    nTimeMyListUpdated = GetTime();

    ui->tableWidgetVnodes->setSortingEnabled(false);
    BOOST_FOREACH (CVnodeConfig::CVnodeEntry mne, vnodeConfig.getEntries()) {
        int nIndex;
        if(!mne.castOutputIndex(nIndex))
            continue;

        CTxIn txin = CTxIn(uint256S(mne.getTxHash()), uint32_t(nIndex));
        CVnode* pmn = mnodeman.Find(txin);
	updateMyVnodeInfo(QString::fromStdString(mne.getAlias()), QString::fromStdString(mne.getIp()), pmn);

    }
    ui->tableWidgetVnodes->setSortingEnabled(true);

    // reset "timer"
    ui->secondsLabel->setText("0");
}


void VnodeList::updateNodeList()
{
    static int64_t nTimeListUpdated = GetTime();

    // to prevent high cpu usage update only once in VNODELIST_UPDATE_SECONDS seconds
    // or VNODELIST_FILTER_COOLDOWN_SECONDS seconds after filter was last changed
    int64_t nSecondsToWait = fFilterUpdated ? nTimeFilterUpdated - GetTime() + VNODELIST_FILTER_COOLDOWN_SECONDS : nTimeListUpdated - GetTime() + VNODELIST_UPDATE_SECONDS;

    if (fFilterUpdated) ui->countLabel->setText(QString::fromStdString(strprintf("Please wait... %d", nSecondsToWait)));
    if (nSecondsToWait > 0) return;

    nTimeListUpdated = GetTime();
    fFilterUpdated = false;

    TRY_LOCK(cs_vnodes, lockVnodes);
    if (!lockVnodes) return;

    QString strToFilter;
    ui->countLabel->setText("Updating...");
    ui->tableWidgetVnodes->setSortingEnabled(false);
    ui->tableWidgetVnodes->clearContents();
    ui->tableWidgetVnodes->setRowCount(0);
    std::vector<CVnode> vVnodes = mnodeman.GetFullVnodeVector();

    BOOST_FOREACH (CVnode& mn, vVnodes) {
        // populate list
        // Address, Protocol, Status, Active Seconds, Last Seen, Pub Key
        QTableWidgetItem* addressItem = new QTableWidgetItem(QString::fromStdString(mn.addr.ToString()));
        QTableWidgetItem* protocolItem = new QTableWidgetItem(QString::number(mn.protocolVersion));
        QTableWidgetItem* statusItem = new QTableWidgetItem(QString::fromStdString(mn.GetStatus()));
        GUIUtil::DHMSTableWidgetItem* activeSecondsItem = new GUIUtil::DHMSTableWidgetItem(mn.lastPing.sigTime - mn.sigTime);
        QTableWidgetItem* lastSeenItem = new QTableWidgetItem(QString::fromStdString(DateTimeStrFormat("%Y-%m-%d %H:%M", mn.lastPing.sigTime)));
        QTableWidgetItem* pubkeyItem = new QTableWidgetItem(QString::fromStdString(CBitcoinAddress(mn.pubKeyCollateralAddress.GetID()).ToString()));

        if (strCurrentFilter != "") {
            strToFilter = addressItem->text() + " " +
                          protocolItem->text() + " " +
                          statusItem->text() + " " +
                          activeSecondsItem->text() + " " +
                          lastSeenItem->text() + " " +
                          pubkeyItem->text();
            if (!strToFilter.contains(strCurrentFilter)) continue;
        }

        ui->tableWidgetVnodes->insertRow(0);
        ui->tableWidgetVnodes->setItem(0, 0, addressItem);
        ui->tableWidgetVnodes->setItem(0, 1, protocolItem);
        ui->tableWidgetVnodes->setItem(0, 2, statusItem);
        ui->tableWidgetVnodes->setItem(0, 3, activeSecondsItem);
        ui->tableWidgetVnodes->setItem(0, 4, lastSeenItem);
        ui->tableWidgetVnodes->setItem(0, 5, pubkeyItem);
    }

    ui->countLabel->setText(QString::number(ui->tableWidgetVnodes->rowCount()));
    ui->tableWidgetVnodes->setSortingEnabled(true);
}


void VnodeList::on_filterLineEdit_textChanged(const QString& strFilterIn)
{
    strCurrentFilter = strFilterIn;
    nTimeFilterUpdated = GetTime();
    fFilterUpdated = true;
    ui->countLabel->setText(QString::fromStdString(strprintf("Please wait... %d", VNODELIST_FILTER_COOLDOWN_SECONDS)));
}

void VnodeList::on_startButton_clicked()
{
    // Find selected node alias
    QItemSelectionModel* selectionModel = ui->tableWidgetMyVnodes->selectionModel();
    QModelIndexList selected = selectionModel->selectedRows();

    if (selected.count() == 0) return;

    QModelIndex index = selected.at(0);
    int nSelectedRow = index.row();
    std::string strAlias = ui->tableWidgetMyVnodes->item(nSelectedRow, 0)->text().toStdString();

    // Display message box
    QMessageBox::StandardButton retval = QMessageBox::question(this, tr("Confirm vnode start"),
        tr("Are you sure you want to start vnode %1?").arg(QString::fromStdString(strAlias)),
        QMessageBox::Yes | QMessageBox::Cancel,
        QMessageBox::Cancel);

    if (retval != QMessageBox::Yes) return;

    WalletModel::EncryptionStatus encStatus = walletModel->getEncryptionStatus();

    if (encStatus == walletModel->Locked || encStatus == walletModel->UnlockedForAnonymizationOnly) {
        WalletModel::UnlockContext ctx(walletModel->requestUnlock());

        if (!ctx.isValid()) return; // Unlock wallet was cancelled

        StartAlias(strAlias);
        return;
    }

    StartAlias(strAlias);
}

void VnodeList::on_startAllButton_clicked()
{
    // Display message box
    QMessageBox::StandardButton retval = QMessageBox::question(this, tr("Confirm all vnodes start"),
        tr("Are you sure you want to start ALL vnodes?"),
        QMessageBox::Yes | QMessageBox::Cancel,
        QMessageBox::Cancel);

    if (retval != QMessageBox::Yes) return;

    WalletModel::EncryptionStatus encStatus = walletModel->getEncryptionStatus();

    if (encStatus == walletModel->Locked || encStatus == walletModel->UnlockedForAnonymizationOnly) {
        WalletModel::UnlockContext ctx(walletModel->requestUnlock());

        if (!ctx.isValid()) return; // Unlock wallet was cancelled

        StartAll();
        return;
    }

    StartAll();
}

void VnodeList::on_startMissingButton_clicked()
{
    if (!vnodeSync.IsVnodeListSynced()) {
        QMessageBox::critical(this, tr("Command is not available right now"),
            tr("You can't use this command until vnode list is synced"));
        return;
    }

    // Display message box
    QMessageBox::StandardButton retval = QMessageBox::question(this,
        tr("Confirm missing vnodes start"),
        tr("Are you sure you want to start MISSING vnodes?"),
        QMessageBox::Yes | QMessageBox::Cancel,
        QMessageBox::Cancel);

    if (retval != QMessageBox::Yes) return;

    WalletModel::EncryptionStatus encStatus = walletModel->getEncryptionStatus();

    if (encStatus == walletModel->Locked || encStatus == walletModel->UnlockedForAnonymizationOnly) {
        WalletModel::UnlockContext ctx(walletModel->requestUnlock());

        if (!ctx.isValid()) return; // Unlock wallet was cancelled

        StartAll("start-missing");
        return;
    }

    StartAll("start-missing");
}

void VnodeList::on_tableWidgetMyVnodes_itemSelectionChanged()
{
    if (ui->tableWidgetMyVnodes->selectedItems().count() > 0) {
        ui->startButton->setEnabled(true);
    }
}

void VnodeList::on_UpdateButton_clicked()
{
    updateMyNodeList(true);
}
