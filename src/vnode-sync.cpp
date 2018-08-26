// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2017 The PIVX developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// clang-format off
#include "main.h"
#include "activevnode.h"
#include "vnode-sync.h"
#include "vnode-payments.h"
#include "vnode-budget.h"
#include "vnode.h"
#include "vnodeman.h"
#include "spork.h"
#include "util.h"
#include "addrman.h"
// clang-format on

class CVnodeSync;
CVnodeSync vnodeSync;

CVnodeSync::CVnodeSync()
{
    Reset();
}

bool CVnodeSync::IsSynced()
{
    return RequestedVnodeAssets == VNODE_SYNC_FINISHED;
}

bool CVnodeSync::IsBlockchainSynced()
{
    static bool fBlockchainSynced = false;
    static int64_t lastProcess = GetTime();

    // if the last call to this function was more than 60 minutes ago (client was in sleep mode) reset the sync process
    if (GetTime() - lastProcess > 60 * 60) {
        Reset();
        fBlockchainSynced = false;
    }
    lastProcess = GetTime();

    if (fBlockchainSynced) return true;

    if (fImporting || fReindex) return false;

    TRY_LOCK(cs_main, lockMain);
    if (!lockMain) return false;

    CBlockIndex* pindex = chainActive.Tip();

    if (chainActive.Height() == 600) {
        return true;
    }

    if (pindex == NULL) return false;


    if (pindex->nTime + (24 *60 * 60) < GetTime())
        return false;

    fBlockchainSynced = true;

    return true;
}

void CVnodeSync::Reset()
{
    lastVnodeList = 0;
    lastVnodeWinner = 0;
    lastBudgetItem = 0;
    mapSeenSyncMNB.clear();
    mapSeenSyncMNW.clear();
    mapSeenSyncBudget.clear();
    lastFailure = 0;
    nCountFailures = 0;
    sumVnodeList = 0;
    sumVnodeWinner = 0;
    sumBudgetItemProp = 0;
    sumBudgetItemFin = 0;
    countVnodeList = 0;
    countVnodeWinner = 0;
    countBudgetItemProp = 0;
    countBudgetItemFin = 0;
    RequestedVnodeAssets = VNODE_SYNC_INITIAL;
    RequestedVnodeAttempt = 0;
    nAssetSyncStarted = GetTime();
}

void CVnodeSync::AddedVnodeList(uint256 hash)
{
    if (mnodeman.mapSeenVnodeBroadcast.count(hash)) {
        if (mapSeenSyncMNB[hash] < VNODE_SYNC_THRESHOLD) {
            lastVnodeList = GetTime();
            mapSeenSyncMNB[hash]++;
        }
    } else {
        lastVnodeList = GetTime();
        mapSeenSyncMNB.insert(make_pair(hash, 1));
    }
}

void CVnodeSync::AddedVnodeWinner(uint256 hash)
{
    if (vnodePayments.mapVnodePayeeVotes.count(hash)) {
        if (mapSeenSyncMNW[hash] < VNODE_SYNC_THRESHOLD) {
            lastVnodeWinner = GetTime();
            mapSeenSyncMNW[hash]++;
        }
    } else {
        lastVnodeWinner = GetTime();
        mapSeenSyncMNW.insert(make_pair(hash, 1));
    }
}

void CVnodeSync::AddedBudgetItem(uint256 hash)
{
    if (budget.mapSeenVnodeBudgetProposals.count(hash) || budget.mapSeenVnodeBudgetVotes.count(hash) ||
        budget.mapSeenFinalizedBudgets.count(hash) || budget.mapSeenFinalizedBudgetVotes.count(hash)) {
        if (mapSeenSyncBudget[hash] < VNODE_SYNC_THRESHOLD) {
            lastBudgetItem = GetTime();
            mapSeenSyncBudget[hash]++;
        }
    } else {
        lastBudgetItem = GetTime();
        mapSeenSyncBudget.insert(make_pair(hash, 1));
    }
}

bool CVnodeSync::IsBudgetPropEmpty()
{
    return sumBudgetItemProp == 0 && countBudgetItemProp > 0;
}

bool CVnodeSync::IsBudgetFinEmpty()
{
    return sumBudgetItemFin == 0 && countBudgetItemFin > 0;
}

void CVnodeSync::GetNextAsset()
{
    switch (RequestedVnodeAssets) {
    case (VNODE_SYNC_INITIAL):
    case (VNODE_SYNC_FAILED): // should never be used here actually, use Reset() instead
        ClearFulfilledRequest();
        RequestedVnodeAssets = VNODE_SYNC_SPORKS;
        break;
    case (VNODE_SYNC_SPORKS):
        RequestedVnodeAssets = VNODE_SYNC_LIST;
        break;
    case (VNODE_SYNC_LIST):
        RequestedVnodeAssets = VNODE_SYNC_MNW;
        break;
    case (VNODE_SYNC_MNW):
        RequestedVnodeAssets = VNODE_SYNC_BUDGET;
        break;
    case (VNODE_SYNC_BUDGET):
        LogPrintf("CVnodeSync::GetNextAsset - Sync has finished\n");
        RequestedVnodeAssets = VNODE_SYNC_FINISHED;
        break;
    }
    RequestedVnodeAttempt = 0;
    nAssetSyncStarted = GetTime();
}

std::string CVnodeSync::GetSyncStatus()
{
    switch (vnodeSync.RequestedVnodeAssets) {
    case VNODE_SYNC_INITIAL:
        return _("Synchronization pending...");
    case VNODE_SYNC_SPORKS:
        return _("Synchronizing sporks...");
    case VNODE_SYNC_LIST:
        return _("Synchronizing vnodes...");
    case VNODE_SYNC_MNW:
        return _("Synchronizing vnode winners...");
    case VNODE_SYNC_BUDGET:
        return _("Synchronizing budgets...");
    case VNODE_SYNC_FAILED:
        return _("Synchronization failed");
    case VNODE_SYNC_FINISHED:
        return _("Synchronization finished");
    }
    return "";
}

void CVnodeSync::ProcessMessage(CNode* pfrom, std::string& strCommand, CDataStream& vRecv)
{
    if (strCommand == "ssc") { //Sync status count
        int nItemID;
        int nCount;
        vRecv >> nItemID >> nCount;

        if (RequestedVnodeAssets >= VNODE_SYNC_FINISHED) return;

        //this means we will receive no further communication
        switch (nItemID) {
        case (VNODE_SYNC_LIST):
            if (nItemID != RequestedVnodeAssets) return;
            sumVnodeList += nCount;
            countVnodeList++;
            break;
        case (VNODE_SYNC_MNW):
            if (nItemID != RequestedVnodeAssets) return;
            sumVnodeWinner += nCount;
            countVnodeWinner++;
            break;
        case (VNODE_SYNC_BUDGET_PROP):
            if (RequestedVnodeAssets != VNODE_SYNC_BUDGET) return;
            sumBudgetItemProp += nCount;
            countBudgetItemProp++;
            break;
        case (VNODE_SYNC_BUDGET_FIN):
            if (RequestedVnodeAssets != VNODE_SYNC_BUDGET) return;
            sumBudgetItemFin += nCount;
            countBudgetItemFin++;
            break;
        }

        LogPrint("vnode", "CVnodeSync:ProcessMessage - ssc - got inventory count %d %d\n", nItemID, nCount);
    }
}

void CVnodeSync::ClearFulfilledRequest()
{
    TRY_LOCK(cs_vNodes, lockRecv);
    if (!lockRecv) return;

    BOOST_FOREACH (CNode* pnode, vNodes) {
        pnode->ClearFulfilledRequest("getspork");
        pnode->ClearFulfilledRequest("mnsync");
        pnode->ClearFulfilledRequest("mnwsync");
        pnode->ClearFulfilledRequest("busync");
    }
}

void CVnodeSync::Process()
{
    static int tick = 0;
    static int syncCount = 0;

    if (tick++ % VNODE_SYNC_TIMEOUT != 0) return;

    if (IsSynced()) {
        /*
            Resync if we lose all vnodes from sleep/wake or failure to sync originally
        */
        if (mnodeman.CountEnabled() == 0 ) {
			if(syncCount < 2){
				Reset();
				syncCount++;
			}
        } else
            return;
    }

    //try syncing again
    if (RequestedVnodeAssets == VNODE_SYNC_FAILED && lastFailure + (1 * 60) < GetTime()) {
        Reset();
    } else if (RequestedVnodeAssets == VNODE_SYNC_FAILED) {
        return;
    }

    LogPrint("vnode", "CVnodeSync::Process() - tick %d RequestedVnodeAssets %d\n", tick, RequestedVnodeAssets);

    if (RequestedVnodeAssets == VNODE_SYNC_INITIAL) GetNextAsset();

    // sporks synced but blockchain is not, wait until we're almost at a recent block to continue
    if (Params().NetworkID() != CBaseChainParams::REGTEST &&
        !IsBlockchainSynced() && RequestedVnodeAssets > VNODE_SYNC_SPORKS) return;

    TRY_LOCK(cs_vNodes, lockRecv);
    if (!lockRecv) return;

    BOOST_FOREACH (CNode* pnode, vNodes) {
        if (Params().NetworkID() == CBaseChainParams::REGTEST) {
            if (RequestedVnodeAttempt <= 2) {
                pnode->PushMessage("getsporks"); //get current network sporks
            } else if (RequestedVnodeAttempt < 4) {
                mnodeman.DsegUpdate(pnode);
            } else if (RequestedVnodeAttempt < 6) {
                int nMnCount = mnodeman.CountEnabled();
                pnode->PushMessage("mnget", nMnCount); //sync payees
                uint256 n = 0;
                pnode->PushMessage("mnvs", n); //sync vnode votes
            } else {
                RequestedVnodeAssets = VNODE_SYNC_FINISHED;
            }
            RequestedVnodeAttempt++;
            return;
        }

        //set to synced
        if (RequestedVnodeAssets == VNODE_SYNC_SPORKS) {
            if (pnode->HasFulfilledRequest("getspork")) continue;
            pnode->FulfilledRequest("getspork");

            pnode->PushMessage("getsporks"); //get current network sporks
            if (RequestedVnodeAttempt >= 2) GetNextAsset();
            RequestedVnodeAttempt++;

            return;
        }

        if (pnode->nVersion >= vnodePayments.GetMinVnodePaymentsProto()) {
            if (RequestedVnodeAssets == VNODE_SYNC_LIST) {
                LogPrint("vnode", "CVnodeSync::Process() - lastVnodeList %lld (GetTime() - VNODE_SYNC_TIMEOUT) %lld\n", lastVnodeList, GetTime() - VNODE_SYNC_TIMEOUT);
                if (lastVnodeList > 0 && lastVnodeList < GetTime() - VNODE_SYNC_TIMEOUT * 2 && RequestedVnodeAttempt >= VNODE_SYNC_THRESHOLD) { //hasn't received a new item in the last five seconds, so we'll move to the
                    GetNextAsset();
                    return;
                }

                if (pnode->HasFulfilledRequest("mnsync")) continue;
                pnode->FulfilledRequest("mnsync");

                // timeout
                if (lastVnodeList == 0 &&
                    (RequestedVnodeAttempt >= VNODE_SYNC_THRESHOLD * 3 || GetTime() - nAssetSyncStarted > VNODE_SYNC_TIMEOUT * 5)) {
                    if (IsSporkActive(SPORK_8_VNODE_PAYMENT_ENFORCEMENT)) {
                        LogPrintf("CVnodeSync::Process - ERROR - Sync has failed, will retry later\n");
                        RequestedVnodeAssets = VNODE_SYNC_FAILED;
                        RequestedVnodeAttempt = 0;
                        lastFailure = GetTime();
                        nCountFailures++;
                    } else {
                        GetNextAsset();
                    }
                    return;
                }

                if (RequestedVnodeAttempt >= VNODE_SYNC_THRESHOLD * 3) return;

                mnodeman.DsegUpdate(pnode);
                RequestedVnodeAttempt++;
                return;
            }

            if (RequestedVnodeAssets == VNODE_SYNC_MNW) {
                if (lastVnodeWinner > 0 && lastVnodeWinner < GetTime() - VNODE_SYNC_TIMEOUT * 2 && RequestedVnodeAttempt >= VNODE_SYNC_THRESHOLD) { //hasn't received a new item in the last five seconds, so we'll move to the
                    GetNextAsset();
                    return;
                }

                if (pnode->HasFulfilledRequest("mnwsync")) continue;
                pnode->FulfilledRequest("mnwsync");

                // timeout
                if (lastVnodeWinner == 0 &&
                    (RequestedVnodeAttempt >= VNODE_SYNC_THRESHOLD * 3 || GetTime() - nAssetSyncStarted > VNODE_SYNC_TIMEOUT * 5)) {
                    if (IsSporkActive(SPORK_8_VNODE_PAYMENT_ENFORCEMENT)) {
                        LogPrintf("CVnodeSync::Process - ERROR - Sync has failed, will retry later\n");
                        RequestedVnodeAssets = VNODE_SYNC_FAILED;
                        RequestedVnodeAttempt = 0;
                        lastFailure = GetTime();
                        nCountFailures++;
                    } else {
                        GetNextAsset();
                    }
                    return;
                }

                if (RequestedVnodeAttempt >= VNODE_SYNC_THRESHOLD * 3) return;

                CBlockIndex* pindexPrev = chainActive.Tip();
                if (pindexPrev == NULL) return;

                int nMnCount = mnodeman.CountEnabled();
                pnode->PushMessage("mnget", nMnCount); //sync payees
                RequestedVnodeAttempt++;

                return;
            }
        }

        if (pnode->nVersion >= ActiveProtocol()) {
            if (RequestedVnodeAssets == VNODE_SYNC_BUDGET) {

                // We'll start rejecting votes if we accidentally get set as synced too soon
                if (lastBudgetItem > 0 && lastBudgetItem < GetTime() - VNODE_SYNC_TIMEOUT * 2 && RequestedVnodeAttempt >= VNODE_SYNC_THRESHOLD) {

                    // Hasn't received a new item in the last five seconds, so we'll move to the
                    GetNextAsset();

                    // Try to activate our vnode if possible
                    activeVnode.ManageStatus();

                    return;
                }

                // timeout
                if (lastBudgetItem == 0 &&
                    (RequestedVnodeAttempt >= VNODE_SYNC_THRESHOLD * 3 || GetTime() - nAssetSyncStarted > VNODE_SYNC_TIMEOUT * 5)) {
                    // maybe there is no budgets at all, so just finish syncing
                    GetNextAsset();
                    activeVnode.ManageStatus();
                    return;
                }

                if (pnode->HasFulfilledRequest("busync")) continue;
                pnode->FulfilledRequest("busync");

                if (RequestedVnodeAttempt >= VNODE_SYNC_THRESHOLD * 3) return;

                uint256 n = 0;
                pnode->PushMessage("mnvs", n); //sync vnode votes
                RequestedVnodeAttempt++;

                return;
            }
        }
    }
}
