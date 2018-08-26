// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2017 The PIVX developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef VNODE_SYNC_H
#define VNODE_SYNC_H

#define VNODE_SYNC_INITIAL 0
#define VNODE_SYNC_SPORKS 1
#define VNODE_SYNC_LIST 2
#define VNODE_SYNC_MNW 3
#define VNODE_SYNC_BUDGET 4
#define VNODE_SYNC_BUDGET_PROP 10
#define VNODE_SYNC_BUDGET_FIN 11
#define VNODE_SYNC_FAILED 998
#define VNODE_SYNC_FINISHED 999

#define VNODE_SYNC_TIMEOUT 5
#define VNODE_SYNC_THRESHOLD 2

class CVnodeSync;
extern CVnodeSync vnodeSync;

//
// CVnodeSync : Sync vnode assets in stages
//

class CVnodeSync
{
public:
    std::map<uint256, int> mapSeenSyncMNB;
    std::map<uint256, int> mapSeenSyncMNW;
    std::map<uint256, int> mapSeenSyncBudget;

    int64_t lastVnodeList;
    int64_t lastVnodeWinner;
    int64_t lastBudgetItem;
    int64_t lastFailure;
    int nCountFailures;

    // sum of all counts
    int sumVnodeList;
    int sumVnodeWinner;
    int sumBudgetItemProp;
    int sumBudgetItemFin;
    // peers that reported counts
    int countVnodeList;
    int countVnodeWinner;
    int countBudgetItemProp;
    int countBudgetItemFin;

    // Count peers we've requested the list from
    int RequestedVnodeAssets;
    int RequestedVnodeAttempt;

    // Time when current vnode asset sync started
    int64_t nAssetSyncStarted;

    CVnodeSync();

    void AddedVnodeList(uint256 hash);
    void AddedVnodeWinner(uint256 hash);
    void AddedBudgetItem(uint256 hash);
    void GetNextAsset();
    std::string GetSyncStatus();
    void ProcessMessage(CNode* pfrom, std::string& strCommand, CDataStream& vRecv);
    bool IsBudgetFinEmpty();
    bool IsBudgetPropEmpty();

    void Reset();
    void Process();
    bool IsSynced();
    bool IsBlockchainSynced();
    bool IsVnodeListSynced() { return RequestedVnodeAssets > VNODE_SYNC_LIST; }
    void ClearFulfilledRequest();
};

#endif
