// Copyright (c) 2014-2016 The Dash developers
// Copyright (c) 2015-2017 The PIVX developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ACTIVEVNODE_H
#define ACTIVEVNODE_H

#include "init.h"
#include "key.h"
#include "vnode.h"
#include "net.h"
#include "obfuscation.h"
#include "sync.h"
#include "wallet.h"

#define ACTIVE_VNODE_INITIAL 0 // initial state
#define ACTIVE_VNODE_SYNC_IN_PROCESS 1
#define ACTIVE_VNODE_INPUT_TOO_NEW 2
#define ACTIVE_VNODE_NOT_CAPABLE 3
#define ACTIVE_VNODE_STARTED 4

// Responsible for activating the Vnode and pinging the network
class CActiveVnode
{
private:
    // critical section to protect the inner data structures
    mutable CCriticalSection cs;

    /// Ping Vnode
    bool SendVnodePing(std::string& errorMessage);

    /// Register any Vnode
    bool Register(CTxIn vin, CService service, CKey key, CPubKey pubKey, CKey keyVnode, CPubKey pubKeyVnode, std::string& errorMessage);

    /// Get 10000 VENTUAL input that can be used for the Vnode
    bool GetVNodeVin(CTxIn& vin, CPubKey& pubkey, CKey& secretKey, std::string strTxHash, std::string strOutputIndex);
    bool GetVinFromOutput(COutput out, CTxIn& vin, CPubKey& pubkey, CKey& secretKey);

public:
    // Initialized by init.cpp
    // Keys for the main Vnode
    CPubKey pubKeyVnode;

    // Initialized while registering Vnode
    CTxIn vin;
    CService service;

    int status;
    std::string notCapableReason;

    CActiveVnode()
    {
        status = ACTIVE_VNODE_INITIAL;
    }

    /// Manage status of main Vnode
    void ManageStatus();
    std::string GetStatus();

    /// Register remote Vnode
    bool Register(std::string strService, std::string strKey, std::string strTxHash, std::string strOutputIndex, std::string& errorMessage);

    /// Get 10000 VENTUAL input that can be used for the Vnode
    bool GetVNodeVin(CTxIn& vin, CPubKey& pubkey, CKey& secretKey);
    vector<COutput> SelectCoinsVnode();

    /// Enable cold wallet mode (run a Vnode with no funds)
    bool EnableHotColdVNode(CTxIn& vin, CService& addr);
};

#endif
