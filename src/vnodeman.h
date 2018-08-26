// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2017 The PIVX developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef VNODEMAN_H
#define VNODEMAN_H

#include "base58.h"
#include "key.h"
#include "main.h"
#include "vnode.h"
#include "net.h"
#include "sync.h"
#include "util.h"

#define VNODES_DUMP_SECONDS (15 * 60)
#define VNODES_DSEG_SECONDS (3 * 60 * 60)

using namespace std;

class CVnodeMan;

extern CVnodeMan mnodeman;
void DumpVnodes();

/** Access to the MN database (mncache.dat)
 */
class CVnodeDB
{
private:
    boost::filesystem::path pathMN;
    std::string strMagicMessage;

public:
    enum ReadResult {
        Ok,
        FileError,
        HashReadError,
        IncorrectHash,
        IncorrectMagicMessage,
        IncorrectMagicNumber,
        IncorrectFormat
    };

    CVnodeDB();
    bool Write(const CVnodeMan& mnodemanToSave);
    ReadResult Read(CVnodeMan& mnodemanToLoad, bool fDryRun = false);
};

class CVnodeMan
{
private:
    // critical section to protect the inner data structures
    mutable CCriticalSection cs;

    // critical section to protect the inner data structures specifically on messaging
    mutable CCriticalSection cs_process_message;

    // map to hold all MNs
    std::vector<CVnode> vVnodes;
    // who's asked for the Vnode list and the last time
    std::map<CNetAddr, int64_t> mAskedUsForVnodeList;
    // who we asked for the Vnode list and the last time
    std::map<CNetAddr, int64_t> mWeAskedForVnodeList;
    // which Vnodes we've asked for
    std::map<COutPoint, int64_t> mWeAskedForVnodeListEntry;

public:
    // Keep track of all broadcasts I've seen
    map<uint256, CVnodeBroadcast> mapSeenVnodeBroadcast;
    // Keep track of all pings I've seen
    map<uint256, CVnodePing> mapSeenVnodePing;

    // keep track of dsq count to prevent vnodes from gaming obfuscation queue
    int64_t nDsqCount;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        LOCK(cs);
        READWRITE(vVnodes);
        READWRITE(mAskedUsForVnodeList);
        READWRITE(mWeAskedForVnodeList);
        READWRITE(mWeAskedForVnodeListEntry);
        READWRITE(nDsqCount);

        READWRITE(mapSeenVnodeBroadcast);
        READWRITE(mapSeenVnodePing);
    }

    CVnodeMan();
    CVnodeMan(CVnodeMan& other);

    /// Add an entry
    bool Add(CVnode& mn);

    /// Ask (source) node for mnb
    void AskForMN(CNode* pnode, CTxIn& vin);

    /// Check all Vnodes
    void Check();

    /// Check all Vnodes and remove inactive
    void CheckAndRemove(bool forceExpiredRemoval = false);

    /// Clear Vnode vector
    void Clear();

    int CountEnabled(int protocolVersion = -1);

    void CountNetworks(int protocolVersion, int& ipv4, int& ipv6, int& onion);

    void DsegUpdate(CNode* pnode);

    /// Find an entry
    CVnode* Find(const CScript& payee);
    CVnode* Find(const CTxIn& vin);
    CVnode* Find(const CPubKey& pubKeyVnode);

    /// Find an entry in the vnode list that is next to be paid
    CVnode* GetNextVnodeInQueueForPayment(int nBlockHeight, bool fFilterSigTime, int& nCount);

    /// Find a random entry
    CVnode* FindRandomNotInVec(std::vector<CTxIn>& vecToExclude, int protocolVersion = -1);

    /// Get the current winner for this block
    CVnode* GetCurrentVNode(int mod = 1, int64_t nBlockHeight = 0, int minProtocol = 0);

    std::vector<CVnode> GetFullVnodeVector()
    {
        Check();
        return vVnodes;
    }

    std::vector<pair<int, CVnode> > GetVnodeRanks(int64_t nBlockHeight, int minProtocol = 0);
    int GetVnodeRank(const CTxIn& vin, int64_t nBlockHeight, int minProtocol = 0, bool fOnlyActive = true);
    CVnode* GetVnodeByRank(int nRank, int64_t nBlockHeight, int minProtocol = 0, bool fOnlyActive = true);

    void ProcessVnodeConnections();

    void ProcessMessage(CNode* pfrom, std::string& strCommand, CDataStream& vRecv);

    /// Return the number of (unique) Vnodes
    int size() { return vVnodes.size(); }

    /// Return the number of Vnodes older than (default) 8000 seconds
    int stable_size ();

    std::string ToString() const;

    void Remove(CTxIn vin);

    /// Update vnode list and maps using provided CVnodeBroadcast
    void UpdateVnodeList(CVnodeBroadcast mnb);
};

#endif
