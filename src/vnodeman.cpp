// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2017 The PIVX developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "vnodeman.h"
#include "activevnode.h"
#include "addrman.h"
#include "vnode.h"
#include "obfuscation.h"
#include "spork.h"
#include "util.h"
#include <boost/filesystem.hpp>
#include <boost/lexical_cast.hpp>

#define MN_WINNER_MINIMUM_AGE 8000    // Age in seconds. This should be > VNODE_REMOVAL_SECONDS to avoid misconfigured new nodes in the list.

/** Vnode manager */
CVnodeMan mnodeman;

struct CompareLastPaid {
    bool operator()(const pair<int64_t, CTxIn>& t1,
        const pair<int64_t, CTxIn>& t2) const
    {
        return t1.first < t2.first;
    }
};

struct CompareScoreTxIn {
    bool operator()(const pair<int64_t, CTxIn>& t1,
        const pair<int64_t, CTxIn>& t2) const
    {
        return t1.first < t2.first;
    }
};

struct CompareScoreMN {
    bool operator()(const pair<int64_t, CVnode>& t1,
        const pair<int64_t, CVnode>& t2) const
    {
        return t1.first < t2.first;
    }
};

//
// CVnodeDB
//

CVnodeDB::CVnodeDB()
{
    pathMN = GetDataDir() / "mncache.dat";
    strMagicMessage = "VnodeCache";
}

bool CVnodeDB::Write(const CVnodeMan& mnodemanToSave)
{
    int64_t nStart = GetTimeMillis();

    // serialize, checksum data up to that point, then append checksum
    CDataStream ssVnodes(SER_DISK, CLIENT_VERSION);
    ssVnodes << strMagicMessage;                   // vnode cache file specific magic message
    ssVnodes << FLATDATA(Params().MessageStart()); // network specific magic number
    ssVnodes << mnodemanToSave;
    uint256 hash = Hash(ssVnodes.begin(), ssVnodes.end());
    ssVnodes << hash;

    // open output file, and associate with CAutoFile
    FILE* file = fopen(pathMN.string().c_str(), "wb");
    CAutoFile fileout(file, SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull())
        return error("%s : Failed to open file %s", __func__, pathMN.string());

    // Write and commit header, data
    try {
        fileout << ssVnodes;
    } catch (std::exception& e) {
        return error("%s : Serialize or I/O error - %s", __func__, e.what());
    }
    //    FileCommit(fileout);
    fileout.fclose();

    LogPrint("vnode","Written info to mncache.dat  %dms\n", GetTimeMillis() - nStart);
    LogPrint("vnode","  %s\n", mnodemanToSave.ToString());

    return true;
}

CVnodeDB::ReadResult CVnodeDB::Read(CVnodeMan& mnodemanToLoad, bool fDryRun)
{
    int64_t nStart = GetTimeMillis();
    // open input file, and associate with CAutoFile
    FILE* file = fopen(pathMN.string().c_str(), "rb");
    CAutoFile filein(file, SER_DISK, CLIENT_VERSION);
    if (filein.IsNull()) {
        error("%s : Failed to open file %s", __func__, pathMN.string());
        return FileError;
    }

    // use file size to size memory buffer
    int fileSize = boost::filesystem::file_size(pathMN);
    int dataSize = fileSize - sizeof(uint256);
    // Don't try to resize to a negative number if file is small
    if (dataSize < 0)
        dataSize = 0;
    vector<unsigned char> vchData;
    vchData.resize(dataSize);
    uint256 hashIn;

    // read data and checksum from file
    try {
        filein.read((char*)&vchData[0], dataSize);
        filein >> hashIn;
    } catch (std::exception& e) {
        error("%s : Deserialize or I/O error - %s", __func__, e.what());
        return HashReadError;
    }
    filein.fclose();

    CDataStream ssVnodes(vchData, SER_DISK, CLIENT_VERSION);

    // verify stored checksum matches input data
    uint256 hashTmp = Hash(ssVnodes.begin(), ssVnodes.end());
    if (hashIn != hashTmp) {
        error("%s : Checksum mismatch, data corrupted", __func__);
        return IncorrectHash;
    }

    unsigned char pchMsgTmp[4];
    std::string strMagicMessageTmp;
    try {
        // de-serialize file header (vnode cache file specific magic message) and ..

        ssVnodes >> strMagicMessageTmp;

        // ... verify the message matches predefined one
        if (strMagicMessage != strMagicMessageTmp) {
            error("%s : Invalid vnode cache magic message", __func__);
            return IncorrectMagicMessage;
        }

        // de-serialize file header (network specific magic number) and ..
        ssVnodes >> FLATDATA(pchMsgTmp);

        // ... verify the network matches ours
        if (memcmp(pchMsgTmp, Params().MessageStart(), sizeof(pchMsgTmp))) {
            error("%s : Invalid network magic number", __func__);
            return IncorrectMagicNumber;
        }
        // de-serialize data into CVnodeMan object
        ssVnodes >> mnodemanToLoad;
    } catch (std::exception& e) {
        mnodemanToLoad.Clear();
        error("%s : Deserialize or I/O error - %s", __func__, e.what());
        return IncorrectFormat;
    }

    LogPrint("vnode","Loaded info from mncache.dat  %dms\n", GetTimeMillis() - nStart);
    LogPrint("vnode","  %s\n", mnodemanToLoad.ToString());
    if (!fDryRun) {
        LogPrint("vnode","Vnode manager - cleaning....\n");
        mnodemanToLoad.CheckAndRemove(true);
        LogPrint("vnode","Vnode manager - result:\n");
        LogPrint("vnode","  %s\n", mnodemanToLoad.ToString());
    }

    return Ok;
}

void DumpVnodes()
{
    int64_t nStart = GetTimeMillis();

    CVnodeDB mndb;
    CVnodeMan tempMnodeman;

    LogPrint("vnode","Verifying mncache.dat format...\n");
    CVnodeDB::ReadResult readResult = mndb.Read(tempMnodeman, true);
    // there was an error and it was not an error on file opening => do not proceed
    if (readResult == CVnodeDB::FileError)
        LogPrint("vnode","Missing vnode cache file - mncache.dat, will try to recreate\n");
    else if (readResult != CVnodeDB::Ok) {
        LogPrint("vnode","Error reading mncache.dat: ");
        if (readResult == CVnodeDB::IncorrectFormat)
            LogPrint("vnode","magic is ok but data has invalid format, will try to recreate\n");
        else {
            LogPrint("vnode","file format is unknown or invalid, please fix it manually\n");
            return;
        }
    }
    LogPrint("vnode","Writting info to mncache.dat...\n");
    mndb.Write(mnodeman);

    LogPrint("vnode","Vnode dump finished  %dms\n", GetTimeMillis() - nStart);
}

CVnodeMan::CVnodeMan()
{
    nDsqCount = 0;
}

bool CVnodeMan::Add(CVnode& mn)
{
    LOCK(cs);

    if (!mn.IsEnabled())
        return false;

    CVnode* pmn = Find(mn.vin);
    if (pmn == NULL) {
        LogPrint("vnode", "CVnodeMan: Adding new Vnode %s - %i now\n", mn.vin.prevout.hash.ToString(), size() + 1);
        vVnodes.push_back(mn);
        return true;
    }

    return false;
}

void CVnodeMan::AskForMN(CNode* pnode, CTxIn& vin)
{
    std::map<COutPoint, int64_t>::iterator i = mWeAskedForVnodeListEntry.find(vin.prevout);
    if (i != mWeAskedForVnodeListEntry.end()) {
        int64_t t = (*i).second;
        if (GetTime() < t) return; // we've asked recently
    }

    // ask for the mnb info once from the node that sent mnp

    LogPrint("vnode", "CVnodeMan::AskForMN - Asking node for missing entry, vin: %s\n", vin.prevout.hash.ToString());
    pnode->PushMessage("dseg", vin);
    int64_t askAgain = GetTime() + VNODE_MIN_MNP_SECONDS;
    mWeAskedForVnodeListEntry[vin.prevout] = askAgain;
}

void CVnodeMan::Check()
{
    LOCK(cs);

    BOOST_FOREACH (CVnode& mn, vVnodes) {
        mn.Check();
    }
}

void CVnodeMan::CheckAndRemove(bool forceExpiredRemoval)
{
    Check();

    LOCK(cs);

    //remove inactive and outdated
    vector<CVnode>::iterator it = vVnodes.begin();
    while (it != vVnodes.end()) {
        if ((*it).activeState == CVnode::VNODE_REMOVE ||
            (*it).activeState == CVnode::VNODE_VIN_SPENT ||
            (forceExpiredRemoval && (*it).activeState == CVnode::VNODE_EXPIRED) ||
            (*it).protocolVersion < vnodePayments.GetMinVnodePaymentsProto()) {
            LogPrint("vnode", "CVnodeMan: Removing inactive Vnode %s - %i now\n", (*it).vin.prevout.hash.ToString(), size() - 1);

            //erase all of the broadcasts we've seen from this vin
            // -- if we missed a few pings and the node was removed, this will allow is to get it back without them
            //    sending a brand new mnb
            map<uint256, CVnodeBroadcast>::iterator it3 = mapSeenVnodeBroadcast.begin();
            while (it3 != mapSeenVnodeBroadcast.end()) {
                if ((*it3).second.vin == (*it).vin) {
                    vnodeSync.mapSeenSyncMNB.erase((*it3).first);
                    mapSeenVnodeBroadcast.erase(it3++);
                } else {
                    ++it3;
                }
            }

            // allow us to ask for this vnode again if we see another ping
            map<COutPoint, int64_t>::iterator it2 = mWeAskedForVnodeListEntry.begin();
            while (it2 != mWeAskedForVnodeListEntry.end()) {
                if ((*it2).first == (*it).vin.prevout) {
                    mWeAskedForVnodeListEntry.erase(it2++);
                } else {
                    ++it2;
                }
            }

            it = vVnodes.erase(it);
        } else {
            ++it;
        }
    }

    // check who's asked for the Vnode list
    map<CNetAddr, int64_t>::iterator it1 = mAskedUsForVnodeList.begin();
    while (it1 != mAskedUsForVnodeList.end()) {
        if ((*it1).second < GetTime()) {
            mAskedUsForVnodeList.erase(it1++);
        } else {
            ++it1;
        }
    }

    // check who we asked for the Vnode list
    it1 = mWeAskedForVnodeList.begin();
    while (it1 != mWeAskedForVnodeList.end()) {
        if ((*it1).second < GetTime()) {
            mWeAskedForVnodeList.erase(it1++);
        } else {
            ++it1;
        }
    }

    // check which Vnodes we've asked for
    map<COutPoint, int64_t>::iterator it2 = mWeAskedForVnodeListEntry.begin();
    while (it2 != mWeAskedForVnodeListEntry.end()) {
        if ((*it2).second < GetTime()) {
            mWeAskedForVnodeListEntry.erase(it2++);
        } else {
            ++it2;
        }
    }

    // remove expired mapSeenVnodeBroadcast
    map<uint256, CVnodeBroadcast>::iterator it3 = mapSeenVnodeBroadcast.begin();
    while (it3 != mapSeenVnodeBroadcast.end()) {
        if ((*it3).second.lastPing.sigTime < GetTime() - (VNODE_REMOVAL_SECONDS * 2)) {
            mapSeenVnodeBroadcast.erase(it3++);
            vnodeSync.mapSeenSyncMNB.erase((*it3).second.GetHash());
        } else {
            ++it3;
        }
    }

    // remove expired mapSeenVnodePing
    map<uint256, CVnodePing>::iterator it4 = mapSeenVnodePing.begin();
    while (it4 != mapSeenVnodePing.end()) {
        if ((*it4).second.sigTime < GetTime() - (VNODE_REMOVAL_SECONDS * 2)) {
            mapSeenVnodePing.erase(it4++);
        } else {
            ++it4;
        }
    }
}

void CVnodeMan::Clear()
{
    LOCK(cs);
    vVnodes.clear();
    mAskedUsForVnodeList.clear();
    mWeAskedForVnodeList.clear();
    mWeAskedForVnodeListEntry.clear();
    mapSeenVnodeBroadcast.clear();
    mapSeenVnodePing.clear();
    nDsqCount = 0;
}

int CVnodeMan::stable_size ()
{
    int nStable_size = 0;
    int nMinProtocol = ActiveProtocol();
    int64_t nVnode_Min_Age = MN_WINNER_MINIMUM_AGE;
    int64_t nVnode_Age = 0;

    BOOST_FOREACH (CVnode& mn, vVnodes) {
        if (mn.protocolVersion < nMinProtocol) {
            continue; // Skip obsolete versions
        }
        if (IsSporkActive (SPORK_8_VNODE_PAYMENT_ENFORCEMENT)) {
            nVnode_Age = GetAdjustedTime() - mn.sigTime;
            if ((nVnode_Age) < nVnode_Min_Age) {
                continue; // Skip vnodes younger than (default) 8000 sec (MUST be > VNODE_REMOVAL_SECONDS)
            }
        }
        mn.Check ();
        if (!mn.IsEnabled ())
            continue; // Skip not-enabled vnodes

        nStable_size++;
    }

    return nStable_size;
}

int CVnodeMan::CountEnabled(int protocolVersion)
{
    int i = 0;
    protocolVersion = protocolVersion == -1 ? vnodePayments.GetMinVnodePaymentsProto() : protocolVersion;

    BOOST_FOREACH (CVnode& mn, vVnodes) {
        mn.Check();
        if (mn.protocolVersion < protocolVersion || !mn.IsEnabled()) continue;
        i++;
    }

    return i;
}

void CVnodeMan::CountNetworks(int protocolVersion, int& ipv4, int& ipv6, int& onion)
{
    protocolVersion = protocolVersion == -1 ? vnodePayments.GetMinVnodePaymentsProto() : protocolVersion;

    BOOST_FOREACH (CVnode& mn, vVnodes) {
        mn.Check();
        std::string strHost;
        int port;
        SplitHostPort(mn.addr.ToString(), port, strHost);
        CNetAddr node = CNetAddr(strHost, false);
        int nNetwork = node.GetNetwork();
        switch (nNetwork) {
            case 1 :
                ipv4++;
                break;
            case 2 :
                ipv6++;
                break;
            case 3 :
                onion++;
                break;
        }
    }
}

void CVnodeMan::DsegUpdate(CNode* pnode)
{
    LOCK(cs);

    if (Params().NetworkID() == CBaseChainParams::MAIN) {
        if (!(pnode->addr.IsRFC1918() || pnode->addr.IsLocal())) {
            std::map<CNetAddr, int64_t>::iterator it = mWeAskedForVnodeList.find(pnode->addr);
            if (it != mWeAskedForVnodeList.end()) {
                if (GetTime() < (*it).second) {
                    LogPrint("vnode", "dseg - we already asked peer %i for the list; skipping...\n", pnode->GetId());
                    return;
                }
            }
        }
    }

    pnode->PushMessage("dseg", CTxIn());
    int64_t askAgain = GetTime() + VNODES_DSEG_SECONDS;
    mWeAskedForVnodeList[pnode->addr] = askAgain;
}

CVnode* CVnodeMan::Find(const CScript& payee)
{
    LOCK(cs);
    CScript payee2;

    BOOST_FOREACH (CVnode& mn, vVnodes) {
        payee2 = GetScriptForDestination(mn.pubKeyCollateralAddress.GetID());
        if (payee2 == payee)
            return &mn;
    }
    return NULL;
}

CVnode* CVnodeMan::Find(const CTxIn& vin)
{
    LOCK(cs);

    BOOST_FOREACH (CVnode& mn, vVnodes) {
        if (mn.vin.prevout == vin.prevout)
            return &mn;
    }
    return NULL;
}


CVnode* CVnodeMan::Find(const CPubKey& pubKeyVnode)
{
    LOCK(cs);

    BOOST_FOREACH (CVnode& mn, vVnodes) {
        if (mn.pubKeyVnode == pubKeyVnode)
            return &mn;
    }
    return NULL;
}

//
// Deterministically select the oldest/best vnode to pay on the network
//
CVnode* CVnodeMan::GetNextVnodeInQueueForPayment(int nBlockHeight, bool fFilterSigTime, int& nCount)
{
    LOCK(cs);

    CVnode* pBestVnode = NULL;
    std::vector<pair<int64_t, CTxIn> > vecVnodeLastPaid;

    /*
        Make a vector with all of the last paid times
    */

    int nMnCount = CountEnabled();
    BOOST_FOREACH (CVnode& mn, vVnodes) {
        mn.Check();
        if (!mn.IsEnabled()) continue;

        // //check protocol version
        if (mn.protocolVersion < vnodePayments.GetMinVnodePaymentsProto()) continue;

        //it's in the list (up to 8 entries ahead of current block to allow propagation) -- so let's skip it
        if (vnodePayments.IsScheduled(mn, nBlockHeight)) continue;

        //it's too new, wait for a cycle
        if (fFilterSigTime && mn.sigTime + (nMnCount * 2.6 * 60) > GetAdjustedTime()) continue;

        //make sure it has as many confirmations as there are vnodes
        if (mn.GetVnodeInputAge() < nMnCount) continue;

        vecVnodeLastPaid.push_back(make_pair(mn.SecondsSincePayment(), mn.vin));
    }

    nCount = (int)vecVnodeLastPaid.size();

    //when the network is in the process of upgrading, don't penalize nodes that recently restarted
    if (fFilterSigTime && nCount < nMnCount / 3) return GetNextVnodeInQueueForPayment(nBlockHeight, false, nCount);

    // Sort them high to low
    sort(vecVnodeLastPaid.rbegin(), vecVnodeLastPaid.rend(), CompareLastPaid());

    // Look at 1/10 of the oldest nodes (by last payment), calculate their scores and pay the best one
    //  -- This doesn't look at who is being paid in the +8-10 blocks, allowing for double payments very rarely
    //  -- 1/100 payments should be a double payment on mainnet - (1/(3000/10))*2
    //  -- (chance per block * chances before IsScheduled will fire)
    int nTenthNetwork = CountEnabled() / 10;
    int nCountTenth = 0;
    uint256 nHigh = 0;
    BOOST_FOREACH (PAIRTYPE(int64_t, CTxIn) & s, vecVnodeLastPaid) {
        CVnode* pmn = Find(s.second);
        if (!pmn) break;

        uint256 n = pmn->CalculateScore(1, nBlockHeight - 100);
        if (n > nHigh) {
            nHigh = n;
            pBestVnode = pmn;
        }
        nCountTenth++;
        if (nCountTenth >= nTenthNetwork) break;
    }
    return pBestVnode;
}

CVnode* CVnodeMan::FindRandomNotInVec(std::vector<CTxIn>& vecToExclude, int protocolVersion)
{
    LOCK(cs);

    protocolVersion = protocolVersion == -1 ? vnodePayments.GetMinVnodePaymentsProto() : protocolVersion;

    int nCountEnabled = CountEnabled(protocolVersion);
    LogPrint("vnode", "CVnodeMan::FindRandomNotInVec - nCountEnabled - vecToExclude.size() %d\n", nCountEnabled - vecToExclude.size());
    if (nCountEnabled - vecToExclude.size() < 1) return NULL;

    int rand = GetRandInt(nCountEnabled - vecToExclude.size());
    LogPrint("vnode", "CVnodeMan::FindRandomNotInVec - rand %d\n", rand);
    bool found;

    BOOST_FOREACH (CVnode& mn, vVnodes) {
        if (mn.protocolVersion < protocolVersion || !mn.IsEnabled()) continue;
        found = false;
        BOOST_FOREACH (CTxIn& usedVin, vecToExclude) {
            if (mn.vin.prevout == usedVin.prevout) {
                found = true;
                break;
            }
        }
        if (found) continue;
        if (--rand < 1) {
            return &mn;
        }
    }

    return NULL;
}

CVnode* CVnodeMan::GetCurrentVNode(int mod, int64_t nBlockHeight, int minProtocol)
{
    int64_t score = 0;
    CVnode* winner = NULL;

    // scan for winner
    BOOST_FOREACH (CVnode& mn, vVnodes) {
        mn.Check();
        if (mn.protocolVersion < minProtocol || !mn.IsEnabled()) continue;

        // calculate the score for each Vnode
        uint256 n = mn.CalculateScore(mod, nBlockHeight);
        int64_t n2 = n.GetCompact(false);

        // determine the winner
        if (n2 > score) {
            score = n2;
            winner = &mn;
        }
    }

    return winner;
}

int CVnodeMan::GetVnodeRank(const CTxIn& vin, int64_t nBlockHeight, int minProtocol, bool fOnlyActive)
{
    std::vector<pair<int64_t, CTxIn> > vecVnodeScores;
    int64_t nVnode_Min_Age = MN_WINNER_MINIMUM_AGE;
    int64_t nVnode_Age = 0;

    //make sure we know about this block
    uint256 hash = 0;
    if (!GetBlockHash(hash, nBlockHeight)) return -1;

    // scan for winner
    BOOST_FOREACH (CVnode& mn, vVnodes) {
        if (mn.protocolVersion < minProtocol) {
            LogPrint("vnode","Skipping Vnode with obsolete version %d\n", mn.protocolVersion);
            continue;                                                       // Skip obsolete versions
        }

        if (IsSporkActive(SPORK_8_VNODE_PAYMENT_ENFORCEMENT)) {
            nVnode_Age = GetAdjustedTime() - mn.sigTime;
            if ((nVnode_Age) < nVnode_Min_Age) {
                if (fDebug) LogPrint("vnode","Skipping just activated Vnode. Age: %ld\n", nVnode_Age);
                continue;                                                   // Skip vnodes younger than (default) 1 hour
            }
        }
        if (fOnlyActive) {
            mn.Check();
            if (!mn.IsEnabled()) continue;
        }
        uint256 n = mn.CalculateScore(1, nBlockHeight);
        int64_t n2 = n.GetCompact(false);

        vecVnodeScores.push_back(make_pair(n2, mn.vin));
    }

    sort(vecVnodeScores.rbegin(), vecVnodeScores.rend(), CompareScoreTxIn());

    int rank = 0;
    BOOST_FOREACH (PAIRTYPE(int64_t, CTxIn) & s, vecVnodeScores) {
        rank++;
        if (s.second.prevout == vin.prevout) {
            return rank;
        }
    }

    return -1;
}

std::vector<pair<int, CVnode> > CVnodeMan::GetVnodeRanks(int64_t nBlockHeight, int minProtocol)
{
    std::vector<pair<int64_t, CVnode> > vecVnodeScores;
    std::vector<pair<int, CVnode> > vecVnodeRanks;

    //make sure we know about this block
    uint256 hash = 0;
    if (!GetBlockHash(hash, nBlockHeight)) return vecVnodeRanks;

    // scan for winner
    BOOST_FOREACH (CVnode& mn, vVnodes) {
        mn.Check();

        if (mn.protocolVersion < minProtocol) continue;

        if (!mn.IsEnabled()) {
            vecVnodeScores.push_back(make_pair(9999, mn));
            continue;
        }

        uint256 n = mn.CalculateScore(1, nBlockHeight);
        int64_t n2 = n.GetCompact(false);

        vecVnodeScores.push_back(make_pair(n2, mn));
    }

    sort(vecVnodeScores.rbegin(), vecVnodeScores.rend(), CompareScoreMN());

    int rank = 0;
    BOOST_FOREACH (PAIRTYPE(int64_t, CVnode) & s, vecVnodeScores) {
        rank++;
        vecVnodeRanks.push_back(make_pair(rank, s.second));
    }

    return vecVnodeRanks;
}

CVnode* CVnodeMan::GetVnodeByRank(int nRank, int64_t nBlockHeight, int minProtocol, bool fOnlyActive)
{
    std::vector<pair<int64_t, CTxIn> > vecVnodeScores;

    // scan for winner
    BOOST_FOREACH (CVnode& mn, vVnodes) {
        if (mn.protocolVersion < minProtocol) continue;
        if (fOnlyActive) {
            mn.Check();
            if (!mn.IsEnabled()) continue;
        }

        uint256 n = mn.CalculateScore(1, nBlockHeight);
        int64_t n2 = n.GetCompact(false);

        vecVnodeScores.push_back(make_pair(n2, mn.vin));
    }

    sort(vecVnodeScores.rbegin(), vecVnodeScores.rend(), CompareScoreTxIn());

    int rank = 0;
    BOOST_FOREACH (PAIRTYPE(int64_t, CTxIn) & s, vecVnodeScores) {
        rank++;
        if (rank == nRank) {
            return Find(s.second);
        }
    }

    return NULL;
}

void CVnodeMan::ProcessVnodeConnections()
{
    //we don't care about this for regtest
    if (Params().NetworkID() == CBaseChainParams::REGTEST) return;

    LOCK(cs_vNodes);
    BOOST_FOREACH (CNode* pnode, vNodes) {
        if (pnode->fObfuScationMaster) {
            if (obfuScationPool.pSubmittedToVnode != NULL && pnode->addr == obfuScationPool.pSubmittedToVnode->addr) continue;
            LogPrint("vnode","Closing Vnode connection peer=%i \n", pnode->GetId());
            pnode->fObfuScationMaster = false;
            pnode->Release();
        }
    }
}

void CVnodeMan::ProcessMessage(CNode* pfrom, std::string& strCommand, CDataStream& vRecv)
{
    if (fLiteMode) return; //disable all Obfuscation/Vnode related functionality
    if (!vnodeSync.IsBlockchainSynced()) return;

    LOCK(cs_process_message);

    if (strCommand == "mnb") { //Vnode Broadcast
        CVnodeBroadcast mnb;
        vRecv >> mnb;

        if (mapSeenVnodeBroadcast.count(mnb.GetHash())) { //seen
            vnodeSync.AddedVnodeList(mnb.GetHash());
            return;
        }
        mapSeenVnodeBroadcast.insert(make_pair(mnb.GetHash(), mnb));

        int nDoS = 0;
        if (!mnb.CheckAndUpdate(nDoS)) {
            if (nDoS > 0)
                Misbehaving(pfrom->GetId(), nDoS);

            //failed
            return;
        }

        // make sure the vout that was signed is related to the transaction that spawned the Vnode
        //  - this is expensive, so it's only done once per Vnode
        if (!obfuScationSigner.IsVinAssociatedWithPubkey(mnb.vin, mnb.pubKeyCollateralAddress)) {
            LogPrint("vnode","mnb - Got mismatched pubkey and vin\n");
            Misbehaving(pfrom->GetId(), 33);
            return;
        }

        // make sure it's still unspent
        //  - this is checked later by .check() in many places and by ThreadCheckObfuScationPool()
        if (mnb.CheckInputsAndAdd(nDoS)) {
            // use this as a peer
            addrman.Add(CAddress(mnb.addr), pfrom->addr, 2 * 60 * 60);
            vnodeSync.AddedVnodeList(mnb.GetHash());
        } else {
            LogPrint("vnode","mnb - Rejected Vnode entry %s\n", mnb.vin.prevout.hash.ToString());

            if (nDoS > 0)
                Misbehaving(pfrom->GetId(), nDoS);
        }
    }

    else if (strCommand == "mnp") { //Vnode Ping
        CVnodePing mnp;
        vRecv >> mnp;

        LogPrint("vnode", "mnp - Vnode ping, vin: %s\n", mnp.vin.prevout.hash.ToString());

        if (mapSeenVnodePing.count(mnp.GetHash())) return; //seen
        mapSeenVnodePing.insert(make_pair(mnp.GetHash(), mnp));

        int nDoS = 0;
        if (mnp.CheckAndUpdate(nDoS)) return;

        if (nDoS > 0) {
            // if anything significant failed, mark that node
            Misbehaving(pfrom->GetId(), nDoS);
        } else {
            // if nothing significant failed, search existing Vnode list
            CVnode* pmn = Find(mnp.vin);
            // if it's known, don't ask for the mnb, just return
            if (pmn != NULL) return;
        }

        // something significant is broken or mn is unknown,
        // we might have to ask for a vnode entry once
        AskForMN(pfrom, mnp.vin);

    } else if (strCommand == "dseg") { //Get Vnode list or specific entry

        CTxIn vin;
        vRecv >> vin;

        if (vin == CTxIn()) { //only should ask for this once
            //local network
            bool isLocal = (pfrom->addr.IsRFC1918() || pfrom->addr.IsLocal());

            if (!isLocal && Params().NetworkID() == CBaseChainParams::MAIN) {
                std::map<CNetAddr, int64_t>::iterator i = mAskedUsForVnodeList.find(pfrom->addr);
                if (i != mAskedUsForVnodeList.end()) {
                    int64_t t = (*i).second;
                    if (GetTime() < t) {
                        Misbehaving(pfrom->GetId(), 34);
                        LogPrint("vnode","dseg - peer already asked me for the list\n");
                        return;
                    }
                }
                int64_t askAgain = GetTime() + VNODES_DSEG_SECONDS;
                mAskedUsForVnodeList[pfrom->addr] = askAgain;
            }
        } //else, asking for a specific node which is ok


        int nInvCount = 0;

        BOOST_FOREACH (CVnode& mn, vVnodes) {
            if (mn.addr.IsRFC1918()) continue; //local network

            if (mn.IsEnabled()) {
                LogPrint("vnode", "dseg - Sending Vnode entry - %s \n", mn.vin.prevout.hash.ToString());
                if (vin == CTxIn() || vin == mn.vin) {
                    CVnodeBroadcast mnb = CVnodeBroadcast(mn);
                    uint256 hash = mnb.GetHash();
                    pfrom->PushInventory(CInv(MSG_VNODE_ANNOUNCE, hash));
                    nInvCount++;

                    if (!mapSeenVnodeBroadcast.count(hash)) mapSeenVnodeBroadcast.insert(make_pair(hash, mnb));

                    if (vin == mn.vin) {
                        LogPrint("vnode", "dseg - Sent 1 Vnode entry to peer %i\n", pfrom->GetId());
                        return;
                    }
                }
            }
        }

        if (vin == CTxIn()) {
            pfrom->PushMessage("ssc", VNODE_SYNC_LIST, nInvCount);
            LogPrint("vnode", "dseg - Sent %d Vnode entries to peer %i\n", nInvCount, pfrom->GetId());
        }
    }
    /*
     * IT'S SAFE TO REMOVE THIS IN FURTHER VERSIONS
     * AFTER MIGRATION TO V12 IS DONE
     */

    // Light version for OLD MASSTERNODES - fake pings, no self-activation
    else if (strCommand == "dsee") { //ObfuScation Election Entry

        if (IsSporkActive(SPORK_10_VNODE_PAY_UPDATED_NODES)) return;

        CTxIn vin;
        CService addr;
        CPubKey pubkey;
        CPubKey pubkey2;
        vector<unsigned char> vchSig;
        int64_t sigTime;
        int count;
        int current;
        int64_t lastUpdated;
        int protocolVersion;
        CScript donationAddress;
        int donationPercentage;
        std::string strMessage;

        vRecv >> vin >> addr >> vchSig >> sigTime >> pubkey >> pubkey2 >> count >> current >> lastUpdated >> protocolVersion >> donationAddress >> donationPercentage;

        // make sure signature isn't in the future (past is OK)
        if (sigTime > GetAdjustedTime() + 60 * 60) {
            LogPrint("vnode","dsee - Signature rejected, too far into the future %s\n", vin.prevout.hash.ToString());
            Misbehaving(pfrom->GetId(), 1);
            return;
        }

        std::string vchPubKey(pubkey.begin(), pubkey.end());
        std::string vchPubKey2(pubkey2.begin(), pubkey2.end());

        strMessage = addr.ToString() + boost::lexical_cast<std::string>(sigTime) + vchPubKey + vchPubKey2 + boost::lexical_cast<std::string>(protocolVersion) + donationAddress.ToString() + boost::lexical_cast<std::string>(donationPercentage);

        if (protocolVersion < vnodePayments.GetMinVnodePaymentsProto()) {
            LogPrint("vnode","dsee - ignoring outdated Vnode %s protocol version %d < %d\n", vin.prevout.hash.ToString(), protocolVersion, vnodePayments.GetMinVnodePaymentsProto());
            Misbehaving(pfrom->GetId(), 1);
            return;
        }

        CScript pubkeyScript;
        pubkeyScript = GetScriptForDestination(pubkey.GetID());

        if (pubkeyScript.size() != 25) {
            LogPrint("vnode","dsee - pubkey the wrong size\n");
            Misbehaving(pfrom->GetId(), 100);
            return;
        }

        CScript pubkeyScript2;
        pubkeyScript2 = GetScriptForDestination(pubkey2.GetID());

        if (pubkeyScript2.size() != 25) {
            LogPrint("vnode","dsee - pubkey2 the wrong size\n");
            Misbehaving(pfrom->GetId(), 100);
            return;
        }

        if (!vin.scriptSig.empty()) {
            LogPrint("vnode","dsee - Ignore Not Empty ScriptSig %s\n", vin.prevout.hash.ToString());
            Misbehaving(pfrom->GetId(), 100);
            return;
        }

        std::string errorMessage = "";
        if (!obfuScationSigner.VerifyMessage(pubkey, vchSig, strMessage, errorMessage)) {
            LogPrint("vnode","dsee - Got bad Vnode address signature\n");
            Misbehaving(pfrom->GetId(), 100);
            return;
        }

        if (Params().NetworkID() == CBaseChainParams::MAIN) {
            if (addr.GetPort() != 7702) return;
        } else if (addr.GetPort() == 7702)
            return;

        //search existing Vnode list, this is where we update existing Vnodes with new dsee broadcasts
        CVnode* pmn = this->Find(vin);
        if (pmn != NULL) {
            // count == -1 when it's a new entry
            //   e.g. We don't want the entry relayed/time updated when we're syncing the list
            // mn.pubkey = pubkey, IsVinAssociatedWithPubkey is validated once below,
            //   after that they just need to match
            if (count == -1 && pmn->pubKeyCollateralAddress == pubkey && (GetAdjustedTime() - pmn->nLastDsee > VNODE_MIN_MNB_SECONDS)) {
                if (pmn->protocolVersion > GETHEADERS_VERSION && sigTime - pmn->lastPing.sigTime < VNODE_MIN_MNB_SECONDS) return;
                if (pmn->nLastDsee < sigTime) { //take the newest entry
                    LogPrint("vnode", "dsee - Got updated entry for %s\n", vin.prevout.hash.ToString());
                    if (pmn->protocolVersion < GETHEADERS_VERSION) {
                        pmn->pubKeyVnode = pubkey2;
                        pmn->sigTime = sigTime;
                        pmn->sig = vchSig;
                        pmn->protocolVersion = protocolVersion;
                        pmn->addr = addr;
                        //fake ping
                        pmn->lastPing = CVnodePing(vin);
                    }
                    pmn->nLastDsee = sigTime;
                    pmn->Check();
                    if (pmn->IsEnabled()) {
                        TRY_LOCK(cs_vNodes, lockNodes);
                        if (!lockNodes) return;
                        BOOST_FOREACH (CNode* pnode, vNodes)
                            if (pnode->nVersion >= vnodePayments.GetMinVnodePaymentsProto())
                                pnode->PushMessage("dsee", vin, addr, vchSig, sigTime, pubkey, pubkey2, count, current, lastUpdated, protocolVersion, donationAddress, donationPercentage);
                    }
                }
            }

            return;
        }

        static std::map<COutPoint, CPubKey> mapSeenDsee;
        if (mapSeenDsee.count(vin.prevout) && mapSeenDsee[vin.prevout] == pubkey) {
            LogPrint("vnode", "dsee - already seen this vin %s\n", vin.prevout.ToString());
            return;
        }
        mapSeenDsee.insert(make_pair(vin.prevout, pubkey));
        // make sure the vout that was signed is related to the transaction that spawned the Vnode
        //  - this is expensive, so it's only done once per Vnode
        if (!obfuScationSigner.IsVinAssociatedWithPubkey(vin, pubkey)) {
            LogPrint("vnode","dsee - Got mismatched pubkey and vin\n");
            Misbehaving(pfrom->GetId(), 100);
            return;
        }


        LogPrint("vnode", "dsee - Got NEW OLD Vnode entry %s\n", vin.prevout.hash.ToString());

        // make sure it's still unspent
        //  - this is checked later by .check() in many places and by ThreadCheckObfuScationPool()

        CValidationState state;
        CMutableTransaction tx = CMutableTransaction();

        CAmount MNCollateral;
        MNCollateral = 999.99 * COIN;
        int MNActive = mnodeman.CountEnabled();
    	if (MNActive < 25) {
    	MNCollateral = 999.99 * COIN;
    	} else if (MNActive < 50) {
    	MNCollateral = 1249.99 * COIN;
    	} else if (MNActive < 75) {
    	MNCollateral = 1499.99 * COIN;
    	} else if (MNActive < 100) {
    	MNCollateral = 1749.99 * COIN;
    	} else if (MNActive < 125) {
    	MNCollateral = 1999.99 * COIN;
    	} else if (MNActive < 150) {
    	MNCollateral = 2249.99 * COIN;
    	} else if (MNActive < 200) {
    	MNCollateral = 2499.99 * COIN;
    	} else if (MNActive < 250) {
    	MNCollateral = 2749.99 * COIN;
    	} else {
    	MNCollateral = 2999.99 * COIN;
    	}

        CTxOut vout = CTxOut(999.99*COIN, obfuScationPool.collateralPubKey);
        tx.vin.push_back(vin);
        tx.vout.push_back(vout);

        bool fAcceptable = false;
        {
            TRY_LOCK(cs_main, lockMain);
            if (!lockMain) return;
            fAcceptable = AcceptableInputs(mempool, state, CTransaction(tx), false, NULL);
        }

        if (fAcceptable) {
            if (GetInputAge(vin) < VNODE_MIN_CONFIRMATIONS) {
                LogPrint("vnode","dsee - Input must have least %d confirmations\n", VNODE_MIN_CONFIRMATIONS);
                Misbehaving(pfrom->GetId(), 20);
                return;
            }

            // verify that sig time is legit in past
            // should be at least not earlier than block when 10000 VENTUAL tx got VNODE_MIN_CONFIRMATIONS
            uint256 hashBlock = 0;
            CTransaction tx2;
            GetTransaction(vin.prevout.hash, tx2, hashBlock, true);
            BlockMap::iterator mi = mapBlockIndex.find(hashBlock);
            if (mi != mapBlockIndex.end() && (*mi).second) {
                CBlockIndex* pMNIndex = (*mi).second;                                                        // block for 10000 VENTUAL tx -> 1 confirmation
                CBlockIndex* pConfIndex = chainActive[pMNIndex->nHeight + VNODE_MIN_CONFIRMATIONS - 1]; // block where tx got VNODE_MIN_CONFIRMATIONS
                if (pConfIndex->GetBlockTime() > sigTime) {
                    LogPrint("vnode","mnb - Bad sigTime %d for Vnode %s (%i conf block is at %d)\n",
                        sigTime, vin.prevout.hash.ToString(), VNODE_MIN_CONFIRMATIONS, pConfIndex->GetBlockTime());
                    return;
                }
            }

            // use this as a peer
            addrman.Add(CAddress(addr), pfrom->addr, 2 * 60 * 60);

            // add Vnode
            CVnode mn = CVnode();
            mn.addr = addr;
            mn.vin = vin;
            mn.pubKeyCollateralAddress = pubkey;
            mn.sig = vchSig;
            mn.sigTime = sigTime;
            mn.pubKeyVnode = pubkey2;
            mn.protocolVersion = protocolVersion;
            // fake ping
            mn.lastPing = CVnodePing(vin);
            mn.Check(true);
            // add v11 vnodes, v12 should be added by mnb only
            if (protocolVersion < GETHEADERS_VERSION) {
                LogPrint("vnode", "dsee - Accepted OLD Vnode entry %i %i\n", count, current);
                Add(mn);
            }
            if (mn.IsEnabled()) {
                TRY_LOCK(cs_vNodes, lockNodes);
                if (!lockNodes) return;
                BOOST_FOREACH (CNode* pnode, vNodes)
                    if (pnode->nVersion >= vnodePayments.GetMinVnodePaymentsProto())
                        pnode->PushMessage("dsee", vin, addr, vchSig, sigTime, pubkey, pubkey2, count, current, lastUpdated, protocolVersion, donationAddress, donationPercentage);
            }
        } else {
            LogPrint("vnode","dsee - Rejected Vnode entry %s\n", vin.prevout.hash.ToString());

            int nDoS = 0;
            if (state.IsInvalid(nDoS)) {
                LogPrint("vnode","dsee - %s from %i %s was not accepted into the memory pool\n", tx.GetHash().ToString().c_str(),
                    pfrom->GetId(), pfrom->cleanSubVer.c_str());
                if (nDoS > 0)
                    Misbehaving(pfrom->GetId(), nDoS);
            }
        }
    }

    else if (strCommand == "dseep") { //ObfuScation Election Entry Ping

        if (IsSporkActive(SPORK_10_VNODE_PAY_UPDATED_NODES)) return;

        CTxIn vin;
        vector<unsigned char> vchSig;
        int64_t sigTime;
        bool stop;
        vRecv >> vin >> vchSig >> sigTime >> stop;

        //LogPrint("vnode","dseep - Received: vin: %s sigTime: %lld stop: %s\n", vin.ToString().c_str(), sigTime, stop ? "true" : "false");

        if (sigTime > GetAdjustedTime() + 60 * 60) {
            LogPrint("vnode","dseep - Signature rejected, too far into the future %s\n", vin.prevout.hash.ToString());
            Misbehaving(pfrom->GetId(), 1);
            return;
        }

        if (sigTime <= GetAdjustedTime() - 60 * 60) {
            LogPrint("vnode","dseep - Signature rejected, too far into the past %s - %d %d \n", vin.prevout.hash.ToString(), sigTime, GetAdjustedTime());
            Misbehaving(pfrom->GetId(), 1);
            return;
        }

        std::map<COutPoint, int64_t>::iterator i = mWeAskedForVnodeListEntry.find(vin.prevout);
        if (i != mWeAskedForVnodeListEntry.end()) {
            int64_t t = (*i).second;
            if (GetTime() < t) return; // we've asked recently
        }

        // see if we have this Vnode
        CVnode* pmn = this->Find(vin);
        if (pmn != NULL && pmn->protocolVersion >= vnodePayments.GetMinVnodePaymentsProto()) {
            // LogPrint("vnode","dseep - Found corresponding mn for vin: %s\n", vin.ToString().c_str());
            // take this only if it's newer
            if (sigTime - pmn->nLastDseep > VNODE_MIN_MNP_SECONDS) {
                std::string strMessage = pmn->addr.ToString() + boost::lexical_cast<std::string>(sigTime) + boost::lexical_cast<std::string>(stop);

                std::string errorMessage = "";
                if (!obfuScationSigner.VerifyMessage(pmn->pubKeyVnode, vchSig, strMessage, errorMessage)) {
                    LogPrint("vnode","dseep - Got bad Vnode address signature %s \n", vin.prevout.hash.ToString());
                    //Misbehaving(pfrom->GetId(), 100);
                    return;
                }

                // fake ping for v11 vnodes, ignore for v12
                if (pmn->protocolVersion < GETHEADERS_VERSION) pmn->lastPing = CVnodePing(vin);
                pmn->nLastDseep = sigTime;
                pmn->Check();
                if (pmn->IsEnabled()) {
                    TRY_LOCK(cs_vNodes, lockNodes);
                    if (!lockNodes) return;
                    LogPrint("vnode", "dseep - relaying %s \n", vin.prevout.hash.ToString());
                    BOOST_FOREACH (CNode* pnode, vNodes)
                        if (pnode->nVersion >= vnodePayments.GetMinVnodePaymentsProto())
                            pnode->PushMessage("dseep", vin, vchSig, sigTime, stop);
                }
            }
            return;
        }

        LogPrint("vnode", "dseep - Couldn't find Vnode entry %s peer=%i\n", vin.prevout.hash.ToString(), pfrom->GetId());

        AskForMN(pfrom, vin);
    }

    /*
     * END OF "REMOVE"
     */
}

void CVnodeMan::Remove(CTxIn vin)
{
    LOCK(cs);

    vector<CVnode>::iterator it = vVnodes.begin();
    while (it != vVnodes.end()) {
        if ((*it).vin == vin) {
            LogPrint("vnode", "CVnodeMan: Removing Vnode %s - %i now\n", (*it).vin.prevout.hash.ToString(), size() - 1);
            vVnodes.erase(it);
            break;
        }
        ++it;
    }
}

void CVnodeMan::UpdateVnodeList(CVnodeBroadcast mnb)
{
    LOCK(cs);
    mapSeenVnodePing.insert(std::make_pair(mnb.lastPing.GetHash(), mnb.lastPing));
    mapSeenVnodeBroadcast.insert(std::make_pair(mnb.GetHash(), mnb));

    LogPrint("vnode","CVnodeMan::UpdateVnodeList -- vnode=%s\n", mnb.vin.prevout.ToStringShort());

    CVnode* pmn = Find(mnb.vin);
    if (pmn == NULL) {
        CVnode mn(mnb);
        if (Add(mn)) {
            vnodeSync.AddedVnodeList(mnb.GetHash());
        }
    } else if (pmn->UpdateFromNewBroadcast(mnb)) {
        vnodeSync.AddedVnodeList(mnb.GetHash());
    }
}

std::string CVnodeMan::ToString() const
{
    std::ostringstream info;

    info << "Vnodes: " << (int)vVnodes.size() << ", peers who asked us for Vnode list: " << (int)mAskedUsForVnodeList.size() << ", peers we asked for Vnode list: " << (int)mWeAskedForVnodeList.size() << ", entries in Vnode list we asked for: " << (int)mWeAskedForVnodeListEntry.size() << ", nDsqCount: " << (int)nDsqCount;

    return info.str();
}
