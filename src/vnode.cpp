// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2017 The PIVX developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "vnode.h"
#include "addrman.h"
#include "vnodeman.h"
#include "obfuscation.h"
#include "sync.h"
#include "util.h"
#include <boost/lexical_cast.hpp>
#include "base58.h"
#include "main.h"
#include "spork.h"

// keep track of the scanning errors I've seen
map<uint256, int> mapSeenVnodeScanningErrors;
// cache block hashes as we calculate them
std::map<int64_t, uint256> mapCacheBlockHashes;

//Get the last hash that matches the modulus given. Processed in reverse order
bool GetBlockHash(uint256& hash, int nBlockHeight)
{
    if (chainActive.Tip() == NULL) return false;

    if (nBlockHeight == 0)
        nBlockHeight = chainActive.Tip()->nHeight;

    if (mapCacheBlockHashes.count(nBlockHeight)) {
        hash = mapCacheBlockHashes[nBlockHeight];
        return true;
    }

    const CBlockIndex* BlockLastSolved = chainActive.Tip();
    const CBlockIndex* BlockReading = chainActive.Tip();

    if (BlockLastSolved == NULL || BlockLastSolved->nHeight == 0 || chainActive.Tip()->nHeight + 1 < nBlockHeight) return false;

    int nBlocksAgo = 0;
    if (nBlockHeight > 0) nBlocksAgo = (chainActive.Tip()->nHeight + 1) - nBlockHeight;
    assert(nBlocksAgo >= 0);

    int n = 0;
    for (unsigned int i = 1; BlockReading && BlockReading->nHeight > 0; i++) {
        if (n >= nBlocksAgo) {
            hash = BlockReading->GetBlockHash();
            mapCacheBlockHashes[nBlockHeight] = hash;
            return true;
        }
        n++;

        if (BlockReading->pprev == NULL) {
            assert(BlockReading);
            break;
        }
        BlockReading = BlockReading->pprev;
    }

    return false;
}

CVnode::CVnode()
{
    LOCK(cs);
    vin = CTxIn();
    addr = CService();
    pubKeyCollateralAddress = CPubKey();
    pubKeyVnode = CPubKey();
    sig = std::vector<unsigned char>();
    activeState = VNODE_ENABLED;
    sigTime = GetAdjustedTime();
    lastPing = CVnodePing();
    cacheInputAge = 0;
    cacheInputAgeBlock = 0;
    unitTest = false;
    allowFreeTx = true;
    nActiveState = VNODE_ENABLED,
    protocolVersion = PROTOCOL_VERSION;
    nLastDsq = 0;
    nScanningErrorCount = 0;
    nLastScanningErrorBlockHeight = 0;
    lastTimeChecked = 0;
    nLastDsee = 0;  // temporary, do not save. Remove after migration to v12
    nLastDseep = 0; // temporary, do not save. Remove after migration to v12
}

CVnode::CVnode(const CVnode& other)
{
    LOCK(cs);
    vin = other.vin;
    addr = other.addr;
    pubKeyCollateralAddress = other.pubKeyCollateralAddress;
    pubKeyVnode = other.pubKeyVnode;
    sig = other.sig;
    activeState = other.activeState;
    sigTime = other.sigTime;
    lastPing = other.lastPing;
    cacheInputAge = other.cacheInputAge;
    cacheInputAgeBlock = other.cacheInputAgeBlock;
    unitTest = other.unitTest;
    allowFreeTx = other.allowFreeTx;
    nActiveState = VNODE_ENABLED,
    protocolVersion = other.protocolVersion;
    nLastDsq = other.nLastDsq;
    nScanningErrorCount = other.nScanningErrorCount;
    nLastScanningErrorBlockHeight = other.nLastScanningErrorBlockHeight;
    lastTimeChecked = 0;
    nLastDsee = other.nLastDsee;   // temporary, do not save. Remove after migration to v12
    nLastDseep = other.nLastDseep; // temporary, do not save. Remove after migration to v12
}

CVnode::CVnode(const CVnodeBroadcast& mnb)
{
    LOCK(cs);
    vin = mnb.vin;
    addr = mnb.addr;
    pubKeyCollateralAddress = mnb.pubKeyCollateralAddress;
    pubKeyVnode = mnb.pubKeyVnode;
    sig = mnb.sig;
    activeState = VNODE_ENABLED;
    sigTime = mnb.sigTime;
    lastPing = mnb.lastPing;
    cacheInputAge = 0;
    cacheInputAgeBlock = 0;
    unitTest = false;
    allowFreeTx = true;
    nActiveState = VNODE_ENABLED,
    protocolVersion = mnb.protocolVersion;
    nLastDsq = mnb.nLastDsq;
    nScanningErrorCount = 0;
    nLastScanningErrorBlockHeight = 0;
    lastTimeChecked = 0;
    nLastDsee = 0;  // temporary, do not save. Remove after migration to v12
    nLastDseep = 0; // temporary, do not save. Remove after migration to v12
}

//
// When a new vnode broadcast is sent, update our information
//
bool CVnode::UpdateFromNewBroadcast(CVnodeBroadcast& mnb)
{
    if (mnb.sigTime > sigTime) {
        pubKeyVnode = mnb.pubKeyVnode;
        pubKeyCollateralAddress = mnb.pubKeyCollateralAddress;
        sigTime = mnb.sigTime;
        sig = mnb.sig;
        protocolVersion = mnb.protocolVersion;
        addr = mnb.addr;
        lastTimeChecked = 0;
        int nDoS = 0;
        if (mnb.lastPing == CVnodePing() || (mnb.lastPing != CVnodePing() && mnb.lastPing.CheckAndUpdate(nDoS, false))) {
            lastPing = mnb.lastPing;
            mnodeman.mapSeenVnodePing.insert(make_pair(lastPing.GetHash(), lastPing));
        }
        return true;
    }
    return false;
}

//
// Deterministically calculate a given "score" for a Vnode depending on how close it's hash is to
// the proof of work for that block. The further away they are the better, the furthest will win the election
// and get paid this block
//
uint256 CVnode::CalculateScore(int mod, int64_t nBlockHeight)
{
    if (chainActive.Tip() == NULL) return 0;

    uint256 hash = 0;
    uint256 aux = vin.prevout.hash + vin.prevout.n;

    if (!GetBlockHash(hash, nBlockHeight)) {
        LogPrint("vnode","CalculateScore ERROR - nHeight %d - Returned 0\n", nBlockHeight);
        return 0;
    }

    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << hash;
    uint256 hash2 = ss.GetHash();

    CHashWriter ss2(SER_GETHASH, PROTOCOL_VERSION);
    ss2 << hash;
    ss2 << aux;
    uint256 hash3 = ss2.GetHash();

    uint256 r = (hash3 > hash2 ? hash3 - hash2 : hash2 - hash3);

    return r;
}

void CVnode::Check(bool forceCheck)
{
    if (ShutdownRequested()) return;

    if (!forceCheck && (GetTime() - lastTimeChecked < VNODE_CHECK_SECONDS)) return;
    lastTimeChecked = GetTime();


    //once spent, stop doing the checks
    if (activeState == VNODE_VIN_SPENT) return;


    if (!IsPingedWithin(VNODE_REMOVAL_SECONDS)) {
        activeState = VNODE_REMOVE;
        return;
    }

    if (!IsPingedWithin(VNODE_EXPIRATION_SECONDS)) {
        activeState = VNODE_EXPIRED;
        return;
    }

    if (!unitTest) {
        CValidationState state;
        CMutableTransaction tx = CMutableTransaction();

        CAmount MNCollateral;
        MNCollateral = 999.99 * COIN;

	CTransaction wtx2;
	uint256 hashBlock2;
	if(GetTransaction(vin.prevout.hash, wtx2, hashBlock2, true)) {
	BlockMap::iterator iter = mapBlockIndex.find(hashBlock2);
	if (iter != mapBlockIndex.end()) {
	int txnheight = iter->second->nHeight;

	if (txnheight <= GetSporkValue(SPORK_18_COLLATERAL_ONE)){
		MNCollateral = 999.99 * COIN;
	} else if (txnheight <= GetSporkValue(SPORK_19_COLLATERAL_TWO)){
                MNCollateral = 1249.99 * COIN;
       	} else if (txnheight <= GetSporkValue(SPORK_20_COLLATERAL_THREE)){
       		MNCollateral = 1499.99 * COIN;
        } else if (txnheight <= GetSporkValue(SPORK_21_COLLATERAL_FOUR)){
                MNCollateral = 1749.99 * COIN;
        } else if (txnheight <= GetSporkValue(SPORK_22_COLLATERAL_FIVE)){
                MNCollateral = 1999.99 * COIN;
        } else if (txnheight <= GetSporkValue(SPORK_23_COLLATERAL_SIX)){
                MNCollateral = 2249.99 * COIN;
        } else if (txnheight <= GetSporkValue(SPORK_24_COLLATERAL_SEVEN)){
                MNCollateral = 2499.99 * COIN;
        } else if (txnheight <= GetSporkValue(SPORK_25_COLLATERAL_EIGHT)){
                MNCollateral = 2749.99 * COIN;
	} else if (txnheight <= GetSporkValue(SPORK_26_COLLATERAL_NINE)){
                MNCollateral = 2999.99 * COIN;
	} else {
		MNCollateral = 999.99 * COIN;
	}
	} else {
		MNCollateral = 999.99 * COIN;
	}
	} else {
		MNCollateral = 999.99 * COIN;
	}

        CTxOut vout = CTxOut(MNCollateral, obfuScationPool.collateralPubKey);
        tx.vin.push_back(vin);
        tx.vout.push_back(vout);

        {
            TRY_LOCK(cs_main, lockMain);
            if (!lockMain) return;

            if (!AcceptableInputs(mempool, state, CTransaction(tx), false, NULL)) {
                activeState = VNODE_VIN_SPENT;
                return;
            }
        }
    }

    activeState = VNODE_ENABLED; // OK
}

int64_t CVnode::SecondsSincePayment()
{
    CScript pubkeyScript;
    pubkeyScript = GetScriptForDestination(pubKeyCollateralAddress.GetID());

    int64_t sec = (GetAdjustedTime() - GetLastPaid());
    int64_t month = 60 * 60 * 24 * 30;
    if (sec < month) return sec; //if it's less than 30 days, give seconds

    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << vin;
    ss << sigTime;
    uint256 hash = ss.GetHash();

    // return some deterministic value for unknown/unpaid but force it to be more than 30 days old
    return month + hash.GetCompact(false);
}

int64_t CVnode::GetLastPaid()
{
    CBlockIndex* pindexPrev = chainActive.Tip();
    if (pindexPrev == NULL) return false;

    CScript mnpayee;
    mnpayee = GetScriptForDestination(pubKeyCollateralAddress.GetID());

    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << vin;
    ss << sigTime;
    uint256 hash = ss.GetHash();

    // use a deterministic offset to break a tie -- 2.5 minutes
    int64_t nOffset = hash.GetCompact(false) % 150;

    if (chainActive.Tip() == NULL) return false;

    const CBlockIndex* BlockReading = chainActive.Tip();

    int nMnCount = mnodeman.CountEnabled() * 1.25;
    int n = 0;
    for (unsigned int i = 1; BlockReading && BlockReading->nHeight > 0; i++) {
        if (n >= nMnCount) {
            return 0;
        }
        n++;

        if (vnodePayments.mapVnodeBlocks.count(BlockReading->nHeight)) {
            /*
                Search for this payee, with at least 2 votes. This will aid in consensus allowing the network
                to converge on the same payees quickly, then keep the same schedule.
            */
            if (vnodePayments.mapVnodeBlocks[BlockReading->nHeight].HasPayeeWithVotes(mnpayee, 2)) {
                return BlockReading->nTime + nOffset;
            }
        }

        if (BlockReading->pprev == NULL) {
            assert(BlockReading);
            break;
        }
        BlockReading = BlockReading->pprev;
    }

    return 0;
}

std::string CVnode::GetStatus()
{
    switch (nActiveState) {
    case CVnode::VNODE_PRE_ENABLED:
        return "PRE_ENABLED";
    case CVnode::VNODE_ENABLED:
        return "ENABLED";
    case CVnode::VNODE_EXPIRED:
        return "EXPIRED";
    case CVnode::VNODE_OUTPOINT_SPENT:
        return "OUTPOINT_SPENT";
    case CVnode::VNODE_REMOVE:
        return "REMOVE";
    case CVnode::VNODE_WATCHDOG_EXPIRED:
        return "WATCHDOG_EXPIRED";
    case CVnode::VNODE_POSE_BAN:
        return "POSE_BAN";
    default:
        return "UNKNOWN";
    }
}

bool CVnode::IsValidNetAddr()
{
    // TODO: regtest is fine with any addresses for now,
    // should probably be a bit smarter if one day we start to implement tests for this
    return Params().NetworkID() == CBaseChainParams::REGTEST ||
           (IsReachable(addr) && addr.IsRoutable());
}

CVnodeBroadcast::CVnodeBroadcast()
{
    vin = CTxIn();
    addr = CService();
    pubKeyCollateralAddress = CPubKey();
    pubKeyVnode1 = CPubKey();
    sig = std::vector<unsigned char>();
    activeState = VNODE_ENABLED;
    sigTime = GetAdjustedTime();
    lastPing = CVnodePing();
    cacheInputAge = 0;
    cacheInputAgeBlock = 0;
    unitTest = false;
    allowFreeTx = true;
    protocolVersion = PROTOCOL_VERSION;
    nLastDsq = 0;
    nScanningErrorCount = 0;
    nLastScanningErrorBlockHeight = 0;
}

CVnodeBroadcast::CVnodeBroadcast(CService newAddr, CTxIn newVin, CPubKey pubKeyCollateralAddressNew, CPubKey pubKeyVnodeNew, int protocolVersionIn)
{
    vin = newVin;
    addr = newAddr;
    pubKeyCollateralAddress = pubKeyCollateralAddressNew;
    pubKeyVnode = pubKeyVnodeNew;
    sig = std::vector<unsigned char>();
    activeState = VNODE_ENABLED;
    sigTime = GetAdjustedTime();
    lastPing = CVnodePing();
    cacheInputAge = 0;
    cacheInputAgeBlock = 0;
    unitTest = false;
    allowFreeTx = true;
    protocolVersion = protocolVersionIn;
    nLastDsq = 0;
    nScanningErrorCount = 0;
    nLastScanningErrorBlockHeight = 0;
}

CVnodeBroadcast::CVnodeBroadcast(const CVnode& mn)
{
    vin = mn.vin;
    addr = mn.addr;
    pubKeyCollateralAddress = mn.pubKeyCollateralAddress;
    pubKeyVnode = mn.pubKeyVnode;
    sig = mn.sig;
    activeState = mn.activeState;
    sigTime = mn.sigTime;
    lastPing = mn.lastPing;
    cacheInputAge = mn.cacheInputAge;
    cacheInputAgeBlock = mn.cacheInputAgeBlock;
    unitTest = mn.unitTest;
    allowFreeTx = mn.allowFreeTx;
    protocolVersion = mn.protocolVersion;
    nLastDsq = mn.nLastDsq;
    nScanningErrorCount = mn.nScanningErrorCount;
    nLastScanningErrorBlockHeight = mn.nLastScanningErrorBlockHeight;
}

bool CVnodeBroadcast::Create(std::string strService, std::string strKeyVnode, std::string strTxHash, std::string strOutputIndex, std::string& strErrorRet, CVnodeBroadcast& mnbRet, bool fOffline)
{
    CTxIn txin;
    CPubKey pubKeyCollateralAddressNew;
    CKey keyCollateralAddressNew;
    CPubKey pubKeyVnodeNew;
    CKey keyVnodeNew;

    //need correct blocks to send ping
    if (!fOffline && !vnodeSync.IsBlockchainSynced()) {
        strErrorRet = "Sync in progress. Must wait until sync is complete to start Vnode";
        LogPrint("vnode","CVnodeBroadcast::Create -- %s\n", strErrorRet);
        return false;
    }

    if (!obfuScationSigner.GetKeysFromSecret(strKeyVnode, keyVnodeNew, pubKeyVnodeNew)) {
        strErrorRet = strprintf("Invalid vnode key %s", strKeyVnode);
        LogPrint("vnode","CVnodeBroadcast::Create -- %s\n", strErrorRet);
        return false;
    }

    if (!pwalletMain->GetVnodeVinAndKeys(txin, pubKeyCollateralAddressNew, keyCollateralAddressNew, strTxHash, strOutputIndex)) {
        strErrorRet = strprintf("Could not allocate txin %s:%s for vnode %s", strTxHash, strOutputIndex, strService);
        LogPrint("vnode","CVnodeBroadcast::Create -- %s\n", strErrorRet);
        return false;
    }

    CService service = CService(strService);
    int mainnetDefaultPort = Params(CBaseChainParams::MAIN).GetDefaultPort();
    if (Params().NetworkID() == CBaseChainParams::MAIN) {
        if (service.GetPort() != mainnetDefaultPort) {
            strErrorRet = strprintf("Invalid port %u for vnode %s, only %d is supported on mainnet.", service.GetPort(), strService, mainnetDefaultPort);
            LogPrint("vnode","CVnodeBroadcast::Create -- %s\n", strErrorRet);
            return false;
        }
    } else if (service.GetPort() == mainnetDefaultPort) {
        strErrorRet = strprintf("Invalid port %u for vnode %s, %d is the only supported on mainnet.", service.GetPort(), strService, mainnetDefaultPort);
        LogPrint("vnode","CVnodeBroadcast::Create -- %s\n", strErrorRet);
        return false;
    }

    return Create(txin, CService(strService), keyCollateralAddressNew, pubKeyCollateralAddressNew, keyVnodeNew, pubKeyVnodeNew, strErrorRet, mnbRet);
}

bool CVnodeBroadcast::Create(CTxIn txin, CService service, CKey keyCollateralAddressNew, CPubKey pubKeyCollateralAddressNew, CKey keyVnodeNew, CPubKey pubKeyVnodeNew, std::string& strErrorRet, CVnodeBroadcast& mnbRet)
{
    // wait for reindex and/or import to finish
    if (fImporting || fReindex) return false;

    LogPrint("vnode", "CVnodeBroadcast::Create -- pubKeyCollateralAddressNew = %s, pubKeyVnodeNew.GetID() = %s\n",
        CBitcoinAddress(pubKeyCollateralAddressNew.GetID()).ToString(),
        pubKeyVnodeNew.GetID().ToString());

    CVnodePing mnp(txin);
    if (!mnp.Sign(keyVnodeNew, pubKeyVnodeNew)) {
        strErrorRet = strprintf("Failed to sign ping, vnode=%s", txin.prevout.hash.ToString());
        LogPrint("vnode","CVnodeBroadcast::Create -- %s\n", strErrorRet);
        mnbRet = CVnodeBroadcast();
        return false;
    }

    mnbRet = CVnodeBroadcast(service, txin, pubKeyCollateralAddressNew, pubKeyVnodeNew, PROTOCOL_VERSION);

    if (!mnbRet.IsValidNetAddr()) {
        strErrorRet = strprintf("Invalid IP address %s, vnode=%s", mnbRet.addr.ToStringIP (), txin.prevout.hash.ToString());
        LogPrint("vnode","CVnodeBroadcast::Create -- %s\n", strErrorRet);
        mnbRet = CVnodeBroadcast();
        return false;
    }

    mnbRet.lastPing = mnp;
    if (!mnbRet.Sign(keyCollateralAddressNew)) {
        strErrorRet = strprintf("Failed to sign broadcast, vnode=%s", txin.prevout.hash.ToString());
        LogPrint("vnode","CVnodeBroadcast::Create -- %s\n", strErrorRet);
        mnbRet = CVnodeBroadcast();
        return false;
    }

    return true;
}

bool CVnodeBroadcast::CheckAndUpdate(int& nDos)
{
    // make sure signature isn't in the future (past is OK)
    if (sigTime > GetAdjustedTime() + 60 * 60) {
        LogPrint("vnode","mnb - Signature rejected, too far into the future %s\n", vin.prevout.hash.ToString());
        nDos = 1;
        return false;
    }

    std::string vchPubKey(pubKeyCollateralAddress.begin(), pubKeyCollateralAddress.end());
    std::string vchPubKey2(pubKeyVnode.begin(), pubKeyVnode.end());
    std::string strMessage = addr.ToString() + boost::lexical_cast<std::string>(sigTime) + vchPubKey + vchPubKey2 + boost::lexical_cast<std::string>(protocolVersion);

    if (protocolVersion < vnodePayments.GetMinVnodePaymentsProto()) {
        LogPrint("vnode","mnb - ignoring outdated Vnode %s protocol version %d\n", vin.prevout.hash.ToString(), protocolVersion);
        return false;
    }

    CScript pubkeyScript;
    pubkeyScript = GetScriptForDestination(pubKeyCollateralAddress.GetID());

    if (pubkeyScript.size() != 25) {
        LogPrint("vnode","mnb - pubkey the wrong size\n");
        nDos = 100;
        return false;
    }

    CScript pubkeyScript2;
    pubkeyScript2 = GetScriptForDestination(pubKeyVnode.GetID());

    if (pubkeyScript2.size() != 25) {
        LogPrint("vnode","mnb - pubkey2 the wrong size\n");
        nDos = 100;
        return false;
    }

    if (!vin.scriptSig.empty()) {
        LogPrint("vnode","mnb - Ignore Not Empty ScriptSig %s\n", vin.prevout.hash.ToString());
        return false;
    }

    std::string errorMessage = "";
    if (!obfuScationSigner.VerifyMessage(pubKeyCollateralAddress, sig, strMessage, errorMessage)) {
        LogPrint("vnode","mnb - Got bad Vnode address signature\n");
        nDos = 100;
        return false;
    }

    if (Params().NetworkID() == CBaseChainParams::MAIN) {
        if (addr.GetPort() != 7702) return false;
    } else if (addr.GetPort() == 7702)
        return false;

    //search existing Vnode list, this is where we update existing Vnodes with new mnb broadcasts
    CVnode* pmn = mnodeman.Find(vin);

    // no such vnode, nothing to update
    if (pmn == NULL)
        return true;
    else {
        // this broadcast older than we have, it's bad.
        if (pmn->sigTime > sigTime) {
            LogPrint("vnode","mnb - Bad sigTime %d for Vnode %s (existing broadcast is at %d)\n",
                sigTime, vin.prevout.hash.ToString(), pmn->sigTime);
            return false;
        }
        // vnode is not enabled yet/already, nothing to update
        if (!pmn->IsEnabled()) return true;
    }

    // mn.pubkey = pubkey, IsVinAssociatedWithPubkey is validated once below,
    //   after that they just need to match
    if (pmn->pubKeyCollateralAddress == pubKeyCollateralAddress && !pmn->IsBroadcastedWithin(VNODE_MIN_MNB_SECONDS)) {
        //take the newest entry
        LogPrint("vnode","mnb - Got updated entry for %s\n", vin.prevout.hash.ToString());
        if (pmn->UpdateFromNewBroadcast((*this))) {
            pmn->Check();
            if (pmn->IsEnabled()) Relay();
        }
        vnodeSync.AddedVnodeList(GetHash());
    }

    return true;
}

bool CVnodeBroadcast::CheckInputsAndAdd(int& nDoS)
{
    // we are a vnode with the same vin (i.e. already activated) and this mnb is ours (matches our Vnode privkey)
    // so nothing to do here for us
    if (fVNode && vin.prevout == activeVnode.vin.prevout && pubKeyVnode == activeVnode.pubKeyVnode)
        return true;

    // search existing Vnode list
    CVnode* pmn = mnodeman.Find(vin);

    if (pmn != NULL) {
        // nothing to do here if we already know about this vnode and it's enabled
        if (pmn->IsEnabled()) return true;
        // if it's not enabled, remove old MN first and continue
        else
            mnodeman.Remove(pmn->vin);
    }

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

    CTxOut vout = CTxOut(MNCollateral, obfuScationPool.collateralPubKey);
    tx.vin.push_back(vin);
    tx.vout.push_back(vout);

    {
        TRY_LOCK(cs_main, lockMain);
        if (!lockMain) {
            // not mnb fault, let it to be checked again later
            mnodeman.mapSeenVnodeBroadcast.erase(GetHash());
            vnodeSync.mapSeenSyncMNB.erase(GetHash());
            return false;
        }

        if (!AcceptableInputs(mempool, state, CTransaction(tx), false, NULL)) {
            //set nDos
            state.IsInvalid(nDoS);
            return false;
        }
    }

    LogPrint("vnode", "mnb - Accepted Vnode entry\n");

    if (GetInputAge(vin) < VNODE_MIN_CONFIRMATIONS) {
        LogPrint("vnode","mnb - Input must have at least %d confirmations\n", VNODE_MIN_CONFIRMATIONS);
        // maybe we miss few blocks, let this mnb to be checked again later
        mnodeman.mapSeenVnodeBroadcast.erase(GetHash());
        vnodeSync.mapSeenSyncMNB.erase(GetHash());
        return false;
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
            return false;
        }
    }

    LogPrint("vnode","mnb - Got NEW Vnode entry - %s - %lli \n", vin.prevout.hash.ToString(), sigTime);
    CVnode mn(*this);
    mnodeman.Add(mn);

    // if it matches our Vnode privkey, then we've been remotely activated
    if (pubKeyVnode == activeVnode.pubKeyVnode && protocolVersion == PROTOCOL_VERSION) {
        activeVnode.EnableHotColdVNode(vin, addr);
    }

    bool isLocal = addr.IsRFC1918() || addr.IsLocal();
    if (Params().NetworkID() == CBaseChainParams::REGTEST) isLocal = false;

    if (!isLocal) Relay();

    return true;
}

void CVnodeBroadcast::Relay()
{
    CInv inv(MSG_VNODE_ANNOUNCE, GetHash());
    RelayInv(inv);
}

bool CVnodeBroadcast::Sign(CKey& keyCollateralAddress)
{
    std::string errorMessage;

    std::string vchPubKey(pubKeyCollateralAddress.begin(), pubKeyCollateralAddress.end());
    std::string vchPubKey2(pubKeyVnode.begin(), pubKeyVnode.end());

    sigTime = GetAdjustedTime();

    std::string strMessage = addr.ToString() + boost::lexical_cast<std::string>(sigTime) + vchPubKey + vchPubKey2 + boost::lexical_cast<std::string>(protocolVersion);

    if (!obfuScationSigner.SignMessage(strMessage, errorMessage, sig, keyCollateralAddress)) {
        LogPrint("vnode","CVnodeBroadcast::Sign() - Error: %s\n", errorMessage);
        return false;
    }

    if (!obfuScationSigner.VerifyMessage(pubKeyCollateralAddress, sig, strMessage, errorMessage)) {
        LogPrint("vnode","CVnodeBroadcast::Sign() - Error: %s\n", errorMessage);
        return false;
    }

    return true;
}

CVnodePing::CVnodePing()
{
    vin = CTxIn();
    blockHash = uint256(0);
    sigTime = 0;
    vchSig = std::vector<unsigned char>();
}

CVnodePing::CVnodePing(CTxIn& newVin)
{
    vin = newVin;
    blockHash = chainActive[chainActive.Height() - 12]->GetBlockHash();
    sigTime = GetAdjustedTime();
    vchSig = std::vector<unsigned char>();
}


bool CVnodePing::Sign(CKey& keyVnode, CPubKey& pubKeyVnode)
{
    std::string errorMessage;
    std::string strVNodeSignMessage;

    sigTime = GetAdjustedTime();
    std::string strMessage = vin.ToString() + blockHash.ToString() + boost::lexical_cast<std::string>(sigTime);

    if (!obfuScationSigner.SignMessage(strMessage, errorMessage, vchSig, keyVnode)) {
        LogPrint("vnode","CVnodePing::Sign() - Error: %s\n", errorMessage);
        return false;
    }

    if (!obfuScationSigner.VerifyMessage(pubKeyVnode, vchSig, strMessage, errorMessage)) {
        LogPrint("vnode","CVnodePing::Sign() - Error: %s\n", errorMessage);
        return false;
    }

    return true;
}

bool CVnodePing::CheckAndUpdate(int& nDos, bool fRequireEnabled)
{
    if (sigTime > GetAdjustedTime() + 60 * 60) {
        LogPrint("vnode","CVnodePing::CheckAndUpdate - Signature rejected, too far into the future %s\n", vin.prevout.hash.ToString());
        nDos = 1;
        return false;
    }

    if (sigTime <= GetAdjustedTime() - 60 * 60) {
        LogPrint("vnode","CVnodePing::CheckAndUpdate - Signature rejected, too far into the past %s - %d %d \n", vin.prevout.hash.ToString(), sigTime, GetAdjustedTime());
        nDos = 1;
        return false;
    }

    LogPrint("vnode","CVnodePing::CheckAndUpdate - New Ping - %s - %lli\n", blockHash.ToString(), sigTime);

    // see if we have this Vnode
    CVnode* pmn = mnodeman.Find(vin);
    if (pmn != NULL && pmn->protocolVersion >= vnodePayments.GetMinVnodePaymentsProto()) {
        if (fRequireEnabled && !pmn->IsEnabled()) return false;

        // LogPrint("vnode","mnping - Found corresponding mn for vin: %s\n", vin.ToString());
        // update only if there is no known ping for this vnode or
        // last ping was more then VNODE_MIN_MNP_SECONDS-60 ago comparing to this one
        if (!pmn->IsPingedWithin(VNODE_MIN_MNP_SECONDS - 60, sigTime)) {
            std::string strMessage = vin.ToString() + blockHash.ToString() + boost::lexical_cast<std::string>(sigTime);

            std::string errorMessage = "";
            if (!obfuScationSigner.VerifyMessage(pmn->pubKeyVnode, vchSig, strMessage, errorMessage)) {
                LogPrint("vnode","CVnodePing::CheckAndUpdate - Got bad Vnode address signature %s\n", vin.prevout.hash.ToString());
                nDos = 33;
                return false;
            }

            BlockMap::iterator mi = mapBlockIndex.find(blockHash);
            if (mi != mapBlockIndex.end() && (*mi).second) {
                if ((*mi).second->nHeight < chainActive.Height() - 24) {
                    LogPrint("vnode","CVnodePing::CheckAndUpdate - Vnode %s block hash %s is too old\n", vin.prevout.hash.ToString(), blockHash.ToString());
                    // Do nothing here (no Vnode update, no mnping relay)
                    // Let this node to be visible but fail to accept mnping

                    return false;
                }
            } else {
                if (fDebug) LogPrint("vnode","CVnodePing::CheckAndUpdate - Vnode %s block hash %s is unknown\n", vin.prevout.hash.ToString(), blockHash.ToString());
                // maybe we stuck so we shouldn't ban this node, just fail to accept it
                // TODO: or should we also request this block?

                return false;
            }

            pmn->lastPing = *this;

            //mnodeman.mapSeenVnodeBroadcast.lastPing is probably outdated, so we'll update it
            CVnodeBroadcast mnb(*pmn);
            uint256 hash = mnb.GetHash();
            if (mnodeman.mapSeenVnodeBroadcast.count(hash)) {
                mnodeman.mapSeenVnodeBroadcast[hash].lastPing = *this;
            }

            pmn->Check(true);
            if (!pmn->IsEnabled()) return false;

            LogPrint("vnode", "CVnodePing::CheckAndUpdate - Vnode ping accepted, vin: %s\n", vin.prevout.hash.ToString());

            Relay();
            return true;
        }
        LogPrint("vnode", "CVnodePing::CheckAndUpdate - Vnode ping arrived too early, vin: %s\n", vin.prevout.hash.ToString());
        //nDos = 1; //disable, this is happening frequently and causing banned peers
        return false;
    }
    LogPrint("vnode", "CVnodePing::CheckAndUpdate - Couldn't find compatible Vnode entry, vin: %s\n", vin.prevout.hash.ToString());

    return false;
}

void CVnodePing::Relay()
{
    CInv inv(MSG_VNODE_PING, GetHash());
    RelayInv(inv);
}
