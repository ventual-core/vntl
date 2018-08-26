// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2017 The PIVX developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "vnode-payments.h"
#include "addrman.h"
#include "vnode-budget.h"
#include "vnode-sync.h"
#include "vnodeman.h"
#include "obfuscation.h"
#include "spork.h"
#include "sync.h"
#include "util.h"
#include "utilmoneystr.h"
#include <boost/filesystem.hpp>
#include <boost/lexical_cast.hpp>

/** Object for who's going to get paid on which blocks */
CVnodePayments vnodePayments;

CCriticalSection cs_vecPayments;
CCriticalSection cs_mapVnodeBlocks;
CCriticalSection cs_mapVnodePayeeVotes;

//
// CVnodePaymentDB
//

CVnodePaymentDB::CVnodePaymentDB()
{
    pathDB = GetDataDir() / "mnpayments.dat";
    strMagicMessage = "VnodePayments";
}

bool CVnodePaymentDB::Write(const CVnodePayments& objToSave)
{
    int64_t nStart = GetTimeMillis();

    // serialize, checksum data up to that point, then append checksum
    CDataStream ssObj(SER_DISK, CLIENT_VERSION);
    ssObj << strMagicMessage;                   // vnode cache file specific magic message
    ssObj << FLATDATA(Params().MessageStart()); // network specific magic number
    ssObj << objToSave;
    uint256 hash = Hash(ssObj.begin(), ssObj.end());
    ssObj << hash;

    // open output file, and associate with CAutoFile
    FILE* file = fopen(pathDB.string().c_str(), "wb");
    CAutoFile fileout(file, SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull())
        return error("%s : Failed to open file %s", __func__, pathDB.string());

    // Write and commit header, data
    try {
        fileout << ssObj;
    } catch (std::exception& e) {
        return error("%s : Serialize or I/O error - %s", __func__, e.what());
    }
    fileout.fclose();

    LogPrint("vnode","Written info to mnpayments.dat  %dms\n", GetTimeMillis() - nStart);

    return true;
}

CVnodePaymentDB::ReadResult CVnodePaymentDB::Read(CVnodePayments& objToLoad, bool fDryRun)
{
    int64_t nStart = GetTimeMillis();
    // open input file, and associate with CAutoFile
    FILE* file = fopen(pathDB.string().c_str(), "rb");
    CAutoFile filein(file, SER_DISK, CLIENT_VERSION);
    if (filein.IsNull()) {
        error("%s : Failed to open file %s", __func__, pathDB.string());
        return FileError;
    }

    // use file size to size memory buffer
    int fileSize = boost::filesystem::file_size(pathDB);
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

    CDataStream ssObj(vchData, SER_DISK, CLIENT_VERSION);

    // verify stored checksum matches input data
    uint256 hashTmp = Hash(ssObj.begin(), ssObj.end());
    if (hashIn != hashTmp) {
        error("%s : Checksum mismatch, data corrupted", __func__);
        return IncorrectHash;
    }

    unsigned char pchMsgTmp[4];
    std::string strMagicMessageTmp;
    try {
        // de-serialize file header (vnode cache file specific magic message) and ..
        ssObj >> strMagicMessageTmp;

        // ... verify the message matches predefined one
        if (strMagicMessage != strMagicMessageTmp) {
            error("%s : Invalid vnode payement cache magic message", __func__);
            return IncorrectMagicMessage;
        }


        // de-serialize file header (network specific magic number) and ..
        ssObj >> FLATDATA(pchMsgTmp);

        // ... verify the network matches ours
        if (memcmp(pchMsgTmp, Params().MessageStart(), sizeof(pchMsgTmp))) {
            error("%s : Invalid network magic number", __func__);
            return IncorrectMagicNumber;
        }

        // de-serialize data into CVnodePayments object
        ssObj >> objToLoad;
    } catch (std::exception& e) {
        objToLoad.Clear();
        error("%s : Deserialize or I/O error - %s", __func__, e.what());
        return IncorrectFormat;
    }

    LogPrint("vnode","Loaded info from mnpayments.dat  %dms\n", GetTimeMillis() - nStart);
    LogPrint("vnode","  %s\n", objToLoad.ToString());
    if (!fDryRun) {
        LogPrint("vnode","Vnode payments manager - cleaning....\n");
        objToLoad.CleanPaymentList();
        LogPrint("vnode","Vnode payments manager - result:\n");
        LogPrint("vnode","  %s\n", objToLoad.ToString());
    }

    return Ok;
}

void DumpVnodePayments()
{
    int64_t nStart = GetTimeMillis();

    CVnodePaymentDB paymentdb;
    CVnodePayments tempPayments;

    LogPrint("vnode","Verifying mnpayments.dat format...\n");
    CVnodePaymentDB::ReadResult readResult = paymentdb.Read(tempPayments, true);
    // there was an error and it was not an error on file opening => do not proceed
    if (readResult == CVnodePaymentDB::FileError)
        LogPrint("vnode","Missing budgets file - mnpayments.dat, will try to recreate\n");
    else if (readResult != CVnodePaymentDB::Ok) {
        LogPrint("vnode","Error reading mnpayments.dat: ");
        if (readResult == CVnodePaymentDB::IncorrectFormat)
            LogPrint("vnode","magic is ok but data has invalid format, will try to recreate\n");
        else {
            LogPrint("vnode","file format is unknown or invalid, please fix it manually\n");
            return;
        }
    }
    LogPrint("vnode","Writting info to mnpayments.dat...\n");
    paymentdb.Write(vnodePayments);

    LogPrint("vnode","Budget dump finished  %dms\n", GetTimeMillis() - nStart);
}

bool IsBlockValueValid(const CBlock& block, CAmount nExpectedValue, CAmount nMinted)
{
    CBlockIndex* pindexPrev = chainActive.Tip();
    if (pindexPrev == NULL) return true;

    int nHeight = 0;
    if (pindexPrev->GetBlockHash() == block.hashPrevBlock) {
        nHeight = pindexPrev->nHeight + 1;
    } else { //out of order
        BlockMap::iterator mi = mapBlockIndex.find(block.hashPrevBlock);
        if (mi != mapBlockIndex.end() && (*mi).second)
            nHeight = (*mi).second->nHeight + 1;
    }

    if (nHeight == 0) {
        LogPrint("vnode","IsBlockValueValid() : WARNING: Couldn't find previous block\n");
    }

    //LogPrintf("XX69----------> IsBlockValueValid(): nMinted: %d, nExpectedValue: %d\n", FormatMoney(nMinted), FormatMoney(nExpectedValue));

    if (!vnodeSync.IsSynced()) { //there is no budget data to use to check anything
        //super blocks will always be on these blocks, max 100 per budgeting
        if (nHeight % GetBudgetPaymentCycleBlocks() < 100) {
            return true;
        } else {
            if (nMinted > nExpectedValue) {
                return false;
            }
        }
    } else { // we're synced and have data so check the budget schedule

        //are these blocks even enabled
        if (!IsSporkActive(SPORK_13_ENABLE_SUPERBLOCKS)) {
            return nMinted <= nExpectedValue;
        }

        if (budget.IsBudgetPaymentBlock(nHeight)) {
            //the value of the block is evaluated in CheckBlock
            return true;
        } else {
            if (nMinted > nExpectedValue) {
                return false;
            }
        }
    }

    return true;
}

bool IsBlockPayeeValid(const CBlock& block, int nBlockHeight)
{
    if (!vnodeSync.IsSynced()) { //there is no budget data to use to check anything -- find the longest chain
        LogPrint("mnpayments", "Client not synced, skipping block payee checks\n");
        return true;
    }

    const CTransaction& txNew = (nBlockHeight > Params().LAST_POW_BLOCK() ? block.vtx[1] : block.vtx[0]);

    //check if it's a budget block
    if (IsSporkActive(SPORK_13_ENABLE_SUPERBLOCKS)) {
        if (budget.IsBudgetPaymentBlock(nBlockHeight)) {
            if (budget.IsTransactionValid(txNew, nBlockHeight))
                return true;

            LogPrint("vnode","Invalid budget payment detected %s\n", txNew.ToString().c_str());
            if (IsSporkActive(SPORK_9_VNODE_BUDGET_ENFORCEMENT))
                return false;

            LogPrint("vnode","Budget enforcement is disabled, accepting block\n");
            return true;
        }
    }

    //check for vnode payee
    if (vnodePayments.IsTransactionValid(txNew, nBlockHeight))
        return true;
    LogPrint("vnode","Invalid mn payment detected %s\n", txNew.ToString().c_str());

    if (IsSporkActive(SPORK_8_VNODE_PAYMENT_ENFORCEMENT))
        return false;
    LogPrint("vnode","Vnode payment enforcement is disabled, accepting block\n");

    return true;
}


void FillBlockPayee(CMutableTransaction& txNew, CAmount nFees, bool fProofOfStake)
{
    CBlockIndex* pindexPrev = chainActive.Tip();
    if (!pindexPrev) return;

    if (IsSporkActive(SPORK_13_ENABLE_SUPERBLOCKS) && budget.IsBudgetPaymentBlock(pindexPrev->nHeight + 1)) {
        budget.FillBlockPayee(txNew, nFees, fProofOfStake);
    } else {
        vnodePayments.FillBlockPayee(txNew, nFees, fProofOfStake);
    }
}

std::string GetRequiredPaymentsString(int nBlockHeight)
{
    if (IsSporkActive(SPORK_13_ENABLE_SUPERBLOCKS) && budget.IsBudgetPaymentBlock(nBlockHeight)) {
        return budget.GetRequiredPaymentsString(nBlockHeight);
    } else {
        return vnodePayments.GetRequiredPaymentsString(nBlockHeight);
    }
}

void CVnodePayments::FillBlockPayee(CMutableTransaction& txNew, int64_t nFees, bool fProofOfStake)
{
    CBlockIndex* pindexPrev = chainActive.Tip();
    if (!pindexPrev) return;

    bool hasPayment = true;
    CScript payee;

    //spork
    if (!vnodePayments.GetBlockPayee(pindexPrev->nHeight + 1, payee)) {
        //no vnode detected
        CVnode* winningNode = mnodeman.GetCurrentVNode(1);
        if (winningNode) {
            payee = GetScriptForDestination(winningNode->pubKeyCollateralAddress.GetID());
        } else {
            LogPrint("vnode","CreateNewBlock: Failed to detect vnode to pay\n");
            hasPayment = false;
        }
    }

    CAmount blockValue = GetBlockValue(pindexPrev->nHeight);
    CAmount vnodePayment = GetVnodePayment(pindexPrev->nHeight, blockValue);

    if (hasPayment) {
        if (fProofOfStake) {
            /**For Proof Of Stake vout[0] must be null
             * Stake reward can be split into many different outputs, so we must
             * use vout.size() to align with several different cases.
             * An additional output is appended as the vnode payment
             */
            unsigned int i = txNew.vout.size();
            txNew.vout.resize(i + 1);
            txNew.vout[i].scriptPubKey = payee;
            txNew.vout[i].nValue = vnodePayment;

            //subtract mn payment from the stake reward
            txNew.vout[i - 1].nValue -= vnodePayment;
        } else {
            txNew.vout.resize(2);
            txNew.vout[1].scriptPubKey = payee;
            txNew.vout[1].nValue = vnodePayment;
            txNew.vout[0].nValue = blockValue - vnodePayment;
        }

        CTxDestination address1;
        ExtractDestination(payee, address1);
        CBitcoinAddress address2(address1);

        LogPrint("vnode","Vnode payment of %s to %s\n", FormatMoney(vnodePayment).c_str(), address2.ToString().c_str());
    } else {
		if (!fProofOfStake)
			txNew.vout[0].nValue = blockValue - vnodePayment;
	}
}

int CVnodePayments::GetMinVnodePaymentsProto()
{
    if (IsSporkActive(SPORK_10_VNODE_PAY_UPDATED_NODES))
        return ActiveProtocol();                          // Allow only updated peers
    else
        return MIN_PEER_PROTO_VERSION_BEFORE_ENFORCEMENT; // Also allow old peers as long as they are allowed to run
}

void CVnodePayments::ProcessMessageVnodePayments(CNode* pfrom, std::string& strCommand, CDataStream& vRecv)
{
    if (!vnodeSync.IsBlockchainSynced()) return;

    if (fLiteMode) return; //disable all Obfuscation/Vnode related functionality


    if (strCommand == "mnget") { //Vnode Payments Request Sync
        if (fLiteMode) return;   //disable all Obfuscation/Vnode related functionality

        int nCountNeeded;
        vRecv >> nCountNeeded;

        if (Params().NetworkID() == CBaseChainParams::MAIN) {
            if (pfrom->HasFulfilledRequest("mnget")) {
                LogPrint("vnode","mnget - peer already asked me for the list\n");
                Misbehaving(pfrom->GetId(), 20);
                return;
            }
        }

        pfrom->FulfilledRequest("mnget");
        vnodePayments.Sync(pfrom, nCountNeeded);
        LogPrint("mnpayments", "mnget - Sent Vnode winners to peer %i\n", pfrom->GetId());
    } else if (strCommand == "mnw") { //Vnode Payments Declare Winner
        //this is required in litemodef
        CVnodePaymentWinner winner;
        vRecv >> winner;

        if (pfrom->nVersion < ActiveProtocol()) return;

        int nHeight;
        {
            TRY_LOCK(cs_main, locked);
            if (!locked || chainActive.Tip() == NULL) return;
            nHeight = chainActive.Tip()->nHeight;
        }

        if (vnodePayments.mapVnodePayeeVotes.count(winner.GetHash())) {
            LogPrint("mnpayments", "mnw - Already seen - %s bestHeight %d\n", winner.GetHash().ToString().c_str(), nHeight);
            vnodeSync.AddedVnodeWinner(winner.GetHash());
            return;
        }

        int nFirstBlock = nHeight - (mnodeman.CountEnabled() * 1.25);
        if (winner.nBlockHeight < nFirstBlock || winner.nBlockHeight > nHeight + 20) {
            LogPrint("mnpayments", "mnw - winner out of range - FirstBlock %d Height %d bestHeight %d\n", nFirstBlock, winner.nBlockHeight, nHeight);
            return;
        }

        std::string strError = "";
        if (!winner.IsValid(pfrom, strError)) {
            // if(strError != "") LogPrint("vnode","mnw - invalid message - %s\n", strError);
            return;
        }

        if (!vnodePayments.CanVote(winner.vinVnode.prevout, winner.nBlockHeight)) {
            //  LogPrint("vnode","mnw - vnode already voted - %s\n", winner.vinVnode.prevout.ToStringShort());
            return;
        }

        if (!winner.SignatureValid()) {
            // LogPrint("vnode","mnw - invalid signature\n");
            if (vnodeSync.IsSynced()) Misbehaving(pfrom->GetId(), 20);
            // it could just be a non-synced vnode
            mnodeman.AskForMN(pfrom, winner.vinVnode);
            return;
        }

        CTxDestination address1;
        ExtractDestination(winner.payee, address1);
        CBitcoinAddress address2(address1);

        //   LogPrint("mnpayments", "mnw - winning vote - Addr %s Height %d bestHeight %d - %s\n", address2.ToString().c_str(), winner.nBlockHeight, nHeight, winner.vinVnode.prevout.ToStringShort());

        if (vnodePayments.AddWinningVnode(winner)) {
            winner.Relay();
            vnodeSync.AddedVnodeWinner(winner.GetHash());
        }
    }
}

bool CVnodePaymentWinner::Sign(CKey& keyVnode, CPubKey& pubKeyVnode)
{
    std::string errorMessage;
    std::string strVNodeSignMessage;

    std::string strMessage = vinVnode.prevout.ToStringShort() +
                             boost::lexical_cast<std::string>(nBlockHeight) +
                             payee.ToString();

    if (!obfuScationSigner.SignMessage(strMessage, errorMessage, vchSig, keyVnode)) {
        LogPrint("vnode","CVnodePing::Sign() - Error: %s\n", errorMessage.c_str());
        return false;
    }

    if (!obfuScationSigner.VerifyMessage(pubKeyVnode, vchSig, strMessage, errorMessage)) {
        LogPrint("vnode","CVnodePing::Sign() - Error: %s\n", errorMessage.c_str());
        return false;
    }

    return true;
}

bool CVnodePayments::GetBlockPayee(int nBlockHeight, CScript& payee)
{
    if (mapVnodeBlocks.count(nBlockHeight)) {
        return mapVnodeBlocks[nBlockHeight].GetPayee(payee);
    }

    return false;
}

// Is this vnode scheduled to get paid soon?
// -- Only look ahead up to 8 blocks to allow for propagation of the latest 2 winners
bool CVnodePayments::IsScheduled(CVnode& mn, int nNotBlockHeight)
{
    LOCK(cs_mapVnodeBlocks);

    int nHeight;
    {
        TRY_LOCK(cs_main, locked);
        if (!locked || chainActive.Tip() == NULL) return false;
        nHeight = chainActive.Tip()->nHeight;
    }

    CScript mnpayee;
    mnpayee = GetScriptForDestination(mn.pubKeyCollateralAddress.GetID());

    CScript payee;
    for (int64_t h = nHeight; h <= nHeight + 8; h++) {
        if (h == nNotBlockHeight) continue;
        if (mapVnodeBlocks.count(h)) {
            if (mapVnodeBlocks[h].GetPayee(payee)) {
                if (mnpayee == payee) {
                    return true;
                }
            }
        }
    }

    return false;
}

bool CVnodePayments::AddWinningVnode(CVnodePaymentWinner& winnerIn)
{
    uint256 blockHash = 0;
    if (!GetBlockHash(blockHash, winnerIn.nBlockHeight - 100)) {
        return false;
    }

    {
        LOCK2(cs_mapVnodePayeeVotes, cs_mapVnodeBlocks);

        if (mapVnodePayeeVotes.count(winnerIn.GetHash())) {
            return false;
        }

        mapVnodePayeeVotes[winnerIn.GetHash()] = winnerIn;

        if (!mapVnodeBlocks.count(winnerIn.nBlockHeight)) {
            CVnodeBlockPayees blockPayees(winnerIn.nBlockHeight);
            mapVnodeBlocks[winnerIn.nBlockHeight] = blockPayees;
        }
    }

    mapVnodeBlocks[winnerIn.nBlockHeight].AddPayee(winnerIn.payee, 1);

    return true;
}

bool CVnodeBlockPayees::IsTransactionValid(const CTransaction& txNew)
{
    LOCK(cs_vecPayments);

    int nMaxSignatures = 0;
    int nVnode_Drift_Count = 0;

    std::string strPayeesPossible = "";

    CAmount nReward = GetBlockValue(nBlockHeight);

    if (IsSporkActive(SPORK_8_VNODE_PAYMENT_ENFORCEMENT)) {
        // Get a stable number of vnodes by ignoring newly activated (< 8000 sec old) vnodes
        nVnode_Drift_Count = mnodeman.stable_size() + Params().VnodeCountDrift();
    }
    else {
        //account for the fact that all peers do not see the same vnode count. A allowance of being off our vnode count is given
        //we only need to look at an increased vnode count because as count increases, the reward decreases. This code only checks
        //for mnPayment >= required, so it only makes sense to check the max node count allowed.
        nVnode_Drift_Count = mnodeman.size() + Params().VnodeCountDrift();
    }

    CAmount requiredVnodePayment = GetVnodePayment(nBlockHeight, nReward, nVnode_Drift_Count);

    //require at least 6 signatures
    BOOST_FOREACH (CVnodePayee& payee, vecPayments)
        if (payee.nVotes >= nMaxSignatures && payee.nVotes >= MNPAYMENTS_SIGNATURES_REQUIRED)
            nMaxSignatures = payee.nVotes;

    // if we don't have at least 6 signatures on a payee, approve whichever is the longest chain
    if (nMaxSignatures < MNPAYMENTS_SIGNATURES_REQUIRED) return true;

    BOOST_FOREACH (CVnodePayee& payee, vecPayments) {
        bool found = false;
        BOOST_FOREACH (CTxOut out, txNew.vout) {
            if (payee.scriptPubKey == out.scriptPubKey) {
                if(out.nValue >= requiredVnodePayment)
                    found = true;
                else
                    LogPrint("vnode","Vnode payment is out of drift range. Paid=%s Min=%s\n", FormatMoney(out.nValue).c_str(), FormatMoney(requiredVnodePayment).c_str());
            }
        }

        if (payee.nVotes >= MNPAYMENTS_SIGNATURES_REQUIRED) {
            if (found) return true;

            CTxDestination address1;
            ExtractDestination(payee.scriptPubKey, address1);
            CBitcoinAddress address2(address1);

            if (strPayeesPossible == "") {
                strPayeesPossible += address2.ToString();
            } else {
                strPayeesPossible += "," + address2.ToString();
            }
        }
    }

    LogPrint("vnode","CVnodePayments::IsTransactionValid - Missing required payment of %s to %s\n", FormatMoney(requiredVnodePayment).c_str(), strPayeesPossible.c_str());
    return false;
}

std::string CVnodeBlockPayees::GetRequiredPaymentsString()
{
    LOCK(cs_vecPayments);

    std::string ret = "Unknown";

    BOOST_FOREACH (CVnodePayee& payee, vecPayments) {
        CTxDestination address1;
        ExtractDestination(payee.scriptPubKey, address1);
        CBitcoinAddress address2(address1);

        if (ret != "Unknown") {
            ret += ", " + address2.ToString() + ":" + boost::lexical_cast<std::string>(payee.nVotes);
        } else {
            ret = address2.ToString() + ":" + boost::lexical_cast<std::string>(payee.nVotes);
        }
    }

    return ret;
}

std::string CVnodePayments::GetRequiredPaymentsString(int nBlockHeight)
{
    LOCK(cs_mapVnodeBlocks);

    if (mapVnodeBlocks.count(nBlockHeight)) {
        return mapVnodeBlocks[nBlockHeight].GetRequiredPaymentsString();
    }

    return "Unknown";
}

bool CVnodePayments::IsTransactionValid(const CTransaction& txNew, int nBlockHeight)
{
    LOCK(cs_mapVnodeBlocks);

    if (mapVnodeBlocks.count(nBlockHeight)) {
        return mapVnodeBlocks[nBlockHeight].IsTransactionValid(txNew);
    }

    return true;
}

void CVnodePayments::CleanPaymentList()
{
    LOCK2(cs_mapVnodePayeeVotes, cs_mapVnodeBlocks);

    int nHeight;
    {
        TRY_LOCK(cs_main, locked);
        if (!locked || chainActive.Tip() == NULL) return;
        nHeight = chainActive.Tip()->nHeight;
    }

    //keep up to five cycles for historical sake
    int nLimit = std::max(int(mnodeman.size() * 1.25), 1000);

    std::map<uint256, CVnodePaymentWinner>::iterator it = mapVnodePayeeVotes.begin();
    while (it != mapVnodePayeeVotes.end()) {
        CVnodePaymentWinner winner = (*it).second;

        if (nHeight - winner.nBlockHeight > nLimit) {
            LogPrint("mnpayments", "CVnodePayments::CleanPaymentList - Removing old Vnode payment - block %d\n", winner.nBlockHeight);
            vnodeSync.mapSeenSyncMNW.erase((*it).first);
            mapVnodePayeeVotes.erase(it++);
            mapVnodeBlocks.erase(winner.nBlockHeight);
        } else {
            ++it;
        }
    }
}

bool CVnodePaymentWinner::IsValid(CNode* pnode, std::string& strError)
{
    CVnode* pmn = mnodeman.Find(vinVnode);

    if (!pmn) {
        strError = strprintf("Unknown Vnode %s", vinVnode.prevout.hash.ToString());
        LogPrint("vnode","CVnodePaymentWinner::IsValid - %s\n", strError);
        mnodeman.AskForMN(pnode, vinVnode);
        return false;
    }

    if (pmn->protocolVersion < ActiveProtocol()) {
        strError = strprintf("Vnode protocol too old %d - req %d", pmn->protocolVersion, ActiveProtocol());
        LogPrint("vnode","CVnodePaymentWinner::IsValid - %s\n", strError);
        return false;
    }

    int n = mnodeman.GetVnodeRank(vinVnode, nBlockHeight - 100, ActiveProtocol());

    if (n > MNPAYMENTS_SIGNATURES_TOTAL) {
        //It's common to have vnodes mistakenly think they are in the top 10
        // We don't want to print all of these messages, or punish them unless they're way off
        if (n > MNPAYMENTS_SIGNATURES_TOTAL * 2) {
            strError = strprintf("Vnode not in the top %d (%d)", MNPAYMENTS_SIGNATURES_TOTAL * 2, n);
            LogPrint("vnode","CVnodePaymentWinner::IsValid - %s\n", strError);
            //if (vnodeSync.IsSynced()) Misbehaving(pnode->GetId(), 20);
        }
        return false;
    }

    return true;
}

bool CVnodePayments::ProcessBlock(int nBlockHeight)
{
    if (!fVNode) return false;

    //reference node - hybrid mode

    int n = mnodeman.GetVnodeRank(activeVnode.vin, nBlockHeight - 100, ActiveProtocol());

    if (n == -1) {
        LogPrint("mnpayments", "CVnodePayments::ProcessBlock - Unknown Vnode\n");
        return false;
    }

    if (n > MNPAYMENTS_SIGNATURES_TOTAL) {
        LogPrint("mnpayments", "CVnodePayments::ProcessBlock - Vnode not in the top %d (%d)\n", MNPAYMENTS_SIGNATURES_TOTAL, n);
        return false;
    }

    if (nBlockHeight <= nLastBlockHeight) return false;

    CVnodePaymentWinner newWinner(activeVnode.vin);

    if (budget.IsBudgetPaymentBlock(nBlockHeight)) {
        //is budget payment block -- handled by the budgeting software
    } else {
        LogPrint("vnode","CVnodePayments::ProcessBlock() Start nHeight %d - vin %s. \n", nBlockHeight, activeVnode.vin.prevout.hash.ToString());

        // pay to the oldest MN that still had no payment but its input is old enough and it was active long enough
        int nCount = 0;
        CVnode* pmn = mnodeman.GetNextVnodeInQueueForPayment(nBlockHeight, true, nCount);

        if (pmn != NULL) {
            LogPrint("vnode","CVnodePayments::ProcessBlock() Found by FindOldestNotInVec \n");

            newWinner.nBlockHeight = nBlockHeight;

            CScript payee = GetScriptForDestination(pmn->pubKeyCollateralAddress.GetID());
            newWinner.AddPayee(payee);

            CTxDestination address1;
            ExtractDestination(payee, address1);
            CBitcoinAddress address2(address1);

            LogPrint("vnode","CVnodePayments::ProcessBlock() Winner payee %s nHeight %d. \n", address2.ToString().c_str(), newWinner.nBlockHeight);
        } else {
            LogPrint("vnode","CVnodePayments::ProcessBlock() Failed to find vnode to pay\n");
        }
    }

    std::string errorMessage;
    CPubKey pubKeyVnode;
    CKey keyVnode;

    if (!obfuScationSigner.SetKey(strVNodePrivKey, errorMessage, keyVnode, pubKeyVnode)) {
        LogPrint("vnode","CVnodePayments::ProcessBlock() - Error upon calling SetKey: %s\n", errorMessage.c_str());
        return false;
    }

    LogPrint("vnode","CVnodePayments::ProcessBlock() - Signing Winner\n");
    if (newWinner.Sign(keyVnode, pubKeyVnode)) {
        LogPrint("vnode","CVnodePayments::ProcessBlock() - AddWinningVnode\n");

        if (AddWinningVnode(newWinner)) {
            newWinner.Relay();
            nLastBlockHeight = nBlockHeight;
            return true;
        }
    }

    return false;
}

void CVnodePaymentWinner::Relay()
{
    CInv inv(MSG_VNODE_WINNER, GetHash());
    RelayInv(inv);
}

bool CVnodePaymentWinner::SignatureValid()
{
    CVnode* pmn = mnodeman.Find(vinVnode);

    if (pmn != NULL) {
        std::string strMessage = vinVnode.prevout.ToStringShort() +
                                 boost::lexical_cast<std::string>(nBlockHeight) +
                                 payee.ToString();

        std::string errorMessage = "";
        if (!obfuScationSigner.VerifyMessage(pmn->pubKeyVnode, vchSig, strMessage, errorMessage)) {
            return error("CVnodePaymentWinner::SignatureValid() - Got bad Vnode address signature %s\n", vinVnode.prevout.hash.ToString());
        }

        return true;
    }

    return false;
}

void CVnodePayments::Sync(CNode* node, int nCountNeeded)
{
    LOCK(cs_mapVnodePayeeVotes);

    int nHeight;
    {
        TRY_LOCK(cs_main, locked);
        if (!locked || chainActive.Tip() == NULL) return;
        nHeight = chainActive.Tip()->nHeight;
    }

    int nCount = (mnodeman.CountEnabled() * 1.25);
    if (nCountNeeded > nCount) nCountNeeded = nCount;

    int nInvCount = 0;
    std::map<uint256, CVnodePaymentWinner>::iterator it = mapVnodePayeeVotes.begin();
    while (it != mapVnodePayeeVotes.end()) {
        CVnodePaymentWinner winner = (*it).second;
        if (winner.nBlockHeight >= nHeight - nCountNeeded && winner.nBlockHeight <= nHeight + 20) {
            node->PushInventory(CInv(MSG_VNODE_WINNER, winner.GetHash()));
            nInvCount++;
        }
        ++it;
    }
    node->PushMessage("ssc", VNODE_SYNC_MNW, nInvCount);
}

std::string CVnodePayments::ToString() const
{
    std::ostringstream info;

    info << "Votes: " << (int)mapVnodePayeeVotes.size() << ", Blocks: " << (int)mapVnodeBlocks.size();

    return info.str();
}


int CVnodePayments::GetOldestBlock()
{
    LOCK(cs_mapVnodeBlocks);

    int nOldestBlock = std::numeric_limits<int>::max();

    std::map<int, CVnodeBlockPayees>::iterator it = mapVnodeBlocks.begin();
    while (it != mapVnodeBlocks.end()) {
        if ((*it).first < nOldestBlock) {
            nOldestBlock = (*it).first;
        }
        it++;
    }

    return nOldestBlock;
}


int CVnodePayments::GetNewestBlock()
{
    LOCK(cs_mapVnodeBlocks);

    int nNewestBlock = 0;

    std::map<int, CVnodeBlockPayees>::iterator it = mapVnodeBlocks.begin();
    while (it != mapVnodeBlocks.end()) {
        if ((*it).first > nNewestBlock) {
            nNewestBlock = (*it).first;
        }
        it++;
    }

    return nNewestBlock;
}
