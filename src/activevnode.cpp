// Copyright (c) 2014-2016 The Dash developers
// Copyright (c) 2015-2017 The PIVX developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "activevnode.h"
#include "addrman.h"
#include "vnode.h"
#include "vnodeconfig.h"
#include "vnodeman.h"
#include "protocol.h"
#include "spork.h"

//
// Bootup the Vnode, look for a 35000 VENTUAL input and register on the network
//
void CActiveVnode::ManageStatus()
{
    std::string errorMessage;

    if (!fVNode) return;

    if (fDebug) LogPrintf("CActiveVnode::ManageStatus() - Begin\n");

    //need correct blocks to send ping
    if (Params().NetworkID() != CBaseChainParams::REGTEST && !vnodeSync.IsBlockchainSynced()) {
        status = ACTIVE_VNODE_SYNC_IN_PROCESS;
        LogPrintf("CActiveVnode::ManageStatus() - %s\n", GetStatus());
        return;
    }

    if (status == ACTIVE_VNODE_SYNC_IN_PROCESS) status = ACTIVE_VNODE_INITIAL;

    if (status == ACTIVE_VNODE_INITIAL) {
        CVnode* pmn;
        pmn = mnodeman.Find(pubKeyVnode);
        if (pmn != NULL) {
            pmn->Check();
            if (pmn->IsEnabled() && pmn->protocolVersion == PROTOCOL_VERSION) EnableHotColdVNode(pmn->vin, pmn->addr);
        }
    }

    if (status != ACTIVE_VNODE_STARTED) {
        // Set defaults
        status = ACTIVE_VNODE_NOT_CAPABLE;
        notCapableReason = "";

        if (pwalletMain->IsLocked()) {
            notCapableReason = "Wallet is locked.";
            LogPrintf("CActiveVnode::ManageStatus() - not capable: %s\n", notCapableReason);
            return;
        }

        if (pwalletMain->GetBalance() == 0) {
            notCapableReason = "Hot node, waiting for remote activation.";
            LogPrintf("CActiveVnode::ManageStatus() - not capable: %s\n", notCapableReason);
            return;
        }

        if (strVNodeAddr.empty()) {
            if (!GetLocal(service)) {
                notCapableReason = "Can't detect external address. Please use the vnodeaddr configuration option.";
                LogPrintf("CActiveVnode::ManageStatus() - not capable: %s\n", notCapableReason);
                return;
            }
        } else {
            service = CService(strVNodeAddr);
        }

        if (Params().NetworkID() == CBaseChainParams::MAIN) {
            if (service.GetPort() != 7702) {
                notCapableReason = strprintf("Invalid port: %u - only 7702 is supported on mainnet.", service.GetPort());
                LogPrintf("CActiveVnode::ManageStatus() - not capable: %s\n", notCapableReason);
                return;
            }
        } else if (service.GetPort() == 7702) {
            notCapableReason = strprintf("Invalid port: %u - 7702 is only supported on mainnet.", service.GetPort());
            LogPrintf("CActiveVnode::ManageStatus() - not capable: %s\n", notCapableReason);
            return;
        }

        LogPrintf("CActiveVnode::ManageStatus() - Checking inbound connection to '%s'\n", service.ToString());

        CNode* pnode = ConnectNode((CAddress)service, NULL, false);
        if (!pnode) {
            notCapableReason = "Could not connect to " + service.ToString();
            LogPrintf("CActiveVnode::ManageStatus() - not capable: %s\n", notCapableReason);
            return;
        }
        pnode->Release();

        // Choose coins to use
        CPubKey pubKeyCollateralAddress;
        CKey keyCollateralAddress;

        if (GetVNodeVin(vin, pubKeyCollateralAddress, keyCollateralAddress)) {
            if (GetInputAge(vin) < VNODE_MIN_CONFIRMATIONS) {
                status = ACTIVE_VNODE_INPUT_TOO_NEW;
                notCapableReason = strprintf("%s - %d confirmations", GetStatus(), GetInputAge(vin));
                LogPrintf("CActiveVnode::ManageStatus() - %s\n", notCapableReason);
                return;
            }

            LOCK(pwalletMain->cs_wallet);
            pwalletMain->LockCoin(vin.prevout);

            // send to all nodes
            CPubKey pubKeyVnode;
            CKey keyVnode;

            if (!obfuScationSigner.SetKey(strVNodePrivKey, errorMessage, keyVnode, pubKeyVnode)) {
                notCapableReason = "Error upon calling SetKey: " + errorMessage;
                LogPrintf("Register::ManageStatus() - %s\n", notCapableReason);
                return;
            }

            if (!Register(vin, service, keyCollateralAddress, pubKeyCollateralAddress, keyVnode, pubKeyVnode, errorMessage)) {
                notCapableReason = "Error on Register: " + errorMessage;
                LogPrintf("Register::ManageStatus() - %s\n", notCapableReason);
                return;
            }

            LogPrintf("CActiveVnode::ManageStatus() - Is capable master node!\n");
            status = ACTIVE_VNODE_STARTED;

            return;
        } else {
            notCapableReason = "Could not find suitable coins!";
            LogPrintf("CActiveVnode::ManageStatus() - %s\n", notCapableReason);
            return;
        }
    }

    //send to all peers
    if (!SendVnodePing(errorMessage)) {
        LogPrintf("CActiveVnode::ManageStatus() - Error on Ping: %s\n", errorMessage);
    }
}

std::string CActiveVnode::GetStatus()
{
    switch (status) {
    case ACTIVE_VNODE_INITIAL:
        return "Node just started, not yet activated";
    case ACTIVE_VNODE_SYNC_IN_PROCESS:
        return "Sync in progress. Must wait until sync is complete to start Vnode";
    case ACTIVE_VNODE_INPUT_TOO_NEW:
        return strprintf("Vnode input must have at least %d confirmations", VNODE_MIN_CONFIRMATIONS);
    case ACTIVE_VNODE_NOT_CAPABLE:
        return "Not capable vnode: " + notCapableReason;
    case ACTIVE_VNODE_STARTED:
        return "Vnode successfully started";
    default:
        return "unknown";
    }
}

bool CActiveVnode::SendVnodePing(std::string& errorMessage)
{
    if (status != ACTIVE_VNODE_STARTED) {
        errorMessage = "Vnode is not in a running status";
        return false;
    }

    CPubKey pubKeyVnode;
    CKey keyVnode;

    if (!obfuScationSigner.SetKey(strVNodePrivKey, errorMessage, keyVnode, pubKeyVnode)) {
        errorMessage = strprintf("Error upon calling SetKey: %s\n", errorMessage);
        return false;
    }

    LogPrintf("CActiveVnode::SendVnodePing() - Relay Vnode Ping vin = %s\n", vin.ToString());

    CVnodePing mnp(vin);
    if (!mnp.Sign(keyVnode, pubKeyVnode)) {
        errorMessage = "Couldn't sign Vnode Ping";
        return false;
    }

    // Update lastPing for our vnode in Vnode list
    CVnode* pmn = mnodeman.Find(vin);
    if (pmn != NULL) {
        if (pmn->IsPingedWithin(VNODE_PING_SECONDS, mnp.sigTime)) {
            errorMessage = "Too early to send Vnode Ping";
            return false;
        }

        pmn->lastPing = mnp;
        mnodeman.mapSeenVnodePing.insert(make_pair(mnp.GetHash(), mnp));

        //mnodeman.mapSeenVnodeBroadcast.lastPing is probably outdated, so we'll update it
        CVnodeBroadcast mnb(*pmn);
        uint256 hash = mnb.GetHash();
        if (mnodeman.mapSeenVnodeBroadcast.count(hash)) mnodeman.mapSeenVnodeBroadcast[hash].lastPing = mnp;

        mnp.Relay();

        /*
         * IT'S SAFE TO REMOVE THIS IN FURTHER VERSIONS
         * AFTER MIGRATION TO V12 IS DONE
         */

        if (IsSporkActive(SPORK_10_VNODE_PAY_UPDATED_NODES)) return true;
        // for migration purposes ping our node on old vnodes network too
        std::string retErrorMessage;
        std::vector<unsigned char> vchVNodeSignature;
        int64_t masterNodeSignatureTime = GetAdjustedTime();

        std::string strMessage = service.ToString() + boost::lexical_cast<std::string>(masterNodeSignatureTime) + boost::lexical_cast<std::string>(false);

        if (!obfuScationSigner.SignMessage(strMessage, retErrorMessage, vchVNodeSignature, keyVnode)) {
            errorMessage = "dseep sign message failed: " + retErrorMessage;
            return false;
        }

        if (!obfuScationSigner.VerifyMessage(pubKeyVnode, vchVNodeSignature, strMessage, retErrorMessage)) {
            errorMessage = "dseep verify message failed: " + retErrorMessage;
            return false;
        }

        LogPrint("vnode", "dseep - relaying from active mn, %s \n", vin.ToString().c_str());
        LOCK(cs_vNodes);
        BOOST_FOREACH (CNode* pnode, vNodes)
            pnode->PushMessage("dseep", vin, vchVNodeSignature, masterNodeSignatureTime, false);

        /*
         * END OF "REMOVE"
         */

        return true;
    } else {
        // Seems like we are trying to send a ping while the Vnode is not registered in the network
        errorMessage = "Obfuscation Vnode List doesn't include our Vnode, shutting down Vnode pinging service! " + vin.ToString();
        status = ACTIVE_VNODE_NOT_CAPABLE;
        notCapableReason = errorMessage;
        return false;
    }
}

bool CActiveVnode::Register(std::string strService, std::string strKeyVnode, std::string strTxHash, std::string strOutputIndex, std::string& errorMessage)
{
    CTxIn vin;
    CPubKey pubKeyCollateralAddress;
    CKey keyCollateralAddress;
    CPubKey pubKeyVnode;
    CKey keyVnode;

    //need correct blocks to send ping
    if (!vnodeSync.IsBlockchainSynced()) {
        errorMessage = GetStatus();
        LogPrintf("CActiveVnode::Register() - %s\n", errorMessage);
        return false;
    }

    if (!obfuScationSigner.SetKey(strKeyVnode, errorMessage, keyVnode, pubKeyVnode)) {
        errorMessage = strprintf("Can't find keys for vnode %s - %s", strService, errorMessage);
        LogPrintf("CActiveVnode::Register() - %s\n", errorMessage);
        return false;
    }

    if (!GetVNodeVin(vin, pubKeyCollateralAddress, keyCollateralAddress, strTxHash, strOutputIndex)) {
        errorMessage = strprintf("Could not allocate vin %s:%s for vnode %s", strTxHash, strOutputIndex, strService);
        LogPrintf("CActiveVnode::Register() - %s\n", errorMessage);
        return false;
    }

    CService service = CService(strService);
    if (Params().NetworkID() == CBaseChainParams::MAIN) {
        if (service.GetPort() != 7702) {
            errorMessage = strprintf("Invalid port %u for vnode %s - only 7702 is supported on mainnet.", service.GetPort(), strService);
            LogPrintf("CActiveVnode::Register() - %s\n", errorMessage);
            return false;
        }
    } else if (service.GetPort() == 7702) {
        errorMessage = strprintf("Invalid port %u for vnode %s - 7702 is only supported on mainnet.", service.GetPort(), strService);
        LogPrintf("CActiveVnode::Register() - %s\n", errorMessage);
        return false;
    }

    addrman.Add(CAddress(service), CNetAddr("127.0.0.1"), 2 * 60 * 60);

    return Register(vin, CService(strService), keyCollateralAddress, pubKeyCollateralAddress, keyVnode, pubKeyVnode, errorMessage);
}

bool CActiveVnode::Register(CTxIn vin, CService service, CKey keyCollateralAddress, CPubKey pubKeyCollateralAddress, CKey keyVnode, CPubKey pubKeyVnode, std::string& errorMessage)
{
    CVnodeBroadcast mnb;
    CVnodePing mnp(vin);
    if (!mnp.Sign(keyVnode, pubKeyVnode)) {
        errorMessage = strprintf("Failed to sign ping, vin: %s", vin.ToString());
        LogPrintf("CActiveVnode::Register() -  %s\n", errorMessage);
        return false;
    }
    mnodeman.mapSeenVnodePing.insert(make_pair(mnp.GetHash(), mnp));

    LogPrintf("CActiveVnode::Register() - Adding to Vnode list\n    service: %s\n    vin: %s\n", service.ToString(), vin.ToString());
    mnb = CVnodeBroadcast(service, vin, pubKeyCollateralAddress, pubKeyVnode, PROTOCOL_VERSION);
    mnb.lastPing = mnp;
    if (!mnb.Sign(keyCollateralAddress)) {
        errorMessage = strprintf("Failed to sign broadcast, vin: %s", vin.ToString());
        LogPrintf("CActiveVnode::Register() - %s\n", errorMessage);
        return false;
    }
    mnodeman.mapSeenVnodeBroadcast.insert(make_pair(mnb.GetHash(), mnb));
    vnodeSync.AddedVnodeList(mnb.GetHash());

    CVnode* pmn = mnodeman.Find(vin);
    if (pmn == NULL) {
        CVnode mn(mnb);
        mnodeman.Add(mn);
    } else {
        pmn->UpdateFromNewBroadcast(mnb);
    }

    //send to all peers
    LogPrintf("CActiveVnode::Register() - RelayElectionEntry vin = %s\n", vin.ToString());
    mnb.Relay();

    /*
     * IT'S SAFE TO REMOVE THIS IN FURTHER VERSIONS
     * AFTER MIGRATION TO V12 IS DONE
     */

    if (IsSporkActive(SPORK_10_VNODE_PAY_UPDATED_NODES)) return true;
    // for migration purposes inject our node in old vnodes' list too
    std::string retErrorMessage;
    std::vector<unsigned char> vchVNodeSignature;
    int64_t masterNodeSignatureTime = GetAdjustedTime();
    std::string donationAddress = "";
    int donationPercantage = 0;

    std::string vchPubKey(pubKeyCollateralAddress.begin(), pubKeyCollateralAddress.end());
    std::string vchPubKey2(pubKeyVnode.begin(), pubKeyVnode.end());

    std::string strMessage = service.ToString() + boost::lexical_cast<std::string>(masterNodeSignatureTime) + vchPubKey + vchPubKey2 + boost::lexical_cast<std::string>(PROTOCOL_VERSION) + donationAddress + boost::lexical_cast<std::string>(donationPercantage);

    if (!obfuScationSigner.SignMessage(strMessage, retErrorMessage, vchVNodeSignature, keyCollateralAddress)) {
        errorMessage = "dsee sign message failed: " + retErrorMessage;
        LogPrintf("CActiveVnode::Register() - Error: %s\n", errorMessage.c_str());
        return false;
    }

    if (!obfuScationSigner.VerifyMessage(pubKeyCollateralAddress, vchVNodeSignature, strMessage, retErrorMessage)) {
        errorMessage = "dsee verify message failed: " + retErrorMessage;
        LogPrintf("CActiveVnode::Register() - Error: %s\n", errorMessage.c_str());
        return false;
    }

    LOCK(cs_vNodes);
    BOOST_FOREACH (CNode* pnode, vNodes)
        pnode->PushMessage("dsee", vin, service, vchVNodeSignature, masterNodeSignatureTime, pubKeyCollateralAddress, pubKeyVnode, -1, -1, masterNodeSignatureTime, PROTOCOL_VERSION, donationAddress, donationPercantage);

    /*
     * END OF "REMOVE"
     */

    return true;
}

bool CActiveVnode::GetVNodeVin(CTxIn& vin, CPubKey& pubkey, CKey& secretKey)
{
    return GetVNodeVin(vin, pubkey, secretKey, "", "");
}

bool CActiveVnode::GetVNodeVin(CTxIn& vin, CPubKey& pubkey, CKey& secretKey, std::string strTxHash, std::string strOutputIndex)
{
    // Find possible candidates
    TRY_LOCK(pwalletMain->cs_wallet, fWallet);
    if (!fWallet) return false;

    vector<COutput> possibleCoins = SelectCoinsVnode();
    COutput* selectedOutput;

    // Find the vin
    if (!strTxHash.empty()) {
        // Let's find it
        uint256 txHash(strTxHash);
        int outputIndex;
        try {
            outputIndex = std::stoi(strOutputIndex.c_str());
        } catch (const std::exception& e) {
            LogPrintf("%s: %s on strOutputIndex\n", __func__, e.what());
            return false;
        }

        bool found = false;
        BOOST_FOREACH (COutput& out, possibleCoins) {
            if (out.tx->GetHash() == txHash && out.i == outputIndex) {
                selectedOutput = &out;
                found = true;
                break;
            }
        }
        if (!found) {
            LogPrintf("CActiveVnode::GetVNodeVin - Could not locate valid vin\n");
            return false;
        }
    } else {
        // No output specified,  Select the first one
        if (possibleCoins.size() > 0) {
            selectedOutput = &possibleCoins[0];
        } else {
            LogPrintf("CActiveVnode::GetVNodeVin - Could not locate specified vin from possible list\n");
            return false;
        }
    }

    // At this point we have a selected output, retrieve the associated info
    return GetVinFromOutput(*selectedOutput, vin, pubkey, secretKey);
}


// Extract Vnode vin information from output
bool CActiveVnode::GetVinFromOutput(COutput out, CTxIn& vin, CPubKey& pubkey, CKey& secretKey)
{
    CScript pubScript;

    vin = CTxIn(out.tx->GetHash(), out.i);
    pubScript = out.tx->vout[out.i].scriptPubKey; // the inputs PubKey

    CTxDestination address1;
    ExtractDestination(pubScript, address1);
    CBitcoinAddress address2(address1);

    CKeyID keyID;
    if (!address2.GetKeyID(keyID)) {
        LogPrintf("CActiveVnode::GetVNodeVin - Address does not refer to a key\n");
        return false;
    }

    if (!pwalletMain->GetKey(keyID, secretKey)) {
        LogPrintf("CActiveVnode::GetVNodeVin - Private key for address is not known\n");
        return false;
    }

    pubkey = secretKey.GetPubKey();
    return true;
}

// get all possible outputs for running Vnode
vector<COutput> CActiveVnode::SelectCoinsVnode()
{
    vector<COutput> vCoins;
    vector<COutput> filteredCoins;
    vector<COutPoint> confLockedCoins;

    // Temporary unlock MN coins from vnode.conf
    if (GetBoolArg("-mnconflock", true)) {
        uint256 mnTxHash;
        BOOST_FOREACH (CVnodeConfig::CVnodeEntry mne, vnodeConfig.getEntries()) {
            mnTxHash.SetHex(mne.getTxHash());

            int nIndex;
            if(!mne.castOutputIndex(nIndex))
                continue;

            COutPoint outpoint = COutPoint(mnTxHash, nIndex);
            confLockedCoins.push_back(outpoint);
            pwalletMain->UnlockCoin(outpoint);
        }
    }

    // Retrieve all possible outputs
    pwalletMain->AvailableCoins(vCoins);

    // Lock MN coins from vnode.conf back if they where temporary unlocked
    if (!confLockedCoins.empty()) {
        BOOST_FOREACH (COutPoint outpoint, confLockedCoins)
            pwalletMain->LockCoin(outpoint);
    }

    // Filter
    BOOST_FOREACH (const COutput& out, vCoins) {
        if ( out.tx->vout[out.i].nValue == 1000 * COIN ||
             out.tx->vout[out.i].nValue == 1250 * COIN ||
             out.tx->vout[out.i].nValue == 1500 * COIN ||
             out.tx->vout[out.i].nValue == 1750 * COIN ||
             out.tx->vout[out.i].nValue == 2000 * COIN ||
             out.tx->vout[out.i].nValue == 2250 * COIN ||
             out.tx->vout[out.i].nValue == 2500 * COIN ||
             out.tx->vout[out.i].nValue == 2750 * COIN ||
             out.tx->vout[out.i].nValue == 3000 * COIN ) { //exactly
            filteredCoins.push_back(out);
        }
    }
    return filteredCoins;
}

// when starting a Vnode, this can enable to run as a hot wallet with no funds
bool CActiveVnode::EnableHotColdVNode(CTxIn& newVin, CService& newService)
{
    if (!fVNode) return false;

    status = ACTIVE_VNODE_STARTED;

    //The values below are needed for signing mnping messages going forward
    vin = newVin;
    service = newService;

    LogPrintf("CActiveVnode::EnableHotColdVNode() - Enabled! You may shut down the cold daemon.\n");

    return true;
}
