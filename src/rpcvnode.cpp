// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2015-2017 The PIVX developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "activevnode.h"
#include "db.h"
#include "init.h"
#include "main.h"
#include "vnode-budget.h"
#include "vnode-payments.h"
#include "vnodeconfig.h"
#include "vnodeman.h"
#include "rpcserver.h"
#include "utilmoneystr.h"

#include <boost/tokenizer.hpp>

#include <fstream>
using namespace json_spirit;

void SendMoney(const CTxDestination& address, CAmount nValue, CWalletTx& wtxNew, AvailableCoinsType coin_type = ALL_COINS)
{
    // Check amount
    if (nValue <= 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid amount");

    if (nValue > pwalletMain->GetBalance())
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds");

    string strError;
    if (pwalletMain->IsLocked()) {
        strError = "Error: Wallet locked, unable to create transaction!";
        LogPrintf("SendMoney() : %s", strError);
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }

    // Parse Ventual address
    CScript scriptPubKey = GetScriptForDestination(address);

    // Create and send the transaction
    CReserveKey reservekey(pwalletMain);
    CAmount nFeeRequired;
    if (!pwalletMain->CreateTransaction(scriptPubKey, nValue, wtxNew, reservekey, nFeeRequired, strError, NULL, coin_type)) {
        if (nValue + nFeeRequired > pwalletMain->GetBalance())
            strError = strprintf("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds!", FormatMoney(nFeeRequired));
        LogPrintf("SendMoney() : %s\n", strError);
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }
    if (!pwalletMain->CommitTransaction(wtxNew, reservekey))
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: The transaction was rejected! This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");
}

Value obfuscation(const Array& params, bool fHelp)
{
    throw runtime_error("Obfuscation is not supported any more. User Zerocoin\n");

    if (fHelp || params.size() == 0)
        throw runtime_error(
            "obfuscation <ventualaddress> <amount>\n"
            "ventualaddress, reset, or auto (AutoDenominate)"
            "<amount> is a real and will be rounded to the next 0.1" +
            HelpRequiringPassphrase());

    if (pwalletMain->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");

    if (params[0].get_str() == "auto") {
        if (fVNode)
            return "ObfuScation is not supported from vnodes";

        return "DoAutomaticDenominating " + (obfuScationPool.DoAutomaticDenominating() ? "successful" : ("failed: " + obfuScationPool.GetStatus()));
    }

    if (params[0].get_str() == "reset") {
        obfuScationPool.Reset();
        return "successfully reset obfuscation";
    }

    if (params.size() != 2)
        throw runtime_error(
            "obfuscation <ventualaddress> <amount>\n"
            "ventualaddress, denominate, or auto (AutoDenominate)"
            "<amount> is a real and will be rounded to the next 0.1" +
            HelpRequiringPassphrase());

    CBitcoinAddress address(params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Ventual address");

    // Amount
    CAmount nAmount = AmountFromValue(params[1]);

    // Wallet comments
    CWalletTx wtx;
    //    string strError = pwalletMain->SendMoneyToDestination(address.Get(), nAmount, wtx, ONLY_DENOMINATED);
    SendMoney(address.Get(), nAmount, wtx, ONLY_DENOMINATED);
    //    if (strError != "")
    //        throw JSONRPCError(RPC_WALLET_ERROR, strError);

    return wtx.GetHash().GetHex();
}

Value getpoolinfo(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getpoolinfo\n"
            "\nReturns anonymous pool-related information\n"

            "\nResult:\n"
            "{\n"
            "  \"current\": \"addr\",    (string) Ventual address of current vnode\n"
            "  \"state\": xxxx,        (string) unknown\n"
            "  \"entries\": xxxx,      (numeric) Number of entries\n"
            "  \"accepted\": xxxx,     (numeric) Number of entries accepted\n"
            "}\n"

            "\nExamples:\n" +
            HelpExampleCli("getpoolinfo", "") + HelpExampleRpc("getpoolinfo", ""));

    Object obj;
    obj.push_back(Pair("current_vnode", mnodeman.GetCurrentVNode()->addr.ToString()));
    obj.push_back(Pair("state", obfuScationPool.GetState()));
    obj.push_back(Pair("entries", obfuScationPool.GetEntriesCount()));
    obj.push_back(Pair("entries_accepted", obfuScationPool.GetCountEntriesAccepted()));
    return obj;
}

// This command is retained for backwards compatibility, but is depreciated.
// Future removal of this command is planned to keep things clean.
Value vnode(const Array& params, bool fHelp)
{
    string strCommand;
    if (params.size() >= 1)
        strCommand = params[0].get_str();

    if (fHelp ||
        (strCommand != "start" && strCommand != "start-alias" && strCommand != "start-many" && strCommand != "start-all" && strCommand != "start-missing" &&
            strCommand != "start-disabled" && strCommand != "list" && strCommand != "list-conf" && strCommand != "count" && strCommand != "enforce" &&
            strCommand != "debug" && strCommand != "current" && strCommand != "winners" && strCommand != "genkey" && strCommand != "connect" &&
            strCommand != "outputs" && strCommand != "status" && strCommand != "calcscore"))
        throw runtime_error(
            "vnode \"command\"...\n"
            "\nSet of commands to execute vnode related actions\n"
            "This command is depreciated, please see individual command documentation for future reference\n\n"

            "\nArguments:\n"
            "1. \"command\"        (string or set of strings, required) The command to execute\n"

            "\nAvailable commands:\n"
            "  count        - Print count information of all known vnodes\n"
            "  current      - Print info on current vnode winner\n"
            "  debug        - Print vnode status\n"
            "  genkey       - Generate new vnodeprivkey\n"
            "  outputs      - Print vnode compatible outputs\n"
            "  start        - Start vnode configured in ventual.conf\n"
            "  start-alias  - Start single vnode by assigned alias configured in vnode.conf\n"
            "  start-<mode> - Start vnodes configured in vnode.conf (<mode>: 'all', 'missing', 'disabled')\n"
            "  status       - Print vnode status information\n"
            "  list         - Print list of all known vnodes (see vnodelist for more info)\n"
            "  list-conf    - Print vnode.conf in JSON format\n"
            "  winners      - Print list of vnode winners\n");

    if (strCommand == "list") {
        Array newParams(params.size() - 1);
        std::copy(params.begin() + 1, params.end(), newParams.begin());
        return listvnodes(newParams, fHelp);
    }

    if (strCommand == "connect") {
        Array newParams(params.size() -1);
        std::copy(params.begin() + 1, params.end(), newParams.begin());
        return vnodeconnect(newParams, fHelp);
    }

    if (strCommand == "count") {
        Array newParams(params.size() - 1);
        std::copy(params.begin() + 1, params.end(), newParams.begin());
        return getvnodecount(newParams, fHelp);
    }

    if (strCommand == "current") {
        Array newParams(params.size() - 1);
        std::copy(params.begin() + 1, params.end(), newParams.begin());
        return vnodecurrent(newParams, fHelp);
    }

    if (strCommand == "debug") {
        Array newParams(params.size() - 1);
        std::copy(params.begin() + 1, params.end(), newParams.begin());
        return vnodedebug(newParams, fHelp);
    }

    if (strCommand == "start" || strCommand == "start-alias" || strCommand == "start-many" || strCommand == "start-all" || strCommand == "start-missing" || strCommand == "start-disabled") {
        return startvnode(params, fHelp);
    }

    if (strCommand == "genkey") {
        Array newParams(params.size() - 1);
        std::copy(params.begin() + 1, params.end(), newParams.begin());
        return createvnodekey(newParams, fHelp);
    }

    if (strCommand == "list-conf") {
        Array newParams(params.size() - 1);
        std::copy(params.begin() + 1, params.end(), newParams.begin());
        return listvnodeconf(newParams, fHelp);
    }

    if (strCommand == "outputs") {
        Array newParams(params.size() - 1);
        std::copy(params.begin() + 1, params.end(), newParams.begin());
        return getvnodeoutputs(newParams, fHelp);
    }

    if (strCommand == "status") {
        Array newParams(params.size() - 1);
        std::copy(params.begin() + 1, params.end(), newParams.begin());
        return getvnodestatus(newParams, fHelp);
    }

    if (strCommand == "winners") {
        Array newParams(params.size() - 1);
        std::copy(params.begin() + 1, params.end(), newParams.begin());
        return getvnodewinners(newParams, fHelp);
    }

    if (strCommand == "calcscore") {
        Array newParams(params.size() - 1);
        std::copy(params.begin() + 1, params.end(), newParams.begin());
        return getvnodescores(newParams, fHelp);
    }

    return Value::null;
}

Value listvnodes(const Array& params, bool fHelp)
{
    std::string strFilter = "";

    if (params.size() == 1) strFilter = params[0].get_str();

    if (fHelp || (params.size() > 1))
        throw runtime_error(
            "listvnodes ( \"filter\" )\n"
            "\nGet a ranked list of vnodes\n"

            "\nArguments:\n"
            "1. \"filter\"    (string, optional) Filter search text. Partial match by txhash, status, or addr.\n"

            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"rank\": n,           (numeric) Vnode Rank (or 0 if not enabled)\n"
            "    \"txhash\": \"hash\",    (string) Collateral transaction hash\n"
            "    \"outidx\": n,         (numeric) Collateral transaction output index\n"
            "    \"status\": s,         (string) Status (ENABLED/EXPIRED/REMOVE/etc)\n"
            "    \"addr\": \"addr\",      (string) Vnode Ventual address\n"
            "    \"version\": v,        (numeric) Vnode protocol version\n"
            "    \"lastseen\": ttt,     (numeric) The time in seconds since epoch (Jan 1 1970 GMT) of the last seen\n"
            "    \"activetime\": ttt,   (numeric) The time in seconds since epoch (Jan 1 1970 GMT) vnode has been active\n"
            "    \"lastpaid\": ttt,     (numeric) The time in seconds since epoch (Jan 1 1970 GMT) vnode was last paid\n"
            "  }\n"
            "  ,...\n"
            "]\n"
            "\nExamples:\n" +
            HelpExampleCli("vnodelist", "") + HelpExampleRpc("vnodelist", ""));

    Array ret;
    int nHeight;
    {
        LOCK(cs_main);
        CBlockIndex* pindex = chainActive.Tip();
        if(!pindex) return 0;
        nHeight = pindex->nHeight;
    }
    std::vector<pair<int, CVnode> > vVnodeRanks = mnodeman.GetVnodeRanks(nHeight);
    BOOST_FOREACH (PAIRTYPE(int, CVnode) & s, vVnodeRanks) {
        Object obj;
        std::string strVin = s.second.vin.prevout.ToStringShort();
        std::string strTxHash = s.second.vin.prevout.hash.ToString();
        uint32_t oIdx = s.second.vin.prevout.n;

        CVnode* mn = mnodeman.Find(s.second.vin);

        if (mn != NULL) {
            if (strFilter != "" && strTxHash.find(strFilter) == string::npos &&
                mn->Status().find(strFilter) == string::npos &&
                CBitcoinAddress(mn->pubKeyCollateralAddress.GetID()).ToString().find(strFilter) == string::npos) continue;

            std::string strStatus = mn->Status();
            std::string strHost;
            int port;
            SplitHostPort(mn->addr.ToString(), port, strHost);
            CNetAddr node = CNetAddr(strHost, false);
            std::string strNetwork = GetNetworkName(node.GetNetwork());

            obj.push_back(Pair("rank", (strStatus == "ENABLED" ? s.first : 0)));
            obj.push_back(Pair("network", strNetwork));
            obj.push_back(Pair("txhash", strTxHash));
            obj.push_back(Pair("outidx", (uint64_t)oIdx));
            obj.push_back(Pair("status", strStatus));
            obj.push_back(Pair("addr", CBitcoinAddress(mn->pubKeyCollateralAddress.GetID()).ToString()));
            obj.push_back(Pair("version", mn->protocolVersion));
            obj.push_back(Pair("lastseen", (int64_t)mn->lastPing.sigTime));
            obj.push_back(Pair("activetime", (int64_t)(mn->lastPing.sigTime - mn->sigTime)));
            obj.push_back(Pair("lastpaid", (int64_t)mn->GetLastPaid()));

            ret.push_back(obj);
        }
    }

    return ret;
}

Value vnodeconnect(const Array& params, bool fHelp)
{
    if (fHelp || (params.size() != 1))
        throw runtime_error(
            "vnodeconnect \"address\"\n"
            "\nAttempts to connect to specified vnode address\n"

            "\nArguments:\n"
            "1. \"address\"     (string, required) IP or net address to connect to\n"

            "\nExamples:\n" +
            HelpExampleCli("vnodeconnect", "\"192.168.0.6:7702\"") + HelpExampleRpc("vnodeconnect", "\"192.168.0.6:7702\""));

    std::string strAddress = params[0].get_str();

    CService addr = CService(strAddress);

    CNode* pnode = ConnectNode((CAddress)addr, NULL, false);
    if (pnode) {
        pnode->Release();
        return Value::null;
    } else {
        throw runtime_error("error connecting\n");
    }
}

Value getvnodecount (const Array& params, bool fHelp)
{
    if (fHelp || (params.size() > 0))
        throw runtime_error(
            "getvnodecount\n"
            "\nGet vnode count values\n"

            "\nResult:\n"
            "{\n"
            "  \"total\": n,        (numeric) Total vnodes\n"
            "  \"stable\": n,       (numeric) Stable count\n"
            "  \"obfcompat\": n,    (numeric) Obfuscation Compatible\n"
            "  \"enabled\": n,      (numeric) Enabled vnodes\n"
            "  \"inqueue\": n       (numeric) Vnodes in queue\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("getvnodecount", "") + HelpExampleRpc("getvnodecount", ""));

    Object obj;
    int nCount = 0;
    int ipv4 = 0, ipv6 = 0, onion = 0;

    if (chainActive.Tip())
        mnodeman.GetNextVnodeInQueueForPayment(chainActive.Tip()->nHeight, true, nCount);

    mnodeman.CountNetworks(ActiveProtocol(), ipv4, ipv6, onion);

    obj.push_back(Pair("total", mnodeman.size()));
    obj.push_back(Pair("stable", mnodeman.stable_size()));
    obj.push_back(Pair("obfcompat", mnodeman.CountEnabled(ActiveProtocol())));
    obj.push_back(Pair("enabled", mnodeman.CountEnabled()));
    obj.push_back(Pair("inqueue", nCount));
    obj.push_back(Pair("ipv4", ipv4));
    obj.push_back(Pair("ipv6", ipv6));
    obj.push_back(Pair("onion", onion));

    return obj;
}

Value vnodecurrent (const Array& params, bool fHelp)
{
    if (fHelp || (params.size() != 0))
        throw runtime_error(
            "vnodecurrent\n"
            "\nGet current vnode winner\n"

            "\nResult:\n"
            "{\n"
            "  \"protocol\": xxxx,        (numeric) Protocol version\n"
            "  \"txhash\": \"xxxx\",      (string) Collateral transaction hash\n"
            "  \"pubkey\": \"xxxx\",      (string) MN Public key\n"
            "  \"lastseen\": xxx,       (numeric) Time since epoch of last seen\n"
            "  \"activeseconds\": xxx,  (numeric) Seconds MN has been active\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("vnodecurrent", "") + HelpExampleRpc("vnodecurrent", ""));

    CVnode* winner = mnodeman.GetCurrentVNode(1);
    if (winner) {
        Object obj;

        obj.push_back(Pair("protocol", (int64_t)winner->protocolVersion));
        obj.push_back(Pair("txhash", winner->vin.prevout.hash.ToString()));
        obj.push_back(Pair("pubkey", CBitcoinAddress(winner->pubKeyCollateralAddress.GetID()).ToString()));
        obj.push_back(Pair("lastseen", (winner->lastPing == CVnodePing()) ? winner->sigTime : (int64_t)winner->lastPing.sigTime));
        obj.push_back(Pair("activeseconds", (winner->lastPing == CVnodePing()) ? 0 : (int64_t)(winner->lastPing.sigTime - winner->sigTime)));
        return obj;
    }

    throw runtime_error("unknown");
}

Value vnodedebug (const Array& params, bool fHelp)
{
    if (fHelp || (params.size() != 0))
        throw runtime_error(
            "vnodedebug\n"
            "\nPrint vnode status\n"

            "\nResult:\n"
            "\"status\"     (string) Vnode status message\n"
            "\nExamples:\n" +
            HelpExampleCli("vnodedebug", "") + HelpExampleRpc("vnodedebug", ""));

    if (activeVnode.status != ACTIVE_VNODE_INITIAL || !vnodeSync.IsSynced())
        return activeVnode.GetStatus();

    CTxIn vin = CTxIn();
    CPubKey pubkey = CScript();
    CKey key;
    if (!activeVnode.GetVNodeVin(vin, pubkey, key))
        throw runtime_error("Missing vnode input, please look at the documentation for instructions on vnode creation\n");
    else
        return activeVnode.GetStatus();
}

Value startvnode (const Array& params, bool fHelp)
{
    std::string strCommand;
    if (params.size() >= 1) {
        strCommand = params[0].get_str();

        // Backwards compatibility with legacy 'vnode' super-command forwarder
        if (strCommand == "start") strCommand = "local";
        if (strCommand == "start-alias") strCommand = "alias";
        if (strCommand == "start-all") strCommand = "all";
        if (strCommand == "start-many") strCommand = "many";
        if (strCommand == "start-missing") strCommand = "missing";
        if (strCommand == "start-disabled") strCommand = "disabled";
    }

    if (fHelp || params.size() < 2 || params.size() > 3 ||
        (params.size() == 2 && (strCommand != "local" && strCommand != "all" && strCommand != "many" && strCommand != "missing" && strCommand != "disabled")) ||
        (params.size() == 3 && strCommand != "alias"))
        throw runtime_error(
            "startvnode \"local|all|many|missing|disabled|alias\" lockwallet ( \"alias\" )\n"
            "\nAttempts to start one or more vnode(s)\n"

            "\nArguments:\n"
            "1. set         (string, required) Specify which set of vnode(s) to start.\n"
            "2. lockwallet  (boolean, required) Lock wallet after completion.\n"
            "3. alias       (string) Vnode alias. Required if using 'alias' as the set.\n"

            "\nResult: (for 'local' set):\n"
            "\"status\"     (string) Vnode status message\n"

            "\nResult: (for other sets):\n"
            "{\n"
            "  \"overall\": \"xxxx\",     (string) Overall status message\n"
            "  \"detail\": [\n"
            "    {\n"
            "      \"node\": \"xxxx\",    (string) Node name or alias\n"
            "      \"result\": \"xxxx\",  (string) 'success' or 'failed'\n"
            "      \"error\": \"xxxx\"    (string) Error message, if failed\n"
            "    }\n"
            "    ,...\n"
            "  ]\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("startvnode", "\"alias\" \"0\" \"my_mn\"") + HelpExampleRpc("startvnode", "\"alias\" \"0\" \"my_mn\""));

    bool fLock = (params[1].get_str() == "true" ? true : false);

    if (strCommand == "local") {
        if (!fVNode) throw runtime_error("you must set vnode=1 in the configuration\n");

        if (pwalletMain->IsLocked())
            throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");

        if (activeVnode.status != ACTIVE_VNODE_STARTED) {
            activeVnode.status = ACTIVE_VNODE_INITIAL; // TODO: consider better way
            activeVnode.ManageStatus();
            if (fLock)
                pwalletMain->Lock();
        }

        return activeVnode.GetStatus();
    }

    if (strCommand == "all" || strCommand == "many" || strCommand == "missing" || strCommand == "disabled") {
        if (pwalletMain->IsLocked())
            throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");

        if ((strCommand == "missing" || strCommand == "disabled") &&
            (vnodeSync.RequestedVnodeAssets <= VNODE_SYNC_LIST ||
                vnodeSync.RequestedVnodeAssets == VNODE_SYNC_FAILED)) {
            throw runtime_error("You can't use this command until vnode list is synced\n");
        }

        std::vector<CVnodeConfig::CVnodeEntry> mnEntries;
        mnEntries = vnodeConfig.getEntries();

        int successful = 0;
        int failed = 0;

        Array resultsObj;

        BOOST_FOREACH (CVnodeConfig::CVnodeEntry mne, vnodeConfig.getEntries()) {
            std::string errorMessage;
            int nIndex;
            if(!mne.castOutputIndex(nIndex))
                continue;
            CTxIn vin = CTxIn(uint256(mne.getTxHash()), uint32_t(nIndex));
            CVnode* pmn = mnodeman.Find(vin);

            if (pmn != NULL) {
                if (strCommand == "missing") continue;
                if (strCommand == "disabled" && pmn->IsEnabled()) continue;
            }

            bool result = activeVnode.Register(mne.getIp(), mne.getPrivKey(), mne.getTxHash(), mne.getOutputIndex(), errorMessage);

            Object statusObj;
            statusObj.push_back(Pair("alias", mne.getAlias()));
            statusObj.push_back(Pair("result", result ? "success" : "failed"));

            if (result) {
                successful++;
                statusObj.push_back(Pair("error", ""));
            } else {
                failed++;
                statusObj.push_back(Pair("error", errorMessage));
            }

            resultsObj.push_back(statusObj);
        }
        if (fLock)
            pwalletMain->Lock();

        Object returnObj;
        returnObj.push_back(Pair("overall", strprintf("Successfully started %d vnodes, failed to start %d, total %d", successful, failed, successful + failed)));
        returnObj.push_back(Pair("detail", resultsObj));

        return returnObj;
    }

    if (strCommand == "alias") {
        std::string alias = params[2].get_str();

        if (pwalletMain->IsLocked())
            throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");

        bool found = false;
        int successful = 0;
        int failed = 0;

        Array resultsObj;
        Object statusObj;
        statusObj.push_back(Pair("alias", alias));

        BOOST_FOREACH (CVnodeConfig::CVnodeEntry mne, vnodeConfig.getEntries()) {
            if (mne.getAlias() == alias) {
                found = true;
                std::string errorMessage;

                bool result = activeVnode.Register(mne.getIp(), mne.getPrivKey(), mne.getTxHash(), mne.getOutputIndex(), errorMessage);

                statusObj.push_back(Pair("result", result ? "successful" : "failed"));

                if (result) {
                    successful++;
                    statusObj.push_back(Pair("error", ""));
                } else {
                    failed++;
                    statusObj.push_back(Pair("error", errorMessage));
                }
                break;
            }
        }

        if (!found) {
            failed++;
            statusObj.push_back(Pair("result", "failed"));
            statusObj.push_back(Pair("error", "could not find alias in config. Verify with list-conf."));
        }

        resultsObj.push_back(statusObj);

        if (fLock)
            pwalletMain->Lock();

        Object returnObj;
        returnObj.push_back(Pair("overall", strprintf("Successfully started %d vnodes, failed to start %d, total %d", successful, failed, successful + failed)));
        returnObj.push_back(Pair("detail", resultsObj));

        return returnObj;
    }
    return Value::null;
}

Value createvnodekey (const Array& params, bool fHelp)
{
    if (fHelp || (params.size() != 0))
        throw runtime_error(
            "createvnodekey\n"
            "\nCreate a new vnode private key\n"

            "\nResult:\n"
            "\"key\"    (string) Vnode private key\n"
            "\nExamples:\n" +
            HelpExampleCli("createvnodekey", "") + HelpExampleRpc("createvnodekey", ""));

    CKey secret;
    secret.MakeNewKey(false);

    return CBitcoinSecret(secret).ToString();
}

Value getvnodeoutputs (const Array& params, bool fHelp)
{
    if (fHelp || (params.size() != 0))
        throw runtime_error(
            "getvnodeoutputs\n"
            "\nPrint all vnode transaction outputs\n"

            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"txhash\": \"xxxx\",    (string) output transaction hash\n"
            "    \"outputidx\": n       (numeric) output index number\n"
            "  }\n"
            "  ,...\n"
            "]\n"

            "\nExamples:\n" +
            HelpExampleCli("getvnodeoutputs", "") + HelpExampleRpc("getvnodeoutputs", ""));

    // Find possible candidates
    vector<COutput> possibleCoins = activeVnode.SelectCoinsVnode();

    Array ret;
    BOOST_FOREACH (COutput& out, possibleCoins) {
        Object obj;
        obj.push_back(Pair("txhash", out.tx->GetHash().ToString()));
        obj.push_back(Pair("outputidx", out.i));
        ret.push_back(obj);
    }

    return ret;
}

Value listvnodeconf (const Array& params, bool fHelp)
{
    std::string strFilter = "";

    if (params.size() == 1) strFilter = params[0].get_str();

    if (fHelp || (params.size() > 1))
        throw runtime_error(
            "listvnodeconf ( \"filter\" )\n"
            "\nPrint vnode.conf in JSON format\n"

            "\nArguments:\n"
            "1. \"filter\"    (string, optional) Filter search text. Partial match on alias, address, txHash, or status.\n"

            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"alias\": \"xxxx\",        (string) vnode alias\n"
            "    \"address\": \"xxxx\",      (string) vnode IP address\n"
            "    \"privateKey\": \"xxxx\",   (string) vnode private key\n"
            "    \"txHash\": \"xxxx\",       (string) transaction hash\n"
            "    \"outputIndex\": n,       (numeric) transaction output index\n"
            "    \"status\": \"xxxx\"        (string) vnode status\n"
            "  }\n"
            "  ,...\n"
            "]\n"

            "\nExamples:\n" +
            HelpExampleCli("listvnodeconf", "") + HelpExampleRpc("listvnodeconf", ""));

    std::vector<CVnodeConfig::CVnodeEntry> mnEntries;
    mnEntries = vnodeConfig.getEntries();

    Array ret;

    BOOST_FOREACH (CVnodeConfig::CVnodeEntry mne, vnodeConfig.getEntries()) {
        int nIndex;
        if(!mne.castOutputIndex(nIndex))
            continue;
        CTxIn vin = CTxIn(uint256(mne.getTxHash()), uint32_t(nIndex));
        CVnode* pmn = mnodeman.Find(vin);

        std::string strStatus = pmn ? pmn->Status() : "MISSING";

        if (strFilter != "" && mne.getAlias().find(strFilter) == string::npos &&
            mne.getIp().find(strFilter) == string::npos &&
            mne.getTxHash().find(strFilter) == string::npos &&
            strStatus.find(strFilter) == string::npos) continue;

        Object mnObj;
        mnObj.push_back(Pair("alias", mne.getAlias()));
        mnObj.push_back(Pair("address", mne.getIp()));
        mnObj.push_back(Pair("privateKey", mne.getPrivKey()));
        mnObj.push_back(Pair("txHash", mne.getTxHash()));
        mnObj.push_back(Pair("outputIndex", mne.getOutputIndex()));
        mnObj.push_back(Pair("status", strStatus));
        ret.push_back(mnObj);
    }

    return ret;
}

Value getvnodestatus (const Array& params, bool fHelp)
{
    if (fHelp || (params.size() != 0))
        throw runtime_error(
            "getvnodestatus\n"
            "\nPrint vnode status\n"

            "\nResult:\n"
            "{\n"
            "  \"txhash\": \"xxxx\",      (string) Collateral transaction hash\n"
            "  \"outputidx\": n,        (numeric) Collateral transaction output index number\n"
            "  \"netaddr\": \"xxxx\",     (string) Vnode network address\n"
            "  \"addr\": \"xxxx\",        (string) Ventual address for vnode payments\n"
            "  \"status\": \"xxxx\",      (string) Vnode status\n"
            "  \"message\": \"xxxx\"      (string) Vnode status message\n"
            "}\n"

            "\nExamples:\n" +
            HelpExampleCli("getvnodestatus", "") + HelpExampleRpc("getvnodestatus", ""));

    if (!fVNode) throw runtime_error("This is not a vnode");

    CVnode* pmn = mnodeman.Find(activeVnode.vin);

    if (pmn) {
        Object mnObj;
        mnObj.push_back(Pair("txhash", activeVnode.vin.prevout.hash.ToString()));
        mnObj.push_back(Pair("outputidx", (uint64_t)activeVnode.vin.prevout.n));
        mnObj.push_back(Pair("netaddr", activeVnode.service.ToString()));
        mnObj.push_back(Pair("addr", CBitcoinAddress(pmn->pubKeyCollateralAddress.GetID()).ToString()));
        mnObj.push_back(Pair("status", activeVnode.status));
        mnObj.push_back(Pair("message", activeVnode.GetStatus()));
        return mnObj;
    }
    throw runtime_error("Vnode not found in the list of available vnodes. Current status: "
                        + activeVnode.GetStatus());
}

Value getvnodewinners (const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 3)
        throw runtime_error(
            "getvnodewinners ( blocks \"filter\" )\n"
            "\nPrint the vnode winners for the last n blocks\n"

            "\nArguments:\n"
            "1. blocks      (numeric, optional) Number of previous blocks to show (default: 10)\n"
            "2. filter      (string, optional) Search filter matching MN address\n"

            "\nResult (single winner):\n"
            "[\n"
            "  {\n"
            "    \"nHeight\": n,           (numeric) block height\n"
            "    \"winner\": {\n"
            "      \"address\": \"xxxx\",    (string) Ventual MN Address\n"
            "      \"nVotes\": n,          (numeric) Number of votes for winner\n"
            "    }\n"
            "  }\n"
            "  ,...\n"
            "]\n"

            "\nResult (multiple winners):\n"
            "[\n"
            "  {\n"
            "    \"nHeight\": n,           (numeric) block height\n"
            "    \"winner\": [\n"
            "      {\n"
            "        \"address\": \"xxxx\",  (string) Ventual MN Address\n"
            "        \"nVotes\": n,        (numeric) Number of votes for winner\n"
            "      }\n"
            "      ,...\n"
            "    ]\n"
            "  }\n"
            "  ,...\n"
            "]\n"
            "\nExamples:\n" +
            HelpExampleCli("getvnodewinners", "") + HelpExampleRpc("getvnodewinners", ""));

    int nHeight;
    {
        LOCK(cs_main);
        CBlockIndex* pindex = chainActive.Tip();
        if(!pindex) return 0;
        nHeight = pindex->nHeight;
    }

    int nLast = 10;
    std::string strFilter = "";

    if (params.size() >= 1)
        nLast = atoi(params[0].get_str());

    if (params.size() == 2)
        strFilter = params[1].get_str();

    Array ret;

    for (int i = nHeight - nLast; i < nHeight + 20; i++) {
        Object obj;
        obj.push_back(Pair("nHeight", i));

        std::string strPayment = GetRequiredPaymentsString(i);
        if (strFilter != "" && strPayment.find(strFilter) == std::string::npos) continue;

        if (strPayment.find(',') != std::string::npos) {
            Array winner;
            boost::char_separator<char> sep(",");
            boost::tokenizer< boost::char_separator<char> > tokens(strPayment, sep);
            BOOST_FOREACH (const string& t, tokens) {
                Object addr;
                std::size_t pos = t.find(":");
                std::string strAddress = t.substr(0,pos);
                uint64_t nVotes = atoi(t.substr(pos+1));
                addr.push_back(Pair("address", strAddress));
                addr.push_back(Pair("nVotes", nVotes));
                winner.push_back(addr);
            }
            obj.push_back(Pair("winner", winner));
        } else if (strPayment.find("Unknown") == std::string::npos) {
            Object winner;
            std::size_t pos = strPayment.find(":");
            std::string strAddress = strPayment.substr(0,pos);
            uint64_t nVotes = atoi(strPayment.substr(pos+1));
            winner.push_back(Pair("address", strAddress));
            winner.push_back(Pair("nVotes", nVotes));
            obj.push_back(Pair("winner", winner));
        } else {
            Object winner;
            winner.push_back(Pair("address", strPayment));
            winner.push_back(Pair("nVotes", 0));
            obj.push_back(Pair("winner", winner));
        }

            ret.push_back(obj);
    }

    return ret;
}

Value getvnodescores (const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "getvnodescores ( blocks )\n"
            "\nPrint list of winning vnode by score\n"

            "\nArguments:\n"
            "1. blocks      (numeric, optional) Show the last n blocks (default 10)\n"

            "\nResult:\n"
            "{\n"
            "  xxxx: \"xxxx\"   (numeric : string) Block height : Vnode hash\n"
            "  ,...\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("getvnodescores", "") + HelpExampleRpc("getvnodescores", ""));

    int nLast = 10;

    if (params.size() == 1) {
        try {
            nLast = std::stoi(params[0].get_str());
        } catch (const boost::bad_lexical_cast &) {
            throw runtime_error("Exception on param 2");
        }
    }
    Object obj;

    std::vector<CVnode> vVnodes = mnodeman.GetFullVnodeVector();
    for (int nHeight = chainActive.Tip()->nHeight - nLast; nHeight < chainActive.Tip()->nHeight + 20; nHeight++) {
        uint256 nHigh = 0;
        CVnode* pBestVnode = NULL;
        BOOST_FOREACH (CVnode& mn, vVnodes) {
            uint256 n = mn.CalculateScore(1, nHeight - 100);
            if (n > nHigh) {
                nHigh = n;
                pBestVnode = &mn;
            }
        }
        if (pBestVnode)
            obj.push_back(Pair(strprintf("%d", nHeight), pBestVnode->vin.prevout.hash.ToString().c_str()));
    }

    return obj;
}
