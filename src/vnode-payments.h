// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2017 The PIVX developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef VNODE_PAYMENTS_H
#define VNODE_PAYMENTS_H

#include "key.h"
#include "main.h"
#include "vnode.h"
#include <boost/lexical_cast.hpp>

using namespace std;

extern CCriticalSection cs_vecPayments;
extern CCriticalSection cs_mapVnodeBlocks;
extern CCriticalSection cs_mapVnodePayeeVotes;

class CVnodePayments;
class CVnodePaymentWinner;
class CVnodeBlockPayees;

extern CVnodePayments vnodePayments;

#define MNPAYMENTS_SIGNATURES_REQUIRED 6
#define MNPAYMENTS_SIGNATURES_TOTAL 10

void ProcessMessageVnodePayments(CNode* pfrom, std::string& strCommand, CDataStream& vRecv);
bool IsBlockPayeeValid(const CBlock& block, int nBlockHeight);
std::string GetRequiredPaymentsString(int nBlockHeight);
bool IsBlockValueValid(const CBlock& block, CAmount nExpectedValue, CAmount nMinted);
void FillBlockPayee(CMutableTransaction& txNew, CAmount nFees, bool fProofOfStake);

void DumpVnodePayments();

/** Save Vnode Payment Data (mnpayments.dat)
 */
class CVnodePaymentDB
{
private:
    boost::filesystem::path pathDB;
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

    CVnodePaymentDB();
    bool Write(const CVnodePayments& objToSave);
    ReadResult Read(CVnodePayments& objToLoad, bool fDryRun = false);
};

class CVnodePayee
{
public:
    CScript scriptPubKey;
    int nVotes;

    CVnodePayee()
    {
        scriptPubKey = CScript();
        nVotes = 0;
    }

    CVnodePayee(CScript payee, int nVotesIn)
    {
        scriptPubKey = payee;
        nVotes = nVotesIn;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(scriptPubKey);
        READWRITE(nVotes);
    }
};

// Keep track of votes for payees from vnodes
class CVnodeBlockPayees
{
public:
    int nBlockHeight;
    std::vector<CVnodePayee> vecPayments;

    CVnodeBlockPayees()
    {
        nBlockHeight = 0;
        vecPayments.clear();
    }
    CVnodeBlockPayees(int nBlockHeightIn)
    {
        nBlockHeight = nBlockHeightIn;
        vecPayments.clear();
    }

    void AddPayee(CScript payeeIn, int nIncrement)
    {
        LOCK(cs_vecPayments);

        BOOST_FOREACH (CVnodePayee& payee, vecPayments) {
            if (payee.scriptPubKey == payeeIn) {
                payee.nVotes += nIncrement;
                return;
            }
        }

        CVnodePayee c(payeeIn, nIncrement);
        vecPayments.push_back(c);
    }

    bool GetPayee(CScript& payee)
    {
        LOCK(cs_vecPayments);

        int nVotes = -1;
        BOOST_FOREACH (CVnodePayee& p, vecPayments) {
            if (p.nVotes > nVotes) {
                payee = p.scriptPubKey;
                nVotes = p.nVotes;
            }
        }

        return (nVotes > -1);
    }

    bool HasPayeeWithVotes(CScript payee, int nVotesReq)
    {
        LOCK(cs_vecPayments);

        BOOST_FOREACH (CVnodePayee& p, vecPayments) {
            if (p.nVotes >= nVotesReq && p.scriptPubKey == payee) return true;
        }

        return false;
    }

    bool IsTransactionValid(const CTransaction& txNew);
    std::string GetRequiredPaymentsString();

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(nBlockHeight);
        READWRITE(vecPayments);
    }
};

// for storing the winning payments
class CVnodePaymentWinner
{
public:
    CTxIn vinVnode;

    int nBlockHeight;
    CScript payee;
    std::vector<unsigned char> vchSig;

    CVnodePaymentWinner()
    {
        nBlockHeight = 0;
        vinVnode = CTxIn();
        payee = CScript();
    }

    CVnodePaymentWinner(CTxIn vinIn)
    {
        nBlockHeight = 0;
        vinVnode = vinIn;
        payee = CScript();
    }

    uint256 GetHash()
    {
        CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
        ss << payee;
        ss << nBlockHeight;
        ss << vinVnode.prevout;

        return ss.GetHash();
    }

    bool Sign(CKey& keyVnode, CPubKey& pubKeyVnode);
    bool IsValid(CNode* pnode, std::string& strError);
    bool SignatureValid();
    void Relay();

    void AddPayee(CScript payeeIn)
    {
        payee = payeeIn;
    }


    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(vinVnode);
        READWRITE(nBlockHeight);
        READWRITE(payee);
        READWRITE(vchSig);
    }

    std::string ToString()
    {
        std::string ret = "";
        ret += vinVnode.ToString();
        ret += ", " + boost::lexical_cast<std::string>(nBlockHeight);
        ret += ", " + payee.ToString();
        ret += ", " + boost::lexical_cast<std::string>((int)vchSig.size());
        return ret;
    }
};

//
// Vnode Payments Class
// Keeps track of who should get paid for which blocks
//

class CVnodePayments
{
private:
    int nSyncedFromPeer;
    int nLastBlockHeight;

public:
    std::map<uint256, CVnodePaymentWinner> mapVnodePayeeVotes;
    std::map<int, CVnodeBlockPayees> mapVnodeBlocks;
    std::map<uint256, int> mapVnodesLastVote; //prevout.hash + prevout.n, nBlockHeight

    CVnodePayments()
    {
        nSyncedFromPeer = 0;
        nLastBlockHeight = 0;
    }

    void Clear()
    {
        LOCK2(cs_mapVnodeBlocks, cs_mapVnodePayeeVotes);
        mapVnodeBlocks.clear();
        mapVnodePayeeVotes.clear();
    }

    bool AddWinningVnode(CVnodePaymentWinner& winner);
    bool ProcessBlock(int nBlockHeight);

    void Sync(CNode* node, int nCountNeeded);
    void CleanPaymentList();
    int LastPayment(CVnode& mn);

    bool GetBlockPayee(int nBlockHeight, CScript& payee);
    bool IsTransactionValid(const CTransaction& txNew, int nBlockHeight);
    bool IsScheduled(CVnode& mn, int nNotBlockHeight);

    bool CanVote(COutPoint outVnode, int nBlockHeight)
    {
        LOCK(cs_mapVnodePayeeVotes);

        if (mapVnodesLastVote.count(outVnode.hash + outVnode.n)) {
            if (mapVnodesLastVote[outVnode.hash + outVnode.n] == nBlockHeight) {
                return false;
            }
        }

        //record this vnode voted
        mapVnodesLastVote[outVnode.hash + outVnode.n] = nBlockHeight;
        return true;
    }

    int GetMinVnodePaymentsProto();
    void ProcessMessageVnodePayments(CNode* pfrom, std::string& strCommand, CDataStream& vRecv);
    std::string GetRequiredPaymentsString(int nBlockHeight);
    void FillBlockPayee(CMutableTransaction& txNew, int64_t nFees, bool fProofOfStake);
    std::string ToString() const;
    int GetOldestBlock();
    int GetNewestBlock();

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(mapVnodePayeeVotes);
        READWRITE(mapVnodeBlocks);
    }
};


#endif
