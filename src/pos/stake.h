// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Copyright (c) 2014-2023 The MaryJane Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POS_STAKE_H
#define BITCOIN_POS_STAKE_H

#include <consensus/params.h>
#include <wallet/wallet.h>

class CChainState;

// logging defaults
static const bool DEFAULT_PRINTCOINSTAKE = false;

bool GetStakeWeight(const CWallet* pwallet, uint64_t& nAverageWeight, uint64_t& nTotalWeight, const Consensus::Params& consensusParams);
bool GetStakeWeight(std::set<CInputCoin>& setCoins, uint64_t& nAverageWeight, uint64_t& nTotalWeight);
bool CreateCoinStake(const CWallet* pwallet, CChainState* chainstate, unsigned int nBits, int64_t nSearchInterval, CMutableTransaction& txNew, const Consensus::Params& consensusParams);

#endif // BITCOIN_POS_STAKE_H

