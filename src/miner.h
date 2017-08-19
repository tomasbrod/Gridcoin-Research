// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2013 The NovaCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef NOVACOIN_MINER_H
#define NOVACOIN_MINER_H

#include "main.h"
#include "wallet.h"

struct CMinerStatus
{
    CCriticalSection lock;
    std::string ReasonNotStaking;
    std::string Message;
    double WeightSum,WeightMin,WeightMax;
    double ValueSum;
    double CoinAgeSum;
    int Version;
    uint64_t CreatedCnt;
    uint64_t AcceptedCnt;
    uint64_t KernelsFound;
    int64_t nLastCoinStakeSearchInterval;

    long int h_sleep, h_iter, h_start;

    void Clear();
    CMinerStatus()
    {
        Clear();
        ReasonNotStaking= "";
        CreatedCnt= AcceptedCnt= KernelsFound= 0;
        h_sleep=8000;
        h_iter=0;
        h_start=0;//999998;
    }
};

extern CMinerStatus MinerStatus;
extern volatile unsigned int nMinerSleep;

#endif // NOVACOIN_MINER_H
