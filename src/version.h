// Copyright (c) 2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_VERSION_H
#define BITCOIN_VERSION_H

#include "clientversion.h"
#include <string>

///////////////////////////////////////////////////////////
// network protocol versioning                           //
//                                                       //
static const int PROTOCOL_VERSION =       180323;        //
// disconnect from peers older than this proto version   //
static const int MIN_PEER_PROTO_VERSION = 180284;        // 
///////////////////////////////////////////////////////////
// intial proto version, to be increased after           //
// version/verack negotiation                            //
static const int INIT_PROTO_VERSION = 180275;            //
//                                                       //
// nTime field added to CAddress, starting with this     //
// version;                                              //
// if possible, avoid requesting addresses nodes older   //
// than this                                             //
static const int CADDR_TIME_VERSION = 180275;            //
//                                                       //
//                                                       //
// only request blocks from nodes outside this range of  //
// versions                                              //
static const int NOBLKS_VERSION_START = 1;               //
static const int NOBLKS_VERSION_END = 180283;            // 
// TESTNET:      										 //
static const int TESTNET_NOBLKS_VERSION_START = 1;       //
static const int TESTNET_NOBLKS_VERSION_END = 180312;    // 
///////////////////////////////////////////////////////////
//
// database format versioning
//
static const int DATABASE_VERSION = 180015;

// BIP 0031, pong message, is enabled for all versions AFTER this one
static const int BIP0031_VERSION = 180014;

// "mempool" command, enhanced "getdata" behavior starts with this version:
static const int MEMPOOL_GD_VERSION = 180014;

#endif
