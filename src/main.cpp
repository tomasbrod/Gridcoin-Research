// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "alert.h"
#include "checkpoints.h"
#include "db.h"
#include "txdb.h"
#include "net.h"
#include "init.h"
#include "ui_interface.h"
#include "kernel.h"
#include "block.h"
#include "scrypt.h"
#include "global_objects_noui.hpp"
#include "util.h"
#include "cpid.h"
#include "bitcoinrpc.h"
#include "json/json_spirit_value.h"
#include "boinc.h"
#include "beacon.h"
#include "serialize.h"

#include <boost/lexical_cast.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/algorithm/string/case_conv.hpp> // for to_lower()
#include <boost/algorithm/string/predicate.hpp> // for startswith() and endswith()
#include <boost/algorithm/string/join.hpp>
#include <boost/thread.hpp>
#include <boost/asio.hpp>

#include <openssl/md5.h>
#include <ctime>
#include <math.h>

void GetBeaconElements(std::string sBeacon,std::string& out_cpid, std::string& out_address, std::string& out_publickey);
extern std::string NodeAddress(CNode* pfrom);
extern std::string ConvertBinToHex(std::string a);
extern std::string ConvertHexToBin(std::string a);
extern bool WalletOutOfSync();
extern bool WriteKey(std::string sKey, std::string sValue);
std::string GetBeaconPublicKey(const std::string& cpid, bool bAdvertisingBeacon);
bool AdvertiseBeacon(bool bFromService, std::string &sOutPrivKey, std::string &sOutPubKey, std::string &sError, std::string &sMessage);
std::string SignBlockWithCPID(std::string sCPID, std::string sBlockHash);
extern void CleanInboundConnections(bool bClearAll);
extern bool PushGridcoinDiagnostics();
double qtPushGridcoinDiagnosticData(std::string data);
int RestartClient();
bool RequestSupermajorityNeuralData();
extern bool AskForOutstandingBlocks(uint256 hashStart);
extern bool CleanChain();
extern void ResetTimerMain(std::string timer_name);
extern std::string UnpackBinarySuperblock(std::string sBlock);
extern std::string PackBinarySuperblock(std::string sBlock);
extern bool TallyResearchAverages(bool Forcefully);
extern void IncrementCurrentNeuralNetworkSupermajority(std::string NeuralHash, std::string GRCAddress, double distance);
bool VerifyCPIDSignature(std::string sCPID, std::string sBlockHash, std::string sSignature);
int DownloadBlocks();
int DetermineCPIDType(std::string cpid);
extern MiningCPID GetInitializedMiningCPID(std::string name, std::map<std::string, MiningCPID>& vRef);
std::string GetListOfWithConsensus(std::string datatype);
extern std::string getHardDriveSerial();
extern bool IsSuperBlock(CBlockIndex* pIndex);
extern bool VerifySuperblock(std::string superblock, int nHeight);
extern double ExtractMagnitudeFromExplainMagnitude();
extern void AddPeek(std::string data);
extern void GridcoinServices();
int64_t BeaconTimeStamp(std::string cpid, bool bZeroOutAfterPOR);
extern bool NeedASuperblock();
extern double SnapToGrid(double d);
extern bool StrLessThanReferenceHash(std::string rh);
void BusyWaitForTally();
extern bool TallyNetworkAverages(bool Forcefully);
extern bool IsContract(CBlockIndex* pIndex);
std::string ExtractValue(std::string data, std::string delimiter, int pos);
extern MiningCPID GetBoincBlockByIndex(CBlockIndex* pblockindex);
json_spirit::Array MagnitudeReport(std::string cpid);
extern void AddCPIDBlockHash(const std::string& cpid, const uint256& blockhash);
extern void ZeroOutResearcherTotals(std::string cpid);
extern StructCPID GetLifetimeCPID(const std::string& cpid, const std::string& sFrom);
extern std::string getCpuHash();
std::string getMacAddress();
std::string TimestampToHRDate(double dtm);
bool CPIDAcidTest2(std::string bpk, std::string externalcpid);
bool HasActiveBeacon(const std::string& cpid);
extern bool BlockNeedsChecked(int64_t BlockTime);
extern void FixInvalidResearchTotals(std::vector<CBlockIndex*> vDisconnect, std::vector<CBlockIndex*> vConnect);
int64_t GetEarliestWalletTransaction();
extern void IncrementVersionCount(const std::string& Version);
double GetSuperblockAvgMag(std::string data,double& out_beacon_count,double& out_participant_count,double& out_avg,bool bIgnoreBeacons, int nHeight);
extern bool LoadAdminMessages(bool bFullTableScan,std::string& out_errors);
extern bool UnusualActivityReport();

extern std::string GetCurrentNeuralNetworkSupermajorityHash(double& out_popularity);
extern std::string GetNeuralNetworkSupermajorityHash(double& out_popularity);
       
extern double CalculatedMagnitude2(std::string cpid, int64_t locktime,bool bUseLederstrumpf);
extern int64_t ComputeResearchAccrual(int64_t nTime, std::string cpid, std::string operation, CBlockIndex* pindexLast, bool bVerifyingBlock, int VerificationPhase, double& dAccrualAge, double& dMagnitudeUnit, double& AvgMagnitude);



extern bool UpdateNeuralNetworkQuorumData();
bool AsyncNeuralRequest(std::string command_name,std::string cpid,int NodeLimit);
double qtExecuteGenericFunction(std::string function,std::string data);
extern std::string GetQuorumHash(const std::string& data);
extern bool FullSyncWithDPORNodes();

std::string qtExecuteDotNetStringFunction(std::string function, std::string data);


bool CheckMessageSignature(std::string sMessageAction, std::string sMessageType, std::string sMsg, std::string sSig,std::string opt_pubkey);
extern std::string ReadCache(std::string section, std::string key);
extern std::string strReplace(std::string& str, const std::string& oldStr, const std::string& newStr);
extern bool GetEarliestStakeTime(std::string grcaddress, std::string cpid);
extern double GetTotalBalance();
extern std::string PubKeyToAddress(const CScript& scriptPubKey);
extern void IncrementNeuralNetworkSupermajority(std::string NeuralHash, std::string GRCAddress,double distance);
extern bool LoadSuperblock(std::string data, int64_t nTime, double height);

extern double GetOutstandingAmountOwed(StructCPID &mag, std::string cpid, int64_t locktime, double& total_owed, double block_magnitude);


extern double GetOwedAmount(std::string cpid);
extern double Round(double d, int place);
extern bool ComputeNeuralNetworkSupermajorityHashes();

extern void DeleteCache(std::string section, std::string keyname);
extern void ClearCache(std::string section);
bool TallyMagnitudesInSuperblock();
extern void WriteCache(std::string section, std::string key, std::string value, int64_t locktime);
std::string qtGetNeuralContract(std::string data);
extern std::string GetNeuralNetworkReport();
void qtSyncWithDPORNodes(std::string data);
std::string GetListOf(std::string datatype);
std::string qtGetNeuralHash(std::string data);
std::string GetCommandNonce(std::string command);
std::string DefaultBlockKey(int key_length);

extern std::string ToOfficialNameNew(std::string proj);

extern double GRCMagnitudeUnit(int64_t locktime);
unsigned int nNodeLifespan;

using namespace std;
using namespace boost;

//
// Global state
//

CCriticalSection cs_setpwalletRegistered;
set<CWallet*> setpwalletRegistered;

CCriticalSection cs_main;

extern std::string NodeAddress(CNode* pfrom);
extern std::string ExtractHTML(std::string HTMLdata, std::string tagstartprefix,  std::string tagstart_suffix, std::string tag_end);

CTxMemPool mempool;
unsigned int nTransactionsUpdated = 0;

unsigned int WHITELISTED_PROJECTS = 0;
unsigned int CHECKPOINT_VIOLATIONS = 0;
int64_t nLastTallied = 0;
int64_t nLastPing = 0;
int64_t nLastPeek = 0;
int64_t nLastAskedForBlocks = 0;
int64_t nBootup = 0;
int64_t nLastCalculatedMedianTimePast = 0;
double nLastBlockAge = 0;
int64_t nLastCalculatedMedianPeerCount = 0;
int nLastMedianPeerCount = 0;
int64_t nLastTallyBusyWait = 0;

int64_t nLastTalliedNeural = 0;
int64_t nLastLoadAdminMessages = 0;
int64_t nCPIDsLoaded = 0;
int64_t nLastGRCtallied = 0;
int64_t nLastCleaned = 0;


extern bool IsCPIDValidv3(std::string cpidv2, bool allow_investor);

std::string DefaultOrg();
std::string DefaultOrgKey(int key_length);

double MintLimiter(double PORDiff,int64_t RSA_WEIGHT,std::string cpid,int64_t locktime);
extern double GetBlockDifficulty(unsigned int nBits);
double GetLastPaymentTimeByCPID(std::string cpid);
extern bool Contains(const std::string& data, const std::string& instring);

extern double CoinToDouble(double surrogate);
extern double PreviousBlockAge();
void CheckForUpgrade();
int64_t GetRSAWeightByCPID(std::string cpid);
extern MiningCPID GetMiningCPID();
extern StructCPID GetStructCPID();

extern void SetAdvisory();
extern bool InAdvisory();
json_spirit::Array MagnitudeReportCSV(bool detail);

bool bNewUserWizardNotified = false;
int64_t nLastBlockSolved = 0;  //Future timestamp
int64_t nLastBlockSubmitted = 0;

uint256 muGlobalCheckpointHash = 0;
uint256 muGlobalCheckpointHashRelayed = 0;
///////////////////////MINOR VERSION////////////////////////////////
std::string msMasterProjectPublicKey  = "049ac003b3318d9fe28b2830f6a95a2624ce2a69fb0c0c7ac0b513efcc1e93a6a6e8eba84481155dd82f2f1104e0ff62c69d662b0094639b7106abc5d84f948c0a";
// The Private Key is revealed by design, for public messages only:
std::string msMasterMessagePrivateKey = "308201130201010420fbd45ffb02ff05a3322c0d77e1e7aea264866c24e81e5ab6a8e150666b4dc6d8a081a53081a2020101302c06072a8648ce3d0101022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f300604010004010704410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141020101a144034200044b2938fbc38071f24bede21e838a0758a52a0085f2e034e7f971df445436a252467f692ec9c5ba7e5eaa898ab99cbd9949496f7e3cafbf56304b1cc2e5bdf06e";
std::string msMasterMessagePublicKey  = "044b2938fbc38071f24bede21e838a0758a52a0085f2e034e7f971df445436a252467f692ec9c5ba7e5eaa898ab99cbd9949496f7e3cafbf56304b1cc2e5bdf06e";

std::string BackupGridcoinWallet();
extern double GetPoSKernelPS2();

extern bool OutOfSyncByAgeWithChanceOfMining();

int RebootClient();

std::string YesNo(bool bin);

int64_t GetMaximumBoincSubsidy(int64_t nTime);
extern double CalculatedMagnitude(int64_t locktime,bool bUseLederstrumpf);
extern int64_t GetCoinYearReward(int64_t nTime);


map<uint256, CBlockIndex*> mapBlockIndex;
set<pair<COutPoint, unsigned int> > setStakeSeen;

CBigNum bnProofOfWorkLimit(~uint256(0) >> 20); // "standard" scrypt target limit for proof of work, results with 0,000244140625 proof-of-work difficulty
CBigNum bnProofOfStakeLimit(~uint256(0) >> 20);
CBigNum bnProofOfStakeLimitV2(~uint256(0) >> 20);
CBigNum bnProofOfWorkLimitTestNet(~uint256(0) >> 16);

//Gridcoin Minimum Stake Age (16 Hours)
unsigned int nStakeMinAge = 16 * 60 * 60; // 16 hours
unsigned int nStakeMaxAge = -1; // unlimited
unsigned int nModifierInterval = 10 * 60; // time to elapse before new modifier is computed
bool bOPReturnEnabled = true;

// Gridcoin:
int nCoinbaseMaturity = 100;
CBlockIndex* pindexGenesisBlock = NULL;

uint256 nBestInvalidTrust = 0;
int64_t nTimeBestReceived = 0;
CMedianFilter<int> cPeerBlockCounts(5, 0); // Amount of blocks that other nodes claim to have

/*
    (Brod) Best chain pointers, cpids, messages, superblock
    All info that is dependant on the best chain stored in this object
*/
CBestChain Best;


map<uint256, CBlock*> mapOrphanBlocks;
multimap<uint256, CBlock*> mapOrphanBlocksByPrev;
set<pair<COutPoint, unsigned int> > setStakeSeenOrphan;

map<uint256, CTransaction> mapOrphanTransactions;
map<uint256, set<uint256> > mapOrphanTransactionsByPrev;

// Constant stuff for coinbase transactions we create:
CScript COINBASE_FLAGS;
const string strMessageMagic = "Gridcoin Signed Message:\n";

// Settings
int64_t nTransactionFee = MIN_TX_FEE;
int64_t nReserveBalance = 0;
int64_t nMinimumInputValue = 0;

std::map<std::string, std::string> mvApplicationCache;
std::map<std::string, int64_t> mvApplicationCacheTimestamp;
std::map<std::string, double> mvNeuralNetworkHash;
std::map<std::string, double> mvCurrentNeuralNetworkHash;

std::map<std::string, double> mvNeuralVersion;

enum Checkpoints::CPMode CheckpointsMode;
BlockFinder blockFinder;

// Gridcoin - Rob Halford

extern std::string RetrieveMd5(std::string s1);
extern std::string aes_complex_hash(uint256 scrypt_hash);

volatile bool bForceUpdate = false;
volatile bool bExecuteCode = false;
volatile bool bCheckedForUpgrade = false;
volatile bool bCheckedForUpgradeLive = false;
volatile bool bGlobalcomInitialized = false;
volatile bool bStakeMinerOutOfSyncWithNetwork = false;
volatile bool bExecuteGridcoinServices = false;
volatile bool bGridcoinGUILoaded = false;

extern double LederstrumpfMagnitude2(double Magnitude, int64_t locktime);
extern double cdbl(std::string s, int place);

extern void WriteAppCache(std::string key, std::string value);
extern std::string AppCache(std::string key);
extern void LoadCPIDsInBackground();

extern void ThreadCPIDs();
extern void GetGlobalStatus();

extern bool OutOfSyncByAge();
extern std::vector<std::string> split(std::string s, std::string delim);
extern bool ProjectIsValid(std::string project);

double GetNetworkAvgByProject(std::string projectname);
extern bool IsCPIDValid_Retired(std::string cpid, std::string ENCboincpubkey);
extern bool IsCPIDValidv2(MiningCPID& mc, int height);
extern std::string getfilecontents(std::string filename);
extern std::string ToOfficialName(std::string proj);
extern bool LessVerbose(int iMax1000);
extern std::string ExtractXML(std::string XMLdata, std::string key, std::string key_end);
extern MiningCPID GetNextProject(bool bForce);
extern void HarvestCPIDs(bool cleardata);

///////////////////////////////
// Standard Boinc Projects ////
///////////////////////////////

//Global variables to display current mined project in various places:
std::string     msMiningCPID = "";
std::string    msPrimaryCPID = "";
double          mdPORNonce = 0;
double         mdPORNonceSolved = 0;
double         mdLastPorNonce = 0;
double         mdMachineTimerLast = 0;
bool           mbBlocksDownloaded = false;
// Mining status variables
std::string    msMiningErrors = "";
std::string    msPoll = "";
std::string    msMiningErrors5 = "";
std::string    msMiningErrors6 = "";
std::string    msMiningErrors7 = "";
std::string    msMiningErrors8 = "";
std::string    msPeek = "";
std::string    msLastCommand = "";
std::string    msAttachmentGuid = "";
std::string    msMiningErrorsIncluded = "";
std::string    msMiningErrorsExcluded = "";
std::string    msContracts = "";
std::string    Organization = "";
std::string    OrganizationKey = "";
std::string    msNeuralResponse = "";
std::string    msHDDSerial = "";

//When syncing, we grandfather block rejection rules up to this block, as rules became stricter over time and fields changed
int nGrandfather = 860000;
int nNewIndex = 271625;
int nNewIndex2 = 364500;

int64_t nGenesisSupply = 340569880;

// Stats for Main Screen:
globalStatusType GlobalStatusStruct;

bool fColdBoot = true;
bool fEnforceCanonical = true;
bool fUseFastIndex = false;

// Gridcoin status    *************
MiningCPID GlobalCPUMiningCPID = GetMiningCPID();
double nMinerPaymentCount = 0;
std::string sRegVer = "";
std::string sDefaultWalletAddress = "";


std::map<std::string, StructCPID> mvCPIDs;        //Contains the project stats at the user level
std::map<std::string, StructCPIDCache> mvAppCache; //Contains cached blocknumbers for CPID+Projects;

std::map<std::string, int> mvTimers; // Contains event timers that reset after max ms duration iterator is exceeded

// End of Gridcoin Global vars

bool bDebugMode = false;
bool bBoincSubsidyEligible = false;

//////////////////////////////////////////////////////////////////////////////
//
// dispatching functions
//
void ResetTimerMain(std::string timer_name)
{
    mvTimers[timer_name] = 0;
}


bool TimerMain(std::string timer_name, int max_ms)
{
    mvTimers[timer_name] = mvTimers[timer_name] + 1;
    if (mvTimers[timer_name] > max_ms)
    {
        mvTimers[timer_name]=0;
        return true;
    }
    return false;
}

bool UpdateNeuralNetworkQuorumData()
{
            #if defined(WIN32) && defined(QT_GUI)
                if (!bGlobalcomInitialized) return false;
                std::string errors1 = "";
                int64_t superblock_age = GetAdjustedTime() - mvApplicationCacheTimestamp["superblock;magnitudes"];
                std::string myNeuralHash = "";
                double popularity = 0;
                std::string consensus_hash = GetNeuralNetworkSupermajorityHash(popularity);
                std::string sAge = RoundToString((double)superblock_age,0);
                std::string sBlock = mvApplicationCache["superblock;block_number"];
                std::string sTimestamp = TimestampToHRDate(mvApplicationCacheTimestamp["superblock;magnitudes"]);
                std::string data = "<QUORUMDATA><AGE>" + sAge + "</AGE><HASH>" + consensus_hash + "</HASH><BLOCKNUMBER>" + sBlock + "</BLOCKNUMBER><TIMESTAMP>"
                    + sTimestamp + "</TIMESTAMP><PRIMARYCPID>" + msPrimaryCPID + "</PRIMARYCPID></QUORUMDATA>";
                std::string testnet_flag = fTestNet ? "TESTNET" : "MAINNET";
                qtExecuteGenericFunction("SetTestNetFlag",testnet_flag);
                qtExecuteDotNetStringFunction("SetQuorumData",data);
                return true;
            #endif
            return false;
}

bool PushGridcoinDiagnostics()
{
        #if defined(WIN32) && defined(QT_GUI)
                if (!bGlobalcomInitialized) return false;
                std::string errors1 = "";
                LoadAdminMessages(false,errors1);
                std::string cpiddata = GetListOf("beacon");
                std::string sWhitelist = GetListOf("project");
                int64_t superblock_age = GetAdjustedTime() - mvApplicationCacheTimestamp["superblock;magnitudes"];
                double popularity = 0;
                std::string consensus_hash = GetNeuralNetworkSupermajorityHash(popularity);
                std::string sAge = RoundToString((double)superblock_age,0);
                std::string sBlock = mvApplicationCache["superblock;block_number"];
                std::string sTimestamp = TimestampToHRDate(mvApplicationCacheTimestamp["superblock;magnitudes"]);
                printf("Pushing diagnostic data...");
                double lastblockage = PreviousBlockAge();
                double PORDiff = GetDifficulty(GetLastBlockIndex(Best.top, true));
                std::string data = "<WHITELIST>" + sWhitelist + "</WHITELIST><CPIDDATA>"
                    + cpiddata + "</CPIDDATA><QUORUMDATA><AGE>" + sAge + "</AGE><HASH>" + consensus_hash + "</HASH><BLOCKNUMBER>" + sBlock + "</BLOCKNUMBER><TIMESTAMP>"
                    + sTimestamp + "</TIMESTAMP><PRIMARYCPID>" + msPrimaryCPID + "</PRIMARYCPID><LASTBLOCKAGE>" + RoundToString(lastblockage,0) + "</LASTBLOCKAGE><DIFFICULTY>" + RoundToString(PORDiff,2) + "</DIFFICULTY></QUORUMDATA>";
                std::string testnet_flag = fTestNet ? "TESTNET" : "MAINNET";
                qtExecuteGenericFunction("SetTestNetFlag",testnet_flag);
                double dResponse = qtPushGridcoinDiagnosticData(data);
                return true;
        #endif
        return false;
}

bool FullSyncWithDPORNodes()
{
            #if defined(WIN32) && defined(QT_GUI)

                std::string sDisabled = GetArgument("disableneuralnetwork", "false");
                if (sDisabled=="true") return false;
                // 3-30-2016 : First try to get the master database from another neural network node if these conditions occur:
                // The foreign node is fully synced.  The foreign nodes quorum hash matches the supermajority hash.  My hash != supermajority hash.
                double dCurrentPopularity = 0;
                std::string sCurrentNeuralSupermajorityHash = GetCurrentNeuralNetworkSupermajorityHash(dCurrentPopularity);
                std::string sMyNeuralHash = "";
                #if defined(WIN32) && defined(QT_GUI)
                           sMyNeuralHash = qtGetNeuralHash("");
                #endif
                if (!sMyNeuralHash.empty() && !sCurrentNeuralSupermajorityHash.empty() && sMyNeuralHash != sCurrentNeuralSupermajorityHash)
                {
                    bool bNodeOnline = RequestSupermajorityNeuralData();
                    if (bNodeOnline) return false;  // Async call to another node will continue after the node responds.
                }
            
                std::string errors1;
                LoadAdminMessages(false,errors1);
                std::string cpiddata = GetListOfWithConsensus("beacon");
		        std::string sWhitelist = GetListOf("project");
                int64_t superblock_age = GetAdjustedTime() - mvApplicationCacheTimestamp["superblock;magnitudes"];
				printf(" list of cpids %s \r\n",cpiddata.c_str());
                double popularity = 0;
                std::string consensus_hash = GetNeuralNetworkSupermajorityHash(popularity);
                std::string sAge = RoundToString((double)superblock_age,0);
                std::string sBlock = mvApplicationCache["superblock;block_number"];
                std::string sTimestamp = TimestampToHRDate(mvApplicationCacheTimestamp["superblock;magnitudes"]);
                std::string data = "<WHITELIST>" + sWhitelist + "</WHITELIST><CPIDDATA>"
                    + cpiddata + "</CPIDDATA><QUORUMDATA><AGE>" + sAge + "</AGE><HASH>" + consensus_hash + "</HASH><BLOCKNUMBER>" + sBlock + "</BLOCKNUMBER><TIMESTAMP>"
                    + sTimestamp + "</TIMESTAMP><PRIMARYCPID>" + msPrimaryCPID + "</PRIMARYCPID></QUORUMDATA>";
                std::string testnet_flag = fTestNet ? "TESTNET" : "MAINNET";
                qtExecuteGenericFunction("SetTestNetFlag",testnet_flag);
                qtSyncWithDPORNodes(data);
            #endif
            return true;
}



double GetPoSKernelPS2()
{
    int nPoSInterval = 72;
    double dStakeKernelsTriedAvg = 0;
    int nStakesHandled = 0, nStakesTime = 0;

    CBlockIndex* pindex = Best.top;
    CBlockIndex* pindexPrevStake = NULL;

    while (pindex && nStakesHandled < nPoSInterval)
    {
        if (pindex->IsProofOfStake)
        {
            dStakeKernelsTriedAvg += GetDifficulty(pindex) * 4294967296.0;
            nStakesTime += pindexPrevStake ? (pindexPrevStake->nTime - pindex->nTime) : 0;
            pindexPrevStake = pindex;
            nStakesHandled++;
        }

        pindex = pindex->GetPrev();
    }

    double result = 0;

    if (nStakesTime)
        result = dStakeKernelsTriedAvg / nStakesTime;

    if (IsProtocolV2(Best.GetHeight()))
        result *= STAKE_TIMESTAMP_MASK + 1;

    return result/100;
}


void GetGlobalStatus()
{
    //Populate overview

    try
    {
        std::string status = "";
        double boincmagnitude = CalculatedMagnitude(GetAdjustedTime(),false);
        uint64_t nWeight = 0;
        pwalletMain->GetStakeWeight(nWeight);
        nBoincUtilization = boincmagnitude; //Legacy Support for the about screen
        double weight = nWeight/COIN+boincmagnitude;
        double PORDiff = GetDifficulty(GetLastBlockIndex(Best.top, true));
        std::string sWeight = RoundToString((double)weight,0);

        //9-6-2015 Add RSA fields to overview
        if ((double)weight > 100000000000000)
        {
            sWeight = sWeight.substr(0,13) + "E" + RoundToString((double)sWeight.length()-13,0);
        }

        LOCK(GlobalStatusStruct.lock);
        GlobalStatusStruct.blocks = RoundToString((double)Best.GetHeight(),0);
        GlobalStatusStruct.difficulty = RoundToString(PORDiff,3);
        GlobalStatusStruct.netWeight = RoundToString(GetPoSKernelPS2(),2);
        GlobalStatusStruct.dporWeight = sWeight;
        GlobalStatusStruct.magnitude = RoundToString(boincmagnitude,2);
        GlobalStatusStruct.project = "deprecated";
        GlobalStatusStruct.cpid = GlobalCPUMiningCPID.cpid;
        GlobalStatusStruct.status = msMiningErrors;
        GlobalStatusStruct.poll = msPoll;
        GlobalStatusStruct.errors =  msMiningErrors5 + " " + msMiningErrors6 + " " + msMiningErrors7 + " " + msMiningErrors8;
        GlobalStatusStruct.rsaOverview =  "deprecated"; // not displayed on overview page anymore.

        return;
    }
    catch (std::exception& e)
    {
        msMiningErrors = _("Error obtaining status.");

        printf("Error obtaining status\r\n");
        return;
    }
    catch(...)
    {
        msMiningErrors = _("Error obtaining status (08-18-2014).");
        return;
    }
}






bool Timer_Main(std::string timer_name, int max_ms)
{
    mvTimers[timer_name] = mvTimers[timer_name] + 1;
    if (mvTimers[timer_name] > max_ms)
    {
        mvTimers[timer_name]=0;
        return true;
    }
    return false;
}



void RegisterWallet(CWallet* pwalletIn)
{
    {
        LOCK(cs_setpwalletRegistered);
        setpwalletRegistered.insert(pwalletIn);
    }
}

void UnregisterWallet(CWallet* pwalletIn)
{
    {
        LOCK(cs_setpwalletRegistered);
        setpwalletRegistered.erase(pwalletIn);
    }
}


// check whether the passed transaction is from us
bool static IsFromMe(CTransaction& tx)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        if (pwallet->IsFromMe(tx))
            return true;
    return false;
}

// get the wallet transaction with the given hash (if it exists)
bool static GetTransaction(const uint256& hashTx, CWalletTx& wtx)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        if (pwallet->GetTransaction(hashTx,wtx))
            return true;
    return false;
}

// erases transaction with the given hash from all wallets
void static EraseFromWallets(uint256 hash)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->EraseFromWallet(hash);
}

// make sure all wallets know about the given transaction, in the given block
void SyncWithWallets(const CTransaction& tx, const CBlock* pblock, bool fUpdate, bool fConnect)
{
    if (!fConnect)
    {
        // ppcoin: wallets need to refund inputs when disconnecting coinstake
        if (tx.IsCoinStake())
        {
            BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
                if (pwallet->IsFromMe(tx))
                    pwallet->DisableTransaction(tx);
        }
        return;
    }

    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->AddToWalletIfInvolvingMe(tx, pblock, fUpdate);
}

// notify wallets about a new best chain
void static SetBestChain(const CBlockLocator& loc)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->SetBestChain(loc);
}

// notify wallets about an updated transaction
void static UpdatedTransaction(const uint256& hashTx)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->UpdatedTransaction(hashTx);
}

// dump all wallets
void static PrintWallets(const CBlock& block)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->PrintWallet(block);
}

// notify wallets about an incoming inventory (for request counts)
void static Inventory(const uint256& hash)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->Inventory(hash);
}

// ask wallets to resend their transactions
void ResendWalletTransactions(bool fForce)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->ResendWalletTransactions(fForce);
}


double CoinToDouble(double surrogate)
{
    //Converts satoshis to a human double amount
    double coin = (double)surrogate/(double)COIN;
    return coin;
}

double GetTotalBalance()
{
    double total = 0;
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
    {
        total = total + pwallet->GetBalance();
        total = total + pwallet->GetStake();
    }
    return total/COIN;
}

//////////////////////////////////////////////////////////////////////////////
//
// mapOrphanTransactions
//

bool AddOrphanTx(const CTransaction& tx)
{
    uint256 hash = tx.GetHash();
    if (mapOrphanTransactions.count(hash))
        return false;

    // Ignore big transactions, to avoid a
    // send-big-orphans memory exhaustion attack. If a peer has a legitimate
    // large transaction with a missing parent then we assume
    // it will rebroadcast it later, after the parent transaction(s)
    // have been mined or received.
    // 10,000 orphans, each of which is at most 5,000 bytes big is
    // at most 500 megabytes of orphans:

    size_t nSize = tx.GetSerializeSize(SER_NETWORK, CTransaction::CURRENT_VERSION);

    if (nSize > 5000)
    {
        printf("ignoring large orphan tx (size: %" PRIszu ", hash: %s)\n", nSize, hash.ToString().substr(0,10).c_str());
        return false;
    }

    mapOrphanTransactions[hash] = tx;
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
        mapOrphanTransactionsByPrev[txin.prevout.hash].insert(hash);

    printf("stored orphan tx %s (mapsz %" PRIszu ")\n", hash.ToString().substr(0,10).c_str(),   mapOrphanTransactions.size());
    return true;
}

void static EraseOrphanTx(uint256 hash)
{
    if (!mapOrphanTransactions.count(hash))
        return;
    const CTransaction& tx = mapOrphanTransactions[hash];
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
        mapOrphanTransactionsByPrev[txin.prevout.hash].erase(hash);
        if (mapOrphanTransactionsByPrev[txin.prevout.hash].empty())
            mapOrphanTransactionsByPrev.erase(txin.prevout.hash);
    }
    mapOrphanTransactions.erase(hash);
}

unsigned int LimitOrphanTxSize(unsigned int nMaxOrphans)
{
    unsigned int nEvicted = 0;
    while (mapOrphanTransactions.size() > nMaxOrphans)
    {
        // Evict a random orphan:
        uint256 randomhash = GetRandHash();
        map<uint256, CTransaction>::iterator it = mapOrphanTransactions.lower_bound(randomhash);
        if (it == mapOrphanTransactions.end())
            it = mapOrphanTransactions.begin();
        EraseOrphanTx(it->first);
        ++nEvicted;
    }
    return nEvicted;
}



std::string DefaultWalletAddress()
{
    static std::string sDefaultWalletAddress;
    if (!sDefaultWalletAddress.empty())
        return sDefaultWalletAddress;
    
    try
    {
        //Gridcoin - Find the default public GRC address (since a user may have many receiving addresses):
        BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, pwalletMain->mapAddressBook)
        {
            const CBitcoinAddress& address = item.first;
            const std::string& strName = item.second;
            bool fMine = IsMine(*pwalletMain, address.Get());
            if (fMine && strName == "Default") 
            {
                sDefaultWalletAddress=CBitcoinAddress(address).ToString();
                return sDefaultWalletAddress;
            }
        }
        
        //Cant Find        
        BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, pwalletMain->mapAddressBook)
        {
            const CBitcoinAddress& address = item.first;
            //const std::string& strName = item.second;
            bool fMine = IsMine(*pwalletMain, address.Get());
            if (fMine)
            {
                sDefaultWalletAddress=CBitcoinAddress(address).ToString();
                return sDefaultWalletAddress;
            }
        }
    }
    catch (std::exception& e)
    {
        return "ERROR";
    }
    return "NA";
}






//////////////////////////////////////////////////////////////////////////////
//
// CTransaction and CTxIndex
//

bool CTransaction::ReadFromDisk(CTxDB& txdb, COutPoint prevout, CTxIndex& txindexRet)
{
    SetNull();
    if (!txdb.ReadTxIndex(prevout.hash, txindexRet))
        return false;
    if (!ReadFromDisk(txindexRet.pos))
        return false;
    if (prevout.n >= vout.size())
    {
        SetNull();
        return false;
    }
    return true;
}

bool CTransaction::ReadFromDisk(CTxDB& txdb, COutPoint prevout)
{
    CTxIndex txindex;
    return ReadFromDisk(txdb, prevout, txindex);
}

bool CTransaction::ReadFromDisk(COutPoint prevout)
{
    CTxDB txdb("r");
    CTxIndex txindex;
    return ReadFromDisk(txdb, prevout, txindex);
}


bool CBlock::WriteToDisk(unsigned int& nFileRet, unsigned int& nBlockPosRet)
{
    // Open history file to append
    CAutoFile fileout = CAutoFile(AppendBlockFile(nFileRet), SER_DISK, CLIENT_VERSION);
    if (!fileout)
        return error("CBlock::WriteToDisk() : AppendBlockFile failed");

    // Write index header
    unsigned int nSize = fileout.GetSerializeSize(*this);
    fileout << FLATDATA(pchMessageStart) << nSize;

    // Write block
    long fileOutPos = ftell(fileout);
    if (fileOutPos < 0)
        return error("CBlock::WriteToDisk() : ftell failed");
    nBlockPosRet = fileOutPos;
    fileout << *this;

    // Flush stdio buffers and commit to disk before returning
    fflush(fileout);
    if (!IsInitialBlockDownload() || (Best.GetHeight()+1) % 500 == 0)
        FileCommit(fileout);

    return true;
}

bool CBlock::ReadFromDisk(unsigned int nFile, unsigned int nBlockPos, bool fReadTransactions)
{
    SetNull();

    // Open history file to read
    CAutoFile filein = CAutoFile(OpenBlockFile(nFile, nBlockPos, "rb"), SER_DISK, CLIENT_VERSION);
    if (!filein)
        return error("CBlock::ReadFromDisk() : OpenBlockFile failed");
    if (!fReadTransactions)
        filein.nType |= SER_BLOCKHEADERONLY;

    // Read block
    try {
        filein >> *this;
    }
    catch (std::exception &e) {
        return error("%s() : deserialize or I/O error", __PRETTY_FUNCTION__);
    }

    // Check the header
    if (fReadTransactions && IsProofOfWork() && !CheckProofOfWork(GetPoWHash(), nBits))
        return error("CBlock::ReadFromDisk() : errors in block header");

    return true;
}

bool CBlockIndex::IsInMainChain() const
{
    return (pnext || this == Best.top);
}




bool IsStandardTx(const CTransaction& tx)
{
    std::string reason = "";
    if (tx.nVersion > CTransaction::CURRENT_VERSION)
        return false;

    // Treat non-final transactions as non-standard to prevent a specific type
    // of double-spend attack, as well as DoS attacks. (if the transaction
    // can't be mined, the attacker isn't expending resources broadcasting it)
    // Basically we don't want to propagate transactions that can't included in
    // the next block.
    //
    // However, IsFinalTx() is confusing... Without arguments, it uses
    // chainActive.Height() to evaluate nLockTime; when a block is accepted, chainActive.Height()
    // is set to the value of nHeight in the block. However, when IsFinalTx()
    // is called within CBlock::AcceptBlock(), the height of the block *being*
    // evaluated is what is used. Thus if we want to know if a transaction can
    // be part of the *next* block, we need to call IsFinalTx() with one more
    // than chainActive.Height().
    //
    // Timestamps on the other hand don't get any special treatment, because we
    // can't know what timestamp the next block will have, and there aren't
    // timestamp applications where it matters.
    if (!IsFinalTx(tx, Best.GetHeight() + 1)) {
        return false;
    }
    // nTime has different purpose from nLockTime but can be used in similar attacks
    if (tx.nTime > FutureDrift(GetAdjustedTime(), Best.GetHeight() + 1)) {
        return false;
    }

    // Extremely large transactions with lots of inputs can cost the network
    // almost as much to process as they cost the sender in fees, because
    // computing signature hashes is O(ninputs*txsize). Limiting transactions
    // to MAX_STANDARD_TX_SIZE mitigates CPU exhaustion attacks.
    unsigned int sz = tx.GetSerializeSize(SER_NETWORK, CTransaction::CURRENT_VERSION);
    if (sz >= MAX_STANDARD_TX_SIZE)
        return false;

    BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {

        // Biggest 'standard' txin is a 15-of-15 P2SH multisig with compressed
        // keys. (remember the 520 byte limit on redeemScript size) That works
        // out to a (15*(33+1))+3=513 byte redeemScript, 513+1+15*(73+1)=1624
        // bytes of scriptSig, which we round off to 1650 bytes for some minor
        // future-proofing. That's also enough to spend a 20-of-20
        // CHECKMULTISIG scriptPubKey, though such a scriptPubKey is not
        // considered standard)

        if (txin.scriptSig.size() > 1650)
            return false;
        if (!txin.scriptSig.IsPushOnly())
            return false;
        if (fEnforceCanonical && !txin.scriptSig.HasCanonicalPushes()) {
            return false;
        }
    }

    unsigned int nDataOut = 0;
    txnouttype whichType;
    BOOST_FOREACH(const CTxOut& txout, tx.vout) {
        if (!::IsStandard(txout.scriptPubKey, whichType))
            return false;
        if (whichType == TX_NULL_DATA)
            nDataOut++;
        if (txout.nValue == 0)
            return false;
        if (fEnforceCanonical && !txout.scriptPubKey.HasCanonicalPushes()) {
            return false;
        }
    }


    // not more than one data txout per non-data txout is permitted
    // only one data txout is permitted too
    if (nDataOut > 1 && nDataOut > tx.vout.size()/2)
    {
        reason = "multi-op-return";
        return false;
    }


    return true;
}

bool IsFinalTx(const CTransaction &tx, int nBlockHeight, int64_t nBlockTime)
{
    AssertLockHeld(cs_main);
    // Time based nLockTime implemented in 0.1.6
    if (tx.nLockTime == 0)
        return true;
    if (nBlockHeight == 0)
        nBlockHeight = Best.GetHeight();
    if (nBlockTime == 0)
        nBlockTime = GetAdjustedTime();
    if ((int64_t)tx.nLockTime < ((int64_t)tx.nLockTime < LOCKTIME_THRESHOLD ? (int64_t)nBlockHeight : nBlockTime))
        return true;
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
        if (!txin.IsFinal())
            return false;
    return true;
}

//
// Check transaction inputs, and make sure any
// pay-to-script-hash transactions are evaluating IsStandard scripts
//
// Why bother? To avoid denial-of-service attacks; an attacker
// can submit a standard HASH... OP_EQUAL transaction,
// which will get accepted into blocks. The redemption
// script can be anything; an attacker could use a very
// expensive-to-check-upon-redemption script like:
//   DUP CHECKSIG DROP ... repeated 100 times... OP_1
//
bool CTransaction::AreInputsStandard(const MapPrevTx& mapInputs) const
{
    if (IsCoinBase())
        return true; // Coinbases don't use vin normally

    for (unsigned int i = 0; i < vin.size(); i++)
    {
        const CTxOut& prev = GetOutputFor(vin[i], mapInputs);

        vector<vector<unsigned char> > vSolutions;
        txnouttype whichType;
        // get the scriptPubKey corresponding to this input:
        const CScript& prevScript = prev.scriptPubKey;
        if (!Solver(prevScript, whichType, vSolutions))
            return false;
        int nArgsExpected = ScriptSigArgsExpected(whichType, vSolutions);
        if (nArgsExpected < 0)
            return false;

        // Transactions with extra stuff in their scriptSigs are
        // non-standard. Note that this EvalScript() call will
        // be quick, because if there are any operations
        // beside "push data" in the scriptSig the
        // IsStandard() call returns false
        vector<vector<unsigned char> > stack;
        if (!EvalScript(stack, vin[i].scriptSig, *this, i, 0))            return false;

        if (whichType == TX_SCRIPTHASH)
        {
            if (stack.empty())
                return false;
            CScript subscript(stack.back().begin(), stack.back().end());
            vector<vector<unsigned char> > vSolutions2;
            txnouttype whichType2;
            if (!Solver(subscript, whichType2, vSolutions2))
                return false;
            if (whichType2 == TX_SCRIPTHASH)
                return false;

            int tmpExpected;
            tmpExpected = ScriptSigArgsExpected(whichType2, vSolutions2);
            if (tmpExpected < 0)
                return false;
            nArgsExpected += tmpExpected;
        }

        if (stack.size() != (unsigned int)nArgsExpected)
            return false;
    }

    return true;
}

unsigned int CTransaction::GetLegacySigOpCount() const
{
    unsigned int nSigOps = 0;
    BOOST_FOREACH(const CTxIn& txin, vin)
    {
        nSigOps += txin.scriptSig.GetSigOpCount(false);
    }
    BOOST_FOREACH(const CTxOut& txout, vout)
    {
        nSigOps += txout.scriptPubKey.GetSigOpCount(false);
    }
    return nSigOps;
}


int CMerkleTx::SetMerkleBranch(const CBlock* pblock)
{
    AssertLockHeld(cs_main);

    CBlock blockTmp;
    if (pblock == NULL)
    {
        // Load the block this tx is in
        CTxIndex txindex;
        if (!CTxDB("r").ReadTxIndex(GetHash(), txindex))
            return 0;
        if (!blockTmp.ReadFromDisk(txindex.pos.nFile, txindex.pos.nBlockPos))
            return 0;
        pblock = &blockTmp;
    }

    // Update the tx's hashBlock
    hashBlock = pblock->GetHash();

    // Locate the transaction
    for (nIndex = 0; nIndex < (int)pblock->vtx.size(); nIndex++)
        if (pblock->vtx[nIndex] == *(CTransaction*)this)
            break;
    if (nIndex == (int)pblock->vtx.size())
    {
        vMerkleBranch.clear();
        nIndex = -1;
        printf("ERROR: SetMerkleBranch() : couldn't find tx in block\n");
        return 0;
    }

    // Fill in merkle branch
    vMerkleBranch = pblock->GetMerkleBranch(nIndex);

    // Is the tx in a block that's in the main chain
    CBlockIndex* pindex = CBlockIndex::GetByHash(hashBlock);
    if (!pindex)
        return 0;
    if (!pindex->IsInMainChain())
        return 0;

    return Best.GetHeight() - pindex->nHeight + 1;
}




bool CTransaction::CheckTransaction() const
{
    // Basic checks that don't depend on any context
    if (vin.empty())
        return DoS(10, error("CTransaction::CheckTransaction() : vin empty"));
    if (vout.empty())
        return DoS(10, error("CTransaction::CheckTransaction() : vout empty"));
    // Size limits
    if (::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION) > MAX_BLOCK_SIZE)
        return DoS(100, error("CTransaction::CheckTransaction() : size limits failed"));

    // Check for negative or overflow output values
    int64_t nValueOut = 0;
    for (unsigned int i = 0; i < vout.size(); i++)
    {
        const CTxOut& txout = vout[i];
        if (txout.IsEmpty() && !IsCoinBase() && !IsCoinStake())
            return DoS(100, error("CTransaction::CheckTransaction() : txout empty for user transaction"));
        if (txout.nValue < 0)
            return DoS(100, error("CTransaction::CheckTransaction() : txout.nValue negative"));
        if (txout.nValue > MAX_MONEY)
            return DoS(100, error("CTransaction::CheckTransaction() : txout.nValue too high"));
        nValueOut += txout.nValue;
        if (!MoneyRange(nValueOut))
            return DoS(100, error("CTransaction::CheckTransaction() : txout total out of range"));
    }

    // Check for duplicate inputs
    set<COutPoint> vInOutPoints;
    BOOST_FOREACH(const CTxIn& txin, vin)
    {
        if (vInOutPoints.count(txin.prevout))
            return false;
        vInOutPoints.insert(txin.prevout);
    }

    if (IsCoinBase())
    {
        if (vin[0].scriptSig.size() < 2 || vin[0].scriptSig.size() > 100)
            return DoS(100, error("CTransaction::CheckTransaction() : coinbase script size is invalid"));
    }
    else
    {
        BOOST_FOREACH(const CTxIn& txin, vin)
            if (txin.prevout.IsNull())
                return DoS(10, error("CTransaction::CheckTransaction() : prevout is null"));
    }

    return true;
}

int64_t CTransaction::GetMinFee(unsigned int nBlockSize, enum GetMinFee_mode mode, unsigned int nBytes) const
{
    // Base fee is either MIN_TX_FEE or MIN_RELAY_TX_FEE
    int64_t nBaseFee = (mode == GMF_RELAY) ? MIN_RELAY_TX_FEE : MIN_TX_FEE;

    unsigned int nNewBlockSize = nBlockSize + nBytes;
    int64_t nMinFee = (1 + (int64_t)nBytes / 1000) * nBaseFee;

    // To limit dust spam, require MIN_TX_FEE/MIN_RELAY_TX_FEE if any output is less than 0.01
    if (nMinFee < nBaseFee)
    {
        BOOST_FOREACH(const CTxOut& txout, vout)
            if (txout.nValue < CENT)
                nMinFee = nBaseFee;
    }

    // Raise the price as the block approaches full
    if (nBlockSize != 1 && nNewBlockSize >= MAX_BLOCK_SIZE_GEN/2)
    {
        if (nNewBlockSize >= MAX_BLOCK_SIZE_GEN)
            return MAX_MONEY;
        nMinFee *= MAX_BLOCK_SIZE_GEN / (MAX_BLOCK_SIZE_GEN - nNewBlockSize);
    }

    if (!MoneyRange(nMinFee))
        nMinFee = MAX_MONEY;
    return nMinFee;
}


bool AcceptToMemoryPool(CTxMemPool& pool, CTransaction &tx, bool* pfMissingInputs)
{
    AssertLockHeld(cs_main);
    if (pfMissingInputs)
        *pfMissingInputs = false;

    if (!tx.CheckTransaction())
        return error("AcceptToMemoryPool : CheckTransaction failed");

    // Coinbase is only valid in a block, not as a loose transaction
    if (tx.IsCoinBase())
        return tx.DoS(100, error("AcceptToMemoryPool : coinbase as individual tx"));

    // ppcoin: coinstake is also only valid in a block, not as a loose transaction
    if (tx.IsCoinStake())
        return tx.DoS(100, error("AcceptToMemoryPool : coinstake as individual tx"));

    // Rather not work on nonstandard transactions (unless -testnet)
    if (!fTestNet && !IsStandardTx(tx))
        return error("AcceptToMemoryPool : nonstandard transaction type");

    // is it already in the memory pool?
    uint256 hash = tx.GetHash();
    if (pool.exists(hash))
        return false;

    // Check for conflicts with in-memory transactions
    CTransaction* ptxOld = NULL;
    {
        LOCK(pool.cs); // protect pool.mapNextTx
        for (unsigned int i = 0; i < tx.vin.size(); i++)
        {
            COutPoint outpoint = tx.vin[i].prevout;
            if (pool.mapNextTx.count(outpoint))
            {
                // Disable replacement feature for now
                return false;

                // Allow replacing with a newer version of the same transaction
                if (i != 0)
                    return false;
                ptxOld = pool.mapNextTx[outpoint].ptx;
                if (IsFinalTx(*ptxOld))
                    return false;
                if (!tx.IsNewerThan(*ptxOld))
                    return false;
                for (unsigned int i = 0; i < tx.vin.size(); i++)
                {
                    COutPoint outpoint = tx.vin[i].prevout;
                    if (!pool.mapNextTx.count(outpoint) || pool.mapNextTx[outpoint].ptx != ptxOld)
                        return false;
                }
                break;
            }
        }
    }

    {
        CTxDB txdb("r");

        // do we already have it?
        if (txdb.ContainsTx(hash))
            return false;

        MapPrevTx mapInputs;
        map<uint256, CTxIndex> mapUnused;
        bool fInvalid = false;
        if (!tx.FetchInputs(txdb, mapUnused, false, false, mapInputs, fInvalid))
        {
            if (fInvalid)
                return error("AcceptToMemoryPool : FetchInputs found invalid tx %s", hash.ToString().substr(0,10).c_str());
            if (pfMissingInputs)
                *pfMissingInputs = true;
            return false;
        }

        // Check for non-standard pay-to-script-hash in inputs
        if (!tx.AreInputsStandard(mapInputs) && !fTestNet)
            return error("AcceptToMemoryPool : nonstandard transaction input");

        // Note: if you modify this code to accept non-standard transactions, then
        // you should add code here to check that the transaction does a
        // reasonable number of ECDSA signature verifications.

        int64_t nFees = tx.GetValueIn(mapInputs)-tx.GetValueOut();
        unsigned int nSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);

        // Don't accept it if it can't get into a block
        int64_t txMinFee = tx.GetMinFee(1000, GMF_RELAY, nSize);
        if (nFees < txMinFee)
            return error("AcceptToMemoryPool : not enough fees %s, %" PRId64 " < %" PRId64,
                         hash.ToString().c_str(),
                         nFees, txMinFee);

        // Continuously rate-limit free transactions
        // This mitigates 'penny-flooding' -- sending thousands of free transactions just to
        // be annoying or make others' transactions take longer to confirm.
        if (nFees < MIN_RELAY_TX_FEE)
        {
            static CCriticalSection cs;
            static double dFreeCount;
            static int64_t nLastTime;
            int64_t nNow =  GetAdjustedTime();

            {
                LOCK(pool.cs);
                // Use an exponentially decaying ~10-minute window:
                dFreeCount *= pow(1.0 - 1.0/600.0, (double)(nNow - nLastTime));
                nLastTime = nNow;
                // -limitfreerelay unit is thousand-bytes-per-minute
                // At default rate it would take over a month to fill 1GB
                if (dFreeCount > GetArg("-limitfreerelay", 15)*10*1000 && !IsFromMe(tx))
                    return error("AcceptToMemoryPool : free transaction rejected by rate limiter");
                if (fDebug)
                    printf("Rate limit dFreeCount: %g => %g\n", dFreeCount, dFreeCount+nSize);
                dFreeCount += nSize;
            }
        }

        // Check against previous transactions
        // This is done last to help prevent CPU exhaustion denial-of-service attacks.
        if (!tx.ConnectInputs(mapInputs, mapUnused, CDiskTxPos(1,1,1), Best.top, false, false))
        {
            // If this happens repeatedly, purge peers
            if (TimerMain("AcceptToMemoryPool", 20))
            {
                printf("\r\nAcceptToMemoryPool::CleaningInboundConnections\r\n");
                CleanInboundConnections(true);
            }   
            if (fDebug || true)
            {
                return error("AcceptToMemoryPool : Unable to Connect Inputs %s", hash.ToString().c_str());
            }
            else
            {
                return false;
            }
        }
    }

    // Store transaction in memory
    {
        LOCK(pool.cs);
        if (ptxOld)
        {
            printf("AcceptToMemoryPool : replacing tx %s with new version\n", ptxOld->GetHash().ToString().c_str());
            pool.remove(*ptxOld);
        }
        pool.addUnchecked(hash, tx);
    }

    ///// are we sure this is ok when loading transactions or restoring block txes
    // If updated, erase old tx from wallet
    if (ptxOld)
        EraseFromWallets(ptxOld->GetHash());
    if (fDebug)     printf("AcceptToMemoryPool : accepted %s (poolsz %" PRIszu ")\n",           hash.ToString().c_str(),           pool.mapTx.size());
    return true;
}

bool CTxMemPool::addUnchecked(const uint256& hash, CTransaction &tx)
{
    // Add to memory pool without checking anything.  Don't call this directly,
    // call AcceptToMemoryPool to properly check the transaction first.
    {
        mapTx[hash] = tx;
        for (unsigned int i = 0; i < tx.vin.size(); i++)
            mapNextTx[tx.vin[i].prevout] = CInPoint(&mapTx[hash], i);
        nTransactionsUpdated++;
    }
    return true;
}


bool CTxMemPool::remove(const CTransaction &tx, bool fRecursive)
{
    // Remove transaction from memory pool
    {
        LOCK(cs);
        uint256 hash = tx.GetHash();
        if (mapTx.count(hash))
        {
            if (fRecursive) {
                for (unsigned int i = 0; i < tx.vout.size(); i++) {
                    std::map<COutPoint, CInPoint>::iterator it = mapNextTx.find(COutPoint(hash, i));
                    if (it != mapNextTx.end())
                        remove(*it->second.ptx, true);
                }
            }
            BOOST_FOREACH(const CTxIn& txin, tx.vin)
                mapNextTx.erase(txin.prevout);
            mapTx.erase(hash);
            nTransactionsUpdated++;
        }
    }
    return true;
}

bool CTxMemPool::removeConflicts(const CTransaction &tx)
{
    // Remove transactions which depend on inputs of tx, recursively
    LOCK(cs);
    BOOST_FOREACH(const CTxIn &txin, tx.vin) {
        std::map<COutPoint, CInPoint>::iterator it = mapNextTx.find(txin.prevout);
        if (it != mapNextTx.end()) {
            const CTransaction &txConflict = *it->second.ptx;
            if (txConflict != tx)
                remove(txConflict, true);
        }
    }
    return true;
}

void CTxMemPool::clear()
{
    LOCK(cs);
    mapTx.clear();
    mapNextTx.clear();
    ++nTransactionsUpdated;
}

void CTxMemPool::queryHashes(std::vector<uint256>& vtxid)
{
    vtxid.clear();

    LOCK(cs);
    vtxid.reserve(mapTx.size());
    for (map<uint256, CTransaction>::iterator mi = mapTx.begin(); mi != mapTx.end(); ++mi)
        vtxid.push_back((*mi).first);
}




int CMerkleTx::GetDepthInMainChainINTERNAL(CBlockIndex* &pindexRet) const
{
    if (hashBlock == 0 || nIndex == -1)
        return 0;
    AssertLockHeld(cs_main);

    // Find the block it claims to be in
    CBlockIndex* pindex = CBlockIndex::GetByHash(hashBlock);
    if (!pindex || !pindex->IsInMainChain())
        return 0;

    // Make sure the merkle branch connects to this block
    if (!fMerkleVerified)
    {
        if (CBlock::CheckMerkleBranch(GetHash(), vMerkleBranch, nIndex) != pindex->hashMerkleRoot)
            return 0;
        fMerkleVerified = true;
    }

    pindexRet = pindex;
    return Best.GetHeight() - pindex->nHeight + 1;
}

int CMerkleTx::GetDepthInMainChain(CBlockIndex* &pindexRet) const
{
    AssertLockHeld(cs_main);
    int nResult = GetDepthInMainChainINTERNAL(pindexRet);
    if (nResult == 0 && !mempool.exists(GetHash()))
        return -1; // Not in chain, not in mempool

    return nResult;
}

int CMerkleTx::GetBlocksToMaturity() const
{
    if (!(IsCoinBase() || IsCoinStake()))
        return 0;
    return max(0, (nCoinbaseMaturity+10) - GetDepthInMainChain());
}


bool CMerkleTx::AcceptToMemoryPool()
{
    return ::AcceptToMemoryPool(mempool, *this, NULL);
}



bool CWalletTx::AcceptWalletTransaction(CTxDB& txdb)
{

    {
        // Add previous supporting transactions first
        BOOST_FOREACH(CMerkleTx& tx, vtxPrev)
        {
            if (!(tx.IsCoinBase() || tx.IsCoinStake()))
            {
                uint256 hash = tx.GetHash();
                if (!mempool.exists(hash) && !txdb.ContainsTx(hash))
                    tx.AcceptToMemoryPool();
            }
        }
        return AcceptToMemoryPool();
    }
    return false;
}

bool CWalletTx::AcceptWalletTransaction()
{
    CTxDB txdb("r");
    return AcceptWalletTransaction(txdb);
}

int CTxIndex::GetDepthInMainChain() const
{
    // Read block header
    CBlock block;
    if (!block.ReadFromDisk(pos.nFile, pos.nBlockPos, false))
        return 0;
    // Find the block in the index
    CBlockIndex* pindex = CBlockIndex::GetByHash(block.GetHash());
    if (!pindex || !pindex->IsInMainChain())
        return 0;
    return 1 + Best.GetHeight() - pindex->nHeight;
}

// Return transaction in tx, and if it was found inside a block, its hash is placed in hashBlock
bool GetTransaction(const uint256 &hash, CTransaction &tx, uint256 &hashBlock)
{
    {
        LOCK(cs_main);
        {
            if (mempool.lookup(hash, tx))
            {
                return true;
            }
        }
        CTxDB txdb("r");
        CTxIndex txindex;
        if (tx.ReadFromDisk(txdb, COutPoint(hash, 0), txindex))
        {
            CBlock block;
            if (block.ReadFromDisk(txindex.pos.nFile, txindex.pos.nBlockPos, false))
                hashBlock = block.GetHash();
            return true;
        }
    }
    return false;
}






//////////////////////////////////////////////////////////////////////////////
//
// CBlock and CBlockIndex
//
bool CBlock::ReadFromDisk(CBlockIndex* pindex, bool fReadTransactions)
{
    if (!fReadTransactions)
    {
        *this = pindex->GetBlockHeader();
        return true;
    }
    if (!ReadFromDisk(pindex->nFile, pindex->nBlockPos, fReadTransactions))
        return false;
    if (GetHash() != pindex->GetBlockHash())
        return error("CBlock::ReadFromDisk() : GetHash() doesn't match index");
    return true;
}

uint256 static GetOrphanRoot(const CBlock* pblock)
{
    // Work back to the first block in the orphan chain
    while (mapOrphanBlocks.count(pblock->hashPrevBlock))
        pblock = mapOrphanBlocks[pblock->hashPrevBlock];
    return pblock->GetHash();
}

// ppcoin: find block wanted by given orphan block
uint256 WantedByOrphan(const CBlock* pblockOrphan)
{
    // Work back to the first block in the orphan chain
    while (mapOrphanBlocks.count(pblockOrphan->hashPrevBlock))
        pblockOrphan = mapOrphanBlocks[pblockOrphan->hashPrevBlock];
    return pblockOrphan->hashPrevBlock;
}


static CBigNum GetProofOfStakeLimit(int nHeight)
{
    if (IsProtocolV2(nHeight))
        return bnProofOfStakeLimitV2;
    else
        return bnProofOfStakeLimit;
}

double CalculatedMagnitude2(std::string cpid, int64_t locktime,bool bUseLederstrumpf)
{
    // Get neural network magnitude:
    StructCPID2 *scp = Best.GetCPID(cpid);
    if(!scp)
        return 0;
    double RawMag=scp->SbMagnitude;
    return bUseLederstrumpf ? LederstrumpfMagnitude2(RawMag,locktime) : RawMag;
}

double CalculatedMagnitude(int64_t locktime,bool bUseLederstrumpf)
{
    // Get neural network magnitude:
    if (!GlobalCPUMiningCPID.initialized)
        return 0;
    return CalculatedMagnitude2(GlobalCPUMiningCPID.cpid,locktime,bUseLederstrumpf);
}

// miner's coin base reward
int64_t GetProofOfWorkReward(int64_t nFees, int64_t locktime, int64_t height)
{
    //NOTE: THIS REWARD IS ONLY USED IN THE POW PHASE (Block < 8000):
    int64_t nSubsidy = CalculatedMagnitude(locktime,true) * COIN;
    if (fDebug && GetBoolArg("-printcreation"))
        printf("GetProofOfWorkReward() : create=%s nSubsidy=%" PRId64 "\n", FormatMoney(nSubsidy).c_str(), nSubsidy);
    if (nSubsidy < (30*COIN)) nSubsidy=30*COIN;
    //Gridcoin Foundation Block:
    if (height==10)
    {
        nSubsidy = nGenesisSupply * COIN;
    }
    if (fTestNet) nSubsidy += 1000*COIN;

    return nSubsidy + nFees;
}


int64_t GetProofOfWorkMaxReward(int64_t nFees, int64_t locktime, int64_t height)
{
    int64_t nSubsidy = (GetMaximumBoincSubsidy(locktime)+1) * COIN;
    if (height==10)
    {
        //R.Halford: 10-11-2014: Gridcoin Foundation Block:
        //Note: Gridcoin Classic emitted these coins.  So we had to add them to block 10.  The coins were burned then given back to the owners that mined them in classic (as research coins).
        nSubsidy = nGenesisSupply * COIN;
    }

    if (fTestNet) nSubsidy += 1000*COIN;
    return nSubsidy + nFees;
}

//Survey Results: Start inflation rate: 9%, end=1%, 30 day steps, 9 steps, mag multiplier start: 2, mag end .3, 9 steps
int64_t GetMaximumBoincSubsidy(int64_t nTime)
{
    // Gridcoin Global Daily Maximum Researcher Subsidy Schedule
    int MaxSubsidy = 500;
    if (nTime >= 1410393600 && nTime <= 1417305600) MaxSubsidy =    500; // between inception  and 11-30-2014
    if (nTime >= 1417305600 && nTime <= 1419897600) MaxSubsidy =    400; // between 11-30-2014 and 12-30-2014
    if (nTime >= 1419897600 && nTime <= 1422576000) MaxSubsidy =    400; // between 12-30-2014 and 01-30-2015
    if (nTime >= 1422576000 && nTime <= 1425254400) MaxSubsidy =    300; // between 01-30-2015 and 02-28-2015
    if (nTime >= 1425254400 && nTime <= 1427673600) MaxSubsidy =    250; // between 02-28-2015 and 03-30-2015
    if (nTime >= 1427673600 && nTime <= 1430352000) MaxSubsidy =    200; // between 03-30-2015 and 04-30-2015
    if (nTime >= 1430352000 && nTime <= 1438310876) MaxSubsidy =    150; // between 05-01-2015 and 07-31-2015
    if (nTime >= 1438310876 && nTime <= 1445309276) MaxSubsidy =    100; // between 08-01-2015 and 10-20-2015
    if (nTime >= 1445309276 && nTime <= 1447977700) MaxSubsidy =     75; // between 10-20-2015 and 11-20-2015
    if (nTime > 1447977700)                         MaxSubsidy =     50; // from  11-20-2015 forever
    return MaxSubsidy+.5;  //The .5 allows for fractional amounts after the 4th decimal place (used to store the POR indicator)
}

int64_t GetCoinYearReward(int64_t nTime)
{
    // Gridcoin Global Interest Rate Schedule
    int64_t INTEREST = 9;
    if (nTime >= 1410393600 && nTime <= 1417305600) INTEREST =   9 * CENT; // 09% between inception  and 11-30-2014
    if (nTime >= 1417305600 && nTime <= 1419897600) INTEREST =   8 * CENT; // 08% between 11-30-2014 and 12-30-2014
    if (nTime >= 1419897600 && nTime <= 1422576000) INTEREST =   8 * CENT; // 08% between 12-30-2014 and 01-30-2015
    if (nTime >= 1422576000 && nTime <= 1425254400) INTEREST =   7 * CENT; // 07% between 01-30-2015 and 02-30-2015
    if (nTime >= 1425254400 && nTime <= 1427673600) INTEREST =   6 * CENT; // 06% between 02-30-2015 and 03-30-2015
    if (nTime >= 1427673600 && nTime <= 1430352000) INTEREST =   5 * CENT; // 05% between 03-30-2015 and 04-30-2015
    if (nTime >= 1430352000 && nTime <= 1438310876) INTEREST =   4 * CENT; // 04% between 05-01-2015 and 07-31-2015
    if (nTime >= 1438310876 && nTime <= 1447977700) INTEREST =   3 * CENT; // 03% between 08-01-2015 and 11-20-2015
    if (nTime > 1447977700)                         INTEREST = 1.5 * CENT; //1.5% from 11-21-2015 forever
    return INTEREST;
}

double GetMagnitudeMultiplier(int64_t nTime)
{
    // Gridcoin Global Resarch Subsidy Multiplier Schedule
    double magnitude_multiplier = 2;
    if (nTime >= 1410393600 && nTime <= 1417305600) magnitude_multiplier =    2;  // between inception and 11-30-2014
    if (nTime >= 1417305600 && nTime <= 1419897600) magnitude_multiplier =  1.5;  // between 11-30-2014 and 12-30-2014
    if (nTime >= 1419897600 && nTime <= 1422576000) magnitude_multiplier =  1.5;  // between 12-30-2014 and 01-30-2015
    if (nTime >= 1422576000 && nTime <= 1425254400) magnitude_multiplier =    1;  // between 01-30-2015 and 02-30-2015
    if (nTime >= 1425254400 && nTime <= 1427673600) magnitude_multiplier =   .9;  // between 02-30-2015 and 03-30-2015
    if (nTime >= 1427673600 && nTime <= 1430352000) magnitude_multiplier =   .8;  // between 03-30-2015 and 04-30-2015
    if (nTime >= 1430352000 && nTime <= 1438310876) magnitude_multiplier =   .7;  // between 05-01-2015 and 07-31-2015
    if (nTime >= 1438310876 && nTime <= 1447977700) magnitude_multiplier =  .60;  // between 08-01-2015 and 11-20-2015
    if (nTime > 1447977700)                         magnitude_multiplier =  .50;  // from 11-21-2015  forever
    return magnitude_multiplier;
}


int64_t GetProofOfStakeMaxReward(int64_t nCoinAge, int64_t nFees, int64_t locktime)
{
    int64_t nInterest = nCoinAge * GetCoinYearReward(locktime) * 33 / (365 * 33 + 8);
    nInterest += 10*COIN;
    int64_t nBoinc    = (GetMaximumBoincSubsidy(locktime)+1) * COIN;
    int64_t nSubsidy  = nInterest + nBoinc;
    return nSubsidy + nFees;
}

// miner's coin stake reward based on coin age spent (coin-days)

int64_t GetProofOfStakeReward(int64_t nCoinAge, int64_t nFees, std::string cpid,
    bool VerifyingBlock, int VerificationPhase, int64_t nTime, CBlockIndex* pindexLast, std::string operation,
    double& OUT_POR, double& OUT_INTEREST, double& dAccrualAge, double& dMagnitudeUnit, double& AvgMagnitude)
{

    // Non Research Age - RSA Mode - Legacy (before 10-20-2015)
    if (!IsResearchAgeEnabled(pindexLast->nHeight))
    {
        return 0;
        //removed
    }
    else
    {
            // Research Age Subsidy - PROD
            int64_t nBoinc = ComputeResearchAccrual(nTime, cpid, operation, pindexLast, VerifyingBlock, VerificationPhase, dAccrualAge, dMagnitudeUnit, AvgMagnitude);
            int64_t nInterest = nCoinAge * GetCoinYearReward(nTime) * 33 / (365 * 33 + 8);

            // TestNet: For any subsidy < 30 day duration, ensure 100% that we have a start magnitude and an end magnitude, otherwise make subsidy 0 : PASS
            // TestNet: For any subsidy > 30 day duration, ensure 100% that we have a midpoint magnitude in Every Period, otherwise, make subsidy 0 : In Test as of 09-06-2015
            // TestNet: Ensure no magnitudes are out of bounds to ensure we do not generate an insane payment : PASS (Lifetime PPD takes care of this)
            // TestNet: Any subsidy with a duration wider than 6 months should not be paid : PASS

            int64_t maxStakeReward = GetMaximumBoincSubsidy(nTime) * COIN * 255;

            if (nBoinc > maxStakeReward) nBoinc = maxStakeReward;
            int64_t nSubsidy = nInterest + nBoinc;

            if (fDebug10 || GetBoolArg("-printcreation"))
            {
                printf("GetProofOfStakeReward(): create=%s nCoinAge=%" PRId64 " nBoinc=%" PRId64 "   \n",
                FormatMoney(nSubsidy).c_str(), nCoinAge, nBoinc);
            }

            int64_t nTotalSubsidy = nSubsidy + nFees;
            if (nBoinc > 1)
            {
                std::string sTotalSubsidy = RoundToString(CoinToDouble(nTotalSubsidy)+.00000123,8);
                if (sTotalSubsidy.length() > 7)
                {
                    sTotalSubsidy = sTotalSubsidy.substr(0,sTotalSubsidy.length()-4) + "0124";
                    nTotalSubsidy = cdbl(sTotalSubsidy,8)*COIN;
                }
            }

            OUT_POR = CoinToDouble(nBoinc);
            OUT_INTEREST = CoinToDouble(nInterest);
            return nTotalSubsidy;

    }
}



static const int64_t nTargetTimespan = 16 * 60;  // 16 mins


// ppcoin: find last block index up to pindex
CBlockIndex* GetLastBlockIndex(CBlockIndex* pindex, bool fProofOfStake)
{
    while (pindex && pindex->GetPrev() && (pindex->IsProofOfStake != fProofOfStake))
        pindex = pindex->GetPrev();
    return pindex;
}


static unsigned int GetNextTargetRequiredV1(CBlockIndex* pindexLast, bool fProofOfStake)
{
    CBigNum bnTargetLimit = fProofOfStake ? bnProofOfStakeLimit : bnProofOfWorkLimit;

    if (pindexLast == NULL)
        return bnTargetLimit.GetCompact(); // genesis block

    CBlockIndex* pindexPrev = GetLastBlockIndex(pindexLast, fProofOfStake);
    if (pindexPrev->GetPrev() == NULL)
        return bnTargetLimit.GetCompact(); // first block
    CBlockIndex* pindexPrevPrev = GetLastBlockIndex(pindexPrev->GetPrev(), fProofOfStake);
    if (pindexPrevPrev->GetPrev() == NULL)
        return bnTargetLimit.GetCompact(); // second block

    int64_t nTargetSpacing = GetTargetSpacing(pindexLast->nHeight);
    int64_t nActualSpacing = pindexPrev->GetBlockTime() - pindexPrevPrev->GetBlockTime();

    // ppcoin: target change every block
    // ppcoin: retarget with exponential moving toward target spacing
    CBigNum bnNew;
    bnNew.SetCompact(pindexPrev->nBits);
    int64_t nInterval = nTargetTimespan / nTargetSpacing;
    bnNew *= ((nInterval - 1) * nTargetSpacing + nActualSpacing + nActualSpacing);
    bnNew /= ((nInterval + 1) * nTargetSpacing);

    if (bnNew > bnTargetLimit)
        bnNew = bnTargetLimit;

    return bnNew.GetCompact();
}

static unsigned int GetNextTargetRequiredV2(CBlockIndex* pindexLast, bool fProofOfStake)
{
    CBigNum bnTargetLimit = fProofOfStake ? GetProofOfStakeLimit(pindexLast->nHeight) : bnProofOfWorkLimit;

    if (pindexLast == NULL)
        return bnTargetLimit.GetCompact(); // genesis block

    CBlockIndex* pindexPrev = GetLastBlockIndex(pindexLast, fProofOfStake);
    if (pindexPrev->GetPrev() == NULL)
        return bnTargetLimit.GetCompact(); // first block
    CBlockIndex* pindexPrevPrev = GetLastBlockIndex(pindexPrev->GetPrev(), fProofOfStake);
    if (pindexPrevPrev->GetPrev() == NULL)
        return bnTargetLimit.GetCompact(); // second block

    int64_t nTargetSpacing = GetTargetSpacing(pindexLast->nHeight);
    int64_t nActualSpacing = pindexPrev->GetBlockTime() - pindexPrevPrev->GetBlockTime();
    if (nActualSpacing < 0)
        nActualSpacing = nTargetSpacing;

    // ppcoin: target change every block
    // ppcoin: retarget with exponential moving toward target spacing
    CBigNum bnNew;
    bnNew.SetCompact(pindexPrev->nBits);

    //Gridcoin - Reset Diff to 1 on 12-19-2014 (R Halford) - Diff sticking at 2065 due to many incompatible features
    if (pindexLast->nHeight >= 91387 && pindexLast->nHeight <= 91500)
    {
            return bnTargetLimit.GetCompact();
    }

    //1-14-2015 R Halford - Make diff reset to zero after periods of exploding diff:
    double PORDiff = GetDifficulty(GetLastBlockIndex(Best.top, true));
    if (PORDiff > 900000)
    {
            return bnTargetLimit.GetCompact();
    }


    //Since our nTargetTimespan is (16 * 60) or 16 mins and our TargetSpacing = 64, the nInterval = 15 min

    int64_t nInterval = nTargetTimespan / nTargetSpacing;
    bnNew *= ((nInterval - 1) * nTargetSpacing + nActualSpacing + nActualSpacing);
    bnNew /= ((nInterval + 1) * nTargetSpacing);

    if (bnNew <= 0 || bnNew > bnTargetLimit)
    {
        bnNew = bnTargetLimit;
    }

    return bnNew.GetCompact();
}

unsigned int GetNextTargetRequired(CBlockIndex* pindexLast, bool fProofOfStake)
{
    //After block 89600, new diff algorithm is used
    if (pindexLast->nHeight < 89600)
        return GetNextTargetRequiredV1(pindexLast, fProofOfStake);
    else
        return GetNextTargetRequiredV2(pindexLast, fProofOfStake);
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits)
{
    CBigNum bnTarget;
    bnTarget.SetCompact(nBits);

    // Check range
    if (bnTarget <= 0 || bnTarget > bnProofOfWorkLimit)
        return error("CheckProofOfWork() : nBits below minimum work");

    // Check proof of work matches claimed amount
    if (hash > bnTarget.getuint256())
        return error("CheckProofOfWork() : hash doesn't match nBits");

    return true;
}

// Return maximum amount of blocks that other nodes claim to have
int GetNumBlocksOfPeers()
{
    //INSECURE!
    if (IsLockTimeWithinMinutes(nLastCalculatedMedianPeerCount,1))
    {
        return nLastMedianPeerCount;
    }
    nLastCalculatedMedianPeerCount = GetAdjustedTime();
    nLastMedianPeerCount = std::max(cPeerBlockCounts.median(), Checkpoints::GetTotalBlocksEstimate());
    return nLastMedianPeerCount;
}

bool IsInitialBlockDownload()
{
    //INSECURE
    LOCK(cs_main);
    if (Best.top == NULL || Best.GetHeight() < GetNumBlocksOfPeers())
        return true;
    static int64_t nLastUpdate;
    static CBlockIndex* pindexLastBest;
    if (Best.top != pindexLastBest)
    {
        pindexLastBest = Best.top;
        nLastUpdate =  GetAdjustedTime();
    }
    return ( GetAdjustedTime() - nLastUpdate < 15 &&
            Best.top->GetBlockTime() <  GetAdjustedTime() - 8 * 60 * 60);
}

void static InvalidChainFound(CTxDB& txdb, CBlockIndex* pindexNew)
{
    if (pindexNew->nChainTrust > nBestInvalidTrust)
    {
        nBestInvalidTrust = pindexNew->nChainTrust;
        CTxDB().WriteBestInvalidTrust(CBigNum(nBestInvalidTrust));
        uiInterface.NotifyBlocksChanged();
    }

    // TODO: mark that block/index as invalid so we don't try to connect it again

    uint256 nBestInvalidBlockTrust = pindexNew->nChainTrust - pindexNew->GetPrev()->nChainTrust;
    uint256 nBestBlockTrust = Best.GetHeight() != 0 ? (Best.top->nChainTrust - Best.top->GetPrev()->nChainTrust) : Best.top->nChainTrust;

    printf("InvalidChainFound: invalid block=%s  height=%d  trust=%s  blocktrust=%" PRId64 "  date=%s\n",
      pindexNew->GetBlockHash().ToString().substr(0,20).c_str(), pindexNew->nHeight,
      CBigNum(pindexNew->nChainTrust).ToString().c_str(), nBestInvalidBlockTrust.Get64(),
      DateTimeStrFormat("%x %H:%M:%S", pindexNew->GetBlockTime()).c_str());
    printf("InvalidChainFound:  current best=%s  height=%d  trust=%s  blocktrust=%" PRId64 "  date=%s\n",
      Best.top->GetBlockHash().ToString().substr(0,20).c_str(), Best.GetHeight(),
      CBigNum(Best.top->nChainTrust).ToString().c_str(),
      nBestBlockTrust.Get64(),
      DateTimeStrFormat("%x %H:%M:%S", Best.top->GetBlockTime()).c_str());
}


void CBlock::UpdateTime(CBlockIndex* pindexPrev)
{
    nTime = max(GetBlockTime(), GetAdjustedTime());
}



bool CTransaction::DisconnectInputs(CTxDB& txdb)
{
    // Relinquish previous transactions' spent pointers
    if (!IsCoinBase())
    {
        BOOST_FOREACH(const CTxIn& txin, vin)
        {
            COutPoint prevout = txin.prevout;
            // Get prev txindex from disk
            CTxIndex txindex;
            if (!txdb.ReadTxIndex(prevout.hash, txindex))
                return error("DisconnectInputs() : ReadTxIndex failed");

            if (prevout.n >= txindex.vSpent.size())
                return error("DisconnectInputs() : prevout.n out of range");

            // Mark outpoint as not spent
            txindex.vSpent[prevout.n].SetNull();

            // Write back
            if (!txdb.UpdateTxIndex(prevout.hash, txindex))
                return error("DisconnectInputs() : UpdateTxIndex failed");
        }
    }

    // Remove transaction from index
    // This can fail if a duplicate of this transaction was in a chain that got
    // reorganized away. This is only possible if this transaction was completely
    // spent, so erasing it would be a no-op anyway.
    txdb.EraseTxIndex(*this);

    return true;
}


bool CTransaction::FetchInputs(CTxDB& txdb, const map<uint256, CTxIndex>& mapTestPool,
                               bool fBlock, bool fMiner, MapPrevTx& inputsRet, bool& fInvalid)
{
    // FetchInputs can return false either because we just haven't seen some inputs
    // (in which case the transaction should be stored as an orphan)
    // or because the transaction is malformed (in which case the transaction should
    // be dropped).  If tx is definitely invalid, fInvalid will be set to true.
    fInvalid = false;

    if (IsCoinBase())
        return true; // Coinbase transactions have no inputs to fetch.

    for (unsigned int i = 0; i < vin.size(); i++)
    {
        COutPoint prevout = vin[i].prevout;
        if (inputsRet.count(prevout.hash))
            continue; // Got it already

        // Read txindex
        CTxIndex& txindex = inputsRet[prevout.hash].first;
        bool fFound = true;
        if ((fBlock || fMiner) && mapTestPool.count(prevout.hash))
        {
            // Get txindex from current proposed changes
            txindex = mapTestPool.find(prevout.hash)->second;
        }
        else
        {
            // Read txindex from txdb
            fFound = txdb.ReadTxIndex(prevout.hash, txindex);
        }
        if (!fFound && (fBlock || fMiner))
            return fMiner ? false : error("FetchInputs() : %s prev tx %s index entry not found", GetHash().ToString().substr(0,10).c_str(),  prevout.hash.ToString().substr(0,10).c_str());

        // Read txPrev
        CTransaction& txPrev = inputsRet[prevout.hash].second;
        if (!fFound || txindex.pos == CDiskTxPos(1,1,1))
        {
            // Get prev tx from single transactions in memory
            if (!mempool.lookup(prevout.hash, txPrev))
            {
                if (fDebug) printf("FetchInputs() : %s mempool Tx prev not found %s", GetHash().ToString().substr(0,10).c_str(),  prevout.hash.ToString().substr(0,10).c_str());
                return false;
            }
            if (!fFound)
                txindex.vSpent.resize(txPrev.vout.size());
        }
        else
        {
            // Get prev tx from disk
            if (!txPrev.ReadFromDisk(txindex.pos))
                return error("FetchInputs() : %s ReadFromDisk prev tx %s failed", GetHash().ToString().substr(0,10).c_str(),  prevout.hash.ToString().substr(0,10).c_str());
        }
    }

    // Make sure all prevout.n indexes are valid:
    for (unsigned int i = 0; i < vin.size(); i++)
    {
        const COutPoint prevout = vin[i].prevout;
        assert(inputsRet.count(prevout.hash) != 0);
        const CTxIndex& txindex = inputsRet[prevout.hash].first;
        const CTransaction& txPrev = inputsRet[prevout.hash].second;
        if (prevout.n >= txPrev.vout.size() || prevout.n >= txindex.vSpent.size())
        {
            // Revisit this if/when transaction replacement is implemented and allows
            // adding inputs:
            fInvalid = true;
            return DoS(100, error("FetchInputs() : %s prevout.n out of range %d %" PRIszu " %" PRIszu " prev tx %s\n%s", GetHash().ToString().substr(0,10).c_str(), prevout.n, txPrev.vout.size(), txindex.vSpent.size(), prevout.hash.ToString().substr(0,10).c_str(), txPrev.ToString().c_str()));
        }
    }

    return true;
}

const CTxOut& CTransaction::GetOutputFor(const CTxIn& input, const MapPrevTx& inputs) const
{
    MapPrevTx::const_iterator mi = inputs.find(input.prevout.hash);
    if (mi == inputs.end())
        throw std::runtime_error("CTransaction::GetOutputFor() : prevout.hash not found");

    const CTransaction& txPrev = (mi->second).second;
    if (input.prevout.n >= txPrev.vout.size())
        throw std::runtime_error("CTransaction::GetOutputFor() : prevout.n out of range");

    return txPrev.vout[input.prevout.n];
}


std::vector<std::string> split(std::string s, std::string delim)
{
    //Split a std::string by a std::string delimiter into a vector of strings:
    // TODO: optimize
    size_t pos = 0;
    std::string token;
    std::vector<std::string> elems;
    while ((pos = s.find(delim)) != std::string::npos)
    {
        token = s.substr(0, pos);
        elems.push_back(token);
        s.erase(0, pos + delim.length());
    }
    elems.push_back(s);
    return elems;

}



int64_t CTransaction::GetValueIn(const MapPrevTx& inputs) const
{
    if (IsCoinBase())
        return 0;

    int64_t nResult = 0;
    for (unsigned int i = 0; i < vin.size(); i++)
    {
        nResult += GetOutputFor(vin[i], inputs).nValue;
    }
    return nResult;

}


double PreviousBlockAge()
{
    //TODO: this attempts to do more than it should
        if (Best.GetHeight() < 10) return 99999;
        if (IsLockTimeWithinMinutes(nLastCalculatedMedianTimePast,1))
        {
            return nLastBlockAge;
        }
        nLastCalculatedMedianTimePast = GetAdjustedTime();
        // Returns the time in seconds since the last block:
        double nTime = max(Best.top->GetMedianTimePast()+1, GetAdjustedTime());
        double nActualTimespan = nTime - Best.top->GetPrev()->GetBlockTime();
        nLastBlockAge = nActualTimespan;
        return nActualTimespan;
}



bool ClientOutOfSync()
{
    //This function will return True if the client is downloading blocks, reindexing, or out of sync by more than 30 blocks as compared to its peers, or if its best block is over 30 mins old
    double lastblockage = PreviousBlockAge();
    if (lastblockage > (30*60)) return true;
    if (Best.top == NULL || Best.GetHeight() < GetNumBlocksOfPeers()-30) return true;
    return false;
}



bool OutOfSyncByMoreThan(double dMinutes)
{
    double lastblockage = PreviousBlockAge();
    if (lastblockage > (60*dMinutes)) return true;
    if (Best.top == NULL || Best.GetHeight() < GetNumBlocksOfPeers()-30) return true;
    return false;
}



bool OutOfSyncByAge()
{
    double lastblockage = PreviousBlockAge();
    if (lastblockage > (60*30)) return true;
    return false;
}

bool OutOfSyncByAgeWithChanceOfMining()
{
    // If the client is out of sync, we dont want it to mine orphan blocks on its own fork, so we return OOS when that is the case 95% of the time:
    // If the client is in sync, this function returns false and the client mines.
    // The reason we allow mining 5% of the time, is if all nodes leave Gridcoin, we want someone to be able to jump start the coin in that extremely rare circumstance (IE End of Life, or Network Outage across the country, etc).
    try
    {
            if (fTestNet) return false;
            if (GetBoolArg("-overrideoutofsyncrule", false)) return false;
            bool oosbyage = OutOfSyncByAge();
            //Rule 1: If  Last Block Out of sync by Age - Return Out of Sync 95% of the time:
            if (oosbyage) if (LessVerbose(900)) return true;
            // Rule 2 : Dont mine on Fork Rule:
            //If the diff is < .00015 in Prod, Most likely the client is mining on a fork: (Make it exceedingly hard):
            double PORDiff = GetDifficulty(GetLastBlockIndex(Best.top, true));
            if (!fTestNet && PORDiff < .00010)
            {
                printf("Most likely you are mining on a fork! Diff %f",PORDiff);
                if (LessVerbose(950)) return true;
            }
            return false;
    }
    catch (std::exception &e)
    {
                printf("Error while assessing Sync Condition\r\n");
                return true;
    }
    catch(...)
    {
                printf("Error while assessing Sync Condition[2].\r\n");
                return true;
    }
    return true;

}


unsigned int CTransaction::GetP2SHSigOpCount(const MapPrevTx& inputs) const
{
    if (IsCoinBase())
        return 0;

    unsigned int nSigOps = 0;
    for (unsigned int i = 0; i < vin.size(); i++)
    {
        const CTxOut& prevout = GetOutputFor(vin[i], inputs);
        if (prevout.scriptPubKey.IsPayToScriptHash())
            nSigOps += prevout.scriptPubKey.GetSigOpCount(vin[i].scriptSig);
    }
    return nSigOps;
}

bool CTransaction::ConnectInputs(MapPrevTx inputs, map<uint256, CTxIndex>& mapTestPool, const CDiskTxPos& posThisTx,
    CBlockIndex* pindexBlock, bool fBlock, bool fMiner)
{
    // Take over previous transactions' spent pointers
    // fBlock is true when this is called from AcceptBlock when a new best-block is added to the blockchain
    // fMiner is true when called from the internal bitcoin miner
    // ... both are false when called from CTransaction::AcceptToMemoryPool
    if (!IsCoinBase())
    {
        int64_t nValueIn = 0;
        int64_t nFees = 0;
        for (unsigned int i = 0; i < vin.size(); i++)
        {
            COutPoint prevout = vin[i].prevout;
            assert(inputs.count(prevout.hash) > 0);
            CTxIndex& txindex = inputs[prevout.hash].first;
            CTransaction& txPrev = inputs[prevout.hash].second;

            if (prevout.n >= txPrev.vout.size() || prevout.n >= txindex.vSpent.size())
                return DoS(100, error("ConnectInputs() : %s prevout.n out of range %d %" PRIszu " %" PRIszu " prev tx %s\n%s", GetHash().ToString().substr(0,10).c_str(), prevout.n, txPrev.vout.size(), txindex.vSpent.size(), prevout.hash.ToString().substr(0,10).c_str(), txPrev.ToString().c_str()));

            // If prev is coinbase or coinstake, check that it's matured
            if (txPrev.IsCoinBase() || txPrev.IsCoinStake())
                for (CBlockIndex* pindex = pindexBlock; pindex && pindexBlock->nHeight - pindex->nHeight < nCoinbaseMaturity; pindex = pindex->GetPrev())
                    if (pindex->nBlockPos == txindex.pos.nBlockPos && pindex->nFile == txindex.pos.nFile)
                        return error("ConnectInputs() : tried to spend %s at depth %d", txPrev.IsCoinBase() ? "coinbase" : "coinstake", pindexBlock->nHeight - pindex->nHeight);

            // ppcoin: check transaction timestamp
            if (txPrev.nTime > nTime)
                return DoS(100, error("ConnectInputs() : transaction timestamp earlier than input transaction"));

            // Check for negative or overflow input values
            nValueIn += txPrev.vout[prevout.n].nValue;
            if (!MoneyRange(txPrev.vout[prevout.n].nValue) || !MoneyRange(nValueIn))
                return DoS(100, error("ConnectInputs() : txin values out of range"));

        }
        // The first loop above does all the inexpensive checks.
        // Only if ALL inputs pass do we perform expensive ECDSA signature checks.
        // Helps prevent CPU exhaustion attacks.
        for (unsigned int i = 0; i < vin.size(); i++)
        {
            COutPoint prevout = vin[i].prevout;
            assert(inputs.count(prevout.hash) > 0);
            CTxIndex& txindex = inputs[prevout.hash].first;
            CTransaction& txPrev = inputs[prevout.hash].second;

            // Check for conflicts (double-spend)
            // This doesn't trigger the DoS code on purpose; if it did, it would make it easier
            // for an attacker to attempt to split the network.
            if (!txindex.vSpent[prevout.n].IsNull())
            {
                if (fMiner)
                {
                    msMiningErrorsExcluded += " ConnectInputs() : " + GetHash().GetHex() + " used at "
                        + txindex.vSpent[prevout.n].ToString() + ";   ";
                    return false;
                }
                if (!txindex.vSpent[prevout.n].IsNull())
                {
                    if (fTestNet && pindexBlock->nHeight < nGrandfather)
                    {
                        return fMiner ? false : true;
                    }
                    if (!fTestNet && pindexBlock->nHeight < nGrandfather)
                    {
                        return fMiner ? false : true;
                    }
                    if (TimerMain("ConnectInputs", 20))
                    {
                        CleanInboundConnections(false);
                    }   
                    
                    if (fMiner) return false;
                    return fDebug ? error("ConnectInputs() : %s prev tx already used at %s", GetHash().ToString().c_str(), txindex.vSpent[prevout.n].ToString().c_str()) : false;
                }

            }

            // Skip ECDSA signature verification when connecting blocks (fBlock=true)
            // before the last blockchain checkpoint. This is safe because block merkle hashes are
            // still computed and checked, and any change will be caught at the next checkpoint.
            // I don't think it is that safe... (Brod)

            if (!(fBlock && (Best.GetHeight() < Checkpoints::GetTotalBlocksEstimate())))
            {
                // Verify signature
                if (!VerifySignature(txPrev, *this, i, 0))
                {
                    return DoS(100,error("ConnectInputs() : %s VerifySignature failed", GetHash().ToString().substr(0,10).c_str()));
                }
            }

            // Mark outpoints as spent
            txindex.vSpent[prevout.n] = posThisTx;

            // Write back
            if (fBlock || fMiner)
            {
                mapTestPool[prevout.hash] = txindex;
            }
        }

        if (!IsCoinStake())
        {
            if (nValueIn < GetValueOut())
            {
                printf("ConnectInputs(): VALUE IN < VALUEOUT \r\n");
                return DoS(100, error("ConnectInputs() : %s value in < value out", GetHash().ToString().substr(0,10).c_str()));
            }

            // Tally transaction fees
            int64_t nTxFee = nValueIn - GetValueOut();

            // enforce transaction fees for every block
            if (nTxFee < 0 || nTxFee < GetMinFee())
                return fBlock? DoS(100, error("ConnectInputs() : %s not paying required fee=%s, paid=%s", GetHash().ToString().substr(0,10).c_str(), FormatMoney(GetMinFee()).c_str(), FormatMoney(nTxFee).c_str())) : false;

            nFees += nTxFee;
            if (!MoneyRange(nFees))
                return DoS(100, error("ConnectInputs() : nFees out of range"));
        }
    }

    return true;
}

std::string PubKeyToAddress(const CScript& scriptPubKey)
{
    //TODO this function is not complete, remove
    //Converts a script Public Key to a Gridcoin wallet address
    txnouttype type;
    vector<CTxDestination> addresses;
    int nRequired;
    if (!ExtractDestinations(scriptPubKey, type, addresses, nRequired))
    {
        return "";
    }
    std::string address = "";
    BOOST_FOREACH(const CTxDestination& addr, addresses)
    {
        address = CBitcoinAddress(addr).ToString();
    }
    return address;
}

bool LoadSuperblock(std::string data, int64_t nTime, double height)
{
        WriteCache("superblock","magnitudes",ExtractXML(data,"<MAGNITUDES>","</MAGNITUDES>"),nTime);
        WriteCache("superblock","averages",ExtractXML(data,"<AVERAGES>","</AVERAGES>"),nTime);
        WriteCache("superblock","quotes",ExtractXML(data,"<QUOTES>","</QUOTES>"),nTime);
        WriteCache("superblock","all",data,nTime);
        WriteCache("superblock","block_number",RoundToString(height,0),nTime);
        return true;
}


    //TODO remove this functions
template< typename T >
std::string int_to_hex( T i )
{
  std::stringstream stream;
  stream << "0x" 
         << std::setfill ('0') << std::setw(sizeof(T)*2) 
         << std::hex << i;
  return stream.str();
}

std::string DoubleToHexStr(double d, int iPlaces)
{
    int nMagnitude = atoi(RoundToString(d,0).c_str()); 
    std::string hex_string = int_to_hex(nMagnitude);
    std::string sOut = "00000000" + hex_string;
    std::string sHex = sOut.substr(sOut.length()-iPlaces,iPlaces);
    return sHex;
}

int HexToInt(std::string sHex)
{
    int x;   
    std::stringstream ss;
    ss << std::hex << sHex;
    ss >> x;
    return x;
}
std::string ConvertHexToBin(std::string a)
{
    if (a.empty()) return "";
    std::string sOut = "";
    for (unsigned int x = 1; x <= a.length(); x += 2)
    {
       std::string sChunk = a.substr(x-1,2);
       int i = HexToInt(sChunk);
       char c = (char)i;
       sOut.push_back(c);
    }
    return sOut;
}


double ConvertHexToDouble(std::string hex)
{
    int d = HexToInt(hex);
    double dOut = (double)d;
    return dOut;
}


std::string ConvertBinToHex(std::string a) 
{
      if (a.empty()) return "0";
      std::string sOut = "";
      for (unsigned int x = 1; x <= a.length(); x++)
      {
           char c = a[x-1];
           int i = (int)c; 
           std::string sHex = DoubleToHexStr((double)i,2);
           sOut += sHex;
      }
      return sOut;
}

std::string UnpackBinarySuperblock(std::string sBlock)
{
    //TODO
    // 12-21-2015: R HALFORD: If the block is not binary, return the legacy format for backward compatibility
    std::string sBinary = ExtractXML(sBlock,"<BINARY>","</BINARY>");
    if (sBinary.empty()) return sBlock;
    std::string sZero = ExtractXML(sBlock,"<ZERO>","</ZERO>");
    double dZero = cdbl(sZero,0);
    // Binary data support structure:
    // Each CPID consumes 16 bytes and 2 bytes for magnitude: (Except CPIDs with zero magnitude - the count of those is stored in XML node <ZERO> to save space)
    // 1234567890123456MM
    // MM = Magnitude stored as 2 bytes
    // No delimiter between CPIDs, Step Rate = 18
    std::string sReconstructedMagnitudes = "";
    for (unsigned int x = 0; x < sBinary.length(); x += 18)
    {
        if (sBinary.length() >= x+18)
        {
            std::string bCPID = sBinary.substr(x,16);
            std::string bMagnitude = sBinary.substr(x+16,2);
            std::string sCPID = ConvertBinToHex(bCPID);
            std::string sHexMagnitude = ConvertBinToHex(bMagnitude);
            double dMagnitude = ConvertHexToDouble("0x" + sHexMagnitude);
            std::string sRow = sCPID + "," + RoundToString(dMagnitude,0) + ";";
            sReconstructedMagnitudes += sRow;
            // if (fDebug3) printf("\r\n HEX CPID %s, HEX MAG %s, dMag %f, Row %s   ",sCPID.c_str(),sHexMagnitude.c_str(),dMagnitude,sRow.c_str());
        }
    }
    // Append zero magnitude researchers so the beacon count matches
    for (double d0 = 1; d0 <= dZero; d0++)
    {
            std::string sZeroCPID = "0";
            std::string sRow1 = sZeroCPID + ",15;";
            sReconstructedMagnitudes += sRow1;
    }
    std::string sAverages   = ExtractXML(sBlock,"<AVERAGES>","</AVERAGES>");
    std::string sQuotes     = ExtractXML(sBlock,"<QUOTES>","</QUOTES>");
    std::string sReconstructedBlock = "<AVERAGES>" + sAverages + "</AVERAGES><QUOTES>" + sQuotes + "</QUOTES><MAGNITUDES>" + sReconstructedMagnitudes + "</MAGNITUDES>";
    return sReconstructedBlock;
}

std::string PackBinarySuperblock(std::string sBlock)
{
    std::string sMagnitudes = ExtractXML(sBlock,"<MAGNITUDES>","</MAGNITUDES>");
    std::string sAverages   = ExtractXML(sBlock,"<AVERAGES>","</AVERAGES>");
    std::string sQuotes     = ExtractXML(sBlock,"<QUOTES>","</QUOTES>");
    // For each CPID in the superblock, convert data to binary
    std::vector<std::string> vSuperblock = split(sMagnitudes.c_str(),";");
    std::string sBinary = "";
    double dZeroMagCPIDCount = 0;
    for (unsigned int i = 0; i < vSuperblock.size(); i++)
    {
            if (vSuperblock[i].length() > 1)
            {
                std::string sPrefix = "00000000000000000000000000000000000" + ExtractValue(vSuperblock[i],",",0);
                std::string sCPID = sPrefix.substr(sPrefix.length()-32,32);
                double magnitude = cdbl(ExtractValue("0"+vSuperblock[i],",",1),0);
                if (magnitude < 0)     magnitude=0;
                if (magnitude > 32767) magnitude = 32767;  // Ensure we do not blow out the binary space (technically we can handle 0-65535)
                std::string sBinaryCPID   = ConvertHexToBin(sCPID);
                std::string sHexMagnitude = DoubleToHexStr(magnitude,4);
                std::string sBinaryMagnitude = ConvertHexToBin(sHexMagnitude);
                std::string sBinaryEntry  = sBinaryCPID+sBinaryMagnitude;
                // if (fDebug3) printf("\r\n PackBinarySuperblock: DecMag %f HEX MAG %s bin_cpid_len %f bm_len %f be_len %f,",  magnitude,sHexMagnitude.c_str(),(double)sBinaryCPID.length(),(double)sBinaryMagnitude.length(),(double)sBinaryEntry.length());
                if (sCPID=="00000000000000000000000000000000")
                {
                    dZeroMagCPIDCount += 1;
                }
                else
                {
                    sBinary += sBinaryEntry;
                }

            }
    }
    std::string sReconstructedBinarySuperblock = "<ZERO>" + RoundToString(dZeroMagCPIDCount,0) + "</ZERO><BINARY>" + sBinary + "</BINARY><AVERAGES>" + sAverages + "</AVERAGES><QUOTES>" + sQuotes + "</QUOTES>";
    return sReconstructedBinarySuperblock;
}

/* Sliding window functions
*/
void SlidingWindowSlide(CTxDB &batch,
    CBlockIndex *lastblock, // block to attach or detach
    short dir) // +1=forward/attach -1=backward/detach
{
    assert(dir==+1 || dir==-1);
    assert(lastblock);

    printf("SlidingWindowSlide(,,,%+d)\n",dir);
    StructCPID2* topcpid = Best.GetCPID(lastblock->cpid);

    // Top    add
    if(dir>0)
    {
        Best.top = lastblock;

        if (topcpid)
        {
            topcpid->vpBlocks.push_back(lastblock);

            if (lastblock->nHeight > nNewIndex2
                && lastblock->nTime < topcpid->LftFirstBlockTime)
            {
                topcpid->LftFirstBlockTime = lastblock->nTime;
            }
        }
    }

    // Top    remove
    if(dir<0)
    {
        Best.top = lastblock->GetPrev();
        if (topcpid)
        {
            assert(topcpid->vpBlocks.back()==lastblock);
            topcpid->vpBlocks.pop_back();

            if (lastblock->nHeight > nNewIndex2
                && lastblock->nTime <= topcpid->LftFirstBlockTime)
            {
                topcpid->LftFirstBlockTime = 0;
            }
        }
    }

    // Top    add/remove
    if (topcpid)
    {
        if(lastblock->nHeight > nNewIndex2)
        {
            topcpid->LftSumReward += dir * lastblock->nResearchSubsidy;
            topcpid->LftSumInterest += dir * lastblock->nInterestSubsidy;
            topcpid->LftCountReward += dir;

            if (lastblock->nMagnitude > 0)
            {
                topcpid->LftCntMagnitude += dir;
                topcpid->LftSumMagnitude += dir * lastblock->nMagnitude;
            }
        }

        topcpid->D14SumReward += dir * lastblock->nResearchSubsidy;
        topcpid->D14SumInterest += dir * lastblock->nInterestSubsidy;
        topcpid->D14SumMagnitude += dir * lastblock->nMagnitude;
        topcpid->D14CountReward += dir;
        topcpid->SaveDb(batch);
    }

    Best.sum.Research += dir * Best.top->nResearchSubsidy;
    Best.sum.Interest += dir * Best.top->nInterestSubsidy;
    Best.sum.blocks += dir;

    // 10 blocks ago
    if( dir>0 && (Best.p10b->nHeight+10)<lastblock->nHeight)
    {
        Best.p10b = Best.p10b->GetNext();
    }

    if( dir<0 && Best.p10b->GetPrev() && (Best.p10b->nHeight+10)>=lastblock->nHeight)
    {
        Best.p10b = Best.p10b->GetPrev();
    }

    // 14 days ago
    while( ( dir<0 && Best.p14d->GetPrev() &&
      ((Best.p14d->GetPrev()->nTime+14*BLOCKS_PER_DAY)>=lastblock->nTime) )
      || ( dir>0 && ((Best.p14d->nTime+14*BLOCKS_PER_DAY)<lastblock->nTime) ) )
    {
        if(dir<0)
            Best.p14d = Best.p14d->GetPrev();

        // 14 days ago   add/remove
        Best.sum.Research -= dir * Best.p14d->nResearchSubsidy;
        Best.sum.Interest -= dir * Best.p14d->nInterestSubsidy;
        Best.sum.blocks -= dir;
        StructCPID2* p14dcpid = Best.GetCPID(Best.p14d->cpid);
        if (p14dcpid)
        {
            p14dcpid->D14SumReward -= dir * Best.p14d->nResearchSubsidy;
            p14dcpid->D14SumInterest -= dir * Best.p14d->nInterestSubsidy;
            p14dcpid->D14SumMagnitude -= dir * lastblock->nMagnitude;
            p14dcpid->D14CountReward -= dir;
            p14dcpid->SaveDb(batch);
        }

        if( dir>0 )
            Best.p14d = Best.p14d->GetNext();
    }

    // 6 months ago    back
    while( dir<0 && Best.p6m->GetPrev() &&
      ((Best.p6m->GetPrev()->nTime+BLOCKS_PER_DAY*6*30)>=lastblock->nTime) )
    {
        Best.p6m = Best.p6m->GetPrev();
        StructCPID2* p6mcpid= Best.GetCPID(Best.p6m->cpid);
        if(p6mcpid)
        {
            p6mcpid->vpBlocks.push_front(Best.p6m);
            p6mcpid->SaveDb(batch);
        }
        // Read contract messages
        if(Best.p6m->IsContract)
        {
            //todo: load the block and reload contracts
        }
    }

    // 6 months ago    forward
    while( dir>0 &&
      ((Best.p6m->nTime+BLOCKS_PER_DAY*6*30)<lastblock->nTime) )
    {
        StructCPID2* p6mcpid= Best.GetCPID(Best.p6m->cpid);
        
        if(p6mcpid)
        {
            assert(p6mcpid->vpBlocks.front()==Best.p6m);
            p6mcpid->vpBlocks.pop_front();
            p6mcpid->SaveDb(batch);
        }
        //contracts left in cache to be cleaned later
        Best.p6m = Best.p6m->GetNext();
    }

    Best.SaveDb(batch);
}

/* Transaction Contract hangling (hashBoinc message)
*/

bool ContractExtractFromBB(const std::string & BB,
    CTxMessage::EMessageType &eType,std::string &sName,bool& fDelete,
    std::string &sPubKey,std::string& sValue,std::string& sSignature)
{

    sType      = ExtractXML(BB,"<MT>","</MT>");
    sName      = ExtractXML(BB,"<MK>","</MK>");
    std::string sMessageAction    = ExtractXML(BB,"<MA>","</MA>");

    if(sType.empty())
        return false;
    if(sName.empty())
        return false;
    if(sMessageAction=="A")
        fDelete=false;
    else if(sMessageAction=="D")
        fDelete=true;
    else return false;

    if(sType=="poll")
        etype = CTxMessage::mpoll;
    else if(sType=="vote")
        etype = CTxMessage::mvote;
    else if(sType=="beacon")
        etype = CTxMessage::mcpid;
    else if(sType=="project")
        etype = CTxMessage::mproject;
    // wrong message type field
    else return false;

    sValue     = ExtractXML(BB,"<MV>","</MV>");
    sSignature = ExtractXML(BB,"<MS>","</MS>");
    sPubKey    = ExtractXML(BB,"<MPK>","</MPK>");
    return true;
}

void MemorizeContract_cpid(CTxDB& txdb, const CTransaction& tx, const bool fcheck, const std::string& sMessageName, const std::string& sMessageValue, const bool fdelete)
{
    if(sMessageName=="INVESTOR"||sMessageName==""||sMessageName=="POOL")
        return;
    uint128 bincpid (sMessageName); //does not throw, skips invalid chars
    StructCPID2* stc = Best.GetCPID(bincpid);
    CPubKey PubKey;
    if(!fdelete)
    {
        std::string out_cpid, out_address,sPublicKey;
        GetBeaconElements(sMessageValue, out_cpid, out_address, sPublicKey);
        if(out_cpid!=sMessageName)
            return;
        PubKey = ParseHex(sPublicKey);
        if(!PubKey.IsValid())
            return;
    }
    if(stc && !fdelete && fcheck && stc->IsValid())
    {
        //cpid exists, trying to overwrite, new contract, old still valid
        if (PubKey!=stc->PublicKey)
        {
            printf("Beacon Overwrite denied, keys dont match and not expired\n");
            return;
        }
    }
    if(!stc)
    {
        //not yet in db, initialize new cpid
        if(fdelete)
            return;
        stc = new StructCPID2;
        ...
    }

    stc->BeaconPublicKey=PubKey;
    stc->BeaconTime=tx.nTime;
    if(fcheck)
        stc->message.AddTrx(tx);
    stc->SaveDb(txdb);
    return;
}

void ReloadContracts(CTxDB& txdb, const std::set<CTxMessage*>& vContractsToReload)
{
    for( CTxMessage* msg : vContractsToReload)
    {

    std::set<CTxMessage*> vContractsToReload;
    for(CBlockIndex *cur= Best.top;
        cur && cur!=proot;
        cur=cur->GetPrev())
    {
        CBlock curblk;
        if(!curblk.ReadFromDisk(cur))
            return error("BranchDisconnect: ReadFromDisk failed");
        if(!curblk.DisconnectBlock(batch, cur, vContractsToReload))
            return error("BranchDisconnect: DisconnectBlock failed");
    }

    ReloadContracts(vContractsToReload);
    //load previous version
    if(!msg.vTxHash.empty())
        const uint256 txphash = msg.vTxHash.back();
        CTransaction txp;
        uint256 hashBlock;
        if(!GetTransaction(txphash, txp, hashBlock))
            throw error("DisconnectContract: Failed to load previous version");
    //extract fields
    std::string sMessageName,sPublicKey, sMessageValue, sSignature;
    CTxMessage::EMessageType type;
    bool fdelete;
    if  ( !ContractExtractFromBB(tx.hashBoinc,
            type, sMessageName, fdelete,
            sPublicKey, sMessageValue, sSignature)
        )
        return;

    // Delegate the contract to specific handler
    if(type == CTxMessage:mcpid)
        MemorizeContract_cpid(tx,false,sMessageName,sMessageValue,fdelete);
}

void MemorizeContract(CTxDB& txdb, const CTransaction& tx, CBlockIndex* pindex)
{

    std::string sMessageName;
    CTxMessage::EMessageType type;
    bool fdelete;
    std::string sPublicKey, sMessageValue, sSignature;
    if  ( !ContractExtractFromBB(tx.hashBoinc,
            type, sMessageName, fdelete,
            sPublicKey, sMessageValue, sSignature)
        )
        return;

    if(!fdelete && sMessageValue.empty())
        return;
    if(sSignature.empty())
        return;

    // Override public key for some message types
    switch(type)
    {
        CTxMessage::mpoll: CTxMessage::mvote: CTxMessage::mbeacon:
            if (fdelete)
                sPublicKey = msMasterProjectPublicKey;
            else
                sPublicKey = msMasterMessagePublicKey;
            break;
        CTxMessage::mproject: CTxMessage::mprojectmapping:
            sPublicKey=msMasterProjectPublicKey;
            break;
    }

    // verify signature
    CHashWriter Hasher(0,0);
    Hasher.write(sMessageType.data(),sMessageType.size());
    Hasher.write(sMessageName.data(),sMessageName.size());
    Hasher.write(sMessageValue.data(),sMessageValue.size());
    std::string sDecodedSig = DecodeBase64(sSignature);
    CKey key;
    if (!key.SetPubKey(ParseHex(sPublicKey))) return;
    std::vector<unsigned char> vchSig = vector<unsigned char>(sDecodedSig.begin(), sDecodedSig.end());
    if (!key.Verify(Hasher.GetHash(), vchSig)) return;

    // Delegate the contract to specific handler
    if(type == CTxMessage:mcpid)
        MemorizeContract_cpid(tx,true,sMessageName,sMessageValue,fdelete);

    /*
    // create, or find existing message struct
    CTxMessage & Msg = pmsg? *pmsg : Best.msg[sMessageType+";"+sMessageName];
    if (!Msg.vTxHash.empty())
        Best.MsgByTx.erase(Msg.vTxHash.back());
    Best.MsgByTx[tx.GetHash()] = & Msg;
    Msg.vTxHash.push_back(tx.GetHash());
    Msg.nTime = tx.nTime;
    Msg.fLoaded = false;

    if(false)
    {
        // Load the fields, so we don't have to later
        Msg.sType = sMessageType;
        Msg.sName = sMessageName;
        Msg.sValue = sMessageValue;
        Msg.fDelete = fdelete;
    }

    Msg.SaveDb(txdb);
    */
}

CTxMessage* CBestChain::GetMessage(std::string sType, std::string sName, unsigned int nCurTime)
{
    
    const int iMonths = 6;
    const unsigned int iMaxSeconds = 60 * 24 * 30 * iMonths * 60;
    auto ppmsg = msg.find(sType+";"+sName);
    if(ppmsg==msg.end())
        return NULL;
    CTxMessage & amsg = ppmsg->second;
    if (amsg.vTxHash.empty())
        return NULL;
    // time will be correct even without fLoaded
    if((amsg.nTime+iMaxSeconds)<nCurTime)
        return NULL;
    if (amsg.fLoaded)
        return &amsg;

    CTransaction tx;
    if(!tx.ReadFromDisk(COutPoint(amsg.vTxHash.back(),0)))
        throw error("Best.GetMessage: CTransaction.ReadFromDisk failed");
    amsg.nTime = tx.nTime;
    std::string sPublicKey, sSignature;
    if  ( !ContractExtractFromBB(tx.hashBoinc,
            amsg.sType, amsg.sName, amsg.fDelete,
            sPublicKey, amsg.sValue, sSignature)
        )
        return NULL;
    amsg.fLoaded=true;

    if((amsg.nTime+iMaxSeconds)<nCurTime)
        return NULL;
    return &amsg;
}

bool VerifyCPIDSignature(const StructCPID2* scpid, const MiningCPID& bb, CBlockIndex* pindex)
{
    CKey key;
    if (!key.SetPubKey(scpid->BeaconPublicKey))
        return false;

    std::vector<unsigned char> vchSig = DecodeBase64(bb.BoincSignature.c_str());
    std::string sPrev = pindex->GetPrev()->GetBlockHash().GetHex();

    CHashWriter Hasher(0,0);
    Hasher.write(bb.cpid.data(),bb.cpid.size());
    Hasher.write(sPrev.data(),sPrev.size());

    if (!key.Verify(Hasher.GetHash(), vchSig))
        return false;

    return true;
}


/*
  *** Block Checking function ***
Only ConnectBlock is context-sensitive.

CheckBlock does checks on that block only. It is run when new block is
recieved. Previous block may not be in index.

AcceptBlock writes the block to disk and block index. Very little checks are
done there. Previous block is already in index, but transactions from it may
not be.

ConnectBlock will after extensive checking of everything connect the block to
previous block in best chain. The block is already on disk and in index as well
as previous block and previous transactions. Gridcoin structures are consistent
with previous block.

*/

bool CBlock::ConnectBlock(CTxDB& txdb, CBlockIndex* pindex, bool fJustCheck, bool fReorganizing)
{
    int nHeight= pindex->nHeight;
    uint256 BlockHash = GetHash();
    printf("ConnectBlock.Begin{%s %d}\n",BlockHash.GetHex().c_str(),nHeight);
    // Check it again in case a previous version let a bad block in, but skip BlockSig checking
    if (!CheckBlock("ConnectBlock",nHeight))
    {
        printf("ConnectBlock: CheckBlock Failed - \r\n");
        return false;
    }

    // check stake here again, TODO
    {
        uint256 hashProof;

        // Verify hash target and signature of coinstake tx
        if (nHeight > nGrandfather && nVersion <= 7)
        {
            if (IsProofOfStake())
            {
                uint256 targetProofOfStake;
                if (!CheckProofOfStake(pindex->GetPrev(), vtx[1], nBits, hashProof, targetProofOfStake, vtx[0].hashBoinc, false, nNonce) && IsLockTimeWithinMinutes(GetBlockTime(),600))
                {
                    return error("ConnectBlock: check proof-of-stake failed for block %s, nonce %f    \n", BlockHash.ToString().c_str(),(double)nNonce);
                }
            }
        }
        if (nVersion >= 8)
        {
            //must be proof of stake
            //no grandfather exceptions
            printf("ConnectBlock: Proof Of Stake V8 %d\n",nVersion);
            if(!CheckProofOfStakeV8(pindex->GetPrev(), *this, false, hashProof))
            {
                return error("ConnectBlock: check proof-of-stake v8 failed for block %s, nonce %f    \n", BlockHash.ToString().c_str(),(double)nNonce);
            }
        }
        if (IsProofOfWork())
        {
            hashProof = GetPoWHash();
        }

        // Record proof hash value into block index
        pindex->hashProof = hashProof;

        // ppcoin: compute stake modifier
        // requires proof hash to be available
        uint64_t nStakeModifier = 0;
        bool fGeneratedStakeModifier = false;
        if (!ComputeNextStakeModifier(pindex->GetPrev(), nStakeModifier, fGeneratedStakeModifier))
        {
            printf("ConnectBlock: ComputeNextStakeModifier() failed");
        }
        pindex->SetStakeModifier(nStakeModifier, fGeneratedStakeModifier);
        //the block index will be saved at end of this function
    }
    //- end kernel verify


    //// issue here: it doesn't know the version
    // WTF^?

    //Deserialize gridcoin data from coinbase
    MiningCPID bb = DeserializeBoincBlock(vtx[0].hashBoinc,nVersion);
    //todo: check deserialize

    //Check Researcher CPID
    StructCPID2* scpid = NULL;
    pindex->SetCPID(bb.cpid);
    if(pindex->HasCPID && nHeight > nGrandfather)
    {
        if (bb.projectname.empty() && !IsResearchAgeEnabled(nHeight))
            return DoS(1,error("CheckBlock: PoR Project Name invalid"));
        scpid = Best.GetCPID(pindex->cpid);
        if(!scpid)
            return DoS(1,error("CheckBlock: Invalid CPID, not in database"));

        //Load beacon/account key, from beacon contract or the stats block
        if(!scpid->LoadAccountKey(bb,pindex))
            return DoS(1,error("CheckBlock: Invalid CPID, Failed to load account key"));

        if (!VerifyCPIDSignature(scpid,bb,pindex))
        {
            return error("CheckBlock: Bad CPID signature, Bad Hashboinc %s", vtx[0].hashBoinc.c_str());
        }
        //assert(bb.cpid==pindex->GetCPID()==scpid->GetCPID());

    }
    else if(bb.cpid!="INVESTOR")
        return DoS(1,error("CheckBlock: Invalid CPID (%s!=INVESTOR)",bb.cpid.c_str()));

    unsigned int nTxPos;
    nTxPos = pindex->nBlockPos + ::GetSerializeSize(CBlock(), SER_DISK, CLIENT_VERSION) - (2 * GetSizeOfCompactSize(0)) + GetSizeOfCompactSize(vtx.size());

    map<uint256, CTxIndex> mapQueuedChanges;
    int64_t nBlockFees = 0;
    int64_t nBlockReward = 0;
    unsigned int nSigOps = 0;


    BOOST_FOREACH(CTransaction& tx, vtx)
    {
        uint256 hashTx = tx.GetHash();

        // Do not allow blocks that contain transactions which 'overwrite' older transactions,
        // unless those are already completely spent.
        // If such overwrites are allowed, coinbases and transactions depending upon those
        // can be duplicated to remove the ability to spend the first instance -- even after
        // being sent to another address.
        // See BIP30 and http://r6.ca/blog/20120206T005236Z.html for more information.
        // This logic is not necessary for memory pool transactions, as AcceptToMemoryPool
        // already refuses previously-known transaction ids entirely.
        // This rule was originally applied all blocks whose timestamp was after March 15, 2012, 0:00 UTC.
        // Now that the whole chain is irreversibly beyond that time it is applied to all blocks except the
        // two in the chain that violate it. This prevents exploiting the issue against nodes in their
        // initial block download.
        CTxIndex txindexOld;
        if (txdb.ReadTxIndex(hashTx, txindexOld)) {
            BOOST_FOREACH(CDiskTxPos &pos, txindexOld.vSpent)
                if (pos.IsNull())
                    return false;
        }

        nSigOps += tx.GetLegacySigOpCount();
        if (nSigOps > MAX_BLOCK_SIGOPS)
            return DoS(100, error("ConnectBlock: too many sigops"));

        CDiskTxPos posThisTx(pindex->nFile, pindex->nBlockPos, nTxPos);
        if (!fJustCheck)
            nTxPos += ::GetSerializeSize(tx, SER_DISK, CLIENT_VERSION);

        MapPrevTx mapInputs;
        if (tx.IsCoinBase())
        {
            //track reward amount
            nBlockReward += tx.GetValueOut();
        }
        else
        {
            bool fInvalid;
            if (!tx.FetchInputs(txdb, mapQueuedChanges, true, false, mapInputs, fInvalid))
                return false;

            // Add in sigops done by pay-to-script-hash inputs;
            // this is to prevent a "rogue miner" from creating
            // an incredibly-expensive-to-validate block.
            nSigOps += tx.GetP2SHSigOpCount(mapInputs);
            if (nSigOps > MAX_BLOCK_SIGOPS)
                return DoS(100, error("ConnectBlock[] : too many sigops"));

            int64_t nTxValueIn = tx.GetValueIn(mapInputs);
            int64_t nTxValueOut = tx.GetValueOut();

            if (tx.IsCoinStake())
            {
                //track reward amount
                nBlockReward += nTxValueOut - nTxValueIn;

                // ResearchAge: Verify vouts cannot contain any other payments except coinstake: PASS (GetValueOut returns the sum of all spent coins in the coinstake)
                // Verify no recipients exist after coinstake (Recipients start at output position 3 (0=Coinstake flag, 1=coinstake amount, 2=splitstake amount)
                if (tx.vout.size() > 3 && pindex->nHeight > nGrandfather)
                {
                    for (unsigned int i = 3; i < tx.vout.size(); i++)
                        if (tx.vout[i].nValue > 0)
                            return DoS(50,error("ConnectBlock: too many stake outputs"));
                    //POR Payment results in an overpayment; Recipient %s, Amount %f \r\n",
                }

                // TODO Check the V8 kernel here when prev tx is available
            }
            else
            {
                //not stake nor base
                nBlockFees += nTxValueIn - nTxValueOut;
            }

            if (!tx.ConnectInputs(mapInputs, mapQueuedChanges, posThisTx, pindex, true, false))
                return false;
        }

        mapQueuedChanges[hashTx] = CTxIndex(posThisTx, tx.vout.size());
    }

    if (IsProofOfWork() && pindex->nHeight > nGrandfather)
    {
        int64_t nReward = GetProofOfWorkMaxReward(nBlockFees,nTime,pindex->nHeight);
        // Check coinbase reward
        if (nBlockReward > nReward)
            return DoS(50, error("ConnectBlock[] : coinbase reward exceeded (actual=%" PRId64 " vs calculated=%" PRId64 ")",
                   nBlockReward,
                   nReward));
    }

    uint64_t nCoinAge = 0;

    double dStakeReward = CoinToDouble(nBlockReward);
    double dBlockMint = CoinToDouble(nBlockReward-nBlockFees);

    if (fDebug) printf("Stake Reward of %f B %f I %f F %.f %s %s  ",
        dStakeReward,bb.ResearchSubsidy,bb.InterestSubsidy,(double)nBlockFees,bb.cpid.c_str(),bb.Organization.c_str());

    if (IsProofOfStake() && nHeight > nGrandfather)
    {
        // ppcoin: coin stake tx earns reward instead of paying fee
        if (!vtx[1].IsCoinStake() || !vtx[1].GetCoinAge(txdb, nCoinAge))
            return error("ConnectBlock[] : %s unable to get coin age for coinstake", vtx[1].GetHash().ToString().substr(0,10).c_str());

        double dMaxStakeReward = CoinToDouble(GetProofOfStakeMaxReward(nCoinAge, nBlockFees, nTime));

        if (dStakeReward > dMaxStakeReward+1 && !IsResearchAgeEnabled(pindex->nHeight))
            return DoS(1, error("ConnectBlock[] : coinstake pays above maximum (actual= %f, vs calculated=%f )", dStakeReward, dMaxStakeReward));

        // One more check that block reward matches that in boincblock
        double dDrift = IsResearchAgeEnabled(pindex->nHeight) ? bb.ResearchSubsidy*.15 : 1;
        if (IsResearchAgeEnabled(pindex->nHeight) && dDrift < 10) dDrift = 10;
        if (dBlockMint > (bb.ResearchSubsidy + bb.InterestSubsidy + dDrift))
            return DoS(10,error("ConnectBlock: Total Mint of %f does not match HashBoinc %s",
                dBlockMint, vtx[0].hashBoinc.c_str()));

    }

    if (nHeight > nGrandfather)
    {
        //Block Spamming
        double mintlimit = MintLimiter(GetBlockDifficulty(nBits),bb.RSAWeight,bb.cpid,GetBlockTime());
        if (dBlockMint < mintlimit && dBlockMint == 0)
            return error("ConnectBlock: Mint %f too Small, min %f",dBlockMint,mintlimit);

        //9-3-2015
        double dMaxResearchAgeReward = CoinToDouble(GetMaximumBoincSubsidy(nTime) * COIN * 255);
        if (bb.ResearchSubsidy > dMaxResearchAgeReward && IsResearchAgeEnabled(pindex->nHeight))
            return DoS(1, error("ConnectBlock[ResearchAge] : Coinstake pays above maximum (actual= %f, vs calculated=%f )", bb.ResearchSubsidy, dMaxResearchAgeReward));

        //Load research and interest reward
        double OUT_POR = 0;
        double OUT_INTEREST = 0;
        double dAccrualAge = 0;
        double dAccrualMagnitudeUnit = 0;
        double dAccrualMagnitude = 0;
        int64_t nCalculatedReward = GetProofOfStakeReward(nCoinAge, nBlockFees, bb.cpid, true, 1, nTime,
            pindex->GetPrev(), "ConnectBlock",
            OUT_POR, OUT_INTEREST, dAccrualAge, dAccrualMagnitudeUnit, dAccrualMagnitude);

        // 6-4-2017 - Verify researchers stored block magnitude
        if(bb.cpid != "INVESTOR" && bb.Magnitude > 0 && (fTestNet || nHeight > 947000))
        {
            double dNeuralNetworkMagnitude = CalculatedMagnitude2(bb.cpid, nTime, false);
            if (bb.Magnitude > (dNeuralNetworkMagnitude*1.25) && (fTestNet || nHeight > 947000))
                return error("CheckBlock[ResearchAge] : Researchers block magnitude > neural network magnitude: Block Magnitude %f, Neural Network Magnitude %f, CPID %s ",
                    (double)bb.Magnitude,(double)dNeuralNetworkMagnitude,bb.cpid.c_str());
        }

        //Verify the reward amount

        if (bb.ResearchSubsidy > ((OUT_POR*1.25)+1))
            return DoS(10,error("ConnectBlock: Research Reward Pays too much: Claimed %f, Calculated %f, BlockReward %f, for CPID %s",
                    bb.ResearchSubsidy,OUT_POR,dStakeReward,bb.cpid.c_str()));

        if (bb.InterestSubsidy > (OUT_INTEREST+1))
            return DoS(10,error("ConnectBlock: Interest Reward Pays too much: Claimed %f, Calculated %f, BlockReward %f, for CPID %s",
                    bb.InterestSubsidy,OUT_INTEREST,dStakeReward,bb.cpid.c_str()));

        if ((nBlockReward > ((nCalculatedReward*1.25)+(1*COIN)))
            ||(dStakeReward > ((OUT_POR*1.25)+OUT_INTEREST+1+CoinToDouble(nBlockFees))))
            return DoS(10,error("ConnectBlock: Total Reward Pays too much: Claimed %f, Calculated %f, Fees %f, Research %f, Interest %f, for CPID %s",
                    dStakeReward, CoinToDouble(nCalculatedReward),CoinToDouble(nBlockFees),OUT_POR,OUT_INTEREST,bb.cpid.c_str()));

    }

    //Gridcoin: Maintain network consensus for Payments and Neural popularity:  (As of 7-5-2015 this is now done exactly every 30 blocks)

    //DPOR - 6/12/2015 - Reject superblocks not hashing to the supermajority:

    if (bb.superblock.length() > 20)
    {
        // Verify that the superblock is valid and matches consensus
        if (pindex->nHeight > nGrandfather)
        {
            // 12-20-2015 : Add support for Binary Superblocks
            std::string superblock = UnpackBinarySuperblock(bb.superblock);
            std::string neural_hash = GetQuorumHash(superblock);
            std::string legacy_neural_hash = RetrieveMd5(superblock);
            double popularity = 0;
            std::string consensus_hash = GetNeuralNetworkSupermajorityHash(popularity);
            if (!VerifySuperblock(superblock,pindex->nHeight))
            {
                return error("ConnectBlock[] : Superblock does not pass validity; SuperblockHash: %s, Consensus Hash: %s",
                                    neural_hash.c_str(), consensus_hash.c_str());
            }
            if (consensus_hash != neural_hash)
            {
                return error("ConnectBlock[] : Superblock hash does not match consensus hash; SuperblockHash: %s, Consensus Hash: %s",
                                neural_hash.c_str(), consensus_hash.c_str());
            }
        }

        /*
            -- Normal Superblocks are loaded 15 blocks later
        */
    }

    if (fJustCheck)
        return true;

    if(!txdb.TxnBegin())
        return error("ConnectBlock: txdb.TxnBegin failed");

    // Commit transaction index changes
    // Write queued txindex changes
    for (map<uint256, CTxIndex>::iterator mi = mapQueuedChanges.begin(); mi != mapQueuedChanges.end(); ++mi)
    {
        if (!txdb.UpdateTxIndex((*mi).first, (*mi).second))
            return error("ConnectBlock[] : UpdateTxIndex failed");
    }

    // Gridcoin: Store verified magnitude and CPID in block index (7-11-2015)
    if (pindex->nHeight > nNewIndex2)
    {
        pindex->SetCPID(bb.cpid);
        pindex->sGRCAddress = bb.GRCAddress;
        pindex->nMagnitude = bb.Magnitude;
        pindex->nResearchSubsidy = bb.ResearchSubsidy;
        pindex->nInterestSubsidy = bb.InterestSubsidy;
        pindex->IsSuperBlock =  (bb.superblock.length() > 20) ? 1 : 0;
        pindex->sGRCAddress = bb.GRCAddress;
    }

    // Track money supply and mint amount info
    pindex->nMint = nBlockReward;

    pindex->nMoneySupply =
        ( pindex->HasPrev()? pindex->GetPrev()->nMoneySupply : 0 )
        + nBlockReward - nBlockFees;

    // Actually connect the block index to previous
    assert(pindex->GetPrev());
    assert(pindex->GetPrev()->GetBlockHash()==hashPrevBlock);
    pindex->DetectedInvalid= false;
    pindex->MakePrevNextConnection(true);

    // Read contract messages
    BOOST_FOREACH(const CTransaction &tx, vtx)
    {
        if(tx.IsCoinStake()||tx.IsCoinBase())
            continue;
        if (tx.hashBoinc.length() > 3)
        {
            MemorizeContract(txdb,tx,pindex);
            if (pindex->nHeight > nNewIndex2)
                pindex->IsContract = 1;
        }
    }

    // Gridcoin: Track payments to CPID, and last block paid
    // and other things (RW operation to Best and CPID)
    SlidingWindowSlide(txdb, pindex, +1);
    assert(Best.top==pindex);

    // Write changed block index (changed a lot)
    if (!txdb.WriteBlockIndex(*pindex))
        throw error("Connect() : WriteBlockIndex for pindex failed");

    // Write changed block index (changed next pointer)
    if (!txdb.WriteBlockIndex(*(pindex->GetPrev())))
        throw error("Connect() : WriteBlockIndex for pindexPrev failed");

    if(!txdb.TxnCommit())
        throw error("ConnectBlock: txdb.TxnCommit failed");

    BOOST_FOREACH(CTransaction& tx, vtx)
    {
        // Watch for transactions paying to me
        SyncWithWallets(tx, this, true);
        // Delete redundant memory transactions
        mempool.remove(tx);
    }
    nTransactionsUpdated++;
    bool fIsInitialDownload = IsInitialBlockDownload();
    // Update best block in wallet (so we can detect restored wallets)
    if (!fIsInitialDownload)
    {
        const CBlockLocator locator(pindex);
        ::SetBestChain(locator);
    }

    // Info
    //uint256 nBlockTrust = pindex->nHeight? (pindex->nChainTrust - pindex->GetPrev()->nChainTrust) : pindex->nChainTrust;
    printf("{SBC} {%s %d}\n",pindex->GetBlockHash().GetHex().c_str(),pindex->nHeight);

    return true;
}

/* Context-Free checks on the block */
bool CBlock::CheckBlock(std::string sCaller, int height1) const
{
    bool HasStake= false;
    double blockdiff = GetBlockDifficulty(nBits);
    set<uint256> uniqueTx;
    unsigned int nSigOps = 0;

    if (GetHash()==hashGenesisBlock || GetHash()==hashGenesisBlockTestNet) return true;

    // These are checks that are independent of context
    // that can be verified before saving an orphan block.

    if (nVersion > CURRENT_VERSION)
        return DoS(100, error("CheckBlock: reject unknown block version %d", nVersion));

    // Size limits
    if (vtx.empty() || vtx.size() > MAX_BLOCK_SIZE || ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION) > MAX_BLOCK_SIZE)
        return DoS(100, error("CheckBlock: size limits failed"));

    //Reject blocks with diff that has grown to an extrordinary level (should never happen)
    if (blockdiff > 10000000000000000)
    {
       return DoS(1, error("CheckBlock: Block Bits larger than 10000000000000000.\r\n"));
    }

    // Check transactions
    // could use foreach but need the index
    for(unsigned txi=0; txi < vtx.size(); txi++)
    {
        const CTransaction& tx= vtx[txi];

        // ppcoin: check transaction timestamp
        if (GetBlockTime() < (int64_t)tx.nTime)
            return DoS(50, error("CheckBlock: block timestamp earlier than transaction timestamp"));

        // First transaction must be coinbase, the rest must not be
        if ((txi==0) != tx.IsCoinBase())
            return DoS(100, error("CheckBlock: coinbase is not in first ransaction"));

        // Second transaction must be coinstake, the rest must not be
        if ((txi==1) && vtx[1].IsCoinStake())
        {
            HasStake= true;
        }

        if ((txi!=1) && vtx[txi].IsCoinStake())
            return DoS(100, error("CheckBlock: more than one coinstake"));

        if (!tx.CheckTransaction())
            return DoS(tx.nDoS, error("CheckBlock: CheckTransaction failed"));

        uniqueTx.insert(tx.GetHash());
        nSigOps += tx.GetLegacySigOpCount();
    }

    if(HasStake != IsProofOfStake())
        return error("CheckBlock: missing coinstake tx in PoS block");

    // Check for duplicate txids. This is caught by ConnectInputs(),
    // but catching it earlier avoids a potential DoS attack:
    if (uniqueTx.size() != vtx.size())
        return DoS(100, error("CheckBlock: duplicate transactions"));

    if (nSigOps > MAX_BLOCK_SIGOPS)
        return DoS(100, error("CheckBlock: too many Sig-Ops"));

    if (height1 > nGrandfather)
    {
        const string &hashBoinc = vtx[0].hashBoinc;
        MiningCPID bb = DeserializeBoincBlock(hashBoinc,nVersion);
        // TODO: check if deserialization failed

        // Block client version
        // -removed

        // Boinc Block field format validation

        if (bb.cpid != "INVESTOR" && bb.cpid.length()!=32)
            return error("CheckBlock: Invalid CPID format '%s'\n",bb.cpid.c_str());

        if( bb.cpid=="INVESTOR" && bb.ResearchSubsidy > 0)
            return error("Investor has non-zero research reward");

        if (HasStake)
        {
            //Mint limiter checks 1-20-2015
            //1-21-2015 - Prevent Hackers from spamming the network with small blocks
            double total_subsidy = bb.ResearchSubsidy + bb.InterestSubsidy;
            double limiter = MintLimiter(blockdiff,bb.RSAWeight,bb.cpid,GetBlockTime());
            if (total_subsidy < limiter)
                return error("CheckBlock: Total Mint too Small %f < %f Research %f Interest %f",
                        total_subsidy,limiter,bb.ResearchSubsidy,bb.InterestSubsidy);
        }
    }

    if (HasStake)
    {
        if (IsProofOfStake() && !CheckBlockSignature())
            return DoS(100, error("CheckBlock: bad proof-of-stake block signature"));

        // Coinbase output should be empty if proof-of-stake block
        if (vtx[0].vout.size() != 1 || !vtx[0].vout[0].IsEmpty())
            return DoS(100, error("CheckBlock: coinbase output not empty for proof-of-stake block"));

    }
    else if (IsProofOfWork())
    {
        // Check proof of work matches claimed amount
        if(!CheckProofOfWork(GetPoWHash(), nBits))
            return DoS(50, error("CheckBlock: proof of work failed"));
    }
    else return DoS(50, error("CheckBlock: has no proof"));

    // Check merkle root
    if (hashMerkleRoot != BuildMerkleTree())
        return DoS(100, error("CheckBlock[] : hashMerkleRoot mismatch"));

    //if (fDebug3) printf(".EOCB.");
    return true;
}

bool CBlock::AcceptBlock(CBlockIndex** out_pinex,bool generated_by_me, CBlockIndex* pindexPrev)
{
    if(out_pinex) *out_pinex = NULL; //safe return
    AssertLockHeld(cs_main); //WTF?

    if (nVersion > CURRENT_VERSION)
        return DoS(100, error("AcceptBlock() : reject unknown block version %d", nVersion));

    // Check for duplicate
    uint256 hash = GetHash();
    CBlockIndex* pindex_tmp = CBlockIndex::GetByHash(hash);
    if(pindex_tmp)
        return error("AcceptBlock() : block already in mapBlockIndex");

    int nHeight = pindexPrev? pindexPrev->nHeight+1 : 1;
    assert(nGrandfather>0);

    if(       (IsProtocolV2(nHeight) && nVersion < 7)
            //||(fTestNet && nHeight > 272280 && nVersion < 8)
        )
        return DoS(100, error("AcceptBlock() : reject too old nVersion = %d", nVersion));
    else if( (!IsProtocolV2(nHeight) && nVersion >= 7)
            ||(!fTestNet && nVersion >=8 )
            ||(fTestNet && nVersion >=8 )
            ||(fTestNet && nHeight < 272270 && nVersion >= 8)
        )
        return DoS(100, error("AcceptBlock() : reject too new nVersion = %d", nVersion));

    if (IsProofOfWork() && nHeight > LAST_POW_BLOCK)
        return DoS(100, error("AcceptBlock() : reject proof-of-work at height %d", nHeight));

    if (nHeight > nGrandfather)
    {
            // Check coinbase timestamp
            if (GetBlockTime() > FutureDrift((int64_t)vtx[0].nTime, nHeight))
                return DoS(80, error("AcceptBlock() : coinbase timestamp is too early"));

            // Check timestamp against prev
            if (GetBlockTime() <= pindexPrev->GetPastTimeLimit() || FutureDrift(GetBlockTime(), nHeight) < pindexPrev->GetBlockTime())
                return DoS(60, error("AcceptBlock() : block's timestamp is too early"));

            // Check proof-of-work or proof-of-stake
            if (nBits != GetNextTargetRequired(pindexPrev, IsProofOfStake()))
                return DoS(100, error("AcceptBlock() : incorrect %s", IsProofOfWork() ? "proof-of-work" : "proof-of-stake"));
    }

    // Check that all transactions are finalized
    BOOST_FOREACH(const CTransaction& tx, vtx)
        if (!IsFinalTx(tx, nHeight, GetBlockTime()))
            return DoS(10, error("AcceptBlock() : contains a non-final transaction"));

    // Check that the block chain matches the known block chain up to a checkpoint
    if (!Checkpoints::CheckHardened(nHeight, hash))
        return DoS(100, error("AcceptBlock() : rejected by hardened checkpoint lock-in at %d", nHeight));

    //Grandfather
    if (nHeight > nGrandfather)
    {
         bool cpSatisfies = Checkpoints::CheckSync(hash, pindexPrev);
         // Check that the block satisfies synchronized checkpoint
         if (CheckpointsMode == Checkpoints::STRICT && !cpSatisfies)
         {
            if (CHECKPOINT_DISTRIBUTED_MODE==1)
            {
                CHECKPOINT_VIOLATIONS++;
                if (CHECKPOINT_VIOLATIONS > 3)
                {
                    //For stability, move the client into ADVISORY MODE:
                    printf("Moving Gridcoin into Checkpoint ADVISORY mode.\r\n");
                    CheckpointsMode = Checkpoints::ADVISORY;
                }
            }
            return error("AcceptBlock() : rejected by synchronized checkpoint");
         }

        if (CheckpointsMode == Checkpoints::ADVISORY && !cpSatisfies)
            strMiscWarning = _("WARNING: synchronized checkpoint violation detected, but skipped!");

        if (CheckpointsMode == Checkpoints::ADVISORY && cpSatisfies && CHECKPOINT_DISTRIBUTED_MODE==1)
        {
            ///Move the client back into STRICT mode
            CHECKPOINT_VIOLATIONS = 0;
            printf("Moving Gridcoin into Checkpoint STRICT mode.\r\n");
            strMiscWarning = "";
            CheckpointsMode = Checkpoints::STRICT;
        }

        // Enforce rule that the coinbase starts with serialized block height
        CScript expect = CScript() << nHeight;
        if (vtx[0].vin[0].scriptSig.size() < expect.size() ||
            !std::equal(expect.begin(), expect.end(), vtx[0].vin[0].scriptSig.begin()))
            return DoS(100, error("AcceptBlock() : block height mismatch in coinbase"));
    }

    // Write block to history file
    if (!CheckDiskSpace(::GetSerializeSize(*this, SER_DISK, CLIENT_VERSION)))
        return error("AcceptBlock() : out of disk space");
    unsigned int nFile = -1;
    unsigned int nBlockPos = 0;
    if (!WriteToDisk(nFile, nBlockPos))
        return error("AcceptBlock() : WriteToDisk failed");

    // Add to Block Index
    CBlockIndex *pindexNew;
    CTxDB txdb ("r+");
    if (!(pindexNew=AddToBlockIndex(txdb, nFile, nBlockPos)))
        return error("AcceptBlock() : AddToBlockIndex failed");

    // Attempt to set as Best Chain
    {
        LOCK(cs_main);
        if (  (pindexNew->nChainTrust > Best.top->nChainTrust)
            &&(!pindexNew->DetectedInvalid))
            if (!SetBestChain(txdb, pindexNew))
                return error("AcceptBlock: SetBestChain Failed");
    }

    // Relay inventory
    // but don't relay old inventory during initial block download
    int nBlockEstimate = Checkpoints::GetTotalBlocksEstimate();
    LOCK(cs_vNodes);
    BOOST_FOREACH(CNode* pnode, vNodes)
        if (Best.GetHeight() > (pnode->nStartingHeight != -1 ? pnode->nStartingHeight - 2000 : nBlockEstimate))
            pnode->PushInventory(CInv(MSG_BLOCK, hash));

    {
        LOCK(cs_main);
        // Notify UI to display prev block's coinbase if it was ours
        if (pindexNew == Best.top)
        {
            assert(Best.top->GetBlockHash() == hash);
            // TODO: move block changed and interface somewhere sensible
            static uint256 hashPrevBestCoinBase;
            UpdatedTransaction(hashPrevBestCoinBase);
            hashPrevBestCoinBase = vtx[0].GetHash();
        }
        uiInterface.NotifyBlocksChanged();

        // ppcoin: Check pending sync-checkpoint
        Checkpoints::AcceptPendingSyncCheckpoint();
        if (fDebug) printf("{ACC}");
        nLastAskedForBlocks=GetAdjustedTime();
        ResetTimerMain("OrphanBarrage");
        if(out_pinex) *out_pinex = pindexNew;
    }
    return true;
}

/* Reorganize and SetBestChain:
    AcceptBlock will call SBC if that block is better than current
    SBC will just connect the block if it can
        otherwise, blocks up to a fork are disconnected
        and connects blocks on new branch
        if connect fails, the block will be marked as failed
        and the reorg will stop on the prev block.
*/

bool FindForkRoot(CBlockIndex *pnew, CBlockIndex*& cur, std::vector<CBlockIndex*>& vToConnect)
{
    //scan back new chain until we find with next!=0
    for(cur = pnew; cur; cur=cur->GetPrev())
    {
        if(cur->HasNext())
            return true;
        // blocks that are not on the main chain go to list
        vToConnect.push_back(cur);
    }
    return false;
}

bool CBlock::DisconnectBlock(CTxDB& txdb, CBlockIndex* pindex, std::set<CTxMessage*> vContractsToReload)
{

    // Disconnect in reverse order
    bool bDiscTxFailed = false;
    for (int i = vtx.size()-1; i >= 0; i--)
    {
        if (!vtx[i].DisconnectInputs(txdb))
        {
            return error("DisconnectBlock: DisconnectInputs() Failed");
        }
        //Disconnect Contract
        {
            const uint256 txhash = vtx[i].GetHash();
            auto ppmsg = Best.MsgByTx.find(txhash);
            if(ppmsg!=Best.MsgByTx.end())
            {
                CTxMessage & msg = *ppmsg->second;
                //update the message struct
                assert(!msg.vTxHash.empty());
                assert(msg.vTxHash.back() == txhash);
                Best.MsgByTx.erase(Msg.vTxHash.back());
                msg.vTxHash.pop_back();
                if(!msg.vTxHash.empty())
                    Best.MsgByTx[msg.vTxHash.back()] = &msg;
                vContractsToReload.insert(&msg);
            }
        }
    }

    // Update block index on disk without changing it in memory.
    // The memory index structure will be changed after the db commits.
    // TODO verify if above is true
    if (pindex->GetPrev())
    {
        CBlockIndex *blockindexPrev=pindex->GetPrev();
        blockindexPrev->hashNext = 0;
        if (!txdb.WriteBlockIndex(*blockindexPrev))
            return error("DisconnectBlock() : WriteBlockIndex failed");
    }

    SlidingWindowSlide(txdb, pindex, -1);

    // ppcoin: clean up wallet after disconnecting coinstake
    BOOST_FOREACH(CTransaction& tx, vtx)
        SyncWithWallets(tx, this, false, false);

    // We normally fail to disconnect a block if we can't find the previous input due to "DisconnectInputs() : ReadTxIndex failed".  Imo, I believe we should let this call succeed, otherwise a chain can never be re-organized in this circumstance.
    /* TODO
    if (bDiscTxFailed && fDebug3) printf("!DisconnectBlock()::Failed, recovering. ");
    */
    return true;
}

bool BranchDisconnect(CTxDB& batch, CBlockIndex *proot)
{
    std::set<CTxMessage*> vContractsToReload;
    for(CBlockIndex *cur= Best.top;
        cur && cur!=proot;
        cur=cur->GetPrev())
    {
        CBlock curblk;
        if(!curblk.ReadFromDisk(cur))
            return error("BranchDisconnect: ReadFromDisk failed");
        if(!curblk.DisconnectBlock(batch, cur, vContractsToReload))
            return error("BranchDisconnect: DisconnectBlock failed");
    }

    ReloadContracts(batch, vContractsToReload);
    return true;
}

bool ForceReorganizeToHash(uint256 NewHash)
{
    CTxDB txdb;


    CBlockIndex* pindexCur = Best.top;
    CBlockIndex* pindexNew = CBlockIndex::GetByHash(NewHash);
    if(!pindexNew)
        return error("ForceReorganizeToHash: failed to find requested block in block index");
    printf("\r\n** Force Reorganize **\r\n");
    printf(" Current best height %f hash %s\n",(double)pindexCur->nHeight,pindexCur->GetBlockHash().GetHex().c_str());
    printf(" Target height %f hash %s\n",(double)pindexNew->nHeight,pindexNew->GetBlockHash().GetHex().c_str());

    CBlock blockNew;
    if (!blockNew.ReadFromDisk(pindexNew))
    {
        printf("ForceReorganizeToHash: Fatal Error while reading new best block.\r\n");
        return false;
    }

    //Re-process the last block to trigger orphan and shit
    if (!blockNew.SetBestChain(txdb, pindexNew))
    {
        return error("ForceReorganizeToHash Fatal Error while setting best chain.\r\n");
    }

    AskForOutstandingBlocks(uint256(0));
    printf("ForceReorganizeToHash: success! height %f hash %s\n\n",(double)Best.GetHeight(),Best.top->GetBlockHash().GetHex().c_str());
    return true;
}



void SetAdvisory()
{
    CheckpointsMode = Checkpoints::ADVISORY;

}

bool InAdvisory()
{
    return (CheckpointsMode == Checkpoints::ADVISORY);
}

bool CBlock::SetBestChain(CTxDB& txdb, CBlockIndex* pindexNew)
{

    if(pindexGenesisBlock==NULL || Best.top == NULL)
    {
        if(hashPrevBlock!=0)
            return error("SetBestChain() : No best block in index");
        /*
        if (hash != (!fTestNet ? hashGenesisBlock : hashGenesisBlockTestNet))
            return error("SetBestChain() : Genesis block hash mis match");
        */
        // special case for genesis
        if (!txdb.TxnBegin())
            return error("SetBestChain() : TxnBegin failed");
        Best.top = pindexNew;
        Best.p6m= Best.p14d= Best.p10b= Best.ppSuper = pindexNew;
        pindexGenesisBlock = pindexNew;
        Best.SaveDb(txdb);
        if (!txdb.TxnCommit())
            return error("SetBestChain() : TxnCommit failed");
    }
    else if (hashPrevBlock == Best.top->GetBlockHash())
    {
        // simple connect
        // Adding to current best branch
        if (!ConnectBlock(txdb, pindexNew, false, false))
        {
            txdb.TxnAbort();
            InvalidChainFound(txdb,pindexNew);
            return error("SetBestChain() : ConnectBlock failed");
        }
    }
    else
    {
        if (!txdb.TxnBegin())
            return error("SetBestChain() : TxnBegin failed");
        // Info
        printf("SetBestChain: Attempting to Reorganize\n  Cur:  {%s %d}\n  New:  {%s %d}\n",
            Best.top->GetBlockHash().GetHex().c_str(),   Best.top->nHeight,
            pindexNew->GetBlockHash().GetHex().c_str(), pindexNew->nHeight);
        // Find branch root
        CBlockIndex* proot= NULL;
        std::vector<CBlockIndex*> vToConnect;
        if( !FindForkRoot(pindexNew,proot,vToConnect) )
            return error("SetBestChain: failed to find fork root");
        // Info
        printf("SetBestChain: will Disconnect %d, Connect %lu blocks\n  Root: {%s %d}\n",
            Best.top->nHeight - proot->nHeight, vToConnect.size(),
            proot->GetBlockHash().GetHex().c_str(), proot->nHeight);
        // Disconnect blocks +commnit
        if(!BranchDisconnect(txdb,proot) || !txdb.TxnCommit())
            throw error("SetBestChain: failed disconnect branch");
            // ^ this means that sliding window is corrupted now!
        // connect blocks one by one and commit each
        printf("SetBestChain: will connect %lu blocks\n",vToConnect.size());
        pindexNew=proot;
        BOOST_FOREACH(CBlockIndex* pcur, vToConnect)
        {
            CBlock block;
            if (!block.ReadFromDisk(pcur))
                return error("SetBestChain.Reorganize: ReadFromDisk for connect failed");
            if (!block.ConnectBlock(txdb, pcur, false, true))
            {
                txdb.TxnAbort();
                InvalidChainFound(txdb,pindexNew);
                error("SetBestChain.Reorganize: ConnectBlock %d (%d.) failed, but continuing",
                    pcur->nHeight,pcur->nHeight-proot->nHeight);
                break;
            }
            pindexNew=pcur;
        }
    }

    // New best block
    blockFinder.Reset();

    std::string strCmd = GetArg("-blocknotify", "");

    bool fIsInitialDownload = IsInitialBlockDownload();
    if (!fIsInitialDownload && !strCmd.empty())
    {
        boost::replace_all(strCmd, "%s", Best.top->GetBlockHash().GetHex());
        boost::thread t(runCommand, strCmd); // thread runs free
    }

    return true;
}

// ppcoin: total coin age spent in transaction, in the unit of coin-days.
// Only those coins meeting minimum age requirement counts. As those
// transactions not in main chain are not currently indexed so we
// might not find out about their coin age. Older transactions are
// guaranteed to be in main chain by sync-checkpoint. This rule is
// introduced to help nodes establish a consistent view of the coin
// age (trust score) of competing branches.
bool CTransaction::GetCoinAge(CTxDB& txdb, uint64_t& nCoinAge) const
{
    CBigNum bnCentSecond = 0;  // coin age in the unit of cent-seconds
    nCoinAge = 0;

    if (IsCoinBase())
        return true;

    BOOST_FOREACH(const CTxIn& txin, vin)
    {
        // First try finding the previous transaction in database
        CTransaction txPrev;
        CTxIndex txindex;
        if (!txPrev.ReadFromDisk(txdb, txin.prevout, txindex))
            continue;  // previous transaction not in main chain
        if (nTime < txPrev.nTime)
            return false;  // Transaction timestamp violation

        // Read block header
        CBlock block;
        if (!block.ReadFromDisk(txindex.pos.nFile, txindex.pos.nBlockPos, false))
            return false; // unable to read block of previous transaction
        if (block.GetBlockTime() + nStakeMinAge > nTime)
            continue; // only count coins meeting min age requirement

        int64_t nValueIn = txPrev.vout[txin.prevout.n].nValue;
        bnCentSecond += CBigNum(nValueIn) * (nTime-txPrev.nTime) / CENT;

        if (fDebug && GetBoolArg("-printcoinage"))
            printf("coin age nValueIn=%" PRId64 " nTimeDiff=%d bnCentSecond=%s\n", nValueIn, nTime - txPrev.nTime, bnCentSecond.ToString().c_str());
    }

    CBigNum bnCoinDay = bnCentSecond * CENT / COIN / (24 * 60 * 60);
    if (fDebug && GetBoolArg("-printcoinage"))
        printf("coin age bnCoinDay=%s\n", bnCoinDay.ToString().c_str());
    nCoinAge = bnCoinDay.getuint64();
    return true;
}

// ppcoin: total coin age spent in block, in the unit of coin-days.
bool CBlock::GetCoinAge(uint64_t& nCoinAge) const
{
    nCoinAge = 0;

    CTxDB txdb("r");
    BOOST_FOREACH(const CTransaction& tx, vtx)
    {
        uint64_t nTxCoinAge;
        if (tx.GetCoinAge(txdb, nTxCoinAge))
            nCoinAge += nTxCoinAge;
        else
            return false;
    }

    if (nCoinAge == 0) // block coin age minimum 1 coin-day
        nCoinAge = 1;
    if (fDebug && GetBoolArg("-printcoinage"))
        printf("block coin age total nCoinDays=%" PRId64 "\n", nCoinAge);
    return true;
}

CBlockIndex* CBlock::AddToBlockIndex(CTxDB &txdb, unsigned int nFile, unsigned int nBlockPos)
{
    // Check for duplicate
    uint256 hash = GetHash();
    if(CBlockIndex::GetByHash(hash))
    {
        error("AddToBlockIndex() : %s already exists", hash.ToString().substr(0,20).c_str());
        return NULL;
    }

    // Construct new block index object
    CBlockIndex* pindexNew = new CBlockIndex(nFile, nBlockPos, *this);
    if (!pindexNew)
    {
        error("AddToBlockIndex() : new CBlockIndex failed");
        return NULL;
    }
    pindexNew->phashBlock = &hash;
    CBlockIndex* pprev = CBlockIndex::GetByHash(hashPrevBlock);
    if (pprev)
    {
        pindexNew->SetPrev(pprev);
        // ppcoin: compute chain trust score
        pindexNew->nHeight = pprev->nHeight + 1;
        pindexNew->nChainTrust = pprev->nChainTrust + pindexNew->GetBlockTrust();
        pindexNew->DetectedInvalid |= pprev->DetectedInvalid;
    } else {
        pindexNew->nHeight = 1;
        pindexNew->nChainTrust = pindexNew->GetBlockTrust();
    }

    // ppcoin: compute stake entropy bit for stake modifier
    // from block header hash
    pindexNew->StakeEntropy= GetStakeEntropyBit();

    // Proof hash value and Stake modifier moved to ConnectBlock (Brod)
    
    // Add to mapBlockIndex
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.insert(make_pair(hash, pindexNew)).first;
    pindexNew->phashBlock = &((*mi).first);

    if (pindexNew->IsProofOfStake) //TODO
        setStakeSeen.insert(make_pair(pindexNew->prevoutStake, pindexNew->nStakeTime));

    // We only adding to block index, no need to commit and hurr

    // Write to disk block index
    if(!txdb.WriteBlockIndex(*pindexNew))
    {
        error("AddToBlockIndex DB write failed");
        delete pindexNew;
        return NULL;
    }

    return pindexNew;
}


uint256 CBlockIndex::GetBlockTrust() const
{
    CBigNum bnTarget;
    bnTarget.SetCompact(nBits);
    if (bnTarget <= 0) return 0;
    int64_t block_mag = 0;
    uint256 chaintrust = (((CBigNum(1)<<256) / (bnTarget+1)) - (block_mag)).getuint256();
    return chaintrust;
}

bool CBlockIndex::IsSuperMajority(int minVersion, CBlockIndex* pstart, unsigned int nRequired, unsigned int nToCheck)
{
    unsigned int nFound = 0;
    for (unsigned int i = 0; i < nToCheck && nFound < nRequired && pstart != NULL; i++)
    {
        if (pstart->nVersion >= minVersion)
            ++nFound;
        pstart = pstart->GetPrev();
    }
    return (nFound >= nRequired);
}

template<typename Stream>
void CBlockIndex::Serialize(Stream& s, int nType, int nVersion) const
{
    CSerActionSerialize ser_action;
    unsigned int nSerSize = 0;
    //hash prev and next should be set already
    int nFlags= 0;
    if(IsProofOfStake) nFlags|= BLOCK_PROOF_OF_STAKE;
    if(StakeEntropy)   nFlags|= BLOCK_STAKE_ENTROPY;
    if(GeneratedStakeModifier) nFlags|= BLOCK_STAKE_MODIFIER;
    if(HasCPID)        nFlags|= BLOCK_HAS_CPID;
    if(IsSuperBlock)   nFlags|= BLOCK_SUPER;
    if(IsContract)     nFlags|= BLOCK_CONTRACT;
    if(DetectedInvalid)     nFlags|= BLOCK_INVALID;
    if (!(nType & SER_GETHASH))
        READWRITE(nVersion);
    READWRITE(hashNext);
    READWRITE(nFile);
    READWRITE(nBlockPos);
    READWRITE(nHeight);
    READWRITE(nMint);
    READWRITE(nMoneySupply);
    READWRITE(nFlags);
    READWRITE(nStakeModifier);
    if (IsProofOfStake)
    {
        READWRITE(prevoutStake);
        READWRITE(nStakeTime);
    }
    READWRITE(hashProof);
    READWRITE(this->nVersion);
    READWRITE(hashPrev);
    READWRITE(hashMerkleRoot);
    READWRITE(nTime);
    READWRITE(nBits);
    READWRITE(nNonce);
    READWRITE(cpid);
    READWRITE(nResearchSubsidy);
    READWRITE(nInterestSubsidy);
    READWRITE(nMagnitude);
}

template<typename Stream>
void CBlockIndex::Unserialize(Stream& s, int nType, int nVersion)
{
    CSerActionUnserialize ser_action;
    unsigned int nSerSize = 0;
    int nFlags;
    if (!(nType & SER_GETHASH))
        READWRITE(nVersion);
    READWRITE(hashNext);
    READWRITE(nFile);
    READWRITE(nBlockPos);
    READWRITE(nHeight);
    READWRITE(nMint);
    READWRITE(nMoneySupply);
    READWRITE(nFlags);
    IsProofOfStake = !!(nFlags & BLOCK_PROOF_OF_STAKE);
    StakeEntropy   = !!(nFlags & BLOCK_STAKE_ENTROPY);
    GeneratedStakeModifier = !!(nFlags & BLOCK_STAKE_MODIFIER);
    HasCPID        = !!(nFlags & BLOCK_HAS_CPID);
    IsSuperBlock   = !!(nFlags & BLOCK_SUPER);
    IsContract     = !!(nFlags & BLOCK_CONTRACT);
    DetectedInvalid= !!(nFlags & BLOCK_INVALID);
    READWRITE(nStakeModifier);
    if (IsProofOfStake)
    {
        READWRITE(prevoutStake);
        READWRITE(nStakeTime);
    }
    else
    {
        prevoutStake.SetNull();
        nStakeTime = 0;
    }
    READWRITE(hashProof);
    READWRITE(this->nVersion);
    READWRITE(hashPrev);
    READWRITE(hashMerkleRoot);
    READWRITE(nTime);
    READWRITE(nBits);
    READWRITE(nNonce);
    READWRITE(cpid);
    READWRITE(nResearchSubsidy);
    READWRITE(nInterestSubsidy);
    READWRITE(nMagnitude);
}

void Serialize(CDataStream& os, std::deque <CBlockIndex*>& v)
{
    WriteCompactSize(os, v.size());
    for (auto vi = v.begin(); vi != v.end(); ++vi)
    {
        uint256 hash = (*vi)? (**vi).GetBlockHash() : 0;
        os<<hash;
    }
}

void ReadBlockListAutoload(CDataStream& os, std::deque <CBlockIndex*>& v)
{
    v.clear();
    uint64_t size= ReadCompactSize(os);
    //v.reserve(size);
    while(--size)
    {
        uint256 hash;
        os>>hash;
        CBlockIndex* i= CBlockIndex::GetByHash(hash);
        v.push_back(i);
    }
}


void CBestChain::LoadDb(CTxDB& batch)
{
    std::string strValue;
    if(!batch.Read(std::string("BestChain"),strValue))
        return; //does not exist yet. use zero
    CDataStream s(strValue.data(), strValue.data() + strValue.size(),
                        SER_DISK, CLIENT_VERSION);

    uint256 bh;
    s>>bh; top=CBlockIndex::GetByHash(bh);
    s>>bh; p10b=CBlockIndex::GetByHash(bh);
    s>>bh; p14d=CBlockIndex::GetByHash(bh);
    s>>bh; p6m=CBlockIndex::GetByHash(bh);
    s>>sum.Research;
    s>>sum.Interest;
    s>>sum.CpidCount;
    s>>sum.blocks;

    ReadBlockListAutoload(s,super.vpBlocks);
}

void CBestChain::SaveDb(CTxDB& batch)
{
    CDataStream s(SER_DISK, CLIENT_VERSION);
    s<< (top? top->GetBlockHash() : 0);
    s<< (p10b? p10b->GetBlockHash() : 0);
    s<< (p14d? p14d->GetBlockHash() : 0);
    s<< (p6m? p6m->GetBlockHash() : 0);
    s<<sum.Research;
    s<<sum.Interest;
    s<<sum.CpidCount;
    s<<sum.blocks;
    Serialize(s,super.vpBlocks);
    if(!batch.Write(std::string("BestChain"),s.str()))
        throw error("Failed to save Chain State");
}

void CBestChain::LoadDbBeacons(CTxDB& batch)
{
    throw 1337;
}
void CBestChain::LoadDbCpids(CTxDB& batch)
{
    throw 1337;
}

/*
bool static ReserealizeBlockSignature(CBlock* pblock)
{
    if (pblock->IsProofOfWork()) {
        pblock->vchBlockSig.clear();
        return true;
    }

    return CKey::ReserealizeSignature(pblock->vchBlockSig);
}
*/


bool ServicesIncludesNN(CNode* pNode)
{
    return (Contains(pNode->strSubVer,"1999")) ? true : false;
}

bool VerifySuperblock(std::string superblock, int nHeight)
{
        bool bPassed = false;
        double out_avg = 0;
        double out_beacon_count=0;
        double out_participant_count=0;
        double avg_mag = 0;
        if (superblock.length() > 20)
        {
            avg_mag = GetSuperblockAvgMag(superblock,out_beacon_count,out_participant_count,out_avg,false,nHeight);
            bPassed=true;
            if (!IsResearchAgeEnabled(nHeight))
            {
                return (avg_mag < 10 ? false : true);
            }
            // New rules added here:
            if (out_avg < 10 && fTestNet)  bPassed = false;
            if (out_avg < 70 && !fTestNet) bPassed = false;
            if (avg_mag < 10 && !fTestNet) bPassed = false;
			// Verify distinct project count matches whitelist
        }
        if (fDebug3 && !bPassed)
        {
            if (fDebug) printf(" Verification of Superblock Failed ");
            //if (fDebug3) printf("\r\n Verification of Superblock Failed outavg: %f, avg_mag %f, Height %f, Out_Beacon_count %f, Out_participant_count %f, block %s", (double)out_avg,(double)avg_mag,(double)nHeight,(double)out_beacon_count,(double)out_participant_count,superblock.c_str());
        }
        return bPassed;
}

bool NeedASuperblock()
{
        bool bDireNeedOfSuperblock = false;
        std::string superblock = ReadCache("superblock","all");
        if (superblock.length() > 20 && !OutOfSyncByAge())
        {
            if (!VerifySuperblock(superblock,Best.GetHeight())) bDireNeedOfSuperblock = true;
			/*
			// Check project count in last superblock
			double out_project_count = 0;
			double out_whitelist_count = 0;
			GetSuperblockProjectCount(superblock, out_project_count, out_whitelist_count);
			*/
        }
        int64_t superblock_age = GetAdjustedTime() - mvApplicationCacheTimestamp["superblock;magnitudes"];
        if ((double)superblock_age > (double)(GetSuperblockAgeSpacing(Best.GetHeight()))) bDireNeedOfSuperblock = true;
        return bDireNeedOfSuperblock;
}




void GridcoinServices()
{

    //Dont do this on headless - SeP
    #if defined(QT_GUI)
       if ((Best.GetHeight() % 125) == 0)
       {
            GetGlobalStatus();
            bForceUpdate=true;
            uiInterface.NotifyBlocksChanged();
       }
    #endif
    // Services thread activity
    
    //This is Gridcoins Service thread; called once per block
    if (Best.GetHeight() > 100 && Best.GetHeight() < 200) //TODO
    {
        if (GetArg("-suppressdownloadblocks", "true") == "false")
        {
            std::string email = GetArgument("email", "NA");
            if (email.length() > 5 && !mbBlocksDownloaded)
            {
                #if defined(WIN32) && defined(QT_GUI)
                    mbBlocksDownloaded=true;
                    DownloadBlocks();
                #endif
            }
        }
    }
    //Dont perform the following functions if out of sync
    if (Best.GetHeight() < nGrandfather) return;
    
    if (OutOfSyncByAge()) return;
    if (fDebug) printf(" {SVC} ");

    //Backup the wallet once per 900 blocks:
    double dWBI = cdbl(GetArgument("walletbackupinterval", "900"),0);
    
    if (TimerMain("backupwallet", dWBI))
    {
        std::string backup_results = BackupGridcoinWallet();
        printf("Daily backup results: %s\r\n",backup_results.c_str());
    }

    if (TimerMain("ResetVars",30))
    {
        //bTallyStarted = false;
    }
    
    if (TimerMain("OutOfSyncDaily",900))
    {
        if (WalletOutOfSync())
        {
            printf("Restarting Gridcoin...");
            #if defined(WIN32) && defined(QT_GUI)
                int iResult = RestartClient();
            #endif
        }
    }

    if (false && TimerMain("FixSpentCoins",60))
    {
            int nMismatchSpent;
            int64_t nBalanceInQuestion;
            pwalletMain->FixSpentCoins(nMismatchSpent, nBalanceInQuestion);
    }

    if (TimerMain("MyNeuralMagnitudeReport",30))
    {
        try
        {
            if (msNeuralResponse.length() < 25 && msPrimaryCPID != "INVESTOR" && !msPrimaryCPID.empty())
            {
                AsyncNeuralRequest("explainmag",msPrimaryCPID,5);
                if (fDebug3) printf("Async explainmag sent for %s.",msPrimaryCPID.c_str());
            }
            // Run the RSA report for the overview page:
            if (!msPrimaryCPID.empty() && msPrimaryCPID != "INVESTOR")
            {
                if (fDebug3) printf("updating rsa\r\n");
                MagnitudeReport(msPrimaryCPID);
                if (fDebug3) printf("updated rsa\r\n");
            }
            if (fDebug3) printf("\r\n MR Complete \r\n");
        }
        catch (std::exception &e)
        {
            printf("Error in MyNeuralMagnitudeReport1.");
        }
        catch(...)
        {
            printf("Error in MyNeuralMagnitudeReport.");
        }
    }

    int64_t superblock_age = GetAdjustedTime() - mvApplicationCacheTimestamp["superblock;magnitudes"];
    bool bNeedSuperblock = ((double)superblock_age > (double)(GetSuperblockAgeSpacing(Best.GetHeight())));
    if ( Best.GetHeight() % 3 == 0 && NeedASuperblock() ) bNeedSuperblock=true;

    if (fDebug10) 
    {
            printf (" MRSA %f, BH %f ",(double)superblock_age,(double)Best.GetHeight());
    }

    if (bNeedSuperblock)
    {
        if ((Best.GetHeight() % 3) == 0)
        {
            if (fDebug10) printf("#CNNSH# ");
            ComputeNeuralNetworkSupermajorityHashes();
            UpdateNeuralNetworkQuorumData();
        }
        if ((Best.GetHeight() % 20) == 0)
        {
            if (fDebug10) printf("#TIB# ");
            bDoTally = true;
        }
    }
    else
    {
        // When superblock is not old, Tally every N mins:
        int nTallyGranularity = fTestNet ? 60 : 20;
        if ((Best.GetHeight() % nTallyGranularity) == 0)
        {
                if (fDebug3) printf("TIB1 ");
                bDoTally = true;
                if (fDebug3) printf("CNNSH2 ");
                ComputeNeuralNetworkSupermajorityHashes();
        }

        if ((Best.GetHeight() % 5)==0)
        {
                UpdateNeuralNetworkQuorumData();
        }

    }

    // Keep Local Neural Network in Sync once every 1/2 day
    if (TimerMain("SyncNeuralNetwork",500))
    {
        FullSyncWithDPORNodes();
    }


    // Every N blocks as a Synchronized TEAM:
    if ((Best.GetHeight() % 30) == 0)
    {
        //Sync RAC with neural network IF superblock is over 24 hours Old, Or if we have No superblock (in case of the latter, age will be 45 years old)
        // Note that nodes will NOT accept superblocks without a supermajority hash, so the last block will not be in memory unless it is a good superblock.
        // Let's start syncing the neural network as soon as the LAST superblock is over 12 hours old.
        // Also, lets do this as a TEAM exactly every 30 blocks (~30 minutes) to try to reach an EXACT consensus every half hour:
        // For effeciency, the network sleeps for 20 hours after a good superblock is accepted
        if (NeedASuperblock() && IsNeuralNodeParticipant(DefaultWalletAddress(), GetAdjustedTime()))
        {
            if (fDebug3) printf("FSWDPOR ");
            FullSyncWithDPORNodes();
        }
    }

    if (( (Best.GetHeight()-10) % 30 ) == 0)
    {
            // 10 Blocks after the network started syncing the neural network as a team, ask the neural network to come to a quorum
            if (NeedASuperblock() && IsNeuralNodeParticipant(DefaultWalletAddress(), GetAdjustedTime()))
            {
                // First verify my node has a synced contract
                std::string contract = "";
                #if defined(WIN32) && defined(QT_GUI)
                    contract = qtGetNeuralContract("");
                #endif
                if (VerifySuperblock(contract,Best.GetHeight()))
                {
                        AsyncNeuralRequest("quorum","gridcoin",25);
                }
            }
    }


    if (TimerMain("send_beacon",180))
    {
        std::string sOutPubKey = "";
        std::string sOutPrivKey = "";
        std::string sError = "";
        std::string sMessage = "";
        bool fResult = AdvertiseBeacon(true,sOutPrivKey,sOutPubKey,sError,sMessage);
        if (!fResult)
        {
            printf("BEACON ERROR!  Unable to send beacon %s \r\n",sError.c_str());
            printf("BEACON ERROR!  Unable to send beacon %s \r\n",sMessage.c_str());
            msMiningErrors6 = _("Unable To Send Beacon! Unlock Wallet!");
        }
    }

    if (false && TimerMain("GridcoinPersistedDataSystem",5))
    {
        std::string errors1 = "";
        LoadAdminMessages(false,errors1);
    }

    if (GetBoolArg("-exportmagnitude", false))
    {
        if (TimerMain("export_magnitude",900))
        {
            json_spirit::Array results;
            results = MagnitudeReportCSV(true);

        }
    }

    if (TimerMain("gather_cpids",480))
    {
            //if (fDebug10) printf("\r\nReharvesting cpids in background thread...\r\n");
            //LoadCPIDsInBackground();
            //printf(" {CPIDs Re-Loaded} ");
            msNeuralResponse="";
    }

    if (TimerMain("clearcache",1000))
    {
        ClearCache("neural_data");
    }

    if (TimerMain("check_for_autoupgrade",240))
    {
        if (fDebug3) printf("Checking for upgrade...");
        bCheckedForUpgradeLive = true;
    }

    #if defined(WIN32) && defined(QT_GUI)
        if (bCheckedForUpgradeLive && !fTestNet && bProjectsInitialized && bGlobalcomInitialized)
        {
            bCheckedForUpgradeLive=false;
            printf("{Checking for Upgrade} ");
            CheckForUpgrade();
            printf("{Done checking for upgrade} ");
        }
    #endif
    if (fDebug10) printf(" {/SVC} ");

}



bool AskForOutstandingBlocks(uint256 hashStart)
{
    if (IsLockTimeWithinMinutes(nLastAskedForBlocks,2)) return true;
    nLastAskedForBlocks = GetAdjustedTime();
        
    int iAsked = 0;
    LOCK(cs_vNodes);
    BOOST_FOREACH(CNode* pNode, vNodes) 
    {
                pNode->ClearBanned();
                if (!pNode->fClient && !pNode->fOneShot && (pNode->nStartingHeight > (Best.GetHeight() - 144)) && (pNode->nVersion < NOBLKS_VERSION_START || pNode->nVersion >= NOBLKS_VERSION_END) )
                {
                        if (hashStart==uint256(0))
                        {
                            pNode->PushGetBlocks(Best.top, uint256(0), true);
                        }
                        else
                        {
                            CBlockIndex* pblockindex = CBlockIndex::GetByHash(hashStart);
                            if (pblockindex)
                            {
                                pNode->PushGetBlocks(pblockindex, uint256(0), true);
                            }
                            else
                            {
                                return error("Unable to find block index %s",hashStart.ToString().c_str());
                            }
                        }
                        printf(".B.");
                        iAsked++;
                        if (iAsked > 10) break;
                }
    }
    return true;
}





void CheckForLatestBlocks()
{
    if (WalletOutOfSync())
    {
            mapOrphanBlocks.clear();
            setStakeSeen.clear();
            setStakeSeenOrphan.clear();
            AskForOutstandingBlocks(uint256(0));
            printf("\r\n ** Clearing Orphan Blocks... ** \r\n");
    }  
}

void CleanInboundConnections(bool bClearAll)
{
        if (IsLockTimeWithinMinutes(nLastCleaned,10)) return;
        nLastCleaned = GetAdjustedTime();
        LOCK(cs_vNodes);
        BOOST_FOREACH(CNode* pNode, vNodes) 
        {
                pNode->ClearBanned();
                if (pNode->nStartingHeight < (Best.GetHeight()-1000) || bClearAll)
                {
                        pNode->fDisconnect=true;
                }
        }
        printf("\r\n Cleaning inbound connections \r\n");
}


bool WalletOutOfSync()
{
    // Only trigger an out of sync condition if the node has synced near the best block prior to going out of sync.
    bool fOut = OutOfSyncByMoreThan(30);
    double PORDiff = GetDifficulty(GetLastBlockIndex(Best.top, true));
    bool fGhostChain = (!fTestNet && PORDiff < .75);
    int iPeerBlocks = GetNumBlocksOfPeers();
    bool bSyncedCloseToTop = Best.GetHeight() > iPeerBlocks-1000;
    if ((fOut || fGhostChain) && bSyncedCloseToTop) return true;
    return false;
}


bool WalletOutOfSyncByMoreThan2000Blocks()
{
    if (Best.GetHeight() < GetNumBlocksOfPeers()-2000) return true;
    return false;
}



void CheckForFutileSync()
{
    // If we stay out of sync for more than 8 iterations of 25 orphans and never recover without accepting a block - attempt to recover the node- if we recover, reset the counters.
    // We reset these counters every time a block is accepted successfully in AcceptBlock().
    // Note: This code will never actually be exercised unless the wallet stays out of sync for a very long time - approx. 24 hours - the wallet normally recovers on its own without this code.
    // I'm leaving this in for people who may be on vacation for a long time - it may keep an external node running when everything else fails.
    if (WalletOutOfSync())
    {
        if (TimerMain("CheckForFutileSync", 25))
        {
            if (TimerMain("OrphansAndNotRecovering",8))                                 
            {
                printf("\r\nGridcoin has not recovered after clearing orphans; Restarting node...\r\n");
                #if defined(WIN32) && defined(QT_GUI)
                    int iResult = RestartClient();
                #endif
            }
            else
            {
                mapAlreadyAskedFor.clear();
                printf("\r\nClearing mapAlreadyAskedFor.\r\n");
                mapOrphanBlocks.clear(); 
                setStakeSeen.clear();  
                setStakeSeenOrphan.clear();
                AskForOutstandingBlocks(uint256(0));
            }
        }
        else
        {
            ResetTimerMain("OrphansAndNotRecovering");
        }
    }
}

bool ProcessBlock(CNode* pfrom, CBlock* pblock, bool generated_by_me)
{
    AssertLockHeld(cs_main);

    // Check for duplicate
    uint256 hash = pblock->GetHash();
    CBlockIndex* pindex = CBlockIndex::GetByHash(hash);
    if (pindex)
        return error("ProcessBlock() : already have block %d %s", pindex->nHeight, hash.ToString().c_str());
    if (mapOrphanBlocks.count(hash))
        return error("ProcessBlock() : already have block (orphan) %s", hash.ToString().c_str());

    // todo: Move to CheckBlock
    // ppcoin: check proof-of-stake
    // Limited duplicity on stake: prevents block flood attack
    // Duplicate stake allowed only when there is orphan child block
    if (pblock->IsProofOfStake() && setStakeSeen.count(pblock->GetProofOfStake()) && !mapOrphanBlocksByPrev.count(hash) && !Checkpoints::WantedByPendingSyncCheckpoint(hash))
        return error("ProcessBlock() : duplicate proof-of-stake (%s, %d) for block %s", pblock->GetProofOfStake().first.ToString().c_str(),
        pblock->GetProofOfStake().second, 
        hash.ToString().c_str());

    CBlockIndex* pcheckpoint = Checkpoints::GetLastSyncCheckpoint();
    if (pcheckpoint && pblock->hashPrevBlock != Best.top->GetBlockHash() && !Checkpoints::WantedByPendingSyncCheckpoint(hash))
    {
        // Extra checks to prevent "fill up memory by spamming with bogus blocks"
        int64_t deltaTime = pblock->GetBlockTime() - pcheckpoint->nTime;
        if (deltaTime < -10*60)
        {
            if (pfrom)
                pfrom->Misbehaving(1);
            return error("ProcessBlock() : block with timestamp before last checkpoint");
        }


    }

    // Preliminary checks
    if (!pblock->CheckBlock("ProcessBlock", Best.GetHeight()))
        return error("ProcessBlock() : CheckBlock FAILED");

    // ppcoin: ask for pending sync-checkpoint if any
    if (!IsInitialBlockDownload())
        Checkpoints::AskForPendingSyncCheckpoint(pfrom);


    // If don't already have its previous block, shunt it off to holding area until we get it
    CBlockIndex* pindexPrev = CBlockIndex::GetByHash(pblock->hashPrevBlock);
    if (!pindexPrev)
    {
        // *****      This area covers Gridcoin Orphan Handling      ***** 
        if (true)
        {
            if (WalletOutOfSync())
            {
                if (TimerMain("OrphanBarrage",100))
                {
                    mapAlreadyAskedFor.clear();
                    printf("\r\nClearing mapAlreadyAskedFor.\r\n");
                    AskForOutstandingBlocks(uint256(0));
                    CheckForFutileSync();
                }
            }
        }

        CBlock* pblock2 = new CBlock(*pblock);
        if (WalletOutOfSyncByMoreThan2000Blocks() || fTestNet)
        {
            printf("ProcessBlock: ORPHAN BLOCK, prev=%s\n", pblock->hashPrevBlock.ToString().c_str());
            // ppcoin: check proof-of-stake
            if (pblock->IsProofOfStake())
            {
                    // Limited duplicity on stake: prevents block flood attack
                    // Duplicate stake allowed only when there is orphan child block
                    if (setStakeSeenOrphan.count(pblock->GetProofOfStake()) && !mapOrphanBlocksByPrev.count(hash) && !Checkpoints::WantedByPendingSyncCheckpoint(hash))
                            return error("ProcessBlock() : duplicate proof-of-stake (%s, %d) for orphan block %s", pblock->GetProofOfStake().first.ToString().c_str(), pblock->GetProofOfStake().second, hash.ToString().c_str());
                        else
                            setStakeSeenOrphan.insert(pblock->GetProofOfStake());
            }
            mapOrphanBlocks.insert(make_pair(hash, pblock2));
            mapOrphanBlocksByPrev.insert(make_pair(pblock2->hashPrevBlock, pblock2));
        }

        // Ask this guy to fill in what we're missing
        if (pfrom)
        {
            pfrom->PushGetBlocks(Best.top, GetOrphanRoot(pblock2), true);
            // ppcoin: getblocks may not obtain the ancestor block rejected
            // earlier by duplicate-stake check so we ask for it again directly
            if (!IsInitialBlockDownload())
                pfrom->AskFor(CInv(MSG_BLOCK, WantedByOrphan(pblock2)));
            // Ask a few other nodes for the missing block

        }
        return true;
    }

    // Store to disk
    CBlockIndex *pindexNew;
    if (!pblock->AcceptBlock(&pindexNew,generated_by_me,pindexPrev))
        return error("ProcessBlock() : AcceptBlock FAILED");

    // Recursively process any orphan blocks that depended on this one
    vector<uint256> vWorkQueue;
    vWorkQueue.push_back(hash);
    for (unsigned int i = 0; i < vWorkQueue.size(); i++)
    {
        uint256 hashPrev = vWorkQueue[i];
        CBlockIndex* pindexOrphanPrev = CBlockIndex::GetByHash(hash);
        for (multimap<uint256, CBlock*>::iterator mi = mapOrphanBlocksByPrev.lower_bound(hashPrev);
             mi != mapOrphanBlocksByPrev.upper_bound(hashPrev);
             ++mi)
        {
            CBlock* pblockOrphan = (*mi).second;
            assert(pindexNew->GetBlockHash()==pblockOrphan->hashPrevBlock);
            if (pblockOrphan->AcceptBlock(NULL,generated_by_me,pindexOrphanPrev))
                vWorkQueue.push_back(pblockOrphan->GetHash());
            mapOrphanBlocks.erase(pblockOrphan->GetHash());
            setStakeSeenOrphan.erase(pblockOrphan->GetProofOfStake());
            delete pblockOrphan;
        }
        mapOrphanBlocksByPrev.erase(hashPrev);
    }

   
    // if responsible for sync-checkpoint send it
    if (false && pfrom && !CSyncCheckpoint::strMasterPrivKey.empty())        Checkpoints::SendSyncCheckpoint(Checkpoints::AutoSelectSyncCheckpoint());
    printf("{PB}: ACC; \r\n");
    GridcoinServices();
    return true;
}


bool CBlock::CheckBlockSignature() const
{
    if (IsProofOfWork())
        return vchBlockSig.empty();

    vector<valtype> vSolutions;
    txnouttype whichType;

    const CTxOut& txout = vtx[1].vout[1];

    if (!Solver(txout.scriptPubKey, whichType, vSolutions))
        return false;

    if (whichType == TX_PUBKEY)
    {
        valtype& vchPubKey = vSolutions[0];
        CKey key;
        if (!key.SetPubKey(vchPubKey))
            return false;
        if (vchBlockSig.empty())
            return false;
        return key.Verify(GetHash(), vchBlockSig);
    }

    return false;
}

bool CheckDiskSpace(uint64_t nAdditionalBytes)
{
    uint64_t nFreeBytesAvailable = filesystem::space(GetDataDir()).available;

    // Check for nMinDiskSpace bytes (currently 50MB)
    if (nFreeBytesAvailable < nMinDiskSpace + nAdditionalBytes)
    {
        fShutdown = true;
        string strMessage = _("Warning: Disk space is low!");
        strMiscWarning = strMessage;
        printf("*** %s\n", strMessage.c_str());
        uiInterface.ThreadSafeMessageBox(strMessage, "Gridcoin", CClientUIInterface::OK | CClientUIInterface::ICON_EXCLAMATION | CClientUIInterface::MODAL);
        StartShutdown();
        return false;
    }
    return true;
}

static filesystem::path BlockFilePath(unsigned int nFile)
{
    string strBlockFn = strprintf("blk%04u.dat", nFile);
    return GetDataDir() / strBlockFn;
}

FILE* OpenBlockFile(unsigned int nFile, unsigned int nBlockPos, const char* pszMode)
{
    if ((nFile < 1) || (nFile == (unsigned int) -1))
        return NULL;
    FILE* file = fopen(BlockFilePath(nFile).string().c_str(), pszMode);
    if (!file)
        return NULL;
    if (nBlockPos != 0 && !strchr(pszMode, 'a') && !strchr(pszMode, 'w'))
    {
        if (fseek(file, nBlockPos, SEEK_SET) != 0)
        {
            fclose(file);
            return NULL;
        }
    }
    return file;
}

static unsigned int nCurrentBlockFile = 1;

FILE* AppendBlockFile(unsigned int& nFileRet)
{
    nFileRet = 0;
    while (true)
    {
        FILE* file = OpenBlockFile(nCurrentBlockFile, 0, "ab");
        if (!file)
            return NULL;
        if (fseek(file, 0, SEEK_END) != 0)
            return NULL;
        // FAT32 file size max 4GB, fseek and ftell max 2GB, so we must stay under 2GB
        if (ftell(file) < (long)(0x7F000000 - MAX_SIZE))
        {
            nFileRet = nCurrentBlockFile;
            return file;
        }
        fclose(file);
        nCurrentBlockFile++;
    }
}

void InitWithGenesisBlock()
{
    // Genesis block - Genesis2
    // MainNet - Official New Genesis Block:
    ////////////////////////////////////////

    const char* pszTimestamp = "10/11/14 Andrea Rossi Industrial Heat vindicated with LENR validation";
    /*
     21:58:24 block.nTime = 1413149999
    10/12/14 21:58:24 block.nNonce = 1572771
    10/12/14 21:58:24 block.GetHash = 00000f762f698b5962aa81e38926c3a3f1f03e0b384850caed34cd9164b7f990
    10/12/14 21:58:24 CBlock(hash=00000f762f698b5962aa81e38926c3a3f1f03e0b384850caed34cd9164b7f990, ver=1,
    hashPrevBlock=0000000000000000000000000000000000000000000000000000000000000000,
    hashMerkleRoot=0bd65ac9501e8079a38b5c6f558a99aea0c1bcff478b8b3023d09451948fe841, nTime=1413149999, nBits=1e0fffff, nNonce=1572771, vtx=1, vchBlockSig=)
    10/12/14 21:58:24   Coinbase(hash=0bd65ac950, nTime=1413149999, ver=1, vin.size=1, vout.size=1, nLockTime=0)
    CTxIn(COutPoint(0000000000, 4294967295), coinbase 00012a4531302f31312f313420416e6472656120526f73736920496e647573747269616c20486561742076696e646963617465642077697468204c454e522076616c69646174696f6e)
    CTxOut(empty)
    vMerkleTree: 0bd65ac950
    */

    CTransaction txNew;
    //GENESIS TIME
    txNew.nTime = 1413033777;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 0 << CBigNum(42) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].SetEmpty();
    CBlock block;
    block.vtx.push_back(txNew);
    block.hashPrevBlock = 0;
    block.hashMerkleRoot = block.BuildMerkleTree();
    block.nVersion = 1;
    //R&D - Testers Wanted Thread:
    block.nTime    = !fTestNet ? 1413033777 : 1406674534;
    //Official Launch time:
    block.nBits    = bnProofOfWorkLimit.GetCompact();
    block.nNonce = !fTestNet ? 130208 : 22436;
    printf("starting Genesis Check...\n");
    // If genesis block hash does not match, then generate new genesis hash.
    if (block.GetHash() != hashGenesisBlock)
    {
        printf("Searching for genesis block...\n");
        // This will figure out a valid hash and Nonce if you're
        // creating a different genesis block: 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000xFFF
        uint256 hashTarget = CBigNum().SetCompact(block.nBits).getuint256();
        uint256 thash;
        while (true)
        {
            thash = block.GetHash();
            if (thash <= hashTarget)
                break;
            if ((block.nNonce & 0xFFF) == 0)
            {
                printf("nonce %08X: hash = %s (target = %s)\n", block.nNonce, thash.ToString().c_str(), hashTarget.ToString().c_str());
            }
            ++block.nNonce;
            if (block.nNonce == 0)
            {
                printf("NONCE WRAPPED, incrementing time\n");
                ++block.nTime;
            }
        }
        printf("block.nTime = %u \n", block.nTime);
        printf("block.nNonce = %u \n", block.nNonce);
        printf("block.GetHash = %s\n", block.GetHash().ToString().c_str());
    }

    block.print();

    //// debug print

    //GENESIS3: Official Merkle Root
    uint256 merkle_root = uint256("0x5109d5782a26e6a5a5eb76c7867f3e8ddae2bff026632c36afec5dc32ed8ce9f");
    assert(block.hashMerkleRoot == merkle_root);
    assert(block.GetHash() == (!fTestNet ? hashGenesisBlock : hashGenesisBlockTestNet));
    assert(block.CheckBlock("LoadBlockIndex",1));

    // Start new block file
    if (!block.AcceptBlock(NULL,true,NULL))
        throw error("LoadBlockIndex() : genesis block not accepted");
    if(!pindexGenesisBlock)
        throw error("LoadBlockIndex() : pindexGenesisBlock does not point to genesis block");

    // ppcoin: initialize synchronized checkpoint
    if (!Checkpoints::WriteSyncCheckpoint((!fTestNet ? hashGenesisBlock : hashGenesisBlockTestNet)))
        throw error("LoadBlockIndex() : failed to init sync checkpoint");
}

CBlockIndex *CBlockIndex::GetByHash(uint256 hash, void* func)
{
    auto mi = mapBlockIndex.find(hash);
    if (mi != mapBlockIndex.end())
    {
        // Already loaded once in this session.
        return (*mi).second;
    }
    CTxDB txdb("r");
    std::string strValue;
    CBlockIndex* item;
    // The block index is an in-memory structure that maps hashes to on-disk
    // locations where the contents of the block can be found.
    //printf("Loading DiskIndex %d\n",nHighest);
    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey << std::string("blockindex");
        ssKey << hash;
    if(!txdb.Read(ssKey.str(), strValue))
        return NULL; //does not exist yet
    CDataStream s(strValue.data(), strValue.data() + strValue.size(),
                        SER_DISK, CLIENT_VERSION);
    // Create new and deserialize
    item = new CBlockIndex();
    s>> (*item); //deserialize
    // insert into map
    mi = mapBlockIndex.insert(make_pair(hash, item)).first;
    item->phashBlock = &((*mi).first);
    {
        // NovaCoin: build setStakeSeen
        // TODO: blocks not loaded wont appear in the set!
        if (item->IsProofOfStake)
            setStakeSeen.insert(make_pair(item->prevoutStake, item->nStakeTime));
    }
    return item;
    (void)func; //TODO
}

void GridcoinSetUpRA()
{
#if 0
    //Gridcoin - In order, set up Research Age hashes and lifetime fields
    CBlockIndex* pindex = BlockFinder().FindByHeight(1);
    
    nLoaded=pindex->nHeight;
    if (pindex && Best.GetHeight() > 10 && pindex->GetNext())
    {
        printf(" RA Starting %i %i %i ", pindex->nHeight, pindex->GetNext()->nHeight, Best.GetHeight());
        while (pindex->nHeight < Best.GetHeight())
        {
            if (!pindex || !pindex->GetNext()) break;  
            pindex = pindex->GetNext();
            if (pindex == Best.top) break;
            if (pindex==NULL || !pindex->IsInMainChain()) continue;
            
#ifdef QT_GUI
            if ((pindex->nHeight % 10000) == 0)
            {
                nLoaded +=10000;
                if (nLoaded > nHighest) nHighest=nLoaded;
                if (nHighest < nGrandfather) nHighest=nGrandfather;
                std::string sBlocksLoaded = RoundToString(nLoaded,0) + "/" + RoundToString(nHighest,0) + " POR Blocks Verified";
                uiInterface.InitMessage(_(sBlocksLoaded.c_str()));
            }
#endif
                        
            if (pindex->nResearchSubsidy > 0 && pindex->IsUserCPID())
            {
                const std::string& scpid = pindex->GetCPID();
                StructCPID stCPID = GetInitializedStructCPID2(scpid, mvResearchAge);
                
                stCPID.InterestSubsidy += pindex->nInterestSubsidy;
                stCPID.ResearchSubsidy += pindex->nResearchSubsidy;
                if (pindex->nHeight > stCPID.LastBlock) 
                {
                    stCPID.LastBlock = pindex->nHeight;
                    stCPID.BlockHash = pindex->GetBlockHash().GetHex();
                }
                
                if (pindex->nMagnitude > 0)
                {
                    stCPID.Accuracy++;
                    stCPID.TotalMagnitude += pindex->nMagnitude;
                    stCPID.ResearchAverageMagnitude = stCPID.TotalMagnitude/(stCPID.Accuracy+.01);
                }
                
                if (pindex->nTime < stCPID.LowLockTime)  stCPID.LowLockTime = pindex->nTime;
                if (pindex->nTime > stCPID.HighLockTime) stCPID.HighLockTime = pindex->nTime;
                
                // Store the updated struct.
                mvResearchAge[scpid] = stCPID;
                AddCPIDBlockHash(scpid, pindex->GetBlockHash());
            }
        }
    }
#endif
}



bool LoadBlockIndex(bool fAllowNew)
{
    LOCK(cs_main);
    int64_t nStart;

    if (fTestNet)
    {
        printf("Running *TestNet* mode\n");
        // GLOBAL TESTNET SETTINGS - R HALFORD
        pchMessageStart[0] = 0xcd;
        pchMessageStart[1] = 0xf2;
        pchMessageStart[2] = 0xc0;
        pchMessageStart[3] = 0xef;
        bnProofOfWorkLimit = bnProofOfWorkLimitTestNet; // 16 bits PoW target limit for testnet
        nStakeMinAge = 1 * 60 * 60; // test net min age is 1 hour
        nCoinbaseMaturity = 10; // test maturity is 10 blocks
        nGrandfather = 196550;
        nNewIndex = 10;
        nNewIndex2 = 36500;
        bOPReturnEnabled = false;
        //1-24-2016
        MAX_OUTBOUND_CONNECTIONS = (int)GetArg("-maxoutboundconnections", 8);
    }
    else
        printf("Running Production mode\n");

    CTxDB txdb("cr+");

    // * Try to load genesis block (necessary?)
    pindexGenesisBlock = CBlockIndex::GetByHash(
        (!fTestNet ? hashGenesisBlock : hashGenesisBlockTestNet));
    // * Load CBestChain persisted data
    Best.LoadDb(txdb);
    // * Load Messages
    Best.LoadDbBeacons(txdb);
    // * Load CPIDs
    Best.LoadDbCpids(txdb);

    // * if blockchain empty, generate genesis block
    if (mapBlockIndex.empty() || NULL==Best.top)
    {
        if (!fAllowNew)
            return false;
        InitWithGenesisBlock();
    }

    if (fRequestShutdown)
        return false;


    printf("LoadBlockIndex(): hashBestChain=%s  height=%d  trust=%s  date=%s\n",
      Best.top->GetBlockHash().ToString().substr(0,20).c_str(), Best.GetHeight(), CBigNum(Best.top?Best.top->nChainTrust:0).ToString().c_str(),
      DateTimeStrFormat("%x %H:%M:%S", Best.top->GetBlockTime()).c_str());

    // NovaCoin: load hashSyncCheckpoint (TODO)
    if (!txdb.ReadSyncCheckpoint(Checkpoints::hashSyncCheckpoint))
        return error("CTxDB::LoadBlockIndex() : hashSyncCheckpoint not loaded");
    printf("LoadBlockIndex(): synchronized checkpoint %s\n", Checkpoints::hashSyncCheckpoint.ToString().c_str());

    // Load bnBestInvalidTrust, OK if it doesn't exist
    CBigNum bnBestInvalidTrust;
    txdb.ReadBestInvalidTrust(bnBestInvalidTrust);
    nBestInvalidTrust = bnBestInvalidTrust.getuint256();

    printf("Set up RA ");  
    nStart = GetTimeMillis();
    GridcoinSetUpRA();
    printf("RA Complete - RA Time %15" PRId64 "ms\n", GetTimeMillis() - nStart);

    #if defined(WIN32) && defined(QT_GUI)
        SetThreadPriority(THREAD_PRIORITY_NORMAL);
    #endif

    // if checkpoint master key changed must reset sync-checkpoint
    string strPubKey = "";
    if (!txdb.ReadCheckpointPubKey(strPubKey) || strPubKey != CSyncCheckpoint::strMasterPubKey)
    {
        // write checkpoint master key to db
        txdb.TxnBegin();
        if (!txdb.WriteCheckpointPubKey(CSyncCheckpoint::strMasterPubKey))
            return error("LoadBlockIndex() : failed to write new checkpoint master key to db");
        if (!txdb.TxnCommit())
            return error("LoadBlockIndex() : failed to commit new checkpoint master key to db");
        if ((!fTestNet) && !Checkpoints::ResetSyncCheckpoint())
            return error("LoadBlockIndex() : failed to reset sync-checkpoint");
    }

    return true;
}

std::string ExtractXML(std::string XMLdata, std::string key, std::string key_end)
{

    std::string extraction = "";
    string::size_type loc = XMLdata.find( key, 0 );
    if( loc != string::npos )
    {
        string::size_type loc_end = XMLdata.find( key_end, loc+3);
        if (loc_end != string::npos )
        {
            extraction = XMLdata.substr(loc+(key.length()),loc_end-loc-(key.length()));

        }
    }
    return extraction;
}

std::string ExtractHTML(std::string HTMLdata, std::string tagstartprefix,  std::string tagstart_suffix, std::string tag_end)
{

    std::string extraction = "";
    string::size_type loc = HTMLdata.find( tagstartprefix, 0 );
    if( loc != string::npos )
    {
        //Find the end of the start tag
        string::size_type loc_EOStartTag = HTMLdata.find( tagstart_suffix, loc+tagstartprefix.length());
        if (loc_EOStartTag != string::npos )
        {

            string::size_type loc_end = HTMLdata.find( tag_end, loc_EOStartTag+tagstart_suffix.length());
            if (loc_end != string::npos )
            {
                extraction = HTMLdata.substr(loc_EOStartTag+(tagstart_suffix.length()), loc_end-loc_EOStartTag-(tagstart_suffix.length()));
                extraction = strReplace(extraction,",","");
                if (Contains(extraction,"\r\n"))
                {
                    std::vector<std::string> vExtract = split(extraction,"\r\n");
                    if (vExtract.size() >= 2)
                    {
                        extraction = vExtract[2];
                        return extraction;
                    }
                }
            }
        }
    }
    return extraction;
}


std::string RetrieveMd5(std::string s1)
{
    try
    {
        const char* chIn = s1.c_str();
        unsigned char digest2[16];
        MD5((unsigned char*)chIn, strlen(chIn), (unsigned char*)&digest2);
        char mdString2[33];
        for(int i = 0; i < 16; i++) sprintf(&mdString2[i*2], "%02x", (unsigned int)digest2[i]);
        std::string xmd5(mdString2);
        return xmd5;
    }
    catch (std::exception &e)
    {
        printf("MD5 INVALID!");
        return "";
    }
}



double Round(double d, int place)
{
    std::ostringstream ss;
    ss << std::fixed << std::setprecision(place) << d ;
    double r = lexical_cast<double>(ss.str());
    return r;
}

double cdbl(std::string s, int place)
{
    if (s=="") s="0";
    s = strReplace(s,"\r","");
    s = strReplace(s,"\n","");
    s = strReplace(s,"a","");
    s = strReplace(s,"a","");
    s = strReplace(s,"b","");
    s = strReplace(s,"c","");
    s = strReplace(s,"d","");
    s = strReplace(s,"e","");
    s = strReplace(s,"f","");
    double r = lexical_cast<double>(s);
    double d = Round(r,place);
    return d;
}


int GetFilesize(FILE* file)
{
    int nSavePos = ftell(file);
    int nFilesize = -1;
    if (fseek(file, 0, SEEK_END) == 0)
        nFilesize = ftell(file);
    fseek(file, nSavePos, SEEK_SET);
    return nFilesize;
}




bool WriteKey(std::string sKey, std::string sValue)
{
    // Allows Gridcoin to store the key value in the config file.
    boost::filesystem::path pathConfigFile(GetArg("-conf", "gridcoinresearch.conf"));
    if (!pathConfigFile.is_complete()) pathConfigFile = GetDataDir(false) / pathConfigFile;
    if (!filesystem::exists(pathConfigFile))  return false; 
    boost::to_lower(sKey);
    std::string sLine = "";
    ifstream streamConfigFile;
    streamConfigFile.open(pathConfigFile.string().c_str());
    std::string sConfig = "";
    bool fWritten = false;
    if(streamConfigFile)
    {
       while(getline(streamConfigFile, sLine))
       {
            std::vector<std::string> vEntry = split(sLine,"=");
            if (vEntry.size() == 2)
            {
                std::string sSourceKey = vEntry[0];
                std::string sSourceValue = vEntry[1];
                boost::to_lower(sSourceKey);

                if (sSourceKey==sKey) 
                {
                    sSourceValue = sValue;
                    sLine = sSourceKey + "=" + sSourceValue;
                    fWritten=true;
                }
            }
            sLine = strReplace(sLine,"\r","");
            sLine = strReplace(sLine,"\n","");
            sLine += "\r\n";
            sConfig += sLine;
       }
    }
    if (!fWritten) 
    {
        sLine = sKey + "=" + sValue + "\r\n";
        sConfig += sLine;
    }
    
    streamConfigFile.close();

    FILE *outFile = fopen(pathConfigFile.string().c_str(),"w");
    fputs(sConfig.c_str(), outFile);
    fclose(outFile);

    ReadConfigFile(mapArgs, mapMultiArgs);
    return true;
}




std::string getfilecontents(std::string filename)
{
    std::string buffer;
    std::string line;
    ifstream myfile;
    if (fDebug10) printf("loading file to string %s",filename.c_str());

    filesystem::path path = filename;

    if (!filesystem::exists(path)) {
        printf("the file does not exist %s",path.string().c_str());
        return "-1";
    }

     FILE *file = fopen(filename.c_str(), "rb");
     CAutoFile filein = CAutoFile(file, SER_DISK, CLIENT_VERSION);
     int fileSize = GetFilesize(filein);
     filein.fclose();

     myfile.open(filename.c_str());

    buffer.reserve(fileSize);
    if (fDebug10) printf("opening file %s",filename.c_str());

    if(myfile)
    {
      while(getline(myfile, line))
      {
            buffer = buffer + line + "\r\n";
      }
    }
    myfile.close();
    return buffer;
}


bool IsCPIDValidv3(std::string cpidv2, bool allow_investor)
{
    // Used for checking the local cpid
    bool result=false;
    if (allow_investor) if (cpidv2 == "INVESTOR" || cpidv2=="investor") return true;
    if (cpidv2.length() < 34) return false;
    result = CPID_IsCPIDValid(cpidv2.substr(0,32),cpidv2,0);
    return result;
}

bool IsCPIDValidv2(MiningCPID& mc, int height)
{
    //09-25-2016: Transition to CPID Keypairs.
    if (height < nGrandfather) return true;
    bool result = false;
    int cpidV2CutOverHeight = fTestNet ? 0 : 97000;
    int cpidV3CutOverHeight = fTestNet ? 196300 : 725000;
    if (height < cpidV2CutOverHeight)
    {
        result = IsCPIDValid_Retired(mc.cpid,mc.enccpid);
    }
    else if (height >= cpidV2CutOverHeight && height <= cpidV3CutOverHeight)
    {
        if (mc.cpid == "INVESTOR" || mc.cpid=="investor") return true;
        result = CPID_IsCPIDValid(mc.cpid, mc.cpidv2, (uint256)mc.lastblockhash);
    }
    else if (height >= cpidV3CutOverHeight)
    {
        if (mc.cpid == "INVESTOR" || mc.cpid=="investor") return true;
        if(mc.cpid.empty()) return false;
        // V3 requires a beacon, a beacon public key and a valid block signature signed by the CPID's private key
        result = VerifyCPIDSignature(mc.cpid,mc.lastblockhash,mc.BoincSignature);
    }

    return result;
}


bool IsLocalCPIDValid(StructCPID& structcpid)
{

    bool new_result = IsCPIDValidv3(structcpid.cpidv2,true);
    return new_result;

}



bool IsCPIDValid_Retired(std::string cpid, std::string ENCboincpubkey)
{

    try
    {
            if(cpid=="" || cpid.length() < 5)
            {
                printf("CPID length empty.");
                return false;
            }
            if (cpid=="INVESTOR") return true;
            if (ENCboincpubkey == "" || ENCboincpubkey.length() < 5)
            {
                    if (fDebug10) printf("ENCBpk length empty.");
                    return false;
            }
            std::string bpk = AdvancedDecrypt(ENCboincpubkey);
            std::string bpmd5 = RetrieveMd5(bpk);
            if (bpmd5==cpid) return true;
            if (fDebug10) printf("Md5<>cpid, md5 %s cpid %s  root bpk %s \r\n     ",bpmd5.c_str(), cpid.c_str(),bpk.c_str());

            return false;
    }
    catch (std::exception &e)
    {
                printf("Error while resolving CPID\r\n");
                return false;
    }
    catch(...)
    {
                printf("Error while Resolving CPID[2].\r\n");
                return false;
    }
    return false;

}

bool BlockNeedsChecked(int64_t BlockTime)
{
    if (IsLockTimeWithin14days(BlockTime))
    {
        if (fColdBoot) return false;
        bool fOut = OutOfSyncByMoreThan(30);
        return !fOut;
    }
    else
    {
        return false;
    }
}

void AdjustTimestamps(StructCPID& strCPID, double timestamp, double subsidy)
{
        if (timestamp > strCPID.LastPaymentTime && subsidy > 0) strCPID.LastPaymentTime = timestamp;
        if (timestamp < strCPID.EarliestPaymentTime) strCPID.EarliestPaymentTime = timestamp;
}

void AddResearchMagnitude(CBlockIndex* pIndex)
{
    // Headless critical section
    if (pIndex->nResearchSubsidy > 0)
    {
        try
        {
            StructCPID stMag = GetInitializedStructCPID2(pIndex->GetCPID(),mvMagnitudesCopy);
            stMag.cpid = pIndex->GetCPID();
            stMag.GRCAddress = pIndex->sGRCAddress;
            if (pIndex->nHeight > stMag.LastBlock)
            {
                stMag.LastBlock = pIndex->nHeight;
            }
            stMag.entries++;
            stMag.payments += pIndex->nResearchSubsidy;
            stMag.interestPayments += pIndex->nInterestSubsidy;

            AdjustTimestamps(stMag,pIndex->nTime, pIndex->nResearchSubsidy);
            // Track detailed payments made to each CPID
            stMag.PaymentTimestamps         += RoundToString(pIndex->nTime,0) + ",";
            stMag.PaymentAmountsResearch    += RoundToString(pIndex->nResearchSubsidy,2) + ",";
            stMag.PaymentAmountsInterest    += RoundToString(pIndex->nInterestSubsidy,2) + ",";
            stMag.PaymentAmountsBlocks      += RoundToString(pIndex->nHeight,0) + ",";
            stMag.Accuracy++;
            stMag.AverageRAC = stMag.rac / (stMag.entries+.01);
            double total_owed = 0;
            stMag.owed = GetOutstandingAmountOwed(stMag,
                                                  pIndex->GetCPID(), pIndex->nTime, total_owed, pIndex->nMagnitude);

            stMag.totalowed = total_owed;
            mvMagnitudesCopy[pIndex->GetCPID()] = stMag;
        }
        catch (const std::bad_alloc& ba)
        {
            printf("\r\nBad Allocation in AddResearchMagnitude() \r\n");
        }
        catch(...)
        {
            printf("Exception in AddResearchMagnitude() \r\n");
        }
    }
}


bool GetEarliestStakeTime(std::string grcaddress, std::string cpid)
{
    if (Best.GetHeight() < 15)
    {
        mvApplicationCacheTimestamp["nGRCTime"] = GetAdjustedTime();
        mvApplicationCacheTimestamp["nCPIDTime"] = GetAdjustedTime();
        return true;
    }

    if (IsLockTimeWithinMinutes(nLastGRCtallied,100) && (mvApplicationCacheTimestamp["nGRCTime"] > 0 ||
		 mvApplicationCacheTimestamp["nCPIDTime"] > 0))  return true;

    nLastGRCtallied = GetAdjustedTime();
    int64_t nGRCTime = 0;
    int64_t nCPIDTime = 0;
    CBlock block;
    int64_t nStart = GetTimeMillis();
    LOCK(cs_main);
    {
            int nMaxDepth = Best.GetHeight();
            int nLookback = BLOCKS_PER_DAY*6*30;  //6 months back for performance
            int nMinDepth = nMaxDepth - nLookback;
            if (nMinDepth < 2) nMinDepth = 2;
            // Start at the earliest block index:
            CBlockIndex* pblockindex = blockFinder.FindByHeight(nMinDepth);
            while (pblockindex->nHeight < nMaxDepth-1)
            {
                        pblockindex = pblockindex->GetNext();
                        if (pblockindex == Best.top) break;
                        if (pblockindex == NULL || !pblockindex->IsInMainChain()) continue;
                        std::string myCPID = "";
                        if (pblockindex->nHeight < nNewIndex)
                        {
                            //Between block 1 and nNewIndex, unfortunately, we have to read from disk.
                            block.ReadFromDisk(pblockindex);
                            std::string hashboinc = "";
                            if (block.vtx.size() > 0) hashboinc = block.vtx[0].hashBoinc;
                            MiningCPID bb = DeserializeBoincBlock(hashboinc,block.nVersion);
                            myCPID = bb.cpid;
                        }
                        else
                        {
						    myCPID = pblockindex->GetCPID();
                        }
                        if (cpid == myCPID && nCPIDTime==0 && myCPID != "INVESTOR")
                        {
                            nCPIDTime = pblockindex->nTime;
                            nGRCTime = pblockindex->nTime;
                            break;
                        }
            }
    }
    int64_t EarliestStakedWalletTx = GetEarliestWalletTransaction();
    if (EarliestStakedWalletTx > 0 && EarliestStakedWalletTx < nGRCTime) nGRCTime = EarliestStakedWalletTx;
	if (cpid=="INVESTOR" && EarliestStakedWalletTx > 0) nGRCTime = EarliestStakedWalletTx;
    if (fTestNet) nGRCTime -= (86400*30);
    if (nGRCTime <= 0)  nGRCTime = GetAdjustedTime();
    if (nCPIDTime <= 0) nCPIDTime = GetAdjustedTime();

    printf("Loaded staketime from index in %f", (double)(GetTimeMillis() - nStart));
    printf("CPIDTime %f, GRCTime %f, WalletTime %f \r\n",(double)nCPIDTime,(double)nGRCTime,(double)EarliestStakedWalletTx);
    mvApplicationCacheTimestamp["nGRCTime"] = nGRCTime;
    mvApplicationCacheTimestamp["nCPIDTime"] = nCPIDTime;
    return true;
}

#if 0
StructCPID GetLifetimeCPID(const std::string& cpid, const std::string& sCalledFrom)
{
    if (fDebug10) printf(" {GLC %s} ",sCalledFrom.c_str());

    StructCPID2* stc = Best.GetCPID(cpid);
    if(!stc)
        throw error("GetLifetimeCPID called for non-existing");

    const HashSet& hashes = GetCPIDBlockHashes(cpid);
    ZeroOutResearcherTotals(cpid);

    for (HashSet::iterator it = hashes.begin(); it != hashes.end(); ++it)
    {
        const uint256& uHash = *it;

        // Ensure that we have this block.
        CBlockIndex* pblockindex = CBlockIndex::GetByHash(uHash);
        // Ensure that the block is valid
        if(pblockindex == NULL ||
           pblockindex->IsInMainChain() == false ||
           pblockindex->GetCPID() != cpid)
            continue;

        // Block located and verified.
        if (pblockindex->nHeight > stCPID.LastBlock && pblockindex->nResearchSubsidy > 0)
        {
            stCPID.LastBlock = pblockindex->nHeight;
            stCPID.BlockHash = pblockindex->GetBlockHash().GetHex();
        }
        stCPID.InterestSubsidy += pblockindex->nInterestSubsidy;
        stCPID.ResearchSubsidy += pblockindex->nResearchSubsidy;
        stCPID.Accuracy++;
        if (pblockindex->nMagnitude > 0)
        {
            stCPID.TotalMagnitude += pblockindex->nMagnitude;
            stCPID.ResearchAverageMagnitude = stCPID.TotalMagnitude/(stCPID.Accuracy+.01);
        }

        if (pblockindex->nTime < stCPID.LowLockTime)  stCPID.LowLockTime  = pblockindex->nTime;
        if (pblockindex->nTime > stCPID.HighLockTime) stCPID.HighLockTime = pblockindex->nTime;
    }

    // Save updated CPID data holder.
    mvResearchAge[cpid] = stCPID;
    return stCPID;
}
#endif

MiningCPID GetInitializedMiningCPID(std::string name,std::map<std::string, MiningCPID>& vRef)
{
   MiningCPID& cpid = vRef[name];
    if (!cpid.initialized)
    {
                cpid = GetMiningCPID();
                cpid.initialized=true;
                cpid.LastPaymentTime = 0;
    }

   return cpid;
}


StructCPID GetInitializedStructCPID2(const std::string& name, std::map<std::string, StructCPID>& vRef)
{
    try
    {
        StructCPID& cpid = vRef[name];
        if (!cpid.initialized)
        {
            cpid = GetStructCPID();
            cpid.initialized=true;
            cpid.LowLockTime = std::numeric_limits<unsigned int>::max();
            cpid.HighLockTime = 0;
            cpid.LastPaymentTime = 0;
            cpid.EarliestPaymentTime = 99999999999;
            cpid.Accuracy = 0;
        }

        return cpid;
    }
    catch (const std::bad_alloc& ba)
    {
        printf("Bad alloc caught in GetInitializedStructCpid2 for %s",name.c_str());
    }
    catch(...)
    {
        printf("Exception caught in GetInitializedStructCpid2 for %s",name.c_str());
    }

    // Error during map's heap allocation. Return an empty object.
    return GetStructCPID();
}


bool ComputeNeuralNetworkSupermajorityHashes()
{
    if (Best.GetHeight() < 15)  return true;
    if (IsLockTimeWithinMinutes(nLastTalliedNeural,5))
    {
        return true;
    }
    nLastTalliedNeural = GetAdjustedTime();
    //Clear the neural network hash buffer
    if (mvNeuralNetworkHash.size() > 0)  mvNeuralNetworkHash.clear();
    if (mvNeuralVersion.size() > 0)  mvNeuralVersion.clear();
    if (mvCurrentNeuralNetworkHash.size() > 0) mvCurrentNeuralNetworkHash.clear();

    //Clear the votes
    WriteCache("neuralsecurity","pending","0",GetAdjustedTime());
    ClearCache("neuralsecurity");
    try
    {
        int nMaxDepth = Best.GetHeight();
        int nLookback = 100;
        int nMinDepth = (nMaxDepth - nLookback);
        if (nMinDepth < 2)   nMinDepth = 2;
        CBlock block;
        CBlockIndex* pblockindex = Best.top;
        while (pblockindex->nHeight > nMinDepth)
        {
            if (!pblockindex || !pblockindex->GetPrev()) return false;
            pblockindex = pblockindex->GetPrev();
            if (pblockindex == pindexGenesisBlock) return false;
            if (!pblockindex->IsInMainChain()) continue;
            block.ReadFromDisk(pblockindex);
            std::string hashboinc = "";
            if (block.vtx.size() > 0) hashboinc = block.vtx[0].hashBoinc;
            if (!hashboinc.empty())
            {
                MiningCPID bb = DeserializeBoincBlock(hashboinc,block.nVersion);
                //If block is pending: 7-25-2015
                if (bb.superblock.length() > 20)
                {
                    std::string superblock = UnpackBinarySuperblock(bb.superblock);
                    if (VerifySuperblock(superblock,pblockindex->nHeight))
                    {
                        WriteCache("neuralsecurity","pending",RoundToString((double)pblockindex->nHeight,0),GetAdjustedTime());
                    }
                }

                IncrementVersionCount(bb.clientversion);
                //Increment Neural Network Hashes Supermajority (over the last N blocks)
                IncrementNeuralNetworkSupermajority(bb.NeuralHash,bb.GRCAddress,(nMaxDepth-pblockindex->nHeight)+10);
                IncrementCurrentNeuralNetworkSupermajority(bb.CurrentNeuralHash,bb.GRCAddress,(nMaxDepth-pblockindex->nHeight)+10);

            }
        }

        if (fDebug3) printf(".11.");
    }
    catch (std::exception &e)
    {
            printf("Neural Error while memorizing hashes.\r\n");
    }
    catch(...)
    {
        printf("Neural error While Memorizing Hashes! [1]\r\n");
    }
    return true;

}

#if 0
bool TallyResearchAverages(bool Forcefully)
{
    //Iterate throught last 14 days, tally network averages
    if (Best.GetHeight() < 15)
    {
        bNetAveragesLoaded = true;
        return true;
    }

    //if (Forcefully) nLastTallied = 0;
    int timespan = fTestNet ? 2 : 6;
    if (IsLockTimeWithinMinutes(nLastTallied,timespan))
    {
        bNetAveragesLoaded=true;
        return true;
    }

    //8-27-2016
     int64_t nStart = GetTimeMillis();


    if (fDebug) printf("Tallying Research Averages (begin) ");
    nLastTallied = GetAdjustedTime();
    bNetAveragesLoaded = false;
    bool superblockloaded = false;
    double NetworkPayments = 0;
    double NetworkInterest = 0;
    
                        //Consensus Start/End block:
                        int nMaxDepth = (Best.GetHeight()-CONSENSUS_LOOKBACK) - ( (Best.GetHeight()-CONSENSUS_LOOKBACK) % BLOCK_GRANULARITY);
                        int nLookback = BLOCKS_PER_DAY * 14; //Daily block count * Lookback in days
                        int nMinDepth = (nMaxDepth - nLookback) - ( (nMaxDepth-nLookback) % BLOCK_GRANULARITY);
                        if (fDebug3) printf("START BLOCK %f, END BLOCK %f ",(double)nMaxDepth,(double)nMinDepth);
                        if (nMinDepth < 2)              nMinDepth = 2;
                        mvMagnitudesCopy.clear();
                        int iRow = 0;
                        //CBlock block;
                        CBlockIndex* pblockindex = Best.top;
                        if (!pblockindex)
                        {
                                bTallyStarted = false;
                                bNetAveragesLoaded = true;
                                return true;
                        }
                        while (pblockindex->nHeight > nMaxDepth)
                        {
                            if (!pblockindex || !pblockindex->GetPrev() || pblockindex == pindexGenesisBlock) return false;
                            pblockindex = pblockindex->GetPrev();
                        }

                        if (fDebug3) printf("Max block %f, seektime %f",(double)pblockindex->nHeight,(double)GetTimeMillis()-nStart);
                        nStart=GetTimeMillis();

   
                        // Headless critical section ()
        try
        {
                        while (pblockindex->nHeight > nMinDepth)
                        {
                            if (!pblockindex || !pblockindex->GetPrev()) return false;
                            pblockindex = pblockindex->GetPrev();
                            if (pblockindex == pindexGenesisBlock) return false;
                            if (!pblockindex->IsInMainChain()) continue;
                            NetworkPayments += pblockindex->nResearchSubsidy;
                            NetworkInterest += pblockindex->nInterestSubsidy;
                            AddResearchMagnitude(pblockindex);

                            iRow++;
                            if (IsSuperBlock(pblockindex) && !superblockloaded)
                            {
                                MiningCPID bb = GetBoincBlockByIndex(pblockindex);
                                if (bb.superblock.length() > 20)
                                {
                                        std::string superblock = UnpackBinarySuperblock(bb.superblock);
                                        if (VerifySuperblock(superblock,pblockindex->nHeight))
                                        {
                                                LoadSuperblock(superblock,pblockindex->nTime,pblockindex->nHeight);
                                                superblockloaded=true;
                                                if (fDebug) printf(" Superblock Loaded %f \r\n",(double)pblockindex->nHeight);
                                        }
                                }
                            }

                        }
                        // End of critical section
                        if (fDebug3) printf("TNA loaded in %f",(double)GetTimeMillis()-nStart);
                        nStart=GetTimeMillis();


                        if (pblockindex)
                        {
                            if (fDebug3) printf("Min block %f, Rows %f \r\n",(double)pblockindex->nHeight,(double)iRow);
                            StructCPID network = GetInitializedStructCPID2("NETWORK",mvNetworkCopy);
                            network.projectname="NETWORK";
                            network.payments = NetworkPayments;
                            network.InterestSubsidy = NetworkInterest;
                            mvNetworkCopy["NETWORK"] = network;
                            if(fDebug3) printf(" TMIS1 ");
                            TallyMagnitudesInSuperblock();
                        }
                        // 11-19-2015 Copy dictionaries to live RAM
                        mvDPOR = mvDPORCopy;
                        mvMagnitudes = mvMagnitudesCopy;
                        mvNetwork = mvNetworkCopy;
                        bTallyStarted = false;
                        bNetAveragesLoaded = true;
                        return true;
        }
        catch (bad_alloc ba)
        {
            printf("Bad Alloc while tallying network averages. [1]\r\n");
            bNetAveragesLoaded=true;
            nLastTallied = 0;
        }
        catch(...)
        {
            printf("Error while tallying network averages. [1]\r\n");
            bNetAveragesLoaded=true;
            nLastTallied = 0;
        }

        if (fDebug3) printf("NA loaded in %f",(double)GetTimeMillis()-nStart);
                        
        bNetAveragesLoaded=true;
        return false;
}
#endif



bool TallyNetworkAverages(bool Forcefully)
{
    if (IsResearchAgeEnabled(Best.GetHeight()))
    {
        return TallyResearchAverages(Forcefully);
    }

    return false;
}


void PrintBlockTree()
{
    AssertLockHeld(cs_main);
    // pre-compute tree structure
    map<CBlockIndex*, vector<CBlockIndex*> > mapNext;
    for (map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.begin(); mi != mapBlockIndex.end(); ++mi)
    {
        CBlockIndex* pindex = (*mi).second;
        mapNext[pindex->GetPrev()].push_back(pindex);
    }

    vector<pair<int, CBlockIndex*> > vStack;
    vStack.push_back(make_pair(0, pindexGenesisBlock));

    int nPrevCol = 0;
    while (!vStack.empty())
    {
        int nCol = vStack.back().first;
        CBlockIndex* pindex = vStack.back().second;
        vStack.pop_back();

        // print split or gap
        if (nCol > nPrevCol)
        {
            for (int i = 0; i < nCol-1; i++)
                printf("| ");
            printf("|\\\n");
        }
        else if (nCol < nPrevCol)
        {
            for (int i = 0; i < nCol; i++)
                printf("| ");
            printf("|\n");
       }
        nPrevCol = nCol;

        // print columns
        for (int i = 0; i < nCol; i++)
            printf("| ");

        // print item
        CBlock block;
        block.ReadFromDisk(pindex);
        printf("%d (%u,%u) %s  %08x  %s  mint %7s  tx %" PRIszu "",
            pindex->nHeight,
            pindex->nFile,
            pindex->nBlockPos,
            block.GetHash().ToString().c_str(),
            block.nBits,
            DateTimeStrFormat("%x %H:%M:%S", block.GetBlockTime()).c_str(),
            FormatMoney(pindex->nMint).c_str(),
            block.vtx.size());

        PrintWallets(block);

        // put the main time-chain first
        vector<CBlockIndex*>& vNext = mapNext[pindex];
        for (unsigned int i = 0; i < vNext.size(); i++)
        {
            if (vNext[i]->GetNext())
            {
                swap(vNext[0], vNext[i]);
                break;
            }
        }

        // iterate children
        for (unsigned int i = 0; i < vNext.size(); i++)
            vStack.push_back(make_pair(nCol+i, vNext[i]));
    }
}

bool LoadExternalBlockFile(FILE* fileIn)
{
    int64_t nStart = GetTimeMillis();

    int nLoaded = 0;
    {
        LOCK(cs_main);
        try {
            CAutoFile blkdat(fileIn, SER_DISK, CLIENT_VERSION);
            unsigned int nPos = 0;
            while (nPos != (unsigned int)-1 && blkdat.good() && !fRequestShutdown)
            {
                unsigned char pchData[65536];
                do {
                    fseek(blkdat, nPos, SEEK_SET);
                    int nRead = fread(pchData, 1, sizeof(pchData), blkdat);
                    if (nRead <= 8)
                    {
                        nPos = (unsigned int)-1;
                        break;
                    }
                    void* nFind = memchr(pchData, pchMessageStart[0], nRead+1-sizeof(pchMessageStart));
                    if (nFind)
                    {
                        if (memcmp(nFind, pchMessageStart, sizeof(pchMessageStart))==0)
                        {
                            nPos += ((unsigned char*)nFind - pchData) + sizeof(pchMessageStart);
                            break;
                        }
                        nPos += ((unsigned char*)nFind - pchData) + 1;
                    }
                    else
                        nPos += sizeof(pchData) - sizeof(pchMessageStart) + 1;
                } while(!fRequestShutdown);
                if (nPos == (unsigned int)-1)
                    break;
                fseek(blkdat, nPos, SEEK_SET);
                unsigned int nSize;
                blkdat >> nSize;
                if (nSize > 0 && nSize <= MAX_BLOCK_SIZE)
                {
                    CBlock block;
                    blkdat >> block;
                    if (ProcessBlock(NULL,&block,false))
                    {
                        nLoaded++;
                        nPos += 4 + nSize;
                    }
                }
            }
        }
        catch (std::exception &e) {
            printf("%s() : Deserialize or I/O error caught during load\n",
                   __PRETTY_FUNCTION__);
        }
    }
    printf("Loaded %i blocks from external file in %" PRId64 "ms\n", nLoaded, GetTimeMillis() - nStart);
    return nLoaded > 0;
}

//////////////////////////////////////////////////////////////////////////////
//
// CAlert
//

extern map<uint256, CAlert> mapAlerts;
extern CCriticalSection cs_mapAlerts;

string GetWarnings(string strFor)
{
    int nPriority = 0;
    string strStatusBar;
    string strRPC;

    if (GetBoolArg("-testsafemode"))
        strRPC = "test";

    // Misc warnings like out of disk space and clock is wrong
    if (strMiscWarning != "")
    {
        nPriority = 1000;
        strStatusBar = strMiscWarning;
    }

    // if detected invalid checkpoint enter safe mode
    if (Checkpoints::hashInvalidCheckpoint != 0)
    {

        if (CHECKPOINT_DISTRIBUTED_MODE==1)
        {
            //10-18-2014-Halford- If invalid checkpoint found, reboot the node:
            printf("Moving Gridcoin into Checkpoint ADVISORY mode.\r\n");
            CheckpointsMode = Checkpoints::ADVISORY;
        }
        else
        {
            #if defined(WIN32) && defined(QT_GUI)
                int nResult = 0;
                std::string rebootme = "";
                if (mapArgs.count("-reboot"))
                {
                    rebootme = GetArg("-reboot", "false");
                }
                if (rebootme == "true")
                {
                    nResult = RebootClient();
                    printf("Rebooting %u",nResult);
                }
            #endif

            nPriority = 3000;
            strStatusBar = strRPC = _("WARNING: Invalid checkpoint found! Displayed transactions may not be correct! You may need to upgrade, or notify developers.");
            printf("WARNING: Invalid checkpoint found! Displayed transactions may not be correct! You may need to upgrade, or notify developers.");
        }


    }

    // Alerts
    {
        LOCK(cs_mapAlerts);
        BOOST_FOREACH(PAIRTYPE(const uint256, CAlert)& item, mapAlerts)
        {
            const CAlert& alert = item.second;
            if (alert.AppliesToMe() && alert.nPriority > nPriority)
            {
                nPriority = alert.nPriority;
                strStatusBar = alert.strStatusBar;
                if (nPriority > 1000)
                    strRPC = strStatusBar;
            }
        }
    }

    if (strFor == "statusbar")
        return strStatusBar;
    else if (strFor == "rpc")
        return strRPC;
    assert(!"GetWarnings() : invalid parameter");
    return "error";
}








//////////////////////////////////////////////////////////////////////////////
//
// Messages
//


bool static AlreadyHave(CTxDB& txdb, const CInv& inv)
{
    switch (inv.type)
    {
    case MSG_TX:
        {
        bool txInMap = false;
        txInMap = mempool.exists(inv.hash);
        return txInMap ||
               mapOrphanTransactions.count(inv.hash) ||
               txdb.ContainsTx(inv.hash);
        }

    case MSG_BLOCK:
        return mapBlockIndex.count(inv.hash) ||
                //dont load that block index here, cuz dos
                // it will load when they send it, then we know we have it
               mapOrphanBlocks.count(inv.hash);
    }
    // Don't know what it is, just say we already got one
    return true;
}


bool AcidTest(std::string precommand, std::string acid, CNode* pfrom)
{
    std::vector<std::string> vCommand = split(acid,",");
    if (vCommand.size() >= 6)
    {
        std::string sboinchashargs = DefaultOrgKey(12);  //Use 12 characters for inter-client communication
        std::string nonce =          vCommand[0];
        std::string command =        vCommand[1];
        std::string hash =           vCommand[2];
        std::string org =            vCommand[3];
        std::string pub_key_prefix = vCommand[4];
        std::string bhrn =           vCommand[5];
        std::string grid_pass =      vCommand[6];
        std::string grid_pass_decrypted = AdvancedDecryptWithSalt(grid_pass,sboinchashargs);

        if (grid_pass_decrypted != bhrn+nonce+org+pub_key_prefix)
        {
            if (fDebug10) printf("Decrypted gridpass %s <> hashed message",grid_pass_decrypted.c_str());
            nonce="";
            command="";
        }

        std::string pw1 = RetrieveMd5(nonce+","+command+","+org+","+pub_key_prefix+","+sboinchashargs);

        if (precommand=="aries")
        {
            //pfrom->securityversion = pw1;
        }
        if (fDebug10) printf(" Nonce %s,comm %s,hash %s,pw1 %s \r\n",nonce.c_str(),command.c_str(),hash.c_str(),pw1.c_str());
        if (false && hash != pw1)
        {
            //2/16 18:06:48 Acid test failed for 192.168.1.4:32749 1478973994,encrypt,1b089d19d23fbc911c6967b948dd8324,windows          if (fDebug) printf("Acid test failed for %s %s.",NodeAddress(pfrom).c_str(),acid.c_str());
            double punishment = GetArg("-punishment", 10);
            pfrom->Misbehaving(punishment);
            return false;
        }
        return true;
    }
    else
    {
        if (fDebug2) printf("Message corrupted. Node %s partially banned.",NodeAddress(pfrom).c_str());
        pfrom->Misbehaving(1);
        return false;
    }
    return true;
}




// The message start string is designed to be unlikely to occur in normal data.
// The characters are rarely used upper ASCII, not valid as UTF-8, and produce
// a large 4-byte int at any alignment.
unsigned char pchMessageStart[4] = { 0x70, 0x35, 0x22, 0x05 };


std::string NodeAddress(CNode* pfrom)
{
    std::string ip = pfrom->addr.ToString();
    return ip;
}

double ExtractMagnitudeFromExplainMagnitude()
{
        if (msNeuralResponse.empty()) return 0;
        try
        {
            std::vector<std::string> vMag = split(msNeuralResponse.c_str(),"<ROW>");
            for (unsigned int i = 0; i < vMag.size(); i++)
            {
                if (Contains(vMag[i],"Total Mag:"))
                {
                    std::vector<std::string> vMyMag = split(vMag[i].c_str(),":");
                    if (vMyMag.size() > 0)
                    {
                        std::string sSubMag = vMyMag[1];
                        sSubMag = strReplace(sSubMag," ","");
                        double dMag = cdbl("0"+sSubMag,0);
                        return dMag;
                    }
                }
            }
            return 0;
        }
        catch(...)
        {
            return 0;
        }
        return 0;
}

bool VerifyExplainMagnitudeResponse()
{
        if (msNeuralResponse.empty()) return false;
        try
        {
            double dMag = ExtractMagnitudeFromExplainMagnitude();
            if (dMag==0)
            {
                    WriteCache("maginvalid","invalid",RoundToString(cdbl("0"+ReadCache("maginvalid","invalid"),0),0),GetAdjustedTime());
                    double failures = cdbl("0"+ReadCache("maginvalid","invalid"),0);
                    if (failures < 10)
                    {
                        msNeuralResponse = "";
                    }
            }
            else
            {
                return true;
            }
        }
        catch(...)
        {
            return false;
        }
        return false;
}


bool SecurityTest(CNode* pfrom, bool acid_test)
{
    if (pfrom->nStartingHeight > (Best.GetHeight()*.5) && acid_test) return true;
    return false;
}


bool PreventCommandAbuse(std::string sNeuralRequestID, std::string sCommandName)
{
                bool bIgnore = false;
                if (cdbl("0"+ReadCache(sCommandName,sNeuralRequestID),0) > 10)
                {
                    if (fDebug10) printf("Ignoring %s request for %s",sCommandName.c_str(),sNeuralRequestID.c_str());
                    bIgnore = true;
                }
                if (!bIgnore)
                {
                    WriteCache(sCommandName,sNeuralRequestID,RoundToString(cdbl("0"+ReadCache(sCommandName,sNeuralRequestID),0),0),GetAdjustedTime());
                }
                return bIgnore;
}

bool static ProcessMessage(CNode* pfrom, string strCommand, CDataStream& vRecv, int64_t nTimeReceived)
{
    RandAddSeedPerfmon();
    if (fDebug10)
        printf("received: %s (%" PRIszu " bytes)\n", strCommand.c_str(), vRecv.size());
    if (mapArgs.count("-dropmessagestest") && GetRand(atoi(mapArgs["-dropmessagestest"])) == 0)
    {
        printf("dropmessagestest DROPPING RECV MESSAGE\n");
        return true;
    }

    // Stay in Sync - 8-9-2016
    if (!IsLockTimeWithinMinutes(nBootup,15))
    {
        if ((!IsLockTimeWithinMinutes(nLastAskedForBlocks,5) && WalletOutOfSync()) || (WalletOutOfSync() && fTestNet))
        {
            if(fDebug) printf("\r\nBootup\r\n");
            AskForOutstandingBlocks(uint256(0));
        }
    }

    // Message Attacks ////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////////

    if (strCommand == "aries")
    {
        // Each connection can only send one version message
        if (pfrom->nVersion != 0)
        {
            pfrom->Misbehaving(10);
            return false;
        }

        int64_t nTime;
        CAddress addrMe;
        CAddress addrFrom;
        uint64_t nNonce = 1;
        std::string acid = "";
        vRecv >> pfrom->nVersion >> pfrom->boinchashnonce >> pfrom->boinchashpw >> pfrom->cpid >> pfrom->enccpid >> acid >> pfrom->nServices >> nTime >> addrMe;

        
        //Halford - 12-26-2014 - Thwart Hackers
        bool ver_valid = AcidTest(strCommand,acid,pfrom);
        if (fDebug10) printf("Ver Acid %s, Validity %s ",acid.c_str(),YesNo(ver_valid).c_str());
        if (!ver_valid)
        {
            pfrom->Misbehaving(100);
            pfrom->fDisconnect = true;
            return false;
        }

        bool unauthorized = false;
        double timedrift = std::abs(GetAdjustedTime() - nTime);

        if (true)
        {
            if (timedrift > (8*60))
            {
                if (fDebug10) printf("Disconnecting unauthorized peer with Network Time so far off by %f seconds!\r\n",(double)timedrift);
                unauthorized = true;
            }
        }
        else
        {
            if (timedrift > (10*60) && LessVerbose(500))
            {
                if (fDebug10) printf("Disconnecting authorized peer with Network Time so far off by %f seconds!\r\n",(double)timedrift);
                unauthorized = true;
            }
        }

        if (unauthorized)
        {
            if (fDebug10) printf("  Disconnected unauthorized peer.         ");
            pfrom->Misbehaving(100);
            pfrom->fDisconnect = true;
            return false;
        }


        // Ensure testnet users are running latest version as of 12-3-2015 (works in conjunction with block spamming)
        if (pfrom->nVersion < 180321 && fTestNet)
        {
            // disconnect from peers older than this proto version
            if (fDebug10) printf("Testnet partner %s using obsolete version %i; disconnecting\n", pfrom->addr.ToString().c_str(), pfrom->nVersion);
            pfrom->fDisconnect = true;
            return false;
        }

        if (pfrom->nVersion < MIN_PEER_PROTO_VERSION)
        {
            // disconnect from peers older than this proto version
            if (fDebug10) printf("partner %s using obsolete version %i; disconnecting\n", pfrom->addr.ToString().c_str(), pfrom->nVersion);
            pfrom->fDisconnect = true;
            return false;
        }

        if (pfrom->nVersion < 180323 && !fTestNet && Best.GetHeight() > 860500)
        {
            // disconnect from peers older than this proto version - Enforce Beacon Age - 3-26-2017
            if (fDebug10) printf("partner %s using obsolete version %i (before enforcing beacon age); disconnecting\n", pfrom->addr.ToString().c_str(), pfrom->nVersion);
            pfrom->fDisconnect = true;
            return false;
        }

        if (!fTestNet && pfrom->nVersion < 180314 && IsResearchAgeEnabled(Best.GetHeight()))
        {
            // disconnect from peers older than this proto version
            if (fDebug10) printf("ResearchAge: partner %s using obsolete version %i; disconnecting\n", pfrom->addr.ToString().c_str(), pfrom->nVersion);
            pfrom->fDisconnect = true;
            return false;
       }

        if (pfrom->nVersion == 10300)
            pfrom->nVersion = 300;
        if (!vRecv.empty())
            vRecv >> addrFrom >> nNonce;
        if (!vRecv.empty())
            vRecv >> pfrom->strSubVer;

        if (!vRecv.empty())
            vRecv >> pfrom->nStartingHeight;
        // 12-5-2015 - Append Trust fields
        pfrom->nTrust = 0;
        
        if (!vRecv.empty())         vRecv >> pfrom->sGRCAddress;
        
        
        // Allow newbies to connect easily with 0 blocks
        if (GetArgument("autoban","true") == "true")
        {
                
                // Note: Hacking attempts start in this area
                if (false && pfrom->nStartingHeight < (Best.GetHeight()/2) && LessVerbose(1) && !fTestNet)
                {
                    if (fDebug3) printf("Node with low height");
                    pfrom->fDisconnect=true;
                    return false;
                }
                /*
                
                if (pfrom->nStartingHeight < 1 && LessVerbose(980) && !fTestNet)
                {
                    pfrom->Misbehaving(100);
                    if (fDebug3) printf("Disconnecting possible hacker node.  Banned for 24 hours.\r\n");
                    pfrom->fDisconnect=true;
                    return false;
                }
                */


                // End of critical Section

                if (pfrom->nStartingHeight < 1 && pfrom->nServices == 0 )
                {
                    pfrom->Misbehaving(100);
                    if (fDebug3) printf("Disconnecting possible hacker node with no services.  Banned for 24 hours.\r\n");
                    pfrom->fDisconnect=true;
                    return false;
                }
        }

    

        if (pfrom->fInbound && addrMe.IsRoutable())
        {
            pfrom->addrLocal = addrMe;
            SeenLocal(addrMe);
        }

        // Disconnect if we connected to ourself
        if (nNonce == nLocalHostNonce && nNonce > 1)
        {
            if (fDebug3) printf("connected to self at %s, disconnecting\n", pfrom->addr.ToString().c_str());
            pfrom->fDisconnect = true;
            return true;
        }

        // record my external IP reported by peer
        if (addrFrom.IsRoutable() && addrMe.IsRoutable())
            addrSeenByPeer = addrMe;

        // Be shy and don't send version until we hear
        if (pfrom->fInbound)
            pfrom->PushVersion();

        pfrom->fClient = !(pfrom->nServices & NODE_NETWORK);

        if (GetBoolArg("-synctime", true))
            AddTimeData(pfrom->addr, nTime);

        // Change version
        pfrom->PushMessage("verack");
        pfrom->ssSend.SetVersion(min(pfrom->nVersion, PROTOCOL_VERSION));

            
        if (!pfrom->fInbound)
        {
            // Advertise our address
            if (!fNoListen && !IsInitialBlockDownload())
            {
                CAddress addr = GetLocalAddress(&pfrom->addr);
                if (addr.IsRoutable())
                    pfrom->PushAddress(addr);
            }

            // Get recent addresses
            if (pfrom->fOneShot || pfrom->nVersion >= CADDR_TIME_VERSION || addrman.size() < 1000)
            {
                pfrom->PushMessage("getaddr");
                pfrom->fGetAddr = true;
            }
            addrman.Good(pfrom->addr);
        }
        else
        {
            if (((CNetAddr)pfrom->addr) == (CNetAddr)addrFrom)
            {
                if (SecurityTest(pfrom,ver_valid))
                {
                    //Dont store the peer unless it passes the test
                    addrman.Add(addrFrom, addrFrom);
                    addrman.Good(addrFrom);
                }
            }
        }

    
        // Ask the first connected node for block updates
        static int nAskedForBlocks = 0;
        if (!pfrom->fClient && !pfrom->fOneShot &&
            (pfrom->nStartingHeight > (Best.GetHeight() - 144)) &&
            (pfrom->nVersion < NOBLKS_VERSION_START ||
             pfrom->nVersion >= NOBLKS_VERSION_END) &&
             (nAskedForBlocks < 1 || (vNodes.size() <= 1 && nAskedForBlocks < 1)))
        {
            nAskedForBlocks++;
            pfrom->PushGetBlocks(Best.top, uint256(0), true);
            if (fDebug3) printf("\r\nAsked For blocks.\r\n");
        }

        // Relay alerts
        {
            LOCK(cs_mapAlerts);
            BOOST_FOREACH(PAIRTYPE(const uint256, CAlert)& item, mapAlerts)
                item.second.RelayTo(pfrom);
        }

        // Relay sync-checkpoint
        {
            LOCK(Checkpoints::cs_hashSyncCheckpoint);
            if (!Checkpoints::checkpointMessage.IsNull())
                Checkpoints::checkpointMessage.RelayTo(pfrom);
        }

        pfrom->fSuccessfullyConnected = true;

        if (fDebug10) printf("receive version message: version %d, blocks=%d, us=%s, them=%s, peer=%s\n", pfrom->nVersion,
            pfrom->nStartingHeight, addrMe.ToString().c_str(), addrFrom.ToString().c_str(), pfrom->addr.ToString().c_str());

        cPeerBlockCounts.input(pfrom->nStartingHeight);

        // ppcoin: ask for pending sync-checkpoint if any
        if (!IsInitialBlockDownload())
            Checkpoints::AskForPendingSyncCheckpoint(pfrom);
    }
    else if (pfrom->nVersion == 0)
    {
        // Must have a version message before anything else 1-10-2015 Halford
        printf("Hack attempt from %s - %s (banned) \r\n",pfrom->addrName.c_str(),NodeAddress(pfrom).c_str());
        pfrom->Misbehaving(100);
        pfrom->fDisconnect=true;
        return false;
    }
    else if (strCommand == "verack")
    {
        pfrom->SetRecvVersion(min(pfrom->nVersion, PROTOCOL_VERSION));
    }
    else if (strCommand == "gridaddr")
    {
        //addr->gridaddr
        vector<CAddress> vAddr;
        vRecv >> vAddr;

        // Don't want addr from older versions unless seeding
        if (pfrom->nVersion < CADDR_TIME_VERSION && addrman.size() > 1000)
            return true;
        if (vAddr.size() > 1000)
        {
            pfrom->Misbehaving(10);
            return error("message addr size() = %" PRIszu "", vAddr.size());
        }

        // Don't store the node address unless they have block height > 50%
        if (pfrom->nStartingHeight < (Best.GetHeight()*.5) && LessVerbose(975)) return true;

        // Store the new addresses
        vector<CAddress> vAddrOk;
        int64_t nNow = GetAdjustedTime();
        int64_t nSince = nNow - 10 * 60;
        BOOST_FOREACH(CAddress& addr, vAddr)
        {
            if (fShutdown)
                return true;
            if (addr.nTime <= 100000000 || addr.nTime > nNow + 10 * 60)
                addr.nTime = nNow - 5 * 24 * 60 * 60;
            pfrom->AddAddressKnown(addr);
            bool fReachable = IsReachable(addr);

            bool bad_node = (pfrom->nStartingHeight < 1 && LessVerbose(700));


            if (addr.nTime > nSince && !pfrom->fGetAddr && vAddr.size() <= 10 && addr.IsRoutable() && !bad_node)
            {
                // Relay to a limited number of other nodes
                {
                    LOCK(cs_vNodes);
                    // Use deterministic randomness to send to the same nodes for 24 hours
                    // at a time so the setAddrKnowns of the chosen nodes prevent repeats
                    static uint256 hashSalt;
                    if (hashSalt == 0)
                        hashSalt = GetRandHash();
                    uint64_t hashAddr = addr.GetHash();
                    uint256 hashRand = hashSalt ^ (hashAddr<<32) ^ (( GetAdjustedTime() +hashAddr)/(24*60*60));
                    hashRand = Hash(BEGIN(hashRand), END(hashRand));
                    multimap<uint256, CNode*> mapMix;
                    BOOST_FOREACH(CNode* pnode, vNodes)
                    {
                        if (pnode->nVersion < CADDR_TIME_VERSION)
                            continue;
                        unsigned int nPointer;
                        memcpy(&nPointer, &pnode, sizeof(nPointer));
                        uint256 hashKey = hashRand ^ nPointer;
                        hashKey = Hash(BEGIN(hashKey), END(hashKey));
                        mapMix.insert(make_pair(hashKey, pnode));
                    }
                    int nRelayNodes = fReachable ? 2 : 1; // limited relaying of addresses outside our network(s)
                    for (multimap<uint256, CNode*>::iterator mi = mapMix.begin(); mi != mapMix.end() && nRelayNodes-- > 0; ++mi)
                        ((*mi).second)->PushAddress(addr);
                }
            }
            // Do not store addresses outside our network
            if (fReachable)
                vAddrOk.push_back(addr);
        }
        addrman.Add(vAddrOk, pfrom->addr, 2 * 60 * 60);
        if (vAddr.size() < 1000)
            pfrom->fGetAddr = false;
        if (pfrom->fOneShot)
            pfrom->fDisconnect = true;
    }

    else if (strCommand == "inv")
    {
        vector<CInv> vInv;
        vRecv >> vInv;
        if (vInv.size() > MAX_INV_SZ)
        {
            pfrom->Misbehaving(50);
            printf("\r\n **Hacker tried to send inventory > MAX_INV_SZ **\r\n");
            return error("message inv size() = %" PRIszu "", vInv.size());
        }

        // find last block in inv vector
        unsigned int nLastBlock = (unsigned int)(-1);
        for (unsigned int nInv = 0; nInv < vInv.size(); nInv++) {
            if (vInv[vInv.size() - 1 - nInv].type == MSG_BLOCK) {
                nLastBlock = vInv.size() - 1 - nInv;
                break;
            }
        }
        CTxDB txdb("r");
        for (unsigned int nInv = 0; nInv < vInv.size(); nInv++)
        {
            const CInv &inv = vInv[nInv];

            if (fShutdown)
                return true;
            pfrom->AddInventoryKnown(inv);

            bool fAlreadyHave = AlreadyHave(txdb, inv);
            if (fDebug10)
                printf("  got inventory: %s  %s\n", inv.ToString().c_str(), fAlreadyHave ? "have" : "new");

            if (!fAlreadyHave)
                pfrom->AskFor(inv);
            else if (inv.type == MSG_BLOCK && mapOrphanBlocks.count(inv.hash)) {
                pfrom->PushGetBlocks(Best.top, GetOrphanRoot(mapOrphanBlocks[inv.hash]), true);
            } else if (nInv == nLastBlock) {
                // In case we are on a very long side-chain, it is possible that we already have
                // the last block in an inv bundle sent in response to getblocks. Try to detect
                // this situation and push another getblocks to continue.
                pfrom->PushGetBlocks(mapBlockIndex[inv.hash], uint256(0), true);
                // same here, dont load the index
                if (fDebug10)
                    printf("force getblock request: %s\n", inv.ToString().c_str());
            }

            // Track requests for our stuff
            Inventory(inv.hash);
        }
    }


    else if (strCommand == "getdata")
    {
        vector<CInv> vInv;
        vRecv >> vInv;
        if (vInv.size() > MAX_INV_SZ)
        {
            pfrom->Misbehaving(10);
            return error("message getdata size() = %" PRIszu "", vInv.size());
        }

        if (fDebugNet || (vInv.size() != 1))
        {
            if (fDebug10)  printf("received getdata (%" PRIszu " invsz)\n", vInv.size());
        }

        BOOST_FOREACH(const CInv& inv, vInv)
        {
            if (fShutdown)
                return true;
            if (fDebugNet || (vInv.size() == 1))
            {
              if (fDebug10)   printf("received getdata for: %s\n", inv.ToString().c_str());
            }

            if (inv.type == MSG_BLOCK)
            {
                // Send block from disk
                CBlockIndex* mi = CBlockIndex::GetByHash(inv.hash);
                if (mi)
                {
                    CBlock block;
                    block.ReadFromDisk(mi);
                    //HALFORD 12-26-2014
                    std::string acid = GetCommandNonce("encrypt");
                    pfrom->PushMessage("encrypt", block, acid);

                    // Trigger them to send a getblocks request for the next batch of inventory
                    if (inv.hash == pfrom->hashContinue)
                    {
                        // ppcoin: send latest proof-of-work block to allow the
                        // download node to accept as orphan (proof-of-stake
                        // block might be rejected by stake connection check)
                        vector<CInv> vInv;
                        vInv.push_back(CInv(MSG_BLOCK, GetLastBlockIndex(Best.top, false)->GetBlockHash()));
                        pfrom->PushMessage("inv", vInv);
                        pfrom->hashContinue = 0;
                    }
                }
            }
             else if (inv.IsKnownType())
            {
                // Send stream from relay memory
                bool pushed = false;
                {
                    LOCK(cs_mapRelay);
                    map<CInv, CDataStream>::iterator mi = mapRelay.find(inv);
                    if (mi != mapRelay.end()) {
                        pfrom->PushMessage(inv.GetCommand(), (*mi).second);
                        pushed = true;
                    }
                }
                if (!pushed && inv.type == MSG_TX) {
                    CTransaction tx;
                    if (mempool.lookup(inv.hash, tx)) {
                        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                        ss.reserve(1000);
                        ss << tx;
                        pfrom->PushMessage("tx", ss);
                    }
                }
            }

            // Track requests for our stuff
            Inventory(inv.hash);
        }
    }

    else if (strCommand == "getblocks")
    {
        CBlockLocator locator;
        uint256 hashStop;
        vRecv >> locator >> hashStop;

        // Find the last block the caller has in the main chain
        CBlockIndex* pindex = locator.GetBlockIndex();

        // Send the rest of the chain
        if (pindex)
            pindex = pindex->GetNext();
        int nLimit = 1000;

        if (fDebug3) printf("\r\ngetblocks %d to %s limit %d\n", (pindex ? pindex->nHeight : -1), hashStop.ToString().substr(0,20).c_str(), nLimit);
        for (; pindex; pindex = pindex->GetNext())
        {
            if (pindex->GetBlockHash() == hashStop)
            {
                if (fDebug3) printf("\r\n  getblocks stopping at %d %s\n", pindex->nHeight, pindex->GetBlockHash().ToString().substr(0,20).c_str());
                // ppcoin: tell downloading node about the latest block if it's
                // without risk being rejected due to stake connection check
                if (hashStop != Best.top->GetBlockHash() && pindex->GetBlockTime() + nStakeMinAge > Best.top->GetBlockTime())
                    pfrom->PushInventory(CInv(MSG_BLOCK, Best.top->GetBlockHash()));
                break;
            }
            pfrom->PushInventory(CInv(MSG_BLOCK, pindex->GetBlockHash()));
            if (--nLimit <= 0)
            {
                // When this block is requested, we'll send an inv that'll make them
                // getblocks the next batch of inventory.
                if (fDebug3) printf("\r\n  getblocks stopping at limit %d %s\n", pindex->nHeight, pindex->GetBlockHash().ToString().substr(0,20).c_str());
                pfrom->hashContinue = pindex->GetBlockHash();
                break;
            }
        }
    }
    else if (strCommand == "checkpoint")
    {
        CSyncCheckpoint checkpoint;
        vRecv >> checkpoint;
        //Checkpoint received from node with more than 1 Million GRC:
        if (CHECKPOINT_DISTRIBUTED_MODE==0 || CHECKPOINT_DISTRIBUTED_MODE==1)
        {
            if (checkpoint.ProcessSyncCheckpoint(pfrom))
            {
                // Relay
                pfrom->hashCheckpointKnown = checkpoint.hashCheckpoint;
                LOCK(cs_vNodes);
                BOOST_FOREACH(CNode* pnode, vNodes)
                    checkpoint.RelayTo(pnode);
            }
        }
        else if (CHECKPOINT_DISTRIBUTED_MODE == 2)
        {
            // R HALFORD: One of our global GRC nodes solved a PoR block, store the last blockhash in memory
            muGlobalCheckpointHash = checkpoint.hashCheckpointGlobal;
            // Relay
            pfrom->hashCheckpointKnown = checkpoint.hashCheckpointGlobal;
            //Prevent broadcast storm: If not broadcast yet, relay the checkpoint globally:
            if (muGlobalCheckpointHashRelayed != checkpoint.hashCheckpointGlobal && checkpoint.hashCheckpointGlobal != 0)
            {
                LOCK(cs_vNodes);
                BOOST_FOREACH(CNode* pnode, vNodes)
                {
                    checkpoint.RelayTo(pnode);
                }
            }
        }
    }

    else if (strCommand == "getheaders")
    {
        CBlockLocator locator;
        uint256 hashStop;
        vRecv >> locator >> hashStop;

        CBlockIndex* pindex = NULL;
        if (locator.IsNull())
        {
            // If locator is null, return the hashStop block
            CBlockIndex* mi = CBlockIndex::GetByHash(hashStop);
            if (mi == NULL)
                return true;
            pindex = mi;
        }
        else
        {
            // Find the last block the caller has in the main chain
            pindex = locator.GetBlockIndex();
            if (pindex)
                pindex = pindex->GetNext();
        }

        vector<CBlock> vHeaders;
        int nLimit = 1000;
        printf("\r\ngetheaders %d to %s\n", (pindex ? pindex->nHeight : -1), hashStop.ToString().substr(0,20).c_str());
        for (; pindex; pindex = pindex->GetNext())
        {
            vHeaders.push_back(pindex->GetBlockHeader());
            if (--nLimit <= 0 || pindex->GetBlockHash() == hashStop)
                break;
        }
        pfrom->PushMessage("headers", vHeaders);
    }
    else if (strCommand == "tx")
    {
        vector<uint256> vWorkQueue;
        vector<uint256> vEraseQueue;
        CTransaction tx;
        vRecv >> tx;

        CInv inv(MSG_TX, tx.GetHash());
        pfrom->AddInventoryKnown(inv);

        bool fMissingInputs = false;
        if (AcceptToMemoryPool(mempool, tx, &fMissingInputs))
        {
            RelayTransaction(tx, inv.hash);
            mapAlreadyAskedFor.erase(inv);
            vWorkQueue.push_back(inv.hash);
            vEraseQueue.push_back(inv.hash);
         
            // Recursively process any orphan transactions that depended on this one
            for (unsigned int i = 0; i < vWorkQueue.size(); i++)
            {
                uint256 hashPrev = vWorkQueue[i];
                for (set<uint256>::iterator mi = mapOrphanTransactionsByPrev[hashPrev].begin();
                     mi != mapOrphanTransactionsByPrev[hashPrev].end();
                     ++mi)
                {
                    const uint256& orphanTxHash = *mi;
                    CTransaction& orphanTx = mapOrphanTransactions[orphanTxHash];
                    bool fMissingInputs2 = false;

                    if (AcceptToMemoryPool(mempool, orphanTx, &fMissingInputs2))
                    {
                        printf("   accepted orphan tx %s\n", orphanTxHash.ToString().substr(0,10).c_str());
                        RelayTransaction(orphanTx, orphanTxHash);
                        mapAlreadyAskedFor.erase(CInv(MSG_TX, orphanTxHash));
                        vWorkQueue.push_back(orphanTxHash);
                        vEraseQueue.push_back(orphanTxHash);
                        pfrom->nTrust++;
                    }
                    else if (!fMissingInputs2)
                    {
                        // invalid orphan
                        vEraseQueue.push_back(orphanTxHash);
                        printf("   removed invalid orphan tx %s\n", orphanTxHash.ToString().substr(0,10).c_str());
                    }
                }
            }

            BOOST_FOREACH(uint256 hash, vEraseQueue)
                EraseOrphanTx(hash);
        }
        else if (fMissingInputs)
        {
            AddOrphanTx(tx);

            // DoS prevention: do not allow mapOrphanTransactions to grow unbounded
            unsigned int nEvicted = LimitOrphanTxSize(MAX_ORPHAN_TRANSACTIONS);
            if (nEvicted > 0)
                printf("mapOrphan overflow, removed %u tx\n", nEvicted);
        }
        if (tx.nDoS) pfrom->Misbehaving(tx.nDoS);
    }


    else if (strCommand == "encrypt")
    {
        //Response from getblocks, message = block

        CBlock block;
        std::string acid = "";
        vRecv >> block >> acid;
        uint256 hashBlock = block.GetHash();

        bool block_valid = AcidTest(strCommand,acid,pfrom);
        if (!block_valid) 
        {   
            printf("\r\n Acid test failed for block %s \r\n",hashBlock.ToString().c_str());
            return false;
        }

        if (fDebug10) printf("Acid %s, Validity %s ",acid.c_str(),YesNo(block_valid).c_str());

        printf(" Received block %s; ", hashBlock.ToString().c_str());
        if (fDebug10) block.print();

        CInv inv(MSG_BLOCK, hashBlock);
        pfrom->AddInventoryKnown(inv);

        if (ProcessBlock(pfrom, &block, false))
        {
            mapAlreadyAskedFor.erase(inv);
            pfrom->nTrust++;
        }
        if (block.nDoS) 
        {
                pfrom->Misbehaving(block.nDoS);
                pfrom->nTrust--;
        }

    }


    else if (strCommand == "getaddr")
    {
        // Don't return addresses older than nCutOff timestamp
        int64_t nCutOff =  GetAdjustedTime() - (nNodeLifespan * 24 * 60 * 60);
        pfrom->vAddrToSend.clear();
        vector<CAddress> vAddr = addrman.GetAddr();
        BOOST_FOREACH(const CAddress &addr, vAddr)
            if(addr.nTime > nCutOff)
                pfrom->PushAddress(addr);
    }


    else if (strCommand == "mempool")
    {
        std::vector<uint256> vtxid;
        mempool.queryHashes(vtxid);
        vector<CInv> vInv;
        for (unsigned int i = 0; i < vtxid.size(); i++) {
            CInv inv(MSG_TX, vtxid[i]);
            vInv.push_back(inv);
            if (i == (MAX_INV_SZ - 1))
                    break;
        }
        if (vInv.size() > 0)
            pfrom->PushMessage("inv", vInv);
    }

    else if (strCommand == "reply")
    {
        uint256 hashReply;
        vRecv >> hashReply;

        CRequestTracker tracker;
        {
            LOCK(pfrom->cs_mapRequests);
            map<uint256, CRequestTracker>::iterator mi = pfrom->mapRequests.find(hashReply);
            if (mi != pfrom->mapRequests.end())
            {
                tracker = (*mi).second;
                pfrom->mapRequests.erase(mi);
            }
        }
        if (!tracker.IsNull())
            tracker.fn(tracker.param1, vRecv);
    }
    else if (strCommand == "neural")
    {
            //printf("Received Neural Request \r\n");

            std::string neural_request = "";
            std::string neural_request_id = "";
            vRecv >> neural_request >> neural_request_id;  // foreign node issued neural request with request ID:
            //printf("neural request %s \r\n",neural_request.c_str());
            std::string neural_response = "generic_response";

            if (neural_request=="neural_data")
            {
                if (!PreventCommandAbuse("neural_data",NodeAddress(pfrom)))
                {
                    std::string contract = "";
                    #if defined(WIN32) && defined(QT_GUI)
                            std::string testnet_flag = fTestNet ? "TESTNET" : "MAINNET";
                            qtExecuteGenericFunction("SetTestNetFlag",testnet_flag);
                            contract = qtGetNeuralContract("");
                    #endif
                    pfrom->PushMessage("ndata_nresp", contract);
                }
            }
            else if (neural_request=="neural_hash")
            {
                #if defined(WIN32) && defined(QT_GUI)
                    neural_response = qtGetNeuralHash("");
                #endif
                //printf("Neural response %s",neural_response.c_str());
                pfrom->PushMessage("hash_nresp", neural_response);
            }
            else if (neural_request=="explainmag")
            {
                // To prevent abuse, only respond to a certain amount of explainmag requests per day per cpid
                bool bIgnore = false;
                if (cdbl("0"+ReadCache("explainmag",neural_request_id),0) > 10)
                {
                    if (fDebug10) printf("Ignoring explainmag request for %s",neural_request_id.c_str());
                    pfrom->Misbehaving(1);
                    bIgnore = true;
                }
                if (!bIgnore)
                {
                    WriteCache("explainmag",neural_request_id,RoundToString(cdbl("0"+ReadCache("explainmag",neural_request_id),0),0),GetAdjustedTime());
                    // 7/11/2015 - Allow linux/mac to make neural requests
                    #if defined(WIN32) && defined(QT_GUI)
                        neural_response = qtExecuteDotNetStringFunction("ExplainMag",neural_request_id);
                    #endif
                    pfrom->PushMessage("expmag_nresp", neural_response);
                }
            }
            else if (neural_request=="quorum")
            {
                // 7-12-2015 Resolve discrepencies in the neural network intelligently - allow nodes to speak to each other
                std::string contract = "";
                #if defined(WIN32) && defined(QT_GUI)
                        std::string testnet_flag = fTestNet ? "TESTNET" : "MAINNET";
                        qtExecuteGenericFunction("SetTestNetFlag",testnet_flag);
                        contract = qtGetNeuralContract("");
                #endif
                //if (fDebug10) printf("Quorum response %f \r\n",(double)contract.length());
                pfrom->PushMessage("quorum_nresp", contract);
            }
            else
            {
                neural_response="generic_response";
            }

    }
    else if (strCommand == "ping")
    {
        std::string acid = "";
        if (pfrom->nVersion > BIP0031_VERSION)
        {
            uint64_t nonce = 0;
            vRecv >> nonce >> acid;
            bool pong_valid = AcidTest(strCommand,acid,pfrom);
            if (!pong_valid) return false;
            //if (fDebug10) printf("pong valid %s",YesNo(pong_valid).c_str());

            // Echo the message back with the nonce. This allows for two useful features:
            //
            // 1) A remote node can quickly check if the connection is operational
            // 2) Remote nodes can measure the latency of the network thread. If this node
            //    is overloaded it won't respond to pings quickly and the remote node can
            //    avoid sending us more work, like chain download requests.
            //
            // The nonce stops the remote getting confused between different pings: without
            // it, if the remote node sends a ping once per second and this node takes 5
            // seconds to respond to each, the 5th ping the remote sends would appear to
            // return very quickly.
            pfrom->PushMessage("pong", nonce);
        }
    }
    else if (strCommand == "pong")
    {
        int64_t pingUsecEnd = GetTimeMicros();
        uint64_t nonce = 0;
        size_t nAvail = vRecv.in_avail();
        bool bPingFinished = false;
        std::string sProblem;

        if (nAvail >= sizeof(nonce)) {
            vRecv >> nonce;

            // Only process pong message if there is an outstanding ping (old ping without nonce should never pong)
            if (pfrom->nPingNonceSent != 0) 
            {
                if (nonce == pfrom->nPingNonceSent) 
                {
                    // Matching pong received, this ping is no longer outstanding
                    bPingFinished = true;
                    int64_t pingUsecTime = pingUsecEnd - pfrom->nPingUsecStart;
                    if (pingUsecTime > 0) {
                        // Successful ping time measurement, replace previous
                        pfrom->nPingUsecTime = pingUsecTime;
                    } else {
                        // This should never happen
                        sProblem = "Timing mishap";
                    }
                } else {
                    // Nonce mismatches are normal when pings are overlapping
                    sProblem = "Nonce mismatch";
                    if (nonce == 0) {
                        // This is most likely a bug in another implementation somewhere, cancel this ping
                        bPingFinished = true;
                        sProblem = "Nonce zero";
                    }
                }
            } else {
                sProblem = "Unsolicited pong without ping";
            }
        } else {
            // This is most likely a bug in another implementation somewhere, cancel this ping
            bPingFinished = true;
            sProblem = "Short payload";
        }

        if (!(sProblem.empty())) {
            printf("pong %s %s: %s, %" PRIx64 " expected, %" PRIx64 " received, %f bytes\n"
                , pfrom->addr.ToString().c_str()
                , pfrom->strSubVer.c_str()
                , sProblem.c_str()                , pfrom->nPingNonceSent                , nonce                , (double)nAvail);
        }
        if (bPingFinished) {
            pfrom->nPingNonceSent = 0;
        }
    }
    else if (strCommand == "hash_nresp")
    {
            std::string neural_response = "";
            vRecv >> neural_response;
            // if (pfrom->nNeuralRequestSent != 0)
            // nNeuralNonce must match request ID
            pfrom->NeuralHash = neural_response;
            if (fDebug10) printf("hash_Neural Response %s \r\n",neural_response.c_str());
    }
    else if (strCommand == "expmag_nresp")
    {
            std::string neural_response = "";
            vRecv >> neural_response;
            if (neural_response.length() > 10)
            {
                msNeuralResponse=neural_response;
                //If invalid, try again 10-20-2015
                VerifyExplainMagnitudeResponse();
            }
            if (fDebug10) printf("expmag_Neural Response %s \r\n",neural_response.c_str());
    }
    else if (strCommand == "quorum_nresp")
    {
            std::string neural_contract = "";
            vRecv >> neural_contract;
            if (fDebug && neural_contract.length() > 100) printf("Quorum contract received %s",neural_contract.substr(0,80).c_str());
            if (neural_contract.length() > 10)
            {
                 std::string results = "";
                 //Resolve discrepancies
                 #if defined(WIN32) && defined(QT_GUI)
                    std::string testnet_flag = fTestNet ? "TESTNET" : "MAINNET";
                    qtExecuteGenericFunction("SetTestNetFlag",testnet_flag);
                    results = qtExecuteDotNetStringFunction("ResolveDiscrepancies",neural_contract);
                 #endif
                 if (fDebug && !results.empty()) printf("Quorum Resolution: %s \r\n",results.c_str());
            }
    }
    else if (strCommand == "ndata_nresp")
    {
            std::string neural_contract = "";
            vRecv >> neural_contract;
            if (fDebug3 && neural_contract.length() > 100) printf("Quorum contract received %s",neural_contract.substr(0,80).c_str());
            if (neural_contract.length() > 10)
            {
                 std::string results = "";
                 //Resolve discrepancies
                 #if defined(WIN32) && defined(QT_GUI)
                    std::string testnet_flag = fTestNet ? "TESTNET" : "MAINNET";
                    qtExecuteGenericFunction("SetTestNetFlag",testnet_flag);
                    printf("\r\n** Sync neural network data from supermajority **\r\n");
                    results = qtExecuteDotNetStringFunction("ResolveCurrentDiscrepancies",neural_contract);
                 #endif
                 if (fDebug && !results.empty()) printf("Quorum Resolution: %s \r\n",results.c_str());
                 // Resume the full DPOR sync at this point now that we have the supermajority data
                 if (results=="SUCCESS")  FullSyncWithDPORNodes();
            }
    }
    else if (strCommand == "alert")
    {
        CAlert alert;
        vRecv >> alert;

        uint256 alertHash = alert.GetHash();
        if (pfrom->setKnown.count(alertHash) == 0)
        {
            if (alert.ProcessAlert())
            {
                // Relay
                pfrom->setKnown.insert(alertHash);
                {
                    LOCK(cs_vNodes);
                    BOOST_FOREACH(CNode* pnode, vNodes)
                        alert.RelayTo(pnode);
                }
            }
            else {
                // Small DoS penalty so peers that send us lots of
                // duplicate/expired/invalid-signature/whatever alerts
                // eventually get banned.
                // This isn't a Misbehaving(100) (immediate ban) because the
                // peer might be an older or different implementation with
                // a different signature key, etc.
                pfrom->Misbehaving(10);
            }
        }
    }


    else
    {
        // Ignore unknown commands for extensibility
        // Let the peer know that we didn't find what it asked for, so it doesn't
        // have to wait around forever. Currently only SPV clients actually care
        // about this message: it's needed when they are recursively walking the
        // dependencies of relevant unconfirmed transactions. SPV clients want to
        // do that because they want to know about (and store and rebroadcast and
        // risk analyze) the dependencies of transactions relevant to them, without
        // having to download the entire memory pool.


    }

    // Update the last seen time for this node's address
    if (pfrom->fNetworkNode)
        if (strCommand == "aries" || strCommand == "gridaddr" || strCommand == "inv" || strCommand == "getdata" || strCommand == "ping")
            AddressCurrentlyConnected(pfrom->addr);

    return true;
}


void AddPeek(std::string data)
{
    return;
    std::string buffer = RoundToString((double)GetAdjustedTime(),0) + ":" + data + "<CR>";
    msPeek += buffer;
    if (msPeek.length() > 60000) msPeek = "";
    if ((GetAdjustedTime() - nLastPeek) > 60)
    {
        if (fDebug) printf("\r\nLong Duration : %s\r\n",buffer.c_str());
    }
    nLastPeek = GetAdjustedTime();
}


// requires LOCK(cs_vRecvMsg)
bool ProcessMessages(CNode* pfrom)
{
    //
    // Message format
    //  (4) message start
    //  (12) command
    //  (4) size
    //  (4) checksum
    //  (x) data
    //
    bool fOk = true;

    std::deque<CNetMessage>::iterator it = pfrom->vRecvMsg.begin();
    while (!pfrom->fDisconnect && it != pfrom->vRecvMsg.end()) {
        // Don't bother if send buffer is too full to respond anyway
        if (pfrom->nSendSize >= SendBufferSize())
            break;

        // get next message
        CNetMessage& msg = *it;

        //if (fDebug10)
        //    printf("ProcessMessages(message %u msgsz, %zu bytes, complete:%s)\n",
        //            msg.hdr.nMessageSize, msg.vRecv.size(),
        //            msg.complete() ? "Y" : "N");

        // end, if an incomplete message is found
        if (!msg.complete())
            break;

        // at this point, any failure means we can delete the current message
        it++;

        // Scan for message start
        if (memcmp(msg.hdr.pchMessageStart, pchMessageStart, sizeof(pchMessageStart)) != 0) {
            if (fDebug10) printf("\n\nPROCESSMESSAGE: INVALID MESSAGESTART\n\n");
            fOk = false;
            break;
        }

        // Read header
        CMessageHeader& hdr = msg.hdr;
        if (!hdr.IsValid())
        {
            printf("\n\nPROCESSMESSAGE: ERRORS IN HEADER %s\n\n\n", hdr.GetCommand().c_str());
            continue;
        }
        string strCommand = hdr.GetCommand();


        // Message size
        unsigned int nMessageSize = hdr.nMessageSize;

        // Have a peek into what this node is doing
        if (false && LessVerbose(100))
        {
            std::string Peek = strCommand + ":" + RoundToString((double)nMessageSize,0) + " [" + NodeAddress(pfrom) + "]";
            AddPeek(Peek);
            std::string sCurrentCommand = RoundToString((double)GetAdjustedTime(),0) + Peek;
            std::string msLastNodeCommand = ReadCache("node_command",NodeAddress(pfrom));
            WriteCache("node_command",NodeAddress(pfrom),sCurrentCommand,GetAdjustedTime());
            if (msLastCommand == sCurrentCommand || (msLastNodeCommand == sCurrentCommand && !sCurrentCommand.empty()))
            {
                  //Node Duplicates
                  double node_duplicates = cdbl(ReadCache("duplicates",NodeAddress(pfrom)),0) + 1;
                  WriteCache("duplicates",NodeAddress(pfrom),RoundToString(node_duplicates,0),GetAdjustedTime());
                  if ((node_duplicates > 350 && !OutOfSyncByAge()))
                  {
                        printf(" Dupe (misbehaving) %s %s ",NodeAddress(pfrom).c_str(),Peek.c_str());
                        pfrom->fDisconnect = true;
                        WriteCache("duplicates",NodeAddress(pfrom),"0",GetAdjustedTime());
                        return false;
                  }
            }
            else
            {
                  double node_duplicates = cdbl(ReadCache("duplicates",NodeAddress(pfrom)),0) - 15;
                  if (node_duplicates < 1) node_duplicates = 0;
                  WriteCache("duplicates",NodeAddress(pfrom),RoundToString(node_duplicates,0),GetAdjustedTime());
            }
            msLastCommand = sCurrentCommand;
        }


        // Checksum
        CDataStream& vRecv = msg.vRecv;
        uint256 hash = Hash(vRecv.begin(), vRecv.begin() + nMessageSize);
        unsigned int nChecksum = 0;
        memcpy(&nChecksum, &hash, sizeof(nChecksum));
        if (nChecksum != hdr.nChecksum)
        {
            printf("ProcessMessages(%s, %u bytes) : CHECKSUM ERROR nChecksum=%08x hdr.nChecksum=%08x\n",
               strCommand.c_str(), nMessageSize, nChecksum, hdr.nChecksum);
            continue;
        }

        // Process message
        bool fRet = false;
        try
        {
            {
                LOCK(cs_main);
                fRet = ProcessMessage(pfrom, strCommand, vRecv, msg.nTime);
            }
            if (fShutdown)
                break;
        }
        catch (std::ios_base::failure& e)
        {
            if (strstr(e.what(), "end of data"))
            {
                // Allow exceptions from under-length message on vRecv
                printf("ProcessMessages(%s, %u bytes) : Exception '%s' caught, normally caused by a message being shorter than its stated length\n", strCommand.c_str(), nMessageSize, e.what());
            }
            else if (strstr(e.what(), "size too large"))
            {
                // Allow exceptions from over-long size
                printf("ProcessMessages(%s, %u bytes) : Exception '%s' caught\n", strCommand.c_str(), nMessageSize, e.what());
            }
            else
            {
                PrintExceptionContinue(&e, "ProcessMessages()");
            }
        }
        catch (std::exception& e) {
            PrintExceptionContinue(&e, "ProcessMessages()");
        } catch (...) {
            PrintExceptionContinue(NULL, "ProcessMessages()");
        }

        if (!fRet)
        {
           if (fDebug10)   printf("ProcessMessage(%s, %u bytes) FAILED\n", strCommand.c_str(), nMessageSize);
        }
    }

    // In case the connection got shut down, its receive buffer was wiped
    if (!pfrom->fDisconnect)
        pfrom->vRecvMsg.erase(pfrom->vRecvMsg.begin(), it);

    return fOk;
}

double LederstrumpfMagnitude2(double Magnitude, int64_t locktime)
{
    //2-1-2015 - Halford - The MagCap is 2000
    double MagCap = 2000;
    double out_mag = Magnitude;
    if (Magnitude >= MagCap*.90 && Magnitude <= MagCap*1.0) out_mag = MagCap*.90;
    if (Magnitude >= MagCap*1.0 && Magnitude <= MagCap*1.1) out_mag = MagCap*.91;
    if (Magnitude >= MagCap*1.1 && Magnitude <= MagCap*1.2) out_mag = MagCap*.92;
    if (Magnitude >= MagCap*1.2 && Magnitude <= MagCap*1.3) out_mag = MagCap*.93;
    if (Magnitude >= MagCap*1.3 && Magnitude <= MagCap*1.4) out_mag = MagCap*.94;
    if (Magnitude >= MagCap*1.4 && Magnitude <= MagCap*1.5) out_mag = MagCap*.95;
    if (Magnitude >= MagCap*1.5 && Magnitude <= MagCap*1.6) out_mag = MagCap*.96;
    if (Magnitude >= MagCap*1.6 && Magnitude <= MagCap*1.7) out_mag = MagCap*.97;
    if (Magnitude >= MagCap*1.7 && Magnitude <= MagCap*1.8) out_mag = MagCap*.98;
    if (Magnitude >= MagCap*1.8 && Magnitude <= MagCap*1.9) out_mag = MagCap*.99;
    if (Magnitude >= MagCap*1.9)                            out_mag = MagCap*1.0;
    return out_mag;
}

double PendingSuperblockHeight()
{
    double height = cdbl(ReadCache("neuralsecurity","pending"),0);
    if (height < (double)(Best.GetHeight()-200)) height = 0;
    return height;
}

std::string GetNeuralNetworkSuperBlock()
{
    //Only try to stake a superblock if the contract expired And the superblock is the highest popularity block And we do not have a pending superblock
    int64_t superblock_age = GetAdjustedTime() - mvApplicationCacheTimestamp["superblock;magnitudes"];
    if (IsNeuralNodeParticipant(DefaultWalletAddress(), GetAdjustedTime()) && NeedASuperblock() && PendingSuperblockHeight()==0)
    {
        std::string myNeuralHash = "";
        #if defined(WIN32) && defined(QT_GUI)
               myNeuralHash = qtGetNeuralHash("");
        #endif
        double popularity = 0;
        std::string consensus_hash = GetNeuralNetworkSupermajorityHash(popularity);
        if (fDebug2 && LessVerbose(5)) printf("SB Age %f, MyHash %s, ConsensusHash %s",(double)superblock_age,myNeuralHash.c_str(),consensus_hash.c_str());
        if (consensus_hash==myNeuralHash)
        {
            //Stake the contract
            std::string contract = "";
            #if defined(WIN32) && defined(QT_GUI)
                contract = qtGetNeuralContract("");
                if (fDebug2 && LessVerbose(5)) printf("Appending SuperBlock %f\r\n",(double)contract.length());
                if (AreBinarySuperblocksEnabled(Best.GetHeight()))
                {
                    // 12-21-2015 : Stake a binary superblock
                    contract = PackBinarySuperblock(contract);
                }
            #endif
            return contract;
        }

    }
    return "";

}

#if 0
void AddStuffToBoincBlock(MiningCPID mcpid, int BlockVersion)
{
    clientversion = FormatFullVersion();
    mcpid.GRCAddress = DefaultWalletAddress();
    if (!IsResearchAgeEnabled(Best.GetHeight()))
    {
        mcpid.Organization = DefaultOrg();
        mcpid.OrganizationKey = DefaultBlockKey(8); //Only reveal 8 characters
    }
    else
    {
        mcpid.projectname = "";
        mcpid.rac = 0;
        mcpid.NetworkRAC = 0;
    }

    std::string sNeuralHash = "";
    // To save network bandwidth, start posting the neural hashes in the CurrentNeuralHash field, so that out of sync neural network nodes can request neural data from those that are already synced and agree with the supermajority over the last 24 hrs
    if (!OutOfSyncByAge())
    {
        #if defined(WIN32) && defined(QT_GUI)
            sNeuralHash = qtGetNeuralHash("");
            mcpid.CurrentNeuralHash = sNeuralHash;
        #endif
    }

    //Add the neural hash only if necessary
    if (!OutOfSyncByAge() && IsNeuralNodeParticipant(DefaultWalletAddress(), GetAdjustedTime()) && NeedASuperblock())
    {
        #if defined(WIN32) && defined(QT_GUI)
            mcpid.NeuralHash = sNeuralHash;
            mcpid.superblock = GetNeuralNetworkSuperBlock();
        #endif
    }

    mcpid.LastPORBlockHash = vnResearchAge[mcpid.cpid].blockHash;


    if (!mcpid.cpid.empty() && mcpid.cpid != "INVESTOR" && mcpid.lastblockhash != "0")
    {
        mcpid.BoincPublicKey = GetBeaconPublicKey(mcpid.cpid, false);
    }
}
#endif

std::string SerializeBoincBlock(MiningCPID mcpid, int BlockVersion)
{
    std::string delim = "<|>";
    int subsidy_places= BlockVersion<8 ? 2 : 8;
    if (mcpid.lastblockhash.empty()) mcpid.lastblockhash = "0";
    if (mcpid.LastPORBlockHash.empty()) mcpid.LastPORBlockHash="0";

    std::string bb = mcpid.cpid + delim + mcpid.projectname + delim + mcpid.aesskein + delim + RoundToString(mcpid.rac,0)
                    + delim + RoundToString(mcpid.pobdifficulty,5) + delim + RoundToString((double)mcpid.diffbytes,0)
                    + delim + mcpid.enccpid
                    + delim + mcpid.encaes + delim + RoundToString(mcpid.nonce,0) + delim + RoundToString(mcpid.NetworkRAC,0)
                    + delim + mcpid.clientversion
                    + delim + RoundToString(mcpid.ResearchSubsidy,subsidy_places)
                    + delim + RoundToString(mcpid.LastPaymentTime,0)
                    + delim + RoundToString(mcpid.RSAWeight,0)
                    + delim + mcpid.cpidv2
                    + delim + RoundToString(mcpid.Magnitude,0)
                    + delim + mcpid.GRCAddress + delim + mcpid.lastblockhash
                    + delim + RoundToString(mcpid.InterestSubsidy,subsidy_places) + delim + mcpid.Organization
                    + delim + mcpid.OrganizationKey + delim + mcpid.NeuralHash + delim + mcpid.superblock
                    + delim + RoundToString(mcpid.ResearchSubsidy2,2) + delim + RoundToString(mcpid.ResearchAge,6)
                    + delim + RoundToString(mcpid.ResearchMagnitudeUnit,6) + delim + RoundToString(mcpid.ResearchAverageMagnitude,2)
                    + delim + mcpid.LastPORBlockHash + delim + mcpid.CurrentNeuralHash + delim + mcpid.BoincPublicKey + delim + mcpid.BoincSignature;
    return bb;
}



MiningCPID DeserializeBoincBlock(std::string block, int BlockVersion)
{
    MiningCPID surrogate = GetMiningCPID();
    int subsidy_places= BlockVersion<8 ? 2 : 8;
    try
    {

    std::vector<std::string> s = split(block,"<|>");
    if (s.size() > 7)
    {
        surrogate.cpid = s[0];
        surrogate.projectname = s[1];
        boost::to_lower(surrogate.projectname);
        surrogate.aesskein = s[2];
        surrogate.rac = cdbl(s[3],0);
        surrogate.pobdifficulty = cdbl(s[4],6);
        surrogate.diffbytes = (unsigned int)cdbl(s[5],0);
        surrogate.enccpid = s[6];
        surrogate.encboincpublickey = s[6];
        surrogate.encaes = s[7];
        surrogate.nonce = cdbl(s[8],0);
        if (s.size() > 9)
        {
            surrogate.NetworkRAC = cdbl(s[9],0);
        }
        if (s.size() > 10)
        {
            surrogate.clientversion = s[10];
        }
        if (s.size() > 11)
        {
            surrogate.ResearchSubsidy = cdbl(s[11],2);
        }
        if (s.size() > 12)
        {
            surrogate.LastPaymentTime = cdbl(s[12],0);
        }
        if (s.size() > 13)
        {
            surrogate.RSAWeight = cdbl(s[13],0);
        }
        if (s.size() > 14)
        {
            surrogate.cpidv2 = s[14];
        }
        if (s.size() > 15)
        {
            surrogate.Magnitude = cdbl(s[15],0);
        }
        if (s.size() > 16)
        {
            surrogate.GRCAddress = s[16];
        }
        if (s.size() > 17)
        {
            surrogate.lastblockhash = s[17];
        }
        if (s.size() > 18)
        {
            surrogate.InterestSubsidy = cdbl(s[18],subsidy_places);
        }
        if (s.size() > 19)
        {
            surrogate.Organization = s[19];
        }
        if (s.size() > 20)
        {
            surrogate.OrganizationKey = s[20];
        }
        if (s.size() > 21)
        {
            surrogate.NeuralHash = s[21];
        }
        if (s.size() > 22)
        {
            surrogate.superblock = s[22];
        }
        if (s.size() > 23)
        {
            surrogate.ResearchSubsidy2 = cdbl(s[23],subsidy_places);
        }
        if (s.size() > 24)
        {
            surrogate.ResearchAge = cdbl(s[24],6);
        }
        if (s.size() > 25)
        {
            surrogate.ResearchMagnitudeUnit = cdbl(s[25],6);
        }
        if (s.size() > 26)
        {
            surrogate.ResearchAverageMagnitude = cdbl(s[26],2);
        }
        if (s.size() > 27)
        {
            surrogate.LastPORBlockHash = s[27];
        }
        if (s.size() > 28)
        {
            surrogate.CurrentNeuralHash = s[28];
        }
        if (s.size() > 29)
        {
            surrogate.BoincPublicKey = s[29];
        }
        if (s.size() > 30)
        {
            surrogate.BoincSignature = s[30];
        }

    }
    }
    catch (...)
    {
            printf("Deserialize ended with an error (06182014) \r\n");
            //TODO: fail block check
    }
    return surrogate;
}

std::string strReplace(std::string& str, const std::string& oldStr, const std::string& newStr)
{
  size_t pos = 0;
  while((pos = str.find(oldStr, pos)) != std::string::npos){
     str.replace(pos, oldStr.length(), newStr);
     pos += newStr.length();
  }
  return str;
}


StructCPID GetStructCPID()
{
    StructCPID c;
    c.initialized=false;
    c.rac = 0;
    c.utc=0;
    c.rectime=0;
    c.age = 0;
    c.verifiedutc=0;
    c.verifiedrectime=0;
    c.verifiedage=0;
    c.entries=0;
    c.AverageRAC=0;
    c.NetworkProjects=0;
    c.Iscpidvalid=false;
    c.NetworkRAC=0;
    c.TotalRAC=0;
    c.Magnitude=0;
    c.PaymentMagnitude=0;
    c.owed=0;
    c.payments=0;
    c.verifiedTotalRAC=0;
    c.verifiedMagnitude=0;
    c.TotalMagnitude=0;
    c.LowLockTime=0;
    c.HighLockTime=0;
    c.Accuracy=0;
    c.totalowed=0;
    c.LastPaymentTime=0;
    c.EarliestPaymentTime=0;
    c.PaymentTimespan=0;
    c.ResearchSubsidy = 0;
    c.InterestSubsidy = 0;
    c.ResearchAverageMagnitude = 0;
    c.interestPayments = 0;
    c.payments = 0;
    c.LastBlock = 0;
    c.NetworkMagnitude=0;
    c.NetworkAvgMagnitude=0;

    return c;

}

MiningCPID GetMiningCPID()
{
    MiningCPID mc;
    mc.rac = 0;
    mc.pobdifficulty = 0;
    mc.diffbytes = 0;
    mc.initialized = false;
    mc.nonce = 0;
    mc.NetworkRAC=0;
    mc.lastblockhash = "0";
    mc.Magnitude = 0;
    mc.RSAWeight = 0;
    mc.LastPaymentTime=0;
    mc.ResearchSubsidy = 0;
    mc.InterestSubsidy = 0;
    mc.ResearchSubsidy2 = 0;
    mc.ResearchAge = 0;
    mc.ResearchMagnitudeUnit = 0;
    mc.ResearchAverageMagnitude = 0;
    return mc;
}


void TrackRequests(CNode* pfrom,std::string sRequestType)
{
        std::string sKey = "request_type" + sRequestType;
        double dReqCt = cdbl(ReadCache(sKey,NodeAddress(pfrom)),0) + 1;
        WriteCache(sKey,NodeAddress(pfrom),RoundToString(dReqCt,0),GetAdjustedTime());
        if ( (dReqCt > 20 && !OutOfSyncByAge()) )
        {
                    printf(" Node requests for %s exceeded threshold (misbehaving) %s ",sRequestType.c_str(),NodeAddress(pfrom).c_str());
                    //pfrom->Misbehaving(1);
                    pfrom->fDisconnect = true;
                    WriteCache(sKey,NodeAddress(pfrom),"0",GetAdjustedTime());
        }
}


bool SendMessages(CNode* pto, bool fSendTrickle)
{
    TRY_LOCK(cs_main, lockMain);
    if (lockMain) {
        // Don't send anything until we get their version message
        if (pto->nVersion == 0)
            return true;

        //
        // Message: ping
        //
        bool pingSend = false;
        if (pto->fPingQueued)
        {
            // RPC ping request by user
            pingSend = true;
        }
        if (pto->nPingNonceSent == 0 && pto->nPingUsecStart + PING_INTERVAL * 1000000 < GetTimeMicros())
        {
            // Ping automatically sent as a latency probe & keepalive.
            pingSend = true;
        }
        if (pingSend)
        {
            uint64_t nonce = 0;
            while (nonce == 0) {
                RAND_bytes((unsigned char*)&nonce, sizeof(nonce));
            }
            pto->fPingQueued = false;
            pto->nPingUsecStart = GetTimeMicros();
            if (pto->nVersion > BIP0031_VERSION)
            {
                pto->nPingNonceSent = nonce;
                std::string acid = GetCommandNonce("ping");
                pto->PushMessage("ping", nonce, acid);
            } else
            {
                // Peer is too old to support ping command with nonce, pong will never arrive.
                pto->nPingNonceSent = 0;
                pto->PushMessage("ping");
            }
        }

        // Resend wallet transactions that haven't gotten in a block yet
        ResendWalletTransactions();

        // Address refresh broadcast
        static int64_t nLastRebroadcast;
        if (!IsInitialBlockDownload() && ( GetAdjustedTime() - nLastRebroadcast > 24 * 60 * 60))
        {
            {
                LOCK(cs_vNodes);
                BOOST_FOREACH(CNode* pnode, vNodes)
                {
                    // Periodically clear setAddrKnown to allow refresh broadcasts
                    if (nLastRebroadcast)
                        pnode->setAddrKnown.clear();

                    // Rebroadcast our address
                    if (!fNoListen)
                    {
                        CAddress addr = GetLocalAddress(&pnode->addr);
                        if (addr.IsRoutable())
                            pnode->PushAddress(addr);
                    }
                }
            }
            nLastRebroadcast =  GetAdjustedTime();
        }

        //
        // Message: addr
        //
        if (fSendTrickle)
        {
            vector<CAddress> vAddr;
            vAddr.reserve(pto->vAddrToSend.size());
            BOOST_FOREACH(const CAddress& addr, pto->vAddrToSend)
            {
                // returns true if wasn't already contained in the set
                if (pto->setAddrKnown.insert(addr).second)
                {
                    vAddr.push_back(addr);
                    // receiver rejects addr messages larger than 1000
                    if (vAddr.size() >= 1000)
                    {
                        pto->PushMessage("gridaddr", vAddr);
                        vAddr.clear();
                    }
                }
            }
            pto->vAddrToSend.clear();
            if (!vAddr.empty())
                pto->PushMessage("gridaddr", vAddr);
        }


        //
        // Message: inventory
        //
        vector<CInv> vInv;
        vector<CInv> vInvWait;
        {
            LOCK(pto->cs_inventory);
            vInv.reserve(pto->vInventoryToSend.size());
            vInvWait.reserve(pto->vInventoryToSend.size());
            BOOST_FOREACH(const CInv& inv, pto->vInventoryToSend)
            {
                if (pto->setInventoryKnown.count(inv))
                    continue;

                // trickle out tx inv to protect privacy
                if (inv.type == MSG_TX && !fSendTrickle)
                {
                    // 1/4 of tx invs blast to all immediately
                    static uint256 hashSalt;
                    if (hashSalt == 0)
                        hashSalt = GetRandHash();
                    uint256 hashRand = inv.hash ^ hashSalt;
                    hashRand = Hash(BEGIN(hashRand), END(hashRand));
                    bool fTrickleWait = ((hashRand & 3) != 0);

                    // always trickle our own transactions
                    if (!fTrickleWait)
                    {
                        CWalletTx wtx;
                        if (GetTransaction(inv.hash, wtx))
                            if (wtx.fFromMe)
                                fTrickleWait = true;
                    }

                    if (fTrickleWait)
                    {
                        vInvWait.push_back(inv);
                        continue;
                    }
                }

                // returns true if wasn't already contained in the set
                if (pto->setInventoryKnown.insert(inv).second)
                {
                     vInv.push_back(inv);
                     if (vInv.size() >= 1000)
                     {
                            if (false)
                            {
                                AddPeek("PushInv-Large " + RoundToString((double)vInv.size(),0));
                                // If node has not been misbehaving (1-30-2016) then push it: (pto->nMisbehavior) && pto->NodeAddress().->addr.IsRoutable()
                                pto->PushMessage("inv", vInv);
                                AddPeek("Pushed Inv-Large " + RoundToString((double)vInv.size(),0));
                                if (fDebug10) printf(" *PIL* ");
                                vInv.clear();
                                if (TimerMain("PushInventoryLarge",50)) CleanInboundConnections(true);
                                // Eventually ban the node if they keep asking for inventory
                                TrackRequests(pto,"Inv-Large");
                                AddPeek("Done with Inv-Large " + RoundToString((double)vInv.size(),0));
                            }
                            else
                            {
                                pto->PushMessage("inv", vInv);
                                vInv.clear();
                            }
       
                    }
                }
            }
            pto->vInventoryToSend = vInvWait;
        }
        if (!vInv.empty())
            pto->PushMessage("inv", vInv);


        //
        // Message: getdata
        //
        vector<CInv> vGetData;
        int64_t nNow =  GetAdjustedTime() * 1000000;
        CTxDB txdb("r");
        while (!pto->mapAskFor.empty() && (*pto->mapAskFor.begin()).first <= nNow)
        {
            const CInv& inv = (*pto->mapAskFor.begin()).second;
            if (!AlreadyHave(txdb, inv))
            {
                if (fDebugNet)        printf("sending getdata: %s\n", inv.ToString().c_str());
                //AddPeek("Getdata " + inv.ToString());
                vGetData.push_back(inv);
                if (vGetData.size() >= 1000)
                {
                    pto->PushMessage("getdata", vGetData);
                    vGetData.clear();
                }
                mapAlreadyAskedFor[inv] = nNow;
            }
            pto->mapAskFor.erase(pto->mapAskFor.begin());
        }
        if (!vGetData.empty())
        {
            pto->PushMessage("getdata", vGetData);
            //AddPeek("GetData");
        }

    }
    return true;
}



std::string ReadCache(std::string section, std::string key)
{
    if (section.empty() || key.empty()) return "";

    try
    {
            std::string value = mvApplicationCache[section + ";" + key];
            if (value.empty())
            {
                mvApplicationCache.insert(map<std::string,std::string>::value_type(section + ";" + key,""));
                mvApplicationCache[section + ";" + key]="";
                return "";
            }
            return value;
    }
    catch(...)
    {
        printf("readcache error %s",section.c_str());
        return "";
    }
}


void WriteCache(std::string section, std::string key, std::string value, int64_t locktime)
{
    if (section.empty() || key.empty()) return;
    std::string temp_value = mvApplicationCache[section + ";" + key];
    if (temp_value.empty())
    {
        mvApplicationCache.insert(map<std::string,std::string>::value_type(section + ";" + key,value));
        mvApplicationCache[section + ";" + key]=value;
    }
    mvApplicationCache[section + ";" + key]=value;
    // Record Cache Entry timestamp
    int64_t temp_locktime = mvApplicationCacheTimestamp[section + ";" + key];
    if (temp_locktime == 0)
    {
        mvApplicationCacheTimestamp.insert(map<std::string,int64_t>::value_type(section+";"+key,1));
        mvApplicationCacheTimestamp[section+";"+key]=locktime;
    }
    mvApplicationCacheTimestamp[section+";"+key] = locktime;

}


void ClearCache(std::string section)
{
       for(map<string,string>::iterator ii=mvApplicationCache.begin(); ii!=mvApplicationCache.end(); ++ii)
       {
                std::string key_section = mvApplicationCache[(*ii).first];
                if (key_section.length() > section.length())
                {
                    if (key_section.substr(0,section.length())==section)
                    {
                        printf("\r\nClearing the cache....of value %s \r\n",mvApplicationCache[key_section].c_str());
                        mvApplicationCache[key_section]="";
                        mvApplicationCacheTimestamp[key_section]=1;
                    }
                }
       }

}


void DeleteCache(std::string section, std::string keyname)
{
       std::string pk = section + ";" +keyname;
       mvApplicationCache.erase(pk);
       mvApplicationCacheTimestamp.erase(pk);
}



void IncrementCurrentNeuralNetworkSupermajority(std::string NeuralHash, std::string GRCAddress, double distance)
{
    if (NeuralHash.length() < 5) return;
    double temp_hashcount = 0;
    if (mvCurrentNeuralNetworkHash.size() > 0)
    {
            temp_hashcount = mvCurrentNeuralNetworkHash[NeuralHash];
    }
    // 6-13-2015 ONLY Count Each Neural Hash Once per GRC address / CPID (1 VOTE PER RESEARCHER)
    std::string Security = ReadCache("currentneuralsecurity",GRCAddress);
    if (Security == NeuralHash)
    {
        //This node has already voted, throw away the vote
        return;
    }
    WriteCache("currentneuralsecurity",GRCAddress,NeuralHash,GetAdjustedTime());
    if (temp_hashcount == 0)
    {
        mvCurrentNeuralNetworkHash.insert(map<std::string,double>::value_type(NeuralHash,0));
    }
    double multiplier = 200;
    if (distance < 40) multiplier = 400;
    double votes = (1/distance)*multiplier;
    temp_hashcount += votes;
    mvCurrentNeuralNetworkHash[NeuralHash] = temp_hashcount;
}



void IncrementNeuralNetworkSupermajority(std::string NeuralHash, std::string GRCAddress, double distance)
{
    if (NeuralHash.length() < 5) return;
    double temp_hashcount = 0;
    if (mvNeuralNetworkHash.size() > 0)
    {
            temp_hashcount = mvNeuralNetworkHash[NeuralHash];
    }
    // 6-13-2015 ONLY Count Each Neural Hash Once per GRC address / CPID (1 VOTE PER RESEARCHER)
    std::string Security = ReadCache("neuralsecurity",GRCAddress);
    if (Security == NeuralHash)
    {
        //This node has already voted, throw away the vote
        return;
    }
    WriteCache("neuralsecurity",GRCAddress,NeuralHash,GetAdjustedTime());
    if (temp_hashcount == 0)
    {
        mvNeuralNetworkHash.insert(map<std::string,double>::value_type(NeuralHash,0));
    }
    double multiplier = 200;
    if (distance < 40) multiplier = 400;
    double votes = (1/distance)*multiplier;
    temp_hashcount += votes;
    mvNeuralNetworkHash[NeuralHash] = temp_hashcount;
}


void IncrementVersionCount(const std::string& Version)
{
    if(!Version.empty())
        mvNeuralVersion[Version]++;
}



std::string GetNeuralNetworkSupermajorityHash(double& out_popularity)
{
    double highest_popularity = -1;
    std::string neural_hash = "";
    for(map<std::string,double>::iterator ii=mvNeuralNetworkHash.begin(); ii!=mvNeuralNetworkHash.end(); ++ii)
    {
                double popularity = mvNeuralNetworkHash[(*ii).first];
                // d41d8 is the hash of an empty magnitude contract - don't count it
                if ( ((*ii).first != "d41d8cd98f00b204e9800998ecf8427e") && popularity > 0 && popularity > highest_popularity && (*ii).first != "TOTAL_VOTES")
                {
                    highest_popularity = popularity;
                    neural_hash = (*ii).first;
                }
    }
    out_popularity = highest_popularity;
    return neural_hash;
}


std::string GetCurrentNeuralNetworkSupermajorityHash(double& out_popularity)
{
    double highest_popularity = -1;
    std::string neural_hash = "";
    for(map<std::string,double>::iterator ii=mvCurrentNeuralNetworkHash.begin(); ii!=mvCurrentNeuralNetworkHash.end(); ++ii)
    {
                double popularity = mvCurrentNeuralNetworkHash[(*ii).first];
                // d41d8 is the hash of an empty magnitude contract - don't count it
                if ( ((*ii).first != "d41d8cd98f00b204e9800998ecf8427e") && popularity > 0 && popularity > highest_popularity && (*ii).first != "TOTAL_VOTES")
                {
                    highest_popularity = popularity;
                    neural_hash = (*ii).first;
                }
    }
    out_popularity = highest_popularity;
    return neural_hash;
}






std::string GetNeuralNetworkReport()
{
    //Returns a report of the networks neural hashes in order of popularity
    std::string neural_hash = "";
    std::string report = "Neural_hash, Popularity\r\n";
    std::string row = "";
    for(map<std::string,double>::iterator ii=mvNeuralNetworkHash.begin(); ii!=mvNeuralNetworkHash.end(); ++ii)
    {
                double popularity = mvNeuralNetworkHash[(*ii).first];
                neural_hash = (*ii).first;
                row = neural_hash+ "," + RoundToString(popularity,0);
                report += row + "\r\n";
    }

    return report;
}

std::string GetOrgSymbolFromFeedKey(std::string feedkey)
{
    std::string Symbol = ExtractValue(feedkey,"-",0);
    return Symbol;

}









bool UnusualActivityReport()
{

    map<uint256, CTxIndex> mapQueuedChanges;
    CTxDB txdb("r");
    int nMaxDepth = Best.GetHeight();
    CBlock block;
    int nMinDepth = fTestNet ? 1 : 1;
    if (nMaxDepth < nMinDepth || nMaxDepth < 10) return false;
    nMinDepth = 50000;
    nMaxDepth = Best.GetHeight();
    int ii = 0;
            for (ii = nMinDepth; ii <= nMaxDepth; ii++)
            {
                CBlockIndex* pblockindex = blockFinder.FindByHeight(ii);
                if (block.ReadFromDisk(pblockindex))
                {
                    int64_t nFees = 0;
                    int64_t nValueIn = 0;
                    int64_t nValueOut = 0;
                    int64_t nStakeReward = 0;
                    //unsigned int nSigOps = 0;
                    double DPOR_Paid = 0;
                    bool bIsDPOR = false;
                    std::string MainRecipient = "";
                    double max_subsidy = GetMaximumBoincSubsidy(block.nTime)+50; //allow for
                    BOOST_FOREACH(CTransaction& tx, block.vtx)
                    {

                            MapPrevTx mapInputs;
                            if (tx.IsCoinBase())
                                    nValueOut += tx.GetValueOut();
                            else
                            {
                                     bool fInvalid;
                                     bool TxOK = tx.FetchInputs(txdb, mapQueuedChanges, true, false, mapInputs, fInvalid);
                                     if (!TxOK) continue;
                                     int64_t nTxValueIn = tx.GetValueIn(mapInputs);
                                     int64_t nTxValueOut = tx.GetValueOut();
                                     nValueIn += nTxValueIn;
                                     nValueOut += nTxValueOut;
                                     if (!tx.IsCoinStake())             nFees += nTxValueIn - nTxValueOut;
                                     if (tx.IsCoinStake())
                                     {
                                            nStakeReward = nTxValueOut - nTxValueIn;
                                            if (tx.vout.size() > 2) bIsDPOR = true;
                                            //DPOR Verification of each recipient (Recipients start at output position 2 (0=Coinstake flag, 1=coinstake)
                                            if (tx.vout.size() > 2)
                                            {
                                                MainRecipient = PubKeyToAddress(tx.vout[2].scriptPubKey);
                                            }
                                            int iStart = 3;
                                            if (ii > 267500) iStart=2;
                                            if (bIsDPOR)
                                            {
                                                    for (unsigned int i = iStart; i < tx.vout.size(); i++)
                                                    {
                                                        std::string Recipient = PubKeyToAddress(tx.vout[i].scriptPubKey);
                                                        double      Amount    = CoinToDouble(tx.vout[i].nValue);
                                                        if (Amount > GetMaximumBoincSubsidy(GetAdjustedTime()))
                                                        {
                                                        }

                                                        if (Amount > max_subsidy)
                                                        {
                                                            printf("Block #%f:%f, Recipient %s, Paid %f\r\n",(double)ii,(double)i,Recipient.c_str(),Amount);
                                                        }
                                                        DPOR_Paid += Amount;

                                                    }

                                           }
                                     }

                                //if (!tx.ConnectInputs(txdb, mapInputs, mapQueuedChanges, posThisTx, pindex, true, false))                return false;
                            }

                    }

                    int64_t TotalMint = nValueOut - nValueIn + nFees;
                    double subsidy = CoinToDouble(TotalMint);
                    if (subsidy > max_subsidy)
                    {
                        std::string hb = block.vtx[0].hashBoinc;
                        MiningCPID bb = DeserializeBoincBlock(hb,block.nVersion);
                        if (bb.cpid != "INVESTOR")
                        {
                                printf("Block #%f:%f, Recipient %s, CPID %s, Paid %f, StakeReward %f \r\n",(double)ii,(double)0,
                                    bb.GRCAddress.c_str(), bb.cpid.c_str(), subsidy,(double)nStakeReward);
                        }
                }

            }
        }


    return true;
}


double GRCMagnitudeUnit(CBestChain &Best)
{
    //7-12-2015 - Calculate GRCMagnitudeUnit (Amount paid per magnitude per day)
    //StructCPID network = GetInitializedStructCPID2("NETWORK",mvNetwork);
    double TotalNetworkMagnitude = Best.super.Magnitude;
    if (TotalNetworkMagnitude < 1000) TotalNetworkMagnitude=1000;
    double MaximumEmission = BLOCKS_PER_DAY*GetMaximumBoincSubsidy(Best.top->nTime);
    double Kitty = MaximumEmission - (Best.sum.Research/14);
    if (Kitty < 1) Kitty = 1;
    double MagnitudeUnit = 0;
    if (AreBinarySuperblocksEnabled(Best.GetHeight()))
    {
        MagnitudeUnit = (Kitty/TotalNetworkMagnitude)*1.25;
    }
    else
    {
        MagnitudeUnit = Kitty/TotalNetworkMagnitude;
    }
    if (MagnitudeUnit > 5) MagnitudeUnit = 5; //Just in case we lose a superblock or something strange happens.
    MagnitudeUnit = SnapToGrid(MagnitudeUnit); //Snaps the value into .025 increments
    return MagnitudeUnit;
}


int64_t ComputeResearchAccrual(CBestChain &Best, int64_t nTime, std::string cpid, std::string operation, bool bVerifyingBlock, int iVerificationPhase, double& dAccrualAge, double& dMagnitudeUnit, double& AvgMagnitude)
{
    StructCPID2* stc = Best.GetCPID(cpid);//mvResearchAge
    if(!stc)
    {
        dAccrualAge=0;
        dMagnitudeUnit=0;
        AvgMagnitude=0;
        return 0;
    }
    double dCurrentMagnitude = stc->SbMagnitude;
    CBlockIndex* pHistorical = GetHistoricalMagnitude(stc);
    if (!pHistorical || pHistorical->nHeight <= nNewIndex || pHistorical->nMagnitude==0 || pHistorical->nTime == 0)
    {
        //No prior block exists... Newbies get .01 age to bootstrap the CPID (otherwise they will not have any prior block to refer to, thus cannot get started):
        if (!AreBinarySuperblocksEnabled(Best.top->nHeight))
        {
                return dCurrentMagnitude > 0 ? ((dCurrentMagnitude/100)*COIN) : 0;
        }
        else
        {
            // New rules - 12-4-2015 - Pay newbie from the moment beacon was sent as long as it is within 6 months old and NN mag > 0 and newbie is in the superblock and their lifetime paid is zero
            // Note: If Magnitude is zero, or researcher is not in superblock, or lifetimepaid > 0, this function returns zero
            int64_t iBeaconTimestamp = BeaconTimeStamp(cpid, true);
            if (IsLockTimeWithinMinutes(iBeaconTimestamp, 60*24*30*6))
            {
                double dNewbieAccrualAge = ((double)nTime - (double)iBeaconTimestamp) / 86400;
                // BUG: dMagnitudeUnit unset, set to 0 by caller,
                // that lifetime=0 shit is a lie
                int64_t iAccrual = (int64_t)((dNewbieAccrualAge*dCurrentMagnitude*dMagnitudeUnit*COIN) + (1*COIN));
                if ((dNewbieAccrualAge*dCurrentMagnitude*dMagnitudeUnit) > 500)
                {
                    printf("Newbie special stake too high, reward=500GRC");
                    return (500*COIN);
                }
                if (fDebug3) printf("\r\n Newbie Special First Stake for CPID %s, Age %f, Accrual %f \r\n",cpid.c_str(),dNewbieAccrualAge,(double)iAccrual);
                return iAccrual;
            }
            else
            {
                return dCurrentMagnitude > 0 ? (((dCurrentMagnitude/100)*COIN) + (1*COIN)): 0;
            }
        }
    }
    // To prevent reorgs and checkblock errors, ensure the research age is > 10 blocks wide:
    int iRABlockSpan = Best.top->nHeight - pHistorical->nHeight;
    double dAvgMag = stc->LftSumMagnitude/(stc->LftCntMagnitude+0.01);
    // ResearchAge: If the accrual age is > 20 days, add in the midpoint lifetime average magnitude to ensure the overall avg magnitude accurate:
    if (iRABlockSpan > (int)(BLOCKS_PER_DAY*20))
    {
            AvgMagnitude = (pHistorical->nMagnitude + dAvgMag + dCurrentMagnitude) / 3;
    }
    else
    {
            AvgMagnitude = (pHistorical->nMagnitude + dCurrentMagnitude) / 2;
    }
    if (AvgMagnitude > 20000) AvgMagnitude = 20000;

    dAccrualAge = ((double)nTime - (double)pHistorical->nTime) / 86400;
    if (dAccrualAge < 0) dAccrualAge=0;
    dMagnitudeUnit = GRCMagnitudeUnit(Best);

    int64_t Accrual = (int64_t)(dAccrualAge*AvgMagnitude*dMagnitudeUnit*COIN);
    // Double check researcher lifetime paid
    double days = (nTime - stc->LftFirstBlockTime) / 86400.0;
    double PPD = stc->LftSumReward/(days+.01);
    double ReferencePPD = dMagnitudeUnit*dAvgMag;
    if ((PPD > ReferencePPD*5))
    {
            printf("Researcher PPD %f > Reference PPD %f for CPID %s with Lifetime Avg Mag of %f, Days %f \r\n",PPD,ReferencePPD,cpid.c_str(),dAvgMag,days);
            Accrual = 0; //Since this condition can occur when a user ramps up computing power, lets return 0 so as to not shortchange the researcher, but instead, owed will continue to accrue and will be paid later when PPD falls below 5
    }
    // Note that if the RA Block Span < 10, we want to return 0 for the Accrual Amount so the CPID can still receive an accurate accrual in the future
    if (iRABlockSpan < 10 && iVerificationPhase != 2) Accrual = 0;

    double verbosity = (operation == "createnewblock" || operation == "createcoinstake") ? 10 : 1000;
    if ((fDebug && LessVerbose(verbosity)) || (fDebug3 && iVerificationPhase==2)) printf(" Operation %s, ComputedAccrual %f, StakeHeight %f, RABlockSpan %f, HistoryHeight%f, AccrualAge %f, AvgMag %f, MagUnit %f, PPD %f, Reference PPD %f  \r\n",
        operation.c_str(),CoinToDouble(Accrual),(double)Best.top->nHeight,(double)iRABlockSpan,
        (double)pHistorical->nHeight,   dAccrualAge,AvgMagnitude,dMagnitudeUnit, PPD, ReferencePPD);
    return Accrual;
}



CBlockIndex* GetHistoricalMagnitude(StructCPID2* stc)
{
    // Starting at the block prior to StartHeight, find the last instance of the CPID in the chain:
    // Limit lookback to 6 months
    int nMinIndex = Best.GetHeight()-(6*30*BLOCKS_PER_DAY);
    if (nMinIndex < 2) nMinIndex=2;
    // Last block Hash paid to researcher (where research reward >0)
    BOOST_REVERSE_FOREACH(CBlockIndex *cur, stc->vpBlocks)
    {
        if (cur->nHeight < nMinIndex)
        {
            // In this case, the last staked block was Found, but it is over 6 months old....
            printf("Last staked block found at height %f, but cannot verify magnitude older than 6 months! \r\n",(double)cur->nHeight);
            break;
        }
        if( cur->nResearchSubsidy < 0 )
            continue; // only blocks with research reward
        return cur;
    }
    return pindexGenesisBlock;
}

#if 0
void ZeroOutResearcherTotals(std::string cpid)
{
    if (!cpid.empty())
    {
                StructCPID stCPID = GetInitializedStructCPID2(cpid,mvResearchAge);
                stCPID.LastBlock = 0;
                stCPID.BlockHash = "";
                stCPID.InterestSubsidy = 0;
                stCPID.ResearchSubsidy = 0;
                stCPID.Accuracy = 0;
                stCPID.LowLockTime = std::numeric_limits<unsigned int>::max();
                stCPID.HighLockTime = 0;
                stCPID.TotalMagnitude = 0;
                stCPID.ResearchAverageMagnitude = 0;

                mvResearchAge[cpid]=stCPID;
    }
}
#endif





MiningCPID GetBoincBlockByIndex(CBlockIndex* pblockindex)
{
    CBlock block;
    MiningCPID bb;
    bb.initialized=false;
    if (!pblockindex || !pblockindex->IsInMainChain()) return bb;
    if (block.ReadFromDisk(pblockindex))
    {
        std::string hashboinc = "";
        if (block.vtx.size() > 0) hashboinc = block.vtx[0].hashBoinc;
        bb = DeserializeBoincBlock(hashboinc,block.nVersion);
        bb.initialized=true;
        return bb;
    }
    return bb;
}

std::string CPIDHash(double dMagIn, std::string sCPID)
{
    std::string sMag = RoundToString(dMagIn,0);
    double dMagLength = (double)sMag.length();
    double dExponent = pow(dMagLength,5);
    std::string sMagComponent1 = RoundToString(dMagIn/(dExponent+.01),0);
    std::string sSuffix = RoundToString(dMagLength * dExponent, 0);
    std::string sHash = sCPID + sMagComponent1 + sSuffix;
    //  printf("%s, %s, %f, %f, %s\r\n",sCPID.c_str(), sMagComponent1.c_str(),dMagLength,dExponent,sSuffix.c_str());
    return sHash;
}

std::string GetQuorumHash(const std::string& data)
{
    //Data includes the Magnitudes, and the Projects:
    std::string sMags = ExtractXML(data,"<MAGNITUDES>","</MAGNITUDES>");
    std::vector<std::string> vMags = split(sMags.c_str(),";");
    std::string sHashIn = "";
    for (unsigned int x = 0; x < vMags.size(); x++)
    {
        std::vector<std::string> vRow = split(vMags[x].c_str(),",");

        // Each row should consist of two fields, CPID and magnitude.
        if(vRow.size() < 2)
            continue;

        // First row (CPID) must be exactly 32 bytes.
        const std::string& sCPID = vRow[0];
        if(sCPID.size() != 32)
            continue;

        double dMag = cdbl(vRow[1],0);
        sHashIn += CPIDHash(dMag, sCPID) + "<COL>";
    }

    return RetrieveMd5(sHashIn);
}


std::string getHardwareID()
{
    std::string ele1 = "?";
    #ifdef QT_GUI
        ele1 = getMacAddress();
    #endif
    ele1 += ":" + getCpuHash();
    ele1 += ":" + getHardDriveSerial();

    std::string hwid = RetrieveMd5(ele1);
    return hwid;
}

#ifdef WIN32
static void getCpuid( unsigned int* p, unsigned int ax )
 {
    __asm __volatile
    (   "movl %%ebx, %%esi\n\t"
        "cpuid\n\t"
        "xchgl %%ebx, %%esi"
        : "=a" (p[0]), "=S" (p[1]),
          "=c" (p[2]), "=d" (p[3])
        : "0" (ax)
    );
 }
#endif

 std::string getCpuHash()
 {
    std::string n = boost::asio::ip::host_name();
    #ifdef WIN32
        unsigned int cpuinfo[4] = { 0, 0, 0, 0 };
        getCpuid( cpuinfo, 0 );
        unsigned short hash = 0;
        unsigned int* ptr = (&cpuinfo[0]);
        for ( unsigned int i = 0; i < 4; i++ )
            hash += (ptr[i] & 0xFFFF) + ( ptr[i] >> 16 );
        double dHash = (double)hash;
        return n + ";" + RoundToString(dHash,0);
    #else
        return n;
    #endif
 }



std::string SystemCommand(const char* cmd)
{
    FILE* pipe = popen(cmd, "r");
    if (!pipe) return "ERROR";
    char buffer[128];
    std::string result = "";
    while(!feof(pipe))
    {
        if(fgets(buffer, 128, pipe) != NULL)
            result += buffer;
    }
    pclose(pipe);
    return result;
}


std::string getHardDriveSerial()
{
    if (!msHDDSerial.empty()) return msHDDSerial;
    std::string cmd1 = "";
    #ifdef WIN32
        cmd1 = "wmic path win32_physicalmedia get SerialNumber";
    #else
        cmd1 = "ls /dev/disk/by-uuid";
    #endif
    std::string result = SystemCommand(cmd1.c_str());
    //if (fDebug3) printf("result %s",result.c_str());
    msHDDSerial = result;
    return result;
}

bool IsContract(CBlockIndex* pIndex)
{
    return pIndex->IsContract==1 ? true : false;
}

bool IsSuperBlock(CBlockIndex* pIndex)
{
    return pIndex->IsSuperBlock==1 ? true : false;
}

double SnapToGrid(double d)
{
    double dDither = .04;
    // OMG, There is modulo operator FFS (todo)
    double dOut = cdbl(RoundToString(d*dDither,3),3) / dDither;
    return dOut;
}

bool IsNeuralNodeParticipant(const std::string& addr, int64_t locktime)
{
    //Calculate the neural network nodes abililty to particiapte by GRC_Address_Day
    int address_day = GetDayOfYear(locktime);
    std::string address_tohash = addr + "_" + std::to_string(address_day);
    std::string address_day_hash = RetrieveMd5(address_tohash);
    // For now, let's call for a 25% participation rate (approx. 125 nodes):
    // When RA is enabled, 25% of the neural network nodes will work on a quorum at any given time to alleviate stress on the project sites:
    uint256 uRef;
    if (IsResearchAgeEnabled(Best.GetHeight()))
    {
        uRef = fTestNet ? uint256("0x00000000000000000000000000000000ed182f81388f317df738fd9994e7020b") : uint256("0x000000000000000000000000000000004d182f81388f317df738fd9994e7020b"); //This hash is approx 25% of the md5 range (90% for testnet)
    }
    else
    {
        uRef = fTestNet ? uint256("0x00000000000000000000000000000000ed182f81388f317df738fd9994e7020b") : uint256("0x00000000000000000000000000000000fd182f81388f317df738fd9994e7020b"); //This hash is approx 25% of the md5 range (90% for testnet)
    }
    uint256 uADH = uint256("0x" + address_day_hash);
    //printf("%s < %s : %s",uADH.GetHex().c_str() ,uRef.GetHex().c_str(), YesNo(uADH  < uRef).c_str());
    //printf("%s < %s : %s",uTest.GetHex().c_str(),uRef.GetHex().c_str(), YesNo(uTest < uRef).c_str());
    return (uADH < uRef);
}


bool StrLessThanReferenceHash(std::string rh)
{
    int address_day = GetDayOfYear(GetAdjustedTime());
    std::string address_tohash = rh + "_" + std::to_string(address_day);
    std::string address_day_hash = RetrieveMd5(address_tohash);
    uint256 uRef = fTestNet ? uint256("0x000000000000000000000000000000004d182f81388f317df738fd9994e7020b") : uint256("0x000000000000000000000000000000004d182f81388f317df738fd9994e7020b"); //This hash is approx 25% of the md5 range (90% for testnet)
    uint256 uADH = uint256("0x" + address_day_hash);
    return (uADH < uRef);
}

// Generate backup filenames with local date and time with suffix support
std::string GetBackupFilename(const std::string& basename, const std::string& suffix)
{
    time_t biTime;
    struct tm * blTime;
    time (&biTime);
    blTime = localtime(&biTime);
    char boTime[200];
    strftime(boTime, sizeof(boTime), "%FT%H-%M-%S", blTime);
    return suffix.empty()
        ? basename + "-" + std::string(boTime)
        : basename + "-" + std::string(boTime) + "-" + suffix;
}
