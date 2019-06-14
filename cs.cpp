/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2014-2018,  Regents of the University of California,
 *                           Arizona Board of Regents,
 *                           Colorado State University,
 *                           University Pierre & Marie Curie, Sorbonne University,
 *                           Washington University in St. Louis,
 *                           Beijing Institute of Technology,
 *                           The University of Memphis.
 *
 * This file is part of NFD (Named Data Networking Forwarding Daemon).
 * See AUTHORS.md for complete list of NFD authors and contributors.
 *
 * NFD is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * NFD is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * NFD, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "cs.hpp"
#include "core/algorithm.hpp"
#include "core/logger.hpp"
#include "ns3/simulator.h"
#include <ndn-cxx/lp/tags.hpp>
#include <ndn-cxx/util/concepts.hpp>
#include <ndn-cxx/security/pib/key.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>
#include <iostream>
#include <fstream>
#include <ctime>
#include <cstdio>
#include <stdio.h>
#include <chrono>
#include <unordered_map>
#include <string>
#include <utility>
#include <memory>
#include <cmath>

#define IDENTITY_NAME "NDNSERVER"
//$B%5!<%P$+$i<h$C$F$-$?$3$H$r>ZL@(B
#define USER_NUM 100
//$B%f!<%6$NAm?t(B
#define ACCESS_STRICT 0.01
//$B%"%/%;%9@)8B(B
#define TRUSTVALUE_INTERVAL 0.025
//$B?.MjCM$N;~4V4V3V(B
#define INTERVAL 1.0
//$B7WB,$N;~4V4V3V(B
#define DATASTRICT_INTERVAL 0.025
//$B%G!<%?@)8B$N;~4V4V3V(B
#define ATTACKER_NUM 10

namespace nfd {
namespace cs {

bool setProposal1 = false;
//$BDs0FJ}<0#1$r<BAu$9$k%U%i%0(B
bool setProposal2 = true;
//$BDs0FJ}<0#2$r<BAu$9$k%U%i%0(B
bool AccessStrictSet1 = true;
//$B%"%/%;%9@)8f$r9T$&$3$H$r<($9%U%i%0(B
bool AccessStrictSet2 = true;
//$B?.MjCM$r$b$H$K$7$?%"%/%;%9@)8f$r9T$&$3$H$r<($9%U%i%0(B
double StartTime = ns3::Simulator::Now().GetSeconds();
//$B%7%_%e%l!<%7%g%s3+;O;~4V(B
double StartTime_TrustValue = 
  ns3::Simulator::Now().GetSeconds();
//$B?.MjCM7WB,3+;O;~4V(B
double StartTime_DataStrict = 
  ns3::Simulator::Now().GetSeconds();
//$B%"%/%;%9@)8B3+;O;~4V(B
int CacheHit_Counter = 0;
//$B%-%c%C%7%e%R%C%H$7$?2s?t(B
int CacheMiss_Counter = 0;
//$B%-%c%C%7%e%_%9$7$?2s?t(B
int Verification_Counter = 0;
//$BHsJ]8n%(%j%"$G%-%c%C%7%e%R%C%H$7$?2s?t(B
int Verification_Attacker_Counter = 0;
//$B967b<T$NHsJ]8n%(%j%"$G%-%c%C%7%e%R%C%H$7$?2s?t(B
bool DataArrive_First[USER_NUM] = {};
//$B%f!<%6$+$i:G=i$N%"%/%;%9$,$"$C$?$3$H$r<($9%U%i%0(B
double ArriveTime = 0;
//$B%G!<%?$NE~Ce;~4V(B
double Before_ArriveTime = 0; 
//$BA0$NE~Ce;~4V(B
std::set<Name>Miss_List;
//1$BIC4V$"$?$j$N%-%c%C%7%e%_%9$7$?%G!<%?$N%j%9%H(B

time_t now = std::time(nullptr);
char DataSet[60];
char TrustValue[60];
char DataStrict[60];
char Accuracy[60];
char Interval[60];
int n1 = sprintf(DataSet
    ,"./Result/DataSet/DataSet_%s.csv",ctime(&now));
int n2 = sprintf(TrustValue
    ,"./Result/TrustValue/TrustValue_%s.csv",ctime(&now));
int n3 = sprintf(DataStrict
    ,"./Result/DataStrict/DataStrict_%s.csv",ctime(&now));
int n4 = sprintf(Accuracy
    ,"./Result/Accuracy/Accuracy_%s.csv",ctime(&now));
int n5 = sprintf(Interval
    ,"./Result/Interval/Interval_%s.csv",ctime(&now));

std::ofstream outputfile1(DataSet);
std::ofstream outputfile2(TrustValue);
std::ofstream outputfile3(DataStrict);
std::ofstream outputfile4(Accuracy);
std::ofstream outputfile5(Interval);
//$B%G!<%?%;%C%H$OogCM$J$I$N%G!<%?(B


//$BDs0FJ}<0#1$G<BAu$7$?$b$N(B
std::unordered_map<int,double>DataArriveTable;
using UserData = std::pair<int,double>;
//$B%f!<%6$N%G!<%?%l!<%H$r5-O?$9$k%F!<%V%k(B($B%f!<%6(BID$B$H!$E~Ce$7$?;~4V(B)$B$r:n@.(B
std::set<Name> User_List[USER_NUM];
//$B%f!<%6#1$,MW5a$7$?%G!<%?$r3JG<$9$k%F!<%V%k(B

//$BDs0FJ}<0#2$G<BAu$7$?$b$N(B
int User_Point[USER_NUM];
//$B%f!<%6$N%]%$%s%H$r3JG<$7$F$*$/$b$N(B
std::set<Name> Result[USER_NUM];
//$B6&DL$9$k%G!<%?$r3JG<$9$k$b$N(B
std::unordered_map<int,double>User_TrustValue_Table;
using User_TrustValue_Data = std::pair<int,double>;
//$B$=$l$>$l$N%f!<%6$N?.MjCM$rJ]B8$7$F$*$/%F!<%V%k!J%f!<%6(BID$B$H!$?.MjCM!K(B
double DataRate[USER_NUM];
//$B?.MjCM$K4p$E$$$?%G!<%?@)8B(B
double AccessStrict2[USER_NUM] = {};
//$B$=$l$>$l$N%f!<%6$N%"%/%;%9@)8B(B
int AccessCount[USER_NUM] = {};
//$B$=$l$>$l$N%f!<%6$N%"%/%;%92s?t(B
int UserSend[USER_NUM] = {};
int UserNotSend[USER_NUM] = {};
double UserAccuracy[USER_NUM] = {};
bool first = true;
//$B7WB,4|4V$G:G=i$N%"%/%;%9$+$I$&$+$N%U%i%0(B

std::unordered_map<int, int> User_Point_Table;
using User_Point_Data = std::pair<int,int>;
// $B?.MjCM2sI|$N0Y$K;29M$K$9$k%F!<%V%k(B($B%f!<%6(BID, $B?.MjCM%+%&%s%?!K(B
std::unordered_map<int, int> User_Count_Table;
using User_Count_Data = std::pair<int,int>;
// $B?.MjCM2sI|$N0Y$K;29M$K$9$k%F!<%V%k(B($B%f!<%6(BID,$B2s?t%+%&%s%?(B)
// int user_count[USER_NUM] = {};
// bool user_judge[USER_NUM] = {};

//$B967b;!CN%b!<%I(B
double result[2] = {};
double interval = 0;

std::unordered_map<int, int> ave_interval_table;
using ave_interval = std::pair<int,int>;

int val_counter = 0;
int ave_counter = 0;
double total_interval = 0;
bool detection_mode[USER_NUM] = {};

NDN_CXX_ASSERT_FORWARD_ITERATOR(Cs::const_iterator);

NFD_LOG_INIT("ContentStore");


unique_ptr<Policy>
makeDefaultPolicy()
{
  const std::string DEFAULT_POLICY = "priority_fifo";
  return Policy::create(DEFAULT_POLICY);
}

Cs::Cs(size_t nMaxPackets)
  : m_shouldAdmit(true)
    //false$B$N>l9gA4$F$N%G!<%?$OG'$a$i$l$J$$(B
  , m_shouldServe(true)
    //$B%-%c%C%7%e$NC5:w$r5v2D(B
{
  this->setPolicyImpl(makeDefaultPolicy());
  //cs$B$K8r49J}<0$r%;%C%H(B
  m_policy->setLimit(nMaxPackets);
  //$B%(%s%H%j!<$N8B3&?t$r%;%C%H(B
  m_key = m_keyChain.getPib().getIdentity(IDENTITY_NAME).getDefaultKey();
}

void
Cs::insert(const Data& data, bool isUnsolicited)
{
  if (!m_shouldAdmit || m_policy->getLimit() == 0) {
    //$BA4$F$N%G!<%?$,G'>Z$5$l$J$$$+MFNL$,#0$J$i%G!<%?$rA^F~$O$7$J$$(B
    return;
  }
  NFD_LOG_DEBUG("insert " << data.getName());
  // recognize CachePolicy
  shared_ptr<lp::CachePolicyTag> tag = data.getTag<lp::CachePolicyTag>();
  //$B%G!<%?$KIUB0$7$F$$$k%-%c%C%7%e%]%j%7!<%?%0$r<hF@(B
  if (tag != nullptr) {
    //$B%?%0$,IU$$$F$?$i<B9T$5$l$k(B
    lp::CachePolicyType policy = tag->get().getPolicy();
    //$B%-%c%C%7%e%]%j%7!<%?%$%W$r<hF@(B
    if (policy == lp::CachePolicyType::NO_CACHE) {
      return;
    }
  }

  iterator it;
  bool isNewEntry = false;
  std::tie(it, isNewEntry) = m_table.emplace(data.shared_from_this(), isUnsolicited);
  //$B%?%W%k$N:n@.(B
  //isUnsolicited$B$O5a$a$F$$$?%G!<%?$+$I$&$+$r??56$GH=Dj$9$k$b$N(B
  EntryImpl& entry = const_cast<EntryImpl&>(*it);

  entry.updateStaleTime();

  if (!isNewEntry) { 
    //$B%(%s%H%j!<$,B8:_$7$?$i(B
    // XXX This doesn't forbid unsolicited Data from refreshing a solicited entry.
    if (entry.isUnsolicited() && !isUnsolicited) {
      entry.unsetUnsolicited();
    }

    m_policy->afterRefresh(it);
    //invoked by CS after an existing entry is refreshed by same Data
  }
  else {
    m_policy->afterInsert(it);
    //invoked by CS after a new entry is inserted
  }
}

void
Cs::erase(const Name& prefix, size_t limit, const AfterEraseCallback& cb)
{
  BOOST_ASSERT(static_cast<bool>(cb));

  iterator first = m_table.lower_bound(prefix);
  //$B;XDj$5$l$?MWAG$NCM$,8=$l$k:G=i$N0LCV$N%$%F%l!<%?$r<hF@$9$k(B
  iterator last = m_table.end();
  if (prefix.size() > 0) {
    last = m_table.lower_bound(prefix.getSuccessor());
  }

  size_t nErased = 0;
  while (first != last && nErased < limit) {
    m_policy->beforeErase(first);
    first = m_table.erase(first);
    ++nErased;
  }

  if (cb) {
    cb(nErased);
  }
}

void
Cs::setAccessStrict(const Interest& interest)
{
  if(interest.getNonce() < USER_NUM){
    //$B%f!<%6(BID$B$N$D$$$?MW5a%Q%1%C%H$N>l9g(B

    auto user_number = interest.getNonce();
    //$B%f!<%6$N(BID$B$r<hF@(B 
    auto itr_trust = User_TrustValue_Table.find(interest.getNonce());
    //$B%f!<%6$N?.MjCM$r<hF@(B
    if (itr_trust == User_TrustValue_Table.end()) {
      //$B$b$7=i$a$F$N%"%/%;%9$N>l9g(B
      AccessStrict2[user_number] = 40;
      //$B:G=i$N%"%/%;%9@)8B$r(B0.01$B$K@_Dj(B
      AccessCount[user_number]++;
      //$B$=$N(BID$B$N%"%/%;%9%+%&%s%H$r%$%s%/%j%a%s%H(B

    }else{
      //$B$9$G$K%"%/%;%9$,$"$C$?>l9g(B
      AccessCount[user_number]++;
      if(ns3::Simulator::Now().GetSeconds()
          - StartTime_DataStrict > DATASTRICT_INTERVAL){
        for(auto itr_trust = User_TrustValue_Table.begin();
            itr_trust != User_TrustValue_Table.end(); 
            ++itr_trust){
          // if(itr_trust->second > 0.38){
            // //$B$b$7?.MjCM$,(B0.35$B$rD6$($F$$$?>l9g(B
            // AccessStrict2[itr_trust->first] = 
            // AccessStrict2[itr_trust->first] *1.01;
            // // AccessStrict2[itr_trust->first] *1.001;
            // //$B%"%/%;%95v2D?t$rA}$d$9(B
          // }else if(itr_trust->second < 0.38){
            // //$B?.MjCM$,(B0.35$B$h$j>.$5$$>l9g(B
            // // AccessStrict2[itr_trust->first] = 10;
            // //$B%"%/%;%9@)8B$r(B0.01$B$K%j%;%C%H(B
          // }
          
          AccessStrict2[itr_trust->first] = (itr_trust->second)*80; 

        }
      }
    }
  }
  if ( (ns3::Simulator::Now().GetSeconds()-StartTime_DataStrict)
      > DATASTRICT_INTERVAL){ 
    for (int i = 0; i < USER_NUM; i++) {
      if (i == 0) {
        outputfile3 << ns3::Simulator::Now().GetSeconds() 
          << "," << AccessStrict2[i];
      }else if (i == USER_NUM-1) {
        outputfile3 << "," << AccessStrict2[i] << std::endl;
      }else {
        outputfile3 << "," << AccessStrict2[i];
      }
    }
  StartTime_DataStrict = ns3::Simulator::Now().GetSeconds();
  }
}

void
Cs::setTrustValue()
{
  if ( (ns3::Simulator::Now().GetSeconds()-StartTime_TrustValue) > TRUSTVALUE_INTERVAL){ 
    // double Point_Average = 0; 
    // $B%U%!%$%k$K(BCacheHit_Rate$B$r=PNO(B

    // for (int j = 0; j < USER_NUM; j++) {
      // for (int i = 0; i < USER_NUM; i++) {
        // //$B%f!<%6(Bj$B$HB>$N%f!<%6$N6&DL$9$k%G!<%?$r(BResult[j]$B$K3JG<(B
        // if (i != j) {
          // std::set_intersection(User_List[j].begin(), User_List[j].end(),
              // User_List[i].begin(), User_List[i].end(),
              // std::inserter(Result[j], Result[j].end()));
          // //User_List[j]$B$H(BUser_List[i]$B$N6&DL$9$k%G!<%?$r(BResult[j]$B$K3JG<(B
        // }
      // }
      // Point_Average += Result[j].size();
      // //Point_Average$B$K(BResult[j]$B$NMWAG?t$r2C;;(B
    // }

    // Point_Average = Point_Average/USER_NUM;
    //ResultTable$B$NMWAG?tJ?6Q$r$@$9(B

    for (int i = 0; i < USER_NUM; i++) {
      //$B$=$NCM$H$=$l$>$l$N(BTable$B$H$N:9$r%f!<%6$K%]%$%s%H$H$7$FM?$($k(B
      // User_Point[i] += (Result[i].size() - Point_Average);
      //$B%f!<%6$KM?$($i$l$k%]%$%s%H$O(BResult[i]-$BMWAG?tJ?6Q(B
      // auto TrustValue = 1/(1+exp(-0.01*User_Point[i]));
      auto TrustValue = 1/(1+exp(-User_Point[i]));
      //$B?.MjCM$NDj5A<0(B
      if (i == 0) {
        outputfile2 << ns3::Simulator::Now().GetSeconds() << "," << TrustValue;
      }else if (i == USER_NUM-1) {
        outputfile2 << "," << TrustValue << std::endl;
      }else {
        outputfile2 << "," << TrustValue;
      }
      auto itr = User_TrustValue_Table.find(i);
      if(itr == User_TrustValue_Table.end()){
        User_TrustValue_Table.insert({User_TrustValue_Data(i,TrustValue)});
      }else{
        itr->second = TrustValue;
      }
      //$B$=$N%]%$%s%H$N9g7W$r85$K?.MjCM$r7hDj(B

      // auto Result_begin = Result[i].begin();
      // auto Result_end = Result[i].end();
      // Result[i].erase(Result_begin, Result_end);
      //ResultTable$B$r=i4|2=(B

      // auto User_begin = User_List[i].begin();
      // auto User_end = User_List[i].end();
      // User_List[i].erase(User_begin, User_end);
      //User_List$B$r=i4|2=(B

    }
    StartTime_TrustValue = ns3::Simulator::Now().GetSeconds();
  }
}

void
Cs::setArriveTimeProposal1(const Interest& interest)
{
  auto itr_arrive = DataArriveTable.find(interest.getNonce());
  //$B%G!<%?%l!<%H%F!<%V%k$+$iMW5a%Q%1%C%H$rAw$C$?%f!<%6$N%$%F%l!<%?$r<hF@(B
  if(itr_arrive == DataArriveTable.end()){
    //$B$=$N%f!<%6$+$i$N=i$a$F$N%"%/%;%9$N>l9g(B
    ArriveTime = ns3::Simulator::Now().GetSeconds();
    //$B$3$NMW5a%Q%1%C%H$N%G!<%?E~Ce;~4V$r<hF@(B 
    DataArriveTable.insert( UserData{ interest.getNonce(), ArriveTime } );
    //$B%G!<%?$r%F!<%V%k$KA^F~(B
  }else{
      //$B$=$N%G!<%?$+$i$N%"%/%;%9$,$9$G$K$"$k>l9g(B
      Before_ArriveTime = itr_arrive->second;
      //$BA0$NMW5a%Q%1%C%H%G!<%?E~Ce;~4V$r<hF@(B
      ArriveTime = ns3::Simulator::Now().GetSeconds();
      //$B$3$NMW5a%Q%1%C%H$N%G!<%?E~Ce;~4V$r<hF@(B 
      //$B%G!<%?@)8B$h$j$bE~Ce;~4V$,Aa$$>l9g$O!$(BArriveTime$B$O3JG<$7$J$$(B
      if((ArriveTime - Before_ArriveTime) > ACCESS_STRICT){
      //$B%G!<%?$NE~Ce4V3V$,(BAccessStrict2$B$h$jBg$-$+$C$?$i(B
        itr_arrive->second = ArriveTime;
        //$BMW5a%Q%1%C%H$rAw$C$?%N!<%I$N(BID$B$HMW5a%Q%1%C%H$NE~Ce;~4V$r%F!<%V%k$K3JG<(B
        AccessStrictSet1 = true;
        //$B%"%/%;%9@)8B$O$7$J$$(B
      }else{
        //AccessStruce2$B$h$j$bC;$$4V3V$GAw$i$l$F$-$?>l9g(B
        AccessStrictSet1 = false;
        //$B%"%/%;%9@)8B<B9T(B
      }
  }
}

void
Cs::setArriveTimeProposal2(const Interest& interest)
{
  auto itr_arrive = DataArriveTable.find(interest.getNonce());
  //$B%G!<%?%l!<%H%F!<%V%k$+$iMW5a%Q%1%C%H$rAw$C$?%f!<%6$N%$%F%l!<%?$r<hF@(B
  if(itr_arrive == DataArriveTable.end()){
    //$B$=$N%f!<%6$+$i$N=i$a$F$N%"%/%;%9$N>l9g(B
    ArriveTime = ns3::Simulator::Now().GetSeconds();
    //$B$3$NMW5a%Q%1%C%H$N%G!<%?E~Ce;~4V$r<hF@(B 
    DataArriveTable.insert( UserData{ interest.getNonce(), ArriveTime } );
    //$B%G!<%?$r%F!<%V%k$KA^F~(B
    if(interest.getNonce() < USER_NUM){
    DataArrive_First[interest.getNonce()] = true;
    //$B0l2sL\$N%"%/%;%9$,=*N;$7$?$3$H%U%i%0$G<($9(B
    }
  }else{
      //$B$=$N%G!<%?$+$i$N%"%/%;%9$,$9$G$K$"$k>l9g(B
      Before_ArriveTime = itr_arrive->second;
      //$BA0$NMW5a%Q%1%C%H%G!<%?E~Ce;~4V$r<hF@(B
      ArriveTime = ns3::Simulator::Now().GetSeconds();
      //$B$3$NMW5a%Q%1%C%H$N%G!<%?E~Ce;~4V$r<hF@(B 
      //$B%G!<%?@)8B$h$j$bE~Ce;~4V$,Aa$$>l9g$O!$(BArriveTime$B$O3JG<$7$J$$(B
      if(AccessCount[interest.getNonce()] < AccessStrict2[interest.getNonce()]){
      //$B%G!<%?$NE~Ce4V3V$,(BAccessStrict2$B$h$jBg$-$+$C$?$i(B
        itr_arrive->second = ArriveTime;
        //$BMW5a%Q%1%C%H$rAw$C$?%N!<%I$N(BID$B$HMW5a%Q%1%C%H$NE~Ce;~4V$r%F!<%V%k$K3JG<(B
        AccessStrictSet2 = true;
        //$B%"%/%;%9@)8B$O$7$J$$(B
      }else{
        //AccessStruce2$B$h$j$bC;$$4V3V$GAw$i$l$F$-$?>l9g(B
        itr_arrive->second = ArriveTime;

        AccessStrictSet2 = false;
        // std::cout << "User" << interest.getNonce() << "strict!" << std::endl;
        //$B%"%/%;%9@)8B<B9T(B
      }
  }
}

void
Cs::measureResult(const Interest& interest)
{
  if ((ns3::Simulator::Now().GetSeconds() - StartTime) > INTERVAL) {
    //$BB,Dj;~4V$,(BINTERVAL$B$r$3$($?>l9g!$B,Dj7k2L$r(Bfile$B$K=PNO(B
    double CacheHit_Rate = 
      (double)CacheHit_Counter/(CacheHit_Counter + CacheMiss_Counter);
    //$B%-%c%C%7%e%R%C%HN(!a%-%c%C%7%e%R%C%H2s?t(B/($B%-%c%C%7%e%R%C%H2s?t!\%-%c%C%7%e%_%92s?t(B)
    double Verification_Rate = 
      (double)Verification_Counter/CacheMiss_Counter;
    //$BG'>ZN(!aG'>Z2s?t(B/$B%-%c%C%7%e%_%92s?t(B
    if (CacheMiss_Counter == 0) {
      Verification_Rate = 0;
    }
    // double Threshold =
      // (double)Verification_Rate/CacheHit_Rate;
    //$BogCM!aG'>ZN((B/$B%-%c%C%7%e%R%C%HN((B
    double Threshold = 0;

    if ((int)CacheHit_Rate != 0) {

      Threshold =
        (double) Verification_Rate/CacheHit_Rate;

    }

    outputfile1 << StartTime 
      << "," << Threshold 
      << "," << CacheHit_Rate 
      << "," << CacheHit_Counter 
      << "," << CacheMiss_Counter 
      << "," << Verification_Counter << std::endl;

    auto Miss_begin = Miss_List.begin();
    auto Miss_end = Miss_List.end();
    Miss_List.erase(Miss_begin, Miss_end);

    CacheHit_Counter = 0;
    CacheMiss_Counter = 0;
    Verification_Counter = 0;
    first = true;
    StartTime = ns3::Simulator::Now().GetSeconds();
    //$BB,Dj7k2L$r5-O?$7$?$i!$$=$l$>$l$NCM$r=i4|2=(B
  }
}

void
Cs::measureResultProposal1(const Interest& interest)
{
  if ((ns3::Simulator::Now().GetSeconds() - StartTime) > INTERVAL) {
    //$BB,Dj;~4V$,(BINTERVAL$B$r$3$($?>l9g!$B,Dj7k2L$r(Bfile$B$K=PNO(B
    double CacheHit_Rate = 
      (double)CacheHit_Counter/(CacheHit_Counter + CacheMiss_Counter);
    //$B%-%c%C%7%e%R%C%HN(!a%-%c%C%7%e%R%C%H2s?t(B/($B%-%c%C%7%e%R%C%H2s?t!\%-%c%C%7%e%_%92s?t(B)
    double Verification_Rate = 
      (double)Verification_Counter/CacheMiss_Counter;
    //$BG'>ZN(!aG'>Z2s?t(B/$B%-%c%C%7%e%_%92s?t(B
    if (CacheMiss_Counter == 0) {
      Verification_Rate = 0;
    }
    double Threshold =
      (double)Verification_Rate/CacheHit_Rate;
    //$BogCM!aG'>ZN((B/$B%-%c%C%7%e%R%C%HN((B

    outputfile4 << StartTime;
    for(int i = 0; i < USER_NUM; i++){
      UserAccuracy[i] = (double)UserSend[i]/(UserSend[i] + UserNotSend[i]);
      outputfile4 << "," << UserAccuracy[i];
      UserSend[i] = 0;
      UserNotSend[i] = 0;
    }
    outputfile4 << std::endl;

    outputfile1 << StartTime 
      << "," << Threshold 
      << "," << CacheHit_Rate 
      << "," << CacheHit_Counter 
      << "," << CacheMiss_Counter 
      << "," << Verification_Counter << std::endl;

    auto Miss_begin = Miss_List.begin();
    auto Miss_end = Miss_List.end();
    Miss_List.erase(Miss_begin, Miss_end);

    CacheHit_Counter = 0;
    CacheMiss_Counter = 0;
    Verification_Counter = 0;
    first = true;
    StartTime = ns3::Simulator::Now().GetSeconds();
    //$BB,Dj7k2L$r5-O?$7$?$i!$$=$l$>$l$NCM$r=i4|2=(B
  }
}

void
Cs::measureResultProposal2(const Interest& interest)
{
  if ((ns3::Simulator::Now().GetSeconds() - StartTime) > INTERVAL) {
    //$BB,Dj;~4V$,(BINTERVAL$B$r$3$($?>l9g!$B,Dj7k2L$r(Bfile$B$K=PNO(B
    double CacheHit_Rate = 
      (double)CacheHit_Counter/(CacheHit_Counter + CacheMiss_Counter);
    //$B%-%c%C%7%e%R%C%HN(!a%-%c%C%7%e%R%C%H2s?t(B/($B%-%c%C%7%e%R%C%H2s?t!\%-%c%C%7%e%_%92s?t(B)
    double Verification_Rate = 
      (double)Verification_Counter/CacheMiss_Counter;
    //$BG'>ZN(!aG'>Z2s?t(B/$B%-%c%C%7%e%_%92s?t(B
    if (CacheMiss_Counter == 0) {
      Verification_Rate = 0;
    }
    double Threshold =
      (double)Verification_Rate/CacheHit_Rate;
    //$BogCM!aG'>ZN((B/$B%-%c%C%7%e%R%C%HN((B

    outputfile1 << StartTime 
      << "," << Threshold 
      << "," << CacheHit_Rate 
      << "," << CacheHit_Counter 
      << "," << CacheMiss_Counter 
      << "," << Verification_Counter
      << "," << Verification_Attacker_Counter << std::endl;

    outputfile4 << StartTime;
    for(int i = 0; i < USER_NUM; i++){
      UserAccuracy[i] = (double)UserSend[i]/(UserSend[i] + UserNotSend[i]);
      outputfile4 << "," << UserAccuracy[i];
      UserSend[i] = 0;
      UserNotSend[i] = 0;
    }
    outputfile4 << std::endl;
    // this->setTrustValue();
    //$B?.MjCM$r%;%C%H(B
    
    auto Miss_begin = Miss_List.begin();
    auto Miss_end = Miss_List.end();
    Miss_List.erase(Miss_begin, Miss_end);

    CacheHit_Counter = 0;
    CacheMiss_Counter = 0;
    Verification_Counter = 0;
    Verification_Attacker_Counter = 0;
    first = true;
    StartTime = ns3::Simulator::Now().GetSeconds();
    //$BB,Dj7k2L$r5-O?$7$?$i!$$=$l$>$l$NCM$r=i4|2=(B
    for(int i = 0; i < USER_NUM; i++){
      AccessCount[i] = 0;
    }
  }
}

void
Cs::setInterval_Detection()
{
    if(result[0] == 0){
      result[0] = ns3::Simulator::Now().GetSeconds();
      
    }else{
      result[1] = ns3::Simulator::Now().GetSeconds();

      interval += result[1] - result[0];

      val_counter++;


      if(val_counter ==100){
      // $B%+%&%s%?!<$,#1#0#0$G$"$l$P!$(Bave_interval$B$K3JG<(B
      
        double sample_interval = interval/100;

        // if(total_interval/ave_counter > 10*sample_interval && ns3::Simulator::Now().GetSeconds() > 10){
        if(total_interval/ave_counter > 10*sample_interval){
          // $BJ?6Q$h$j$b%"%/%;%94V3V$,6KC<$KC;$$>l9g(B  
          for(int i = 0;i < USER_NUM; i++){

            AccessStrict2[i] = 40;
            // $BA4%f!<%6$K@)8B$r$+$1$k(B
            detection_mode[i] = true;
            // $B967b$r;!CN$7$?$?$a!$967b<TFCDj%b!<%I$K0\9T(B
            
          }
        }else{

            total_interval += sample_interval;
        }

        outputfile5 << ns3::Simulator::Now().GetSeconds() << "," << sample_interval << std::endl;
        ave_interval_table.insert( ave_interval{ ave_counter, sample_interval } );
        // $B%"%/%;%9%$%s%?!<%P%k$r5-O?(B

        ave_counter++;

        interval = 0;

        val_counter = 0;

      }
      result[0] = 0;

      result[1] = 0;

    }

}

  void
Cs::recover_trustvalue(const Interest& interest, int num)
{

  auto result = User_Point_Table.find(interest.getNonce());
  auto counter = User_Count_Table.find(interest.getNonce());
  auto trust = User_TrustValue_Table.find(interest.getNonce());

  if(result == User_Point_Table.end()){

    User_Point_Table.insert( User_Point_Data{ interest.getNonce(), 0} );
    User_Count_Table.insert( User_Count_Data{ interest.getNonce(), num} );

  }else{


    auto count = counter->second;
    count++;
    counter->second = count;
    if(num == -1){

      result->second = num;

    }
    if(counter->second == 5){

      if(interest.getNonce() < USER_NUM){

        if(result->second != -1){

          User_Point[interest.getNonce()]++; 
          // $B2a5n(B5$B2s$N%"%/%;%9$r$_$F%-%c%C%7%e%R%C%H$,$J$+$C$?$i?.MjCM$r$"$2$k(B

          if(detection_mode[interest.getNonce()] == true){
            // $B967b$r8!CN$7!$A4%f!<%6$N%"%/%;%9$r@)8B$7$F$$$k>l9g(B
            trust->second = 1.0; 
            //$B967b<T$G$J$$$?$a?.MjCM$r2sI|(B
            detection_mode[interest.getNonce()] = false;
            //$B%"%/%;%9$7$F$-$?%f!<%6$N@)8B$r2r=|(B
          }

        }
      }
      result->second = 0;
      counter->second = 0;
    }

  }
}

void
Cs::find(const Interest& interest,
         const HitCallback& hitCallback,
         const MissCallback& missCallback)
{
  //$BE,9g$9$k%G!<%?%Q%1%C%H$r8+$D$1$k(B
  BOOST_ASSERT(static_cast<bool>(hitCallback));
  BOOST_ASSERT(static_cast<bool>(missCallback));
  
  if (interest.getNonce() < USER_NUM) {
    //$B%f!<%6$N%G!<%?$G$"$k>l9g(B
    User_List[interest.getNonce()].insert(interest.getName());
    //$B%f!<%6$N%F!<%V%k$K%G!<%?$r3JG<(B
  }

  if (setProposal1 == false && setProposal2 == false) {
    this->measureResult(interest);
    //$B%G!<%?$rB,Dj(B
  }

  if (setProposal1 == true) {
    this->setArriveTimeProposal1(interest);
    //$BE~Ce;~4V$r%;%C%H(B
    this->measureResultProposal1(interest);
    //$B%G!<%?$rB,Dj(B
  }

  if (setProposal2 == true) {
    this->setTrustValue();
    //$B?.MjCM$r%;%C%H(B
    this->setAccessStrict(interest);
    //$B%"%/%;%9@)8B$r%;%C%H(B
    this->setArriveTimeProposal2(interest);
    //$BE~Ce;~4V$r%;%C%H(B
    this->measureResultProposal2(interest);
    //$B%G!<%?$rB,Dj(B
  }

  if (!m_shouldServe || m_policy->getLimit() == 0) {
    missCallback(interest);
    return;
  }
  const Name& prefix = interest.getName();
  //$BMW5a%Q%1%C%H$NL>A0$r<hF@(B
  bool isRightmost = interest.getChildSelector() == 1;
  NFD_LOG_DEBUG("find " << prefix << (isRightmost ? " R" : " L"));

  iterator first = m_table.lower_bound(prefix);
  iterator last = m_table.end();
  if (prefix.size() > 0) {
    last = m_table.lower_bound(prefix.getSuccessor());
  }

  iterator match = last;
  if (isRightmost) {
    match = this->findRightmost(interest, first, last);
  }else {
    match = this->findLeftmost(interest, first, last);
  }

  if (match == last) {
    // NFD_LOG_DEBUG("  no-match");

    // $BL$G'>Z%3%s%F%s%D$X$NMW5a$N$?$a!$MW5a$5$l$?;~4V$r5-O?(B
    this->setInterval_Detection();
    //$BL$G'>Z%(%j%"$X$N%"%/%;%94V3V$r7WB,$7!$967b$r;!CN(B
    this->recover_trustvalue(interest,0);
    //$B2a5n$N%-%c%C%7%e%R%C%H$r$_$F?.MjCM$r2sI|(B
    CacheMiss_Counter++;
    //$B%-%c%C%7%e%_%9$N%+%&%s%?!<$r%$%s%/%j%a%s%H(B
    Miss_List.insert(interest.getName());
    //$B%-%c%C%7%e%_%9%j%9%H$K%G!<%?$r2C$($k(B
    if (AccessStrictSet1 == true && AccessStrictSet2 == true) { 
      // && DataArrive_First[interest.getNonce()] == true)){
      //$B$b$7%G!<%?@)8B$,$+$+$C$F$$$?$i%G!<%?$rAw$jJV$5$J$$(B
      if(interest.getNonce() < USER_NUM){
        UserSend[interest.getNonce()]++;
        missCallback(interest);
      }else {
        //Nonce$B$,(BUSER_NUM$B0J>e$N$b$N!J7PO)9=C[$N%Q%1%C%H!K$G$"$k>l9g(B
        missCallback(interest);
      }
    }else {
      if(interest.getNonce() < USER_NUM){
        UserNotSend[interest.getNonce()]++;
      }
    }
    return;
  }
  CacheHit_Counter++;
  //$B%-%c%C%7%e%R%C%H$N%+%&%s%?$r%$%s%/%j%a%s%H(B
  m_policy->beforeUse(match);
  //$B%^%C%A$7$?%G!<%?$N>l=j$rJQ$($k(B
  if (match->getFLag() == true) {
    //$B$9$G$KG'>Z:Q$_$N%U%i%0$,IU$$$F$$$?$iG'>Z$rHt$P$9(B
    
    User_Point[interest.getNonce()]++;
    //$B$=$N%3%s%F%s%D$rMW5a$7$?%f!<%6$N?.MjCM$r$"$2$k(B

    // $BDs0FJ}<0#2$N<BAu(B
    this->recover_trustvalue(interest,1);
    // $B?.MjCM$N2sI|:n6H$r9T$&(B
    if (AccessStrictSet1 == true && AccessStrictSet2 == true) { 

      //$B$b$7%G!<%?@)8B$,$+$+$C$F$$$?$i%G!<%?$rAw$jJV$5$J$$(B
      UserSend[interest.getNonce()]++;

      hitCallback(interest, match->getData());

    }else if (interest.getNonce() > USER_NUM) {
      //Nonce$B$,(BUSER_NUM$B0J>e$N$b$N!J7PO)9=C[$N%Q%1%C%H!K$G$"$k>l9g(B
      UserSend[interest.getNonce()]++;

      hitCallback(interest, match->getData()); 

    }else {

      UserNotSend[interest.getNonce()]++;

    }
  }else{
    //$BG'>Z$r$^$@9T$J$C$F$$$J$$%G!<%?$N>l9g(B
    
    // $BL$G'>Z%3%s%F%s%D$KBP$9$kMW5a$G$"$k$?$a;~4V$r5-O?(B
    this->setInterval_Detection();

    //$B%f!<%6$N?.MjCM$r2<$2$k(B
    User_Point[interest.getNonce()]--;

    this->recover_trustvalue(interest,-1);

    // auto itr_miss = Miss_List.find(interest.getName());
    // if (itr_miss != Miss_List.end()) {
      // Verification_Counter++;
      // //$BG'>Z$N%+%&%s%?$r%$%s%/%j%a%s%H(B
      // if(1<=interest.getNonce()&& interest.getNonce() <= ATTACKER_NUM){
        // Verification_Attacker_Counter++;
      // }
    // }

    
    if (AccessStrictSet1 == true && AccessStrictSet2 == true) { 
      //$B$b$7%G!<%?@)8B$,@)8B$,$+$+$C$F$$$J$$>l9g%G!<%?$rAw$jJV$9(B
      if (ndn::security::verifySignature(match->getData(), m_key) == true) {
        //$B%G!<%?$,@5$7$$$+$I$&$+G'>Z(B
        auto itr_miss = Miss_List.find(interest.getName());
        if (itr_miss != Miss_List.end()) {
          Verification_Counter++;
          //$BG'>Z$N%+%&%s%?$r%$%s%/%j%a%s%H(B
          if(1<=interest.getNonce()&& interest.getNonce() <= ATTACKER_NUM){
            Verification_Attacker_Counter++;
          }
        }
        EntryImpl& entry = const_cast<EntryImpl&>(*match);
        entry.setFlag();
        //$B%G!<%?$K@5$7$$%G!<%?$G$"$k$3$H$r<($9%U%i%0$r$D$1$k(B
        UserSend[interest.getNonce()]++;
        hitCallback(interest, match->getData());
      }else if (interest.getNonce() > USER_NUM) {
        //Nonce$B$,(BUSER_NUM$B0J>e$N$b$N!J7PO)9=C[$N%Q%1%C%H!K$G$"$k>l9g(B
        hitCallback(interest, match->getData());
      }else {
        UserNotSend[interest.getNonce()]++;
      }
    }
    // if (ndn::security::verifySignature(match->getData(), m_key) == true) {
      // //$B%G!<%?$,@5$7$$$+$I$&$+G'>Z(B
      // EntryImpl& entry = const_cast<EntryImpl&>(*match);
      // entry.setFlag();
      // //$B%G!<%?$K@5$7$$%G!<%?$G$"$k$3$H$r<($9%U%i%0$r$D$1$k(B
      // if (AccessStrictSet1 == true && AccessStrictSet2 == true) { 
        // //$B$b$7%G!<%?@)8B$,@)8B$,$+$+$C$F$$$J$$>l9g%G!<%?$rAw$jJV$9(B
        // UserSend[interest.getNonce()]++;
        // hitCallback(interest, match->getData());
      // }else if (interest.getNonce() > USER_NUM) {
        // //Nonce$B$,(BUSER_NUM$B0J>e$N$b$N!J7PO)9=C[$N%Q%1%C%H!K$G$"$k>l9g(B
        // hitCallback(interest, match->getData());
      // }else {
        // UserNotSend[interest.getNonce()]++;
      // }
    // }
  }
}

iterator
Cs::findLeftmost(const Interest& interest, iterator first, iterator last) const
{
  //$BHO0OFb$+$i;XDj$5$l$?>r7o$rK~$?$9:G=i$NMWAG$r8!:w$9$k(B
  return std::find_if(first, last, bind(&cs::EntryImpl::canSatisfy, _1, interest));
}

iterator
Cs::findRightmost(const Interest& interest, iterator first, iterator last) const
{
  // Each loop visits a sub-namespace under a prefix one component longer than Interest Name.
  // If there is a match in that sub-namespace, the leftmost match is returned;
  // otherwise, loop continues.

  size_t interestNameLength = interest.getName().size();
  for (iterator right = last; right != first;) {
    iterator prev = std::prev(right);

    // special case: [first,prev] have exact Names
    if (prev->getName().size() == interestNameLength) {
      NFD_LOG_TRACE("  find-among-exact " << prev->getName());
      iterator matchExact = this->findRightmostAmongExact(interest, first, right);
      return matchExact == right ? last : matchExact;
    }

    Name prefix = prev->getName().getPrefix(interestNameLength + 1);
    iterator left = m_table.lower_bound(prefix);

    // normal case: [left,right) are under one-component-longer prefix
    NFD_LOG_TRACE("  find-under-prefix " << prefix);
    iterator match = this->findLeftmost(interest, left, right);
    if (match != right) {
      return match;
    }
    right = left;
  }
  return last;
}

iterator
Cs::findRightmostAmongExact(const Interest& interest, iterator first, iterator last) const
{
  return find_last_if(first, last, bind(&EntryImpl::canSatisfy, _1, interest));
}

void
Cs::dump()
{
  NFD_LOG_DEBUG("dump table");
  for (const EntryImpl& entry : m_table) {
    NFD_LOG_TRACE(entry.getFullName());
  }
}

void
Cs::setPolicy(unique_ptr<Policy> policy)
{
  BOOST_ASSERT(policy != nullptr);
  BOOST_ASSERT(m_policy != nullptr);
  size_t limit = m_policy->getLimit();
  this->setPolicyImpl(std::move(policy));
  m_policy->setLimit(limit);
}

void
Cs::setPolicyImpl(unique_ptr<Policy> policy)
{
  NFD_LOG_DEBUG("set-policy " << policy->getName());
  m_policy = std::move(policy);
  m_beforeEvictConnection = m_policy->beforeEvict.connect([this] (iterator it) {
      m_table.erase(it);
    });

  m_policy->setCs(this);
  BOOST_ASSERT(m_policy->getCs() == this);
}

void
Cs::enableAdmit(bool shouldAdmit)
{
  if (m_shouldAdmit == shouldAdmit) {
    return;
  }
  m_shouldAdmit = shouldAdmit;
  NFD_LOG_INFO((shouldAdmit ? "Enabling" : "Disabling") << " Data admittance");
}

void
Cs::enableServe(bool shouldServe)
{
  if (m_shouldServe == shouldServe) {
    return;
  }
  m_shouldServe = shouldServe;
  NFD_LOG_INFO((shouldServe ? "Enabling" : "Disabling") << " Data serving");
}

} //cs$B$NL>A06u4V$N=*N;(B
} //nfd$B$NL>A06u4V$N=*N;(B
