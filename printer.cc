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
#define USER_NUM 10
#define ACCESS_STRICT 0.01
#define TRUSTVALUE_INTERVAL 0.025
#define INTERVAL 1.0
#define DATASTRICT_INTERVAL 0.025

namespace nfd {
namespace cs {

bool setProposal1 = true;
bool setProposal2 = false;
bool AccessStrictSet1 = true;
bool AccessStrictSet2 = true;
double StartTime = ns3::Simulator::Now().GetSeconds();
double StartTime_TrustValue = 
  ns3::Simulator::Now().GetSeconds();
double StartTime_DataStrict = 
  ns3::Simulator::Now().GetSeconds();
int CacheHit_Counter = 0;
int CacheMiss_Counter = 0;
int Verification_Counter = 0;
int Verification_Attacker_Counter = 0;
bool DataArrive_First[USER_NUM] = {};
double ArriveTime = 0;
double Before_ArriveTime = 0; 
std::set<Name>Miss_List;

time_t now = std::time(nullptr);
char DataSet[60];
char TrustValue[60];
char DataStrict[60];
char Accuracy[60];
int n1 = sprintf(DataSet
    ,"./Result/DataSet/DataSet_%s.csv",ctime(&now));
int n2 = sprintf(TrustValue
    ,"./Result/TrustValue/TrustValue_%s.csv",ctime(&now));
int n3 = sprintf(DataStrict
    ,"./Result/DataStrict/DataStrict_%s.csv",ctime(&now));
int n4 = sprintf(Accuracy
    ,"./Result/Accuracy/Accuracy_%s.csv",ctime(&now));
std::ofstream outputfile1(DataSet);
std::ofstream outputfile2(TrustValue);
std::ofstream outputfile3(DataStrict);
std::ofstream outputfile4(Accuracy);


std::unordered_map<int,double>DataArriveTable;
using UserData = std::pair<int,double>;
std::set<Name> User_List[USER_NUM];

int User_Point[USER_NUM];
std::set<Name> Result[USER_NUM];
std::unordered_map<int,double>User_TrustValue_Table;
using User_TrustValue_Data = std::pair<int,double>;
double DataRate[USER_NUM];
double AccessStrict2[USER_NUM] = {};
int AccessCount[USER_NUM] = {};
int UserSend[USER_NUM] = {};
int UserNotSend[USER_NUM] = {};
double UserAccuracy[USER_NUM] = {};
bool first = true;

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
  , m_shouldServe(true)
{
  this->setPolicyImpl(makeDefaultPolicy());
  //csに交換方式をセット
  m_policy->setLimit(nMaxPackets);
  //エントリーの限界数をセット
  m_key = m_keyChain.getPib().getIdentity(IDENTITY_NAME).getDefaultKey();
}

void
Cs::insert(const Data& data, bool isUnsolicited)
{
  if (!m_shouldAdmit || m_policy->getLimit() == 0) {
    return;
  }
  NFD_LOG_DEBUG("insert " << data.getName());
  shared_ptr<lp::CachePolicyTag> tag = data.getTag<lp::CachePolicyTag>();
  if (tag != nullptr) {
    lp::CachePolicyType policy = tag->get().getPolicy();
    if (policy == lp::CachePolicyType::NO_CACHE) {
      return;
    }
  }

  iterator it;
  bool isNewEntry = false;
  std::tie(it, isNewEntry) = m_table.emplace(data.shared_from_this(), isUnsolicited);
  EntryImpl& entry = const_cast<EntryImpl&>(*it);

  entry.updateStaleTime();

  if (!isNewEntry) { 
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

    auto user_number = interest.getNonce();
    auto itr_trust = User_TrustValue_Table.find(interest.getNonce());
    if (itr_trust == User_TrustValue_Table.end()) {
      AccessStrict2[user_number] = 100;
      AccessCount[user_number]++;

    }else{
      AccessCount[user_number]++;
      if(ns3::Simulator::Now().GetSeconds()
          - StartTime_DataStrict > DATASTRICT_INTERVAL){
        for(auto itr_trust = User_TrustValue_Table.begin();
            itr_trust != User_TrustValue_Table.end(); 
            ++itr_trust){
          if(itr_trust->second > 0.38){
            AccessStrict2[itr_trust->first] = 
            AccessStrict2[itr_trust->first] *1.01;
          }else if(itr_trust->second < 0.38){
            AccessStrict2[itr_trust->first] = 10;
          }
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
    double Point_Average = 0; 

    for (int j = 0; j < USER_NUM; j++) {
      for (int i = 0; i < USER_NUM; i++) {
        if (i != j) {
          std::set_intersection(User_List[j].begin(), User_List[j].end(),
                                User_List[i].begin(), User_List[i].end(),
                                std::inserter(Result[j], Result[j].end()));
        }
      }
      Point_Average += Result[j].size();
    }

    Point_Average = Point_Average/USER_NUM;

    for (int i = 0; i < USER_NUM; i++) {
      User_Point[i] += (Result[i].size() - Point_Average);
      auto TrustValue = 1/(1+exp(-0.01*User_Point[i]));
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

      auto Result_begin = Result[i].begin();
      auto Result_end = Result[i].end();
      Result[i].erase(Result_begin, Result_end);

      auto User_begin = User_List[i].begin();
      auto User_end = User_List[i].end();
      User_List[i].erase(User_begin, User_end);

    }
    StartTime_TrustValue = ns3::Simulator::Now().GetSeconds();
  }
}

void
Cs::setArriveTimeProposal1(const Interest& interest)
{
  auto itr_arrive = DataArriveTable.find(interest.getNonce());
  if(itr_arrive == DataArriveTable.end()){
    ArriveTime = ns3::Simulator::Now().GetSeconds();
    DataArriveTable.insert( UserData{ interest.getNonce(), ArriveTime } );
  }else{
      Before_ArriveTime = itr_arrive->second;
      ArriveTime = ns3::Simulator::Now().GetSeconds();
      if((ArriveTime - Before_ArriveTime) > ACCESS_STRICT){
        itr_arrive->second = ArriveTime;
        AccessStrictSet1 = true;
      }else{
        AccessStrictSet1 = false;
      }
  }
}

void
Cs::setArriveTimeProposal2(const Interest& interest)
{
  auto itr_arrive = DataArriveTable.find(interest.getNonce());
  if(itr_arrive == DataArriveTable.end()){
    ArriveTime = ns3::Simulator::Now().GetSeconds();
    DataArriveTable.insert( UserData{ interest.getNonce(), ArriveTime } );
  }else{
      Before_ArriveTime = itr_arrive->second;
      ArriveTime = ns3::Simulator::Now().GetSeconds();
      if(AccessCount[interest.getNonce()] < AccessStrict2[interest.getNonce()]){
        itr_arrive->second = ArriveTime;
        AccessStrictSet2 = true;
      }else{
        itr_arrive->second = ArriveTime;

        AccessStrictSet2 = false;
      }
  }
}

void
Cs::measureResult(const Interest& interest)
{
  if ((ns3::Simulator::Now().GetSeconds() - StartTime) > INTERVAL) {
    double CacheHit_Rate = 
      (double)CacheHit_Counter/(CacheHit_Counter + CacheMiss_Counter);
    double Verification_Rate = 
      (double)Verification_Counter/CacheMiss_Counter;
    if (CacheMiss_Counter == 0) {
      Verification_Rate = 0;
    }
    double Threshold =
      (double)Verification_Rate/CacheHit_Rate;

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
  }
}

void
Cs::measureResultProposal1(const Interest& interest)
{
  if ((ns3::Simulator::Now().GetSeconds() - StartTime) > INTERVAL) {
    double CacheHit_Rate = 
      (double)CacheHit_Counter/(CacheHit_Counter + CacheMiss_Counter);
    double Verification_Rate = 
      (double)Verification_Counter/CacheMiss_Counter;
    if (CacheMiss_Counter == 0) {
      Verification_Rate = 0;
    }
    double Threshold =
      (double)Verification_Rate/CacheHit_Rate;

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
  }
}

void
Cs::measureResultProposal2(const Interest& interest)
{
  if ((ns3::Simulator::Now().GetSeconds() - StartTime) > INTERVAL) {
    double CacheHit_Rate = 
      (double)CacheHit_Counter/(CacheHit_Counter + CacheMiss_Counter);
    double Verification_Rate = 
      (double)Verification_Counter/CacheMiss_Counter;
    if (CacheMiss_Counter == 0) {
      Verification_Rate = 0;
    }
    double Threshold =
      (double)Verification_Rate/CacheHit_Rate;

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
    
    auto Miss_begin = Miss_List.begin();
    auto Miss_end = Miss_List.end();
    Miss_List.erase(Miss_begin, Miss_end);

    CacheHit_Counter = 0;
    CacheMiss_Counter = 0;
    Verification_Counter = 0;
    Verification_Attacker_Counter = 0;
    first = true;
    StartTime = ns3::Simulator::Now().GetSeconds();
    for(int i = 0; i < USER_NUM; i++){
      AccessCount[i] = 0;
    }
  }
}

void
Cs::find(const Interest& interest,
         const HitCallback& hitCallback,
         const MissCallback& missCallback)
{
  BOOST_ASSERT(static_cast<bool>(hitCallback));
  BOOST_ASSERT(static_cast<bool>(missCallback));
  
  if (interest.getNonce() < USER_NUM) {
    User_List[interest.getNonce()].insert(interest.getName());
  }

  if (setProposal1 == false && setProposal2 == false) {
    this->measureResult(interest);
  }

  if (setProposal1 == true) {
    this->setArriveTimeProposal1(interest);
    this->measureResultProposal1(interest);
  }

  if (setProposal2 == true) {
    this->setTrustValue();
    this->setAccessStrict(interest);
    this->setArriveTimeProposal2(interest);
    this->measureResultProposal2(interest);
  }

  if (!m_shouldServe || m_policy->getLimit() == 0) {
    missCallback(interest);
    return;
  }
  const Name& prefix = interest.getName();
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
    CacheMiss_Counter++;
    Miss_List.insert(interest.getName());
    if (AccessStrictSet1 == true && AccessStrictSet2 == true) { 
      if(interest.getNonce() < USER_NUM){
        UserSend[interest.getNonce()]++;
        missCallback(interest);
      }else {
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
  m_policy->beforeUse(match);
  if (match->getFLag() == true) {
    if (AccessStrictSet1 == true && AccessStrictSet2 == true) { 
      UserSend[interest.getNonce()]++;
      hitCallback(interest, match->getData());
    }else if (interest.getNonce() > USER_NUM) {
      UserSend[interest.getNonce()]++;
      hitCallback(interest, match->getData()); 
    }else {
      UserNotSend[interest.getNonce()]++;
    }
  }else{
    auto itr_miss = Miss_List.find(interest.getName());
    if (itr_miss != Miss_List.end()) {
      Verification_Counter++;
      if(interest.getNonce() == 1 || interest.getNonce() == 2){
        Verification_Attacker_Counter++;
      }
    }
    if (ndn::security::verifySignature(match->getData(), m_key) == true) {
      EntryImpl& entry = const_cast<EntryImpl&>(*match);
      entry.setFlag();
      if (AccessStrictSet1 == true && AccessStrictSet2 == true) { 
        UserSend[interest.getNonce()]++;
        hitCallback(interest, match->getData());
      }else if (interest.getNonce() > USER_NUM) {
        hitCallback(interest, match->getData());
      }else {
        UserNotSend[interest.getNonce()]++;
      }
    }
  }
}

iterator
Cs::findLeftmost(const Interest& interest, iterator first, iterator last) const
{
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

} 
} 
