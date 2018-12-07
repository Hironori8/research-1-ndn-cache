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
#include<stdio.h>
#include <chrono>

#define IDENTITY_NAME "NDNSERVER"

namespace nfd {
namespace cs {
  
int StartTime = 0;
int CacheHit_Counter = 0;
int CacheMiss_Counter = 0;
int Verification_Counter = 0;

time_t now = std::time(nullptr);
char JudgeValue[60];
char JudgeValue[60];

int n1 = sprintf(JudgeValue, "./Result/JudgeValue/JudgeValue_%s.csv",ctime(&now));
int n2 = sprintf(DataRateTable, "DataRateTable_%s.csv",ctime(&now));

std::ofstream outputfile1(JudgeValue);
std::ofstream outputfile2(DataRateTable);

std::unorderd_map<Name,int> DataRateTable;
using UserData = std::pair<Name,int>;
//ユーザのデータレートを記録するテーブルを作成

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
    //falseの場合全てのデータは認められない
  , m_shouldServe(true)
    //キャッシュの探索を許可
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
    //全てのデータが認証されないか容量が０ならデータを挿入はしない
    return;
  }
  NFD_LOG_DEBUG("insert " << data.getName());
  // recognize CachePolicy
  shared_ptr<lp::CachePolicyTag> tag = data.getTag<lp::CachePolicyTag>();
  //データに付属しているキャッシュポリシータグを取得
  if (tag != nullptr) {
    //タグが付いてたら実行される
    lp::CachePolicyType policy = tag->get().getPolicy();
    //キャッシュポリシータイプを取得
    if (policy == lp::CachePolicyType::NO_CACHE) {
      return;
    }
  }

  iterator it;
  bool isNewEntry = false;
  std::tie(it, isNewEntry) = m_table.emplace(data.shared_from_this(), isUnsolicited);
  //タプルの作成
  //isUnsolicitedは求めていたデータかどうかを真偽で判定するもの
  EntryImpl& entry = const_cast<EntryImpl&>(*it);

  entry.updateStaleTime();

  if (!isNewEntry) { //エントリーが存在したら
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
  //指定された要素の値が現れる最初の位置のイテレータを取得する
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
Cs::find(const Interest& interest,
         const HitCallback& hitCallback,
         const MissCallback& missCallback)
{
  //適合するデータパケットを見つける
  BOOST_ASSERT(static_cast<bool>(hitCallback));
  BOOST_ASSERT(static_cast<bool>(missCallback));
  
  InterestTimeTable.insert(UserData{interest.getName(),interest.getNonce});
  // outputfile2 << interest.getName() << "," << interest.getNonce() << std::endl;

  if((ns3::Simulator::Now().GetSeconds() - StartTime) > 1.0){
    double CacheHit_Rate = 
      (double)CacheHit_Counter/(CacheHit_Counter + CacheMiss_Counter);
    double Verification_Rate = 
      (double)Verification_Counter/CacheMiss_Counter;
    double Judge_Value =
      (double)(Verification_Counter/CacheMiss_Counter)/CacheHit_Rate;
    outputfile1 << StartTime << "," << Judge_Value << ","<< CacheMiss_Counter 
      << "," << CacheHit_Rate <<"," << Verification_Counter << std::endl;
    //ファイルにCacheHit_Rateを出力
    
    CacheHit_Counter = 0;
    CacheMiss_Counter = 0;
    Verification_Counter = 0;
    StartTime = ns3::Simulator::Now().GetSeconds();
  }
  
  if (!m_shouldServe || m_policy->getLimit() == 0) {
    missCallback(interest);
    return;
  }
  const Name& prefix = interest.getName();
  //要求パケットの名前を取得
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
  }
  else {
    match = this->findLeftmost(interest, first, last);
  }

  if (match == last) {
    // NFD_LOG_DEBUG("  no-match");
    CacheMiss_Counter++;
    //std::cout << "CacheMiss!" << std::endl;
    missCallback(interest);
    return;
  }
  CacheHit_Counter++;
  // std::cout<< ns3::Simulator::Now() << "  matching " << match->getName() << std::endl;
  m_policy->beforeUse(match);
  //マッチしたデータの場所を変える
  //std::cout << "CacheHit!" << std::endl;
    if(match->getFLag() == true){
    //すでに認証済みのフラグが付いていたら認証を飛ばす
    std::cout << "Already verified!" << std::endl;
    hitCallback(interest, match->getData());
    }else{
      // if(interest.matchesData(match->getData())==true){
      Verification_Counter++;
      if(ndn::security::verifySignature(match->getData(), m_key)==true){
      //データが正しいかどうか認証
      std::cout << "verification OK!" << std::endl;
      EntryImpl& entry = const_cast<EntryImpl&>(*match);
      entry.setFlag();
      // std::cout << entry.getFLag() << std::endl;
      //データに正しいデータであることを示すフラグをつける
      hitCallback(interest, match->getData());
      }
    }
}

iterator
Cs::findLeftmost(const Interest& interest, iterator first, iterator last) const
{
  //範囲内から指定された条件を満たす最初の要素を検索する
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

} // namespace cs
} // namespace nfd
