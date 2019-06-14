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
//サーバから取ってきたことを証明
#define USER_NUM 100
//ユーザの総数
#define ACCESS_STRICT 0.01
//アクセス制限
#define TRUSTVALUE_INTERVAL 0.025
//信頼値の時間間隔
#define INTERVAL 1.0
//計測の時間間隔
#define DATASTRICT_INTERVAL 0.025
//データ制限の時間間隔
#define ATTACKER_NUM 10

namespace nfd {
namespace cs {

bool setProposal1 = false;
//提案方式１を実装するフラグ
bool setProposal2 = true;
//提案方式２を実装するフラグ
bool AccessStrictSet1 = true;
//アクセス制御を行うことを示すフラグ
bool AccessStrictSet2 = true;
//信頼値をもとにしたアクセス制御を行うことを示すフラグ
double StartTime = ns3::Simulator::Now().GetSeconds();
//シミュレーション開始時間
double StartTime_TrustValue = 
  ns3::Simulator::Now().GetSeconds();
//信頼値計測開始時間
double StartTime_DataStrict = 
  ns3::Simulator::Now().GetSeconds();
//アクセス制限開始時間
int CacheHit_Counter = 0;
//キャッシュヒットした回数
int CacheMiss_Counter = 0;
//キャッシュミスした回数
int Verification_Counter = 0;
//非保護エリアでキャッシュヒットした回数
int Verification_Attacker_Counter = 0;
//攻撃者の非保護エリアでキャッシュヒットした回数
bool DataArrive_First[USER_NUM] = {};
//ユーザから最初のアクセスがあったことを示すフラグ
double ArriveTime = 0;
//データの到着時間
double Before_ArriveTime = 0; 
//前の到着時間
std::set<Name>Miss_List;
//1秒間あたりのキャッシュミスしたデータのリスト

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
//データセットは閾値などのデータ


//提案方式１で実装したもの
std::unordered_map<int,double>DataArriveTable;
using UserData = std::pair<int,double>;
//ユーザのデータレートを記録するテーブル(ユーザIDと，到着した時間)を作成
std::set<Name> User_List[USER_NUM];
//ユーザ１が要求したデータを格納するテーブル

//提案方式２で実装したもの
int User_Point[USER_NUM];
//ユーザのポイントを格納しておくもの
std::set<Name> Result[USER_NUM];
//共通するデータを格納するもの
std::unordered_map<int,double>User_TrustValue_Table;
using User_TrustValue_Data = std::pair<int,double>;
//それぞれのユーザの信頼値を保存しておくテーブル（ユーザIDと，信頼値）
double DataRate[USER_NUM];
//信頼値に基づいたデータ制限
double AccessStrict2[USER_NUM] = {};
//それぞれのユーザのアクセス制限
int AccessCount[USER_NUM] = {};
//それぞれのユーザのアクセス回数
int UserSend[USER_NUM] = {};
int UserNotSend[USER_NUM] = {};
double UserAccuracy[USER_NUM] = {};
bool first = true;
//計測期間で最初のアクセスかどうかのフラグ

std::unordered_map<int, int> User_Point_Table;
using User_Point_Data = std::pair<int,int>;
// 信頼値回復の為に参考にするテーブル(ユーザID, 信頼値カウンタ）
std::unordered_map<int, int> User_Count_Table;
using User_Count_Data = std::pair<int,int>;
// 信頼値回復の為に参考にするテーブル(ユーザID,回数カウンタ)
// int user_count[USER_NUM] = {};
// bool user_judge[USER_NUM] = {};

//攻撃察知モード
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

  if (!isNewEntry) { 
    //エントリーが存在したら
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
Cs::setAccessStrict(const Interest& interest)
{
  if(interest.getNonce() < USER_NUM){
    //ユーザIDのついた要求パケットの場合

    auto user_number = interest.getNonce();
    //ユーザのIDを取得 
    auto itr_trust = User_TrustValue_Table.find(interest.getNonce());
    //ユーザの信頼値を取得
    if (itr_trust == User_TrustValue_Table.end()) {
      //もし初めてのアクセスの場合
      AccessStrict2[user_number] = 40;
      //最初のアクセス制限を0.01に設定
      AccessCount[user_number]++;
      //そのIDのアクセスカウントをインクリメント

    }else{
      //すでにアクセスがあった場合
      AccessCount[user_number]++;
      if(ns3::Simulator::Now().GetSeconds()
          - StartTime_DataStrict > DATASTRICT_INTERVAL){
        for(auto itr_trust = User_TrustValue_Table.begin();
            itr_trust != User_TrustValue_Table.end(); 
            ++itr_trust){
          // if(itr_trust->second > 0.38){
            // //もし信頼値が0.35を超えていた場合
            // AccessStrict2[itr_trust->first] = 
            // AccessStrict2[itr_trust->first] *1.01;
            // // AccessStrict2[itr_trust->first] *1.001;
            // //アクセス許可数を増やす
          // }else if(itr_trust->second < 0.38){
            // //信頼値が0.35より小さい場合
            // // AccessStrict2[itr_trust->first] = 10;
            // //アクセス制限を0.01にリセット
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
    // ファイルにCacheHit_Rateを出力

    // for (int j = 0; j < USER_NUM; j++) {
      // for (int i = 0; i < USER_NUM; i++) {
        // //ユーザjと他のユーザの共通するデータをResult[j]に格納
        // if (i != j) {
          // std::set_intersection(User_List[j].begin(), User_List[j].end(),
              // User_List[i].begin(), User_List[i].end(),
              // std::inserter(Result[j], Result[j].end()));
          // //User_List[j]とUser_List[i]の共通するデータをResult[j]に格納
        // }
      // }
      // Point_Average += Result[j].size();
      // //Point_AverageにResult[j]の要素数を加算
    // }

    // Point_Average = Point_Average/USER_NUM;
    //ResultTableの要素数平均をだす

    for (int i = 0; i < USER_NUM; i++) {
      //その値とそれぞれのTableとの差をユーザにポイントとして与える
      // User_Point[i] += (Result[i].size() - Point_Average);
      //ユーザに与えられるポイントはResult[i]-要素数平均
      // auto TrustValue = 1/(1+exp(-0.01*User_Point[i]));
      auto TrustValue = 1/(1+exp(-User_Point[i]));
      //信頼値の定義式
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
      //そのポイントの合計を元に信頼値を決定

      // auto Result_begin = Result[i].begin();
      // auto Result_end = Result[i].end();
      // Result[i].erase(Result_begin, Result_end);
      //ResultTableを初期化

      // auto User_begin = User_List[i].begin();
      // auto User_end = User_List[i].end();
      // User_List[i].erase(User_begin, User_end);
      //User_Listを初期化

    }
    StartTime_TrustValue = ns3::Simulator::Now().GetSeconds();
  }
}

void
Cs::setArriveTimeProposal1(const Interest& interest)
{
  auto itr_arrive = DataArriveTable.find(interest.getNonce());
  //データレートテーブルから要求パケットを送ったユーザのイテレータを取得
  if(itr_arrive == DataArriveTable.end()){
    //そのユーザからの初めてのアクセスの場合
    ArriveTime = ns3::Simulator::Now().GetSeconds();
    //この要求パケットのデータ到着時間を取得 
    DataArriveTable.insert( UserData{ interest.getNonce(), ArriveTime } );
    //データをテーブルに挿入
  }else{
      //そのデータからのアクセスがすでにある場合
      Before_ArriveTime = itr_arrive->second;
      //前の要求パケットデータ到着時間を取得
      ArriveTime = ns3::Simulator::Now().GetSeconds();
      //この要求パケットのデータ到着時間を取得 
      //データ制限よりも到着時間が早い場合は，ArriveTimeは格納しない
      if((ArriveTime - Before_ArriveTime) > ACCESS_STRICT){
      //データの到着間隔がAccessStrict2より大きかったら
        itr_arrive->second = ArriveTime;
        //要求パケットを送ったノードのIDと要求パケットの到着時間をテーブルに格納
        AccessStrictSet1 = true;
        //アクセス制限はしない
      }else{
        //AccessStruce2よりも短い間隔で送られてきた場合
        AccessStrictSet1 = false;
        //アクセス制限実行
      }
  }
}

void
Cs::setArriveTimeProposal2(const Interest& interest)
{
  auto itr_arrive = DataArriveTable.find(interest.getNonce());
  //データレートテーブルから要求パケットを送ったユーザのイテレータを取得
  if(itr_arrive == DataArriveTable.end()){
    //そのユーザからの初めてのアクセスの場合
    ArriveTime = ns3::Simulator::Now().GetSeconds();
    //この要求パケットのデータ到着時間を取得 
    DataArriveTable.insert( UserData{ interest.getNonce(), ArriveTime } );
    //データをテーブルに挿入
    if(interest.getNonce() < USER_NUM){
    DataArrive_First[interest.getNonce()] = true;
    //一回目のアクセスが終了したことフラグで示す
    }
  }else{
      //そのデータからのアクセスがすでにある場合
      Before_ArriveTime = itr_arrive->second;
      //前の要求パケットデータ到着時間を取得
      ArriveTime = ns3::Simulator::Now().GetSeconds();
      //この要求パケットのデータ到着時間を取得 
      //データ制限よりも到着時間が早い場合は，ArriveTimeは格納しない
      if(AccessCount[interest.getNonce()] < AccessStrict2[interest.getNonce()]){
      //データの到着間隔がAccessStrict2より大きかったら
        itr_arrive->second = ArriveTime;
        //要求パケットを送ったノードのIDと要求パケットの到着時間をテーブルに格納
        AccessStrictSet2 = true;
        //アクセス制限はしない
      }else{
        //AccessStruce2よりも短い間隔で送られてきた場合
        itr_arrive->second = ArriveTime;

        AccessStrictSet2 = false;
        // std::cout << "User" << interest.getNonce() << "strict!" << std::endl;
        //アクセス制限実行
      }
  }
}

void
Cs::measureResult(const Interest& interest)
{
  if ((ns3::Simulator::Now().GetSeconds() - StartTime) > INTERVAL) {
    //測定時間がINTERVALをこえた場合，測定結果をfileに出力
    double CacheHit_Rate = 
      (double)CacheHit_Counter/(CacheHit_Counter + CacheMiss_Counter);
    //キャッシュヒット率＝キャッシュヒット回数/(キャッシュヒット回数＋キャッシュミス回数)
    double Verification_Rate = 
      (double)Verification_Counter/CacheMiss_Counter;
    //認証率＝認証回数/キャッシュミス回数
    if (CacheMiss_Counter == 0) {
      Verification_Rate = 0;
    }
    // double Threshold =
      // (double)Verification_Rate/CacheHit_Rate;
    //閾値＝認証率/キャッシュヒット率
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
    //測定結果を記録したら，それぞれの値を初期化
  }
}

void
Cs::measureResultProposal1(const Interest& interest)
{
  if ((ns3::Simulator::Now().GetSeconds() - StartTime) > INTERVAL) {
    //測定時間がINTERVALをこえた場合，測定結果をfileに出力
    double CacheHit_Rate = 
      (double)CacheHit_Counter/(CacheHit_Counter + CacheMiss_Counter);
    //キャッシュヒット率＝キャッシュヒット回数/(キャッシュヒット回数＋キャッシュミス回数)
    double Verification_Rate = 
      (double)Verification_Counter/CacheMiss_Counter;
    //認証率＝認証回数/キャッシュミス回数
    if (CacheMiss_Counter == 0) {
      Verification_Rate = 0;
    }
    double Threshold =
      (double)Verification_Rate/CacheHit_Rate;
    //閾値＝認証率/キャッシュヒット率

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
    //測定結果を記録したら，それぞれの値を初期化
  }
}

void
Cs::measureResultProposal2(const Interest& interest)
{
  if ((ns3::Simulator::Now().GetSeconds() - StartTime) > INTERVAL) {
    //測定時間がINTERVALをこえた場合，測定結果をfileに出力
    double CacheHit_Rate = 
      (double)CacheHit_Counter/(CacheHit_Counter + CacheMiss_Counter);
    //キャッシュヒット率＝キャッシュヒット回数/(キャッシュヒット回数＋キャッシュミス回数)
    double Verification_Rate = 
      (double)Verification_Counter/CacheMiss_Counter;
    //認証率＝認証回数/キャッシュミス回数
    if (CacheMiss_Counter == 0) {
      Verification_Rate = 0;
    }
    double Threshold =
      (double)Verification_Rate/CacheHit_Rate;
    //閾値＝認証率/キャッシュヒット率

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
    //信頼値をセット
    
    auto Miss_begin = Miss_List.begin();
    auto Miss_end = Miss_List.end();
    Miss_List.erase(Miss_begin, Miss_end);

    CacheHit_Counter = 0;
    CacheMiss_Counter = 0;
    Verification_Counter = 0;
    Verification_Attacker_Counter = 0;
    first = true;
    StartTime = ns3::Simulator::Now().GetSeconds();
    //測定結果を記録したら，それぞれの値を初期化
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
      // カウンターが１００であれば，ave_intervalに格納
      
        double sample_interval = interval/100;

        // if(total_interval/ave_counter > 10*sample_interval && ns3::Simulator::Now().GetSeconds() > 10){
        if(total_interval/ave_counter > 10*sample_interval){
          // 平均よりもアクセス間隔が極端に短い場合  
          for(int i = 0;i < USER_NUM; i++){

            AccessStrict2[i] = 40;
            // 全ユーザに制限をかける
            detection_mode[i] = true;
            // 攻撃を察知したため，攻撃者特定モードに移行
            
          }
        }else{

            total_interval += sample_interval;
        }

        outputfile5 << ns3::Simulator::Now().GetSeconds() << "," << sample_interval << std::endl;
        ave_interval_table.insert( ave_interval{ ave_counter, sample_interval } );
        // アクセスインターバルを記録

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
          // 過去5回のアクセスをみてキャッシュヒットがなかったら信頼値をあげる

          if(detection_mode[interest.getNonce()] == true){
            // 攻撃を検知し，全ユーザのアクセスを制限している場合
            trust->second = 1.0; 
            //攻撃者でないため信頼値を回復
            detection_mode[interest.getNonce()] = false;
            //アクセスしてきたユーザの制限を解除
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
  //適合するデータパケットを見つける
  BOOST_ASSERT(static_cast<bool>(hitCallback));
  BOOST_ASSERT(static_cast<bool>(missCallback));
  
  if (interest.getNonce() < USER_NUM) {
    //ユーザのデータである場合
    User_List[interest.getNonce()].insert(interest.getName());
    //ユーザのテーブルにデータを格納
  }

  if (setProposal1 == false && setProposal2 == false) {
    this->measureResult(interest);
    //データを測定
  }

  if (setProposal1 == true) {
    this->setArriveTimeProposal1(interest);
    //到着時間をセット
    this->measureResultProposal1(interest);
    //データを測定
  }

  if (setProposal2 == true) {
    this->setTrustValue();
    //信頼値をセット
    this->setAccessStrict(interest);
    //アクセス制限をセット
    this->setArriveTimeProposal2(interest);
    //到着時間をセット
    this->measureResultProposal2(interest);
    //データを測定
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
  }else {
    match = this->findLeftmost(interest, first, last);
  }

  if (match == last) {
    // NFD_LOG_DEBUG("  no-match");

    // 未認証コンテンツへの要求のため，要求された時間を記録
    this->setInterval_Detection();
    //未認証エリアへのアクセス間隔を計測し，攻撃を察知
    this->recover_trustvalue(interest,0);
    //過去のキャッシュヒットをみて信頼値を回復
    CacheMiss_Counter++;
    //キャッシュミスのカウンターをインクリメント
    Miss_List.insert(interest.getName());
    //キャッシュミスリストにデータを加える
    if (AccessStrictSet1 == true && AccessStrictSet2 == true) { 
      // && DataArrive_First[interest.getNonce()] == true)){
      //もしデータ制限がかかっていたらデータを送り返さない
      if(interest.getNonce() < USER_NUM){
        UserSend[interest.getNonce()]++;
        missCallback(interest);
      }else {
        //NonceがUSER_NUM以上のもの（経路構築のパケット）である場合
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
  //キャッシュヒットのカウンタをインクリメント
  m_policy->beforeUse(match);
  //マッチしたデータの場所を変える
  if (match->getFLag() == true) {
    //すでに認証済みのフラグが付いていたら認証を飛ばす
    
    User_Point[interest.getNonce()]++;
    //そのコンテンツを要求したユーザの信頼値をあげる

    // 提案方式２の実装
    this->recover_trustvalue(interest,1);
    // 信頼値の回復作業を行う
    if (AccessStrictSet1 == true && AccessStrictSet2 == true) { 

      //もしデータ制限がかかっていたらデータを送り返さない
      UserSend[interest.getNonce()]++;

      hitCallback(interest, match->getData());

    }else if (interest.getNonce() > USER_NUM) {
      //NonceがUSER_NUM以上のもの（経路構築のパケット）である場合
      UserSend[interest.getNonce()]++;

      hitCallback(interest, match->getData()); 

    }else {

      UserNotSend[interest.getNonce()]++;

    }
  }else{
    //認証をまだ行なっていないデータの場合
    
    // 未認証コンテンツに対する要求であるため時間を記録
    this->setInterval_Detection();

    //ユーザの信頼値を下げる
    User_Point[interest.getNonce()]--;

    this->recover_trustvalue(interest,-1);

    // auto itr_miss = Miss_List.find(interest.getName());
    // if (itr_miss != Miss_List.end()) {
      // Verification_Counter++;
      // //認証のカウンタをインクリメント
      // if(1<=interest.getNonce()&& interest.getNonce() <= ATTACKER_NUM){
        // Verification_Attacker_Counter++;
      // }
    // }

    
    if (AccessStrictSet1 == true && AccessStrictSet2 == true) { 
      //もしデータ制限が制限がかかっていない場合データを送り返す
      if (ndn::security::verifySignature(match->getData(), m_key) == true) {
        //データが正しいかどうか認証
        auto itr_miss = Miss_List.find(interest.getName());
        if (itr_miss != Miss_List.end()) {
          Verification_Counter++;
          //認証のカウンタをインクリメント
          if(1<=interest.getNonce()&& interest.getNonce() <= ATTACKER_NUM){
            Verification_Attacker_Counter++;
          }
        }
        EntryImpl& entry = const_cast<EntryImpl&>(*match);
        entry.setFlag();
        //データに正しいデータであることを示すフラグをつける
        UserSend[interest.getNonce()]++;
        hitCallback(interest, match->getData());
      }else if (interest.getNonce() > USER_NUM) {
        //NonceがUSER_NUM以上のもの（経路構築のパケット）である場合
        hitCallback(interest, match->getData());
      }else {
        UserNotSend[interest.getNonce()]++;
      }
    }
    // if (ndn::security::verifySignature(match->getData(), m_key) == true) {
      // //データが正しいかどうか認証
      // EntryImpl& entry = const_cast<EntryImpl&>(*match);
      // entry.setFlag();
      // //データに正しいデータであることを示すフラグをつける
      // if (AccessStrictSet1 == true && AccessStrictSet2 == true) { 
        // //もしデータ制限が制限がかかっていない場合データを送り返す
        // UserSend[interest.getNonce()]++;
        // hitCallback(interest, match->getData());
      // }else if (interest.getNonce() > USER_NUM) {
        // //NonceがUSER_NUM以上のもの（経路構築のパケット）である場合
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

} //csの名前空間の終了
} //nfdの名前空間の終了
