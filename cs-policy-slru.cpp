#include "cs-policy-slru.hpp"
#include "cs.hpp"
#include <boost/foreach.hpp>
#include <iostream>
#include <fstream>
#include <math.h>
#include <time.h>
#include <cstdio>
#include "ns3/simulator.h"

namespace nfd {
namespace cs {
namespace slru {

int c = 0;
//キャッシュへのアクセス回数のカウンタ

time_t now = std::time(nullptr);
char CacheMiss[60];
char NoProtectList[60];
int n1 = sprintf(CacheMiss,"./Result/CacheMiss/CacheMiss_%s.csv",ctime(&now));
int n2 = sprintf(NoProtectList,"./Result/NoProtectList/NoProtectList_%s.csv",ctime(&now));

std::ofstream outputfile(CacheMiss);
//キャッシュヒット，ミスをファイルに出力
std::ofstream outputfile2(NoProtectList);
//非保護リストをファイルに出力

const std::string SLruPolicy::POLICY_NAME = "slru";
NFD_REGISTER_CS_POLICY(SLruPolicy);

SLruPolicy::SLruPolicy()
  : Policy(POLICY_NAME)
{
}
void
SLruPolicy::doAfterInsert(iterator i)
{
  //挿入されたあとに呼び出されるメソッド
  outputfile <<ns3::Simulator::Now().GetSeconds() 
    << "CacheMiss:"<< "no_protect:"<< m_queue.size() 
    << "protect:"<< m_queue_protect.size() << std::endl;
  
  //キャッシュミスしたことをプリント
  std::cout << "insert:" << i->getName() << std::endl;
  //挿入されたデータをプリント
  this->insertToQueue(i, true);
  //CSに挿入されたときに呼び出されるメソッド
  this->evictEntries();
  //非保護エリアから容量を超えたデータを削除
  this->evictProtectEntries();
  //保護エリアから容量を超えたデータを削除
  // this->printQueue();
  //非保護エリアのデータをプリント
  // this->printQueue_Protect();
  //保護エリアのデータをプリント
  c++;
  //アクセスがあった分カウンタをプラス
}

void
SLruPolicy::doAfterRefresh(iterator i)
{
  //キャッシュヒットした際に呼び出されるメソッド
  // outputfile << ns3::Simulator::Now().GetSeconds() 
  // << "CacheHit:"<<"no_protect:"<< m_queue.size() 
  // << "protect:"<< m_queue_protect.size()<< std::endl;
  //キャッシュミスしたことをプリント
  this->insertToQueue(i, false);
  //CS内のデータにアクセスがあった場合呼び出されるメソッド
  this->evictEntries();
  //非保護エリアから容量を超えたデータを削除
  this->evictProtectEntries();
  //保護エリアから容量を超えたデータを削除
  // this->printQueue();
  //非保護エリアのデータをプリント
  // this->printQueue_Protect();
  //保護エリアのデータをプリント
}

void
SLruPolicy::doBeforeErase(iterator i)
//指定のものを削除するためのメソッド
{
  m_queue.get<1>().erase(i);
  m_queue_protect.get<1>().erase(i);
  //辞書順のソートを呼び出し指定のものを消去
}

void
SLruPolicy::doBeforeUse(iterator i)
//CSにマッチしたデータがあった際に呼び出されるメソッド
{
  // outputfile << ns3::Simulator::Now().GetSeconds() 
  // << ":CacheHit:"<<"no_protect:"<< m_queue.size() 
  // << "protect:"<< m_queue_protect.size() << std::endl;
  this->insertToQueue(i, false);
  this->evictEntries();
  this->evictProtectEntries();
}

void
SLruPolicy::evictEntries()
{
  //非保護エリアの容量を超えたデータを排除する
  BOOST_ASSERT(this->getCs() != nullptr);
  //CSがなかったら強制終了
  while(m_queue.size() > this->getLimit()) 
  {
    //非保護エリアのサイズが制限を超えた場合
    BOOST_ASSERT(!m_queue.empty());
    iterator i1 = m_queue.front();
    // std::cout << i1->getName() << std::endl;
    //先頭要素を参照する
    // std::cout << "delete from  noprotect" << std::endl;
    m_queue.pop_front();
    //先頭要素を排除する
    this->emitSignal(beforeEvict, i1);
  }
}
void
SLruPolicy::evictProtectEntries()
{
  //保護エリアの容量を超えたデータを排除する
  BOOST_ASSERT(this->getCs() != nullptr);
  //CSがなかったら強制終了
  while (m_queue_protect.size() > this->getLimit_protect()) 
  {
  //保護エリアのサイズが制限を超えた場合
  BOOST_ASSERT(!m_queue_protect.empty());
  iterator i2 = m_queue_protect.front();
  //先頭要素を参照する
  m_queue.push_back(i2);
  //その要素を保護エリアから削除する．
  m_queue_protect.pop_front();
  // std::cout << "send noprotect"<< i2->getName() << std::endl;
  //その要素を保護エリアから非保護エリアへ移動する．
  }
}
void
SLruPolicy::insertToQueue(iterator i, bool isNewEntry)
//要素を挿入するためのコマンド
{
  if(ns3::Simulator::Now().GetSeconds()==20.8){
    BOOST_FOREACH(const iterator& i,m_queue)
    outputfile2 <<"NoProtectList:"<< i->getName() << std::endl;
  }
  //新たな要素を末尾に追加
  if(!isNewEntry){
    //既存のデータであった場合
    auto result = std::find(m_queue.begin(),m_queue.end(),i);
    if(result != m_queue.end()){
      //非保護エリアにある既存のデータにアクセスがあった場合，
      // std::cout << "CacheHit in NoProtect" << std::endl;
      //非保護でキャッシュヒットが起きたことをプリント
      m_queue_protect.push_back(i);
      //そのデータを保護エリアの最後尾に挿入
      m_queue.erase(result);
      //非保護エリアのデータを削除
      outputfile << ns3::Simulator::Now().GetSeconds() 
        << ":CacheHitInNoProtect:"<<"no_protect:"<< m_queue.size() 
        << "protect:"<< m_queue_protect.size() << std::endl;
      //データをcsvに出力

       // this->printQueue();
      // 非保護エリアにあるデータを表示

       // this->printQueue_Protect();
      // 保護エリアにあるデータを表示

    }else{
      auto result_protect = 
        std::find(m_queue_protect.begin(),m_queue_protect.end(),i);
      //そのデータが保護エリアにあった場合
      if(result_protect != m_queue_protect.end()){

        std::cout << "CacheHit in Protect" << std::endl;
        //保護エリアでキャッシュヒットが起きたことをプリント

        m_queue_protect.relocate(m_queue_protect.end(),result_protect);
        //そのデータを保護エリアの最後尾に移動

        outputfile << ns3::Simulator::Now().GetSeconds() 
          << ":CacheHitInProtect:"<<"no_protect:"<< m_queue.size() 
          << "protect:"<< m_queue_protect.size() << std::endl;

        // this->printQueue();
        // 非保護エリアにあるデータを表示

        // this->printQueue_Protect();
        // 保護エリアにあるデータを表示
      }
    }
  }
  else{
    //新しいエントリーの場合，非保護エリアに挿入
    m_queue.push_back(i);
  }
}
void
SLruPolicy::printQueue()
{
  BOOST_FOREACH(const iterator& i,m_queue)
    std::cout <<"NoProtectList:"<< i->getName() << std::endl;
    std::cout <<"NoProtectLimit" << this->getLimit() <<std::endl;
}
void
SLruPolicy::printQueue_Protect()
{
  BOOST_FOREACH(const iterator& i,m_queue_protect)
    std::cout <<"ProtectList:"<< i->getName() << std::endl;
}
  
} //　lruの名前空間
} //　csの名前空間
} //　nfdの名前空間
