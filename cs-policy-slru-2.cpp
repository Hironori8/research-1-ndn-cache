#include "cs-policy-slru-2.hpp"
#include "cs.hpp"
#include <boost/foreach.hpp>

namespace nfd {
namespace cs {
namespace slruNoPrint {


const std::string SLruPolicy2::POLICY_NAME = "slruNoPrint";
NFD_REGISTER_CS_POLICY(SLruPolicy2);

SLruPolicy2::SLruPolicy2()
  : Policy(POLICY_NAME)
{
}

void
SLruPolicy2::doAfterInsert(iterator i)
{
  //挿入されたあとに呼び出されるメソッド
  this->insertToQueue(i, true);

  this->evictEntries();

  this->evictProtectEntries();

}

void
SLruPolicy2::doAfterRefresh(iterator i)
{
  this->insertToQueue(i, false);
  this->evictEntries();
  this->evictProtectEntries();
}

void
SLruPolicy2::doBeforeErase(iterator i)
//指定のものを削除するためのメソッド
{
  m_queue.get<1>().erase(i);
  m_queue_protect.get<1>().erase(i);
}

void
SLruPolicy2::doBeforeUse(iterator i)
//CSにマッチしたデータがあった際に呼び出されるメソッド
{
  this->insertToQueue(i, false);
  this->evictEntries();
  this->evictProtectEntries();
}

void
SLruPolicy2::evictEntries()
{
  //非保護エリアの容量を超えたデータを排除する
  BOOST_ASSERT(this->getCs() != nullptr);
  //CSがなかったら強制終了
  while(m_queue.size() > this->getLimit()) 
  {
    //非保護エリアのサイズが制限を超えた場合
    BOOST_ASSERT(!m_queue.empty());
    iterator i1 = m_queue.front();
    //先頭要素を参照する
    m_queue.pop_front();
    //先頭要素を排除する
    this->emitSignal(beforeEvict, i1);
  }
}
void
SLruPolicy2::evictProtectEntries()
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
  m_queue_protect.pop_front();
  //その要素を保護エリアから削除する．
  // std::cout << "send noprotect"<< i2->getName() << std::endl;
  //その要素を保護エリアから非保護エリアへ移動する．
  }
}
void
SLruPolicy2::insertToQueue(iterator i, bool isNewEntry)
//要素を挿入するためのコマンド
{
  if(!isNewEntry){
    //既存のデータであった場合
    auto result = std::find(m_queue.begin(),m_queue.end(),i);
    if(result != m_queue.end()){
      //非保護エリアにある既存のデータにアクセスがあった場合，
      m_queue_protect.push_back(i);
      //そのデータを保護エリアの最後尾に挿入
      m_queue.erase(result);
      //非保護エリアのデータを削除
    }else{
      auto result_protect = std::find(m_queue_protect.begin(),m_queue_protect.end(),i);
      //そのデータが保護エリアにあった場合
      if(result_protect != m_queue_protect.end()){
        // std::cout << "CacheHit in Protect" << std::endl;
        m_queue_protect.relocate(m_queue_protect.end(),result_protect);
        //そのデータを保護エリアの最後尾に移動
      }
    }
  }
  else{
    //新しいエントリーの場合，非保護エリアに挿入
    m_queue.push_back(i);
  }
}
void
SLruPolicy2::printQueue()
{
  BOOST_FOREACH(const iterator& i,m_queue)
    std::cout <<"NoProtectList:"<< i->getName() << std::endl;
}
void
SLruPolicy2::printQueue_Protect()
{
  BOOST_FOREACH(const iterator& i,m_queue_protect)
    std::cout <<"ProtectList:"<< i->getName() << std::endl;
}

} // namespace lru
} // namespace cs
} // namespace nfd
