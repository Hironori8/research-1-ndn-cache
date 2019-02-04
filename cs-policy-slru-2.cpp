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
  //$BA^F~$5$l$?$"$H$K8F$S=P$5$l$k%a%=%C%I(B
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
//$B;XDj$N$b$N$r:o=|$9$k$?$a$N%a%=%C%I(B
{
  m_queue.get<1>().erase(i);
  m_queue_protect.get<1>().erase(i);
}

void
SLruPolicy2::doBeforeUse(iterator i)
//CS$B$K%^%C%A$7$?%G!<%?$,$"$C$?:]$K8F$S=P$5$l$k%a%=%C%I(B
{
  this->insertToQueue(i, false);
  this->evictEntries();
  this->evictProtectEntries();
}

void
SLruPolicy2::evictEntries()
{
  //$BHsJ]8n%(%j%"$NMFNL$rD6$($?%G!<%?$rGS=|$9$k(B
  BOOST_ASSERT(this->getCs() != nullptr);
  //CS$B$,$J$+$C$?$i6/@)=*N;(B
  while(m_queue.size() > this->getLimit()) 
  {
    //$BHsJ]8n%(%j%"$N%5%$%:$,@)8B$rD6$($?>l9g(B
    BOOST_ASSERT(!m_queue.empty());
    iterator i1 = m_queue.front();
    //$B@hF,MWAG$r;2>H$9$k(B
    m_queue.pop_front();
    //$B@hF,MWAG$rGS=|$9$k(B
    this->emitSignal(beforeEvict, i1);
  }
}
void
SLruPolicy2::evictProtectEntries()
{
  //$BJ]8n%(%j%"$NMFNL$rD6$($?%G!<%?$rGS=|$9$k(B
  BOOST_ASSERT(this->getCs() != nullptr);
  //CS$B$,$J$+$C$?$i6/@)=*N;(B
  while (m_queue_protect.size() > this->getLimit_protect()) 
  {
  //$BJ]8n%(%j%"$N%5%$%:$,@)8B$rD6$($?>l9g(B
  BOOST_ASSERT(!m_queue_protect.empty());
  iterator i2 = m_queue_protect.front();
  //$B@hF,MWAG$r;2>H$9$k(B
  m_queue.push_back(i2);
  m_queue_protect.pop_front();
  //$B$=$NMWAG$rJ]8n%(%j%"$+$i:o=|$9$k!%(B
  // std::cout << "send noprotect"<< i2->getName() << std::endl;
  //$B$=$NMWAG$rJ]8n%(%j%"$+$iHsJ]8n%(%j%"$X0\F0$9$k!%(B
  }
}
void
SLruPolicy2::insertToQueue(iterator i, bool isNewEntry)
//$BMWAG$rA^F~$9$k$?$a$N%3%^%s%I(B
{
  if(!isNewEntry){
    //$B4{B8$N%G!<%?$G$"$C$?>l9g(B
    auto result = std::find(m_queue.begin(),m_queue.end(),i);
    if(result != m_queue.end()){
      //$BHsJ]8n%(%j%"$K$"$k4{B8$N%G!<%?$K%"%/%;%9$,$"$C$?>l9g!$(B
      m_queue_protect.push_back(i);
      //$B$=$N%G!<%?$rJ]8n%(%j%"$N:G8eHx$KA^F~(B
      m_queue.erase(result);
      //$BHsJ]8n%(%j%"$N%G!<%?$r:o=|(B
    }else{
      auto result_protect = std::find(m_queue_protect.begin(),m_queue_protect.end(),i);
      //$B$=$N%G!<%?$,J]8n%(%j%"$K$"$C$?>l9g(B
      if(result_protect != m_queue_protect.end()){
        // std::cout << "CacheHit in Protect" << std::endl;
        m_queue_protect.relocate(m_queue_protect.end(),result_protect);
        //$B$=$N%G!<%?$rJ]8n%(%j%"$N:G8eHx$K0\F0(B
      }
    }
  }
  else{
    //$B?7$7$$%(%s%H%j!<$N>l9g!$HsJ]8n%(%j%"$KA^F~(B
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
