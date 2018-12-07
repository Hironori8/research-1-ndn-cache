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
//$B%-%c%C%7%e$X$N%"%/%;%92s?t$N%+%&%s%?(B

time_t now = std::time(nullptr);
char CacheMiss[60];
char NoProtectList[60];
int n1 = sprintf(CacheMiss,"./Result/CacheMiss/CacheMiss_%s.csv",ctime(&now));
int n2 = sprintf(NoProtectList,"./Result/NoProtectList/NoProtectList_%s.csv",ctime(&now));

std::ofstream outputfile(CacheMiss);
//$B%-%c%C%7%e%R%C%H!$%_%9$r%U%!%$%k$K=PNO(B
std::ofstream outputfile2(NoProtectList);
//$BHsJ]8n%j%9%H$r%U%!%$%k$K=PNO(B

const std::string SLruPolicy::POLICY_NAME = "slru";
NFD_REGISTER_CS_POLICY(SLruPolicy);

SLruPolicy::SLruPolicy()
  : Policy(POLICY_NAME)
{
}
void
SLruPolicy::doAfterInsert(iterator i)
{
  //$BA^F~$5$l$?$"$H$K8F$S=P$5$l$k%a%=%C%I(B
  outputfile <<ns3::Simulator::Now().GetSeconds() 
    << "CacheMiss:"<< "no_protect:"<< m_queue.size() 
    << "protect:"<< m_queue_protect.size() << std::endl;
  
  //$B%-%c%C%7%e%_%9$7$?$3$H$r%W%j%s%H(B
  std::cout << "insert:" << i->getName() << std::endl;
  //$BA^F~$5$l$?%G!<%?$r%W%j%s%H(B
  this->insertToQueue(i, true);
  //CS$B$KA^F~$5$l$?$H$-$K8F$S=P$5$l$k%a%=%C%I(B
  this->evictEntries();
  //$BHsJ]8n%(%j%"$+$iMFNL$rD6$($?%G!<%?$r:o=|(B
  this->evictProtectEntries();
  //$BJ]8n%(%j%"$+$iMFNL$rD6$($?%G!<%?$r:o=|(B
  // this->printQueue();
  //$BHsJ]8n%(%j%"$N%G!<%?$r%W%j%s%H(B
  // this->printQueue_Protect();
  //$BJ]8n%(%j%"$N%G!<%?$r%W%j%s%H(B
  c++;
  //$B%"%/%;%9$,$"$C$?J,%+%&%s%?$r%W%i%9(B
}

void
SLruPolicy::doAfterRefresh(iterator i)
{
  //$B%-%c%C%7%e%R%C%H$7$?:]$K8F$S=P$5$l$k%a%=%C%I(B
  // outputfile << ns3::Simulator::Now().GetSeconds() 
  // << "CacheHit:"<<"no_protect:"<< m_queue.size() 
  // << "protect:"<< m_queue_protect.size()<< std::endl;
  //$B%-%c%C%7%e%_%9$7$?$3$H$r%W%j%s%H(B
  this->insertToQueue(i, false);
  //CS$BFb$N%G!<%?$K%"%/%;%9$,$"$C$?>l9g8F$S=P$5$l$k%a%=%C%I(B
  this->evictEntries();
  //$BHsJ]8n%(%j%"$+$iMFNL$rD6$($?%G!<%?$r:o=|(B
  this->evictProtectEntries();
  //$BJ]8n%(%j%"$+$iMFNL$rD6$($?%G!<%?$r:o=|(B
  // this->printQueue();
  //$BHsJ]8n%(%j%"$N%G!<%?$r%W%j%s%H(B
  // this->printQueue_Protect();
  //$BJ]8n%(%j%"$N%G!<%?$r%W%j%s%H(B
}

void
SLruPolicy::doBeforeErase(iterator i)
//$B;XDj$N$b$N$r:o=|$9$k$?$a$N%a%=%C%I(B
{
  m_queue.get<1>().erase(i);
  m_queue_protect.get<1>().erase(i);
  //$B<-=q=g$N%=!<%H$r8F$S=P$7;XDj$N$b$N$r>C5n(B
}

void
SLruPolicy::doBeforeUse(iterator i)
//CS$B$K%^%C%A$7$?%G!<%?$,$"$C$?:]$K8F$S=P$5$l$k%a%=%C%I(B
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
  //$BHsJ]8n%(%j%"$NMFNL$rD6$($?%G!<%?$rGS=|$9$k(B
  BOOST_ASSERT(this->getCs() != nullptr);
  //CS$B$,$J$+$C$?$i6/@)=*N;(B
  while(m_queue.size() > this->getLimit()) 
  {
    //$BHsJ]8n%(%j%"$N%5%$%:$,@)8B$rD6$($?>l9g(B
    BOOST_ASSERT(!m_queue.empty());
    iterator i1 = m_queue.front();
    // std::cout << i1->getName() << std::endl;
    //$B@hF,MWAG$r;2>H$9$k(B
    // std::cout << "delete from  noprotect" << std::endl;
    m_queue.pop_front();
    //$B@hF,MWAG$rGS=|$9$k(B
    this->emitSignal(beforeEvict, i1);
  }
}
void
SLruPolicy::evictProtectEntries()
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
  //$B$=$NMWAG$rJ]8n%(%j%"$+$i:o=|$9$k!%(B
  m_queue_protect.pop_front();
  // std::cout << "send noprotect"<< i2->getName() << std::endl;
  //$B$=$NMWAG$rJ]8n%(%j%"$+$iHsJ]8n%(%j%"$X0\F0$9$k!%(B
  }
}
void
SLruPolicy::insertToQueue(iterator i, bool isNewEntry)
//$BMWAG$rA^F~$9$k$?$a$N%3%^%s%I(B
{
  if(ns3::Simulator::Now().GetSeconds()==20.8){
    BOOST_FOREACH(const iterator& i,m_queue)
    outputfile2 <<"NoProtectList:"<< i->getName() << std::endl;
  }
  //$B?7$?$JMWAG$rKvHx$KDI2C(B
  if(!isNewEntry){
    //$B4{B8$N%G!<%?$G$"$C$?>l9g(B
    auto result = std::find(m_queue.begin(),m_queue.end(),i);
    if(result != m_queue.end()){
      //$BHsJ]8n%(%j%"$K$"$k4{B8$N%G!<%?$K%"%/%;%9$,$"$C$?>l9g!$(B
      // std::cout << "CacheHit in NoProtect" << std::endl;
      //$BHsJ]8n$G%-%c%C%7%e%R%C%H$,5/$-$?$3$H$r%W%j%s%H(B
      m_queue_protect.push_back(i);
      //$B$=$N%G!<%?$rJ]8n%(%j%"$N:G8eHx$KA^F~(B
      m_queue.erase(result);
      //$BHsJ]8n%(%j%"$N%G!<%?$r:o=|(B
      outputfile << ns3::Simulator::Now().GetSeconds() 
        << ":CacheHitInNoProtect:"<<"no_protect:"<< m_queue.size() 
        << "protect:"<< m_queue_protect.size() << std::endl;
      //$B%G!<%?$r(Bcsv$B$K=PNO(B

       // this->printQueue();
      // $BHsJ]8n%(%j%"$K$"$k%G!<%?$rI=<((B

       // this->printQueue_Protect();
      // $BJ]8n%(%j%"$K$"$k%G!<%?$rI=<((B

    }else{
      auto result_protect = 
        std::find(m_queue_protect.begin(),m_queue_protect.end(),i);
      //$B$=$N%G!<%?$,J]8n%(%j%"$K$"$C$?>l9g(B
      if(result_protect != m_queue_protect.end()){

        std::cout << "CacheHit in Protect" << std::endl;
        //$BJ]8n%(%j%"$G%-%c%C%7%e%R%C%H$,5/$-$?$3$H$r%W%j%s%H(B

        m_queue_protect.relocate(m_queue_protect.end(),result_protect);
        //$B$=$N%G!<%?$rJ]8n%(%j%"$N:G8eHx$K0\F0(B

        outputfile << ns3::Simulator::Now().GetSeconds() 
          << ":CacheHitInProtect:"<<"no_protect:"<< m_queue.size() 
          << "protect:"<< m_queue_protect.size() << std::endl;

        // this->printQueue();
        // $BHsJ]8n%(%j%"$K$"$k%G!<%?$rI=<((B

        // this->printQueue_Protect();
        // $BJ]8n%(%j%"$K$"$k%G!<%?$rI=<((B
      }
    }
  }
  else{
    //$B?7$7$$%(%s%H%j!<$N>l9g!$HsJ]8n%(%j%"$KA^F~(B
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
  
} //$B!!(Blru$B$NL>A06u4V(B
} //$B!!(Bcs$B$NL>A06u4V(B
} //$B!!(Bnfd$B$NL>A06u4V(B
