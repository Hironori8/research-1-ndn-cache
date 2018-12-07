//$B%]%j%7!<$NEPO?$H<B:]$N%]%j%7!<$N5sF0$r<($7$?%U%!%$%k(B
#include "cs-policy.hpp"
#include "cs.hpp"
#include "core/logger.hpp"
#include <boost/range/adaptor/map.hpp>
#include <boost/range/algorithm/copy.hpp>

NFD_LOG_INIT("CsPolicy");

namespace nfd {
namespace cs {

Policy::Registry&
Policy::getRegistry()
{
  static Registry registry;
  return registry;
}

unique_ptr<Policy>
Policy::create(const std::string& policyName)
{
  Registry& registry = getRegistry();
  auto i = registry.find(policyName);
  return i == registry.end() ? nullptr : i->second();
}

std::set<std::string>
Policy::getPolicyNames()
{
  std::set<std::string> policyNames;
  boost::copy(getRegistry() | boost::adaptors::map_keys,
              std::inserter(policyNames, policyNames.end()));
  return policyNames;
}

Policy::Policy(const std::string& policyName)
  : m_policyName(policyName)
{
}

void
Policy::setLimit(size_t nMaxEntries)
{
  NFD_LOG_INFO("setLimit " << nMaxEntries);
  m_limit = nMaxEntries/2;
  m_limit_protect = nMaxEntries/2;
  this->evictEntries();
  // this->evictProtectEntries();
}
size_t
Policy::getLimit_protect()const
{
  return m_limit_protect;
}
void
Policy::afterInsert(iterator i)
{
  BOOST_ASSERT(m_cs != nullptr);
  //cs$B$,$J$+$C$?$i6/@)=*N;(B
  this->doAfterInsert(i);
}

void
Policy::afterRefresh(iterator i)
{
  BOOST_ASSERT(m_cs != nullptr);
  //cs$B$,$J$+$C$?$i6/@)=*N;(B
  this->doAfterRefresh(i);
}

void
Policy::beforeErase(iterator i)
{
  // m_cs = nullptr;
  BOOST_ASSERT(m_cs != nullptr);
  //cs$B$,$J$+$C$?$i6/@)=*N;(B
  this->doBeforeErase(i);
  // std::cout << "erase" << i->getName() << std::endl;
}

void
Policy::beforeUse(iterator i)
{
  BOOST_ASSERT(m_cs != nullptr);
  //cs$B$,$J$+$C$?$i6/@)=*N;(B
  this->doBeforeUse(i);
}

} // namespace cs
} // namespace nfd
