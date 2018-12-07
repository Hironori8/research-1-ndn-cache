//エントリーデーブルの動作に付いて記述しているファイル
#include "cs-entry-impl.hpp"

namespace nfd {
namespace cs {

EntryImpl::EntryImpl(const Name& name)
  : m_queryName(name)
{
  BOOST_ASSERT(this->isQuery());
}

EntryImpl::EntryImpl(shared_ptr<const Data> data, bool isUnsolicited)//,bool Flag)
{
  //データを格納するためのエントリーテーブルを作成
  this->setData(data, isUnsolicited);
  // this->setMark(data,Flag);
  BOOST_ASSERT(!this->isQuery());
  //データパケットがない場合異常終了
}


bool
EntryImpl::isQuery() const
{
  //データパケットがある場合falseを返す
  return !this->hasData();
}

void
EntryImpl::unsetUnsolicited()
{
  BOOST_ASSERT(!this->isQuery());
  //データパケットがない場合異常終了
  this->setData(this->getData(), false);
}

void
EntryImpl::setFlag()
{
  BOOST_ASSERT(!this->isQuery());
  //データパケットがない場合異常終了
  this->setMark(this->getData(),true);
}


int
compareQueryWithData(const Name& queryName, const Data& data)
{
  bool queryIsFullName = !queryName.empty() && queryName[-1].isImplicitSha256Digest();
  //キュエリーの名前が空でないかつImplicitShaDigestであるかどうか判定

  int cmp = queryIsFullName ?
            queryName.compare(0, queryName.size() - 1, data.getName()) :
            queryName.compare(data.getName());

  if (cmp != 0) { // Name without digest differs
    return cmp;
  }

  if (queryIsFullName) { // Name without digest equals, compare digest
    return queryName[-1].compare(data.getFullName()[-1]);
  }
  else { // queryName is a proper prefix of Data fullName
    return -1;
  }
}

int
compareDataWithData(const Data& lhs, const Data& rhs)
{
  int cmp = lhs.getName().compare(rhs.getName());
  if (cmp != 0) {
    return cmp;
  }

  return lhs.getFullName()[-1].compare(rhs.getFullName()[-1]);
}

bool
EntryImpl::operator<(const EntryImpl& other) const
{
  if (this->isQuery()) {
    if (other.isQuery()) {
      return m_queryName < other.m_queryName;
    }
    else {
      return compareQueryWithData(m_queryName, other.getData()) < 0;
    }
  }
  else {
    if (other.isQuery()) {
      return compareQueryWithData(other.m_queryName, this->getData()) > 0;
    }
    else {
      return compareDataWithData(this->getData(), other.getData()) < 0;
    }
  }
}

} // namespace cs
} // namespace nfd

