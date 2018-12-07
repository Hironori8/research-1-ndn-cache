/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2014-2017,  Regents of the University of California,
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
//$B%(%s%H%j!<Fb$N%G!<%?$N?6$kIq$$$K4X$7$F5-=R$7$F$$$k$b$N(B
#include "cs-entry.hpp"

namespace nfd {
namespace cs {

void
Entry::setData(shared_ptr<const Data> data, bool isUnsolicited)
{
  m_data = data;
  m_isUnsolicited = isUnsolicited;
  m_Flag = false;
  updateStaleTime();
  //$B;~4V$r8=:_$N;~4V$KJQ99$9$k(B
}
void
Entry::setMark(shared_ptr<const Data> data, bool Flag)
{
  m_data = data;
  m_Flag = Flag;
}


bool
Entry::isStale() const
{
  BOOST_ASSERT(this->hasData());
  //$B%G!<%?$r;}$C$F$$$J$$>l9g0[>o=*N;(B
  return m_staleTime < time::steady_clock::now();
}

void
Entry::updateStaleTime()
{
  BOOST_ASSERT(this->hasData());
  //$B%G!<%?$r;}$C$F$$$J$$>l9g0[>o=*N;(B
  m_staleTime = time::steady_clock::now() + time::milliseconds(m_data->getFreshnessPeriod());
}

bool
Entry::canSatisfy(const Interest& interest) const
{
  BOOST_ASSERT(this->hasData());
  // if (!interest.matchesData(*m_data)) {
     // return false;
  // }

  if (interest.getMustBeFresh() == static_cast<int>(true) && this->isStale()) {
    return false;
  }

  return true;
}

void
Entry::reset()
{
  m_data.reset();
  m_isUnsolicited = false;
  m_Flag = false;
  m_staleTime = time::steady_clock::TimePoint();
}

} // namespace cs
} // namespace nfd
