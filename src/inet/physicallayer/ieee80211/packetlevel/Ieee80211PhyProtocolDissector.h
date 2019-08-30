//
// Copyright (C) 2018 OpenSim Ltd.
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program; if not, see <http://www.gnu.org/licenses/>.
//
// @author: Zoltan Bojthe
//

#ifndef __INET_IEEE80211PHYDISSECTOR_H_
#define __INET_IEEE80211PHYDISSECTOR_H_

#include "inet/common/INETDefs.h"
#include "inet/common/packet/dissector/ProtocolDissector.h"
#include "inet/physicallayer/ieee80211/mode/Ieee80211DsssMode.h"
#include "inet/physicallayer/ieee80211/mode/Ieee80211DsssOfdmMode.h"
#include "inet/physicallayer/ieee80211/mode/Ieee80211ErpOfdmMode.h"
#include "inet/physicallayer/ieee80211/mode/Ieee80211FhssMode.h"
#include "inet/physicallayer/ieee80211/mode/Ieee80211HrDsssMode.h"
#include "inet/physicallayer/ieee80211/mode/Ieee80211HtMode.h"
#include "inet/physicallayer/ieee80211/mode/Ieee80211IrMode.h"
#include "inet/physicallayer/ieee80211/mode/Ieee80211OfdmMode.h"
#include "inet/physicallayer/ieee80211/mode/Ieee80211VhtMode.h"
#include "inet/physicallayer/ieee80211/packetlevel/Ieee80211Tag_m.h"
#include "inet/physicallayer/ieee80211/packetlevel/Ieee80211TransmitterBase.h"

namespace inet {

class INET_API Ieee80211PhyProtocolDissector : public ProtocolDissector
{
  public:
    virtual void dissect(Packet *packet, const Protocol *protocol, ICallback& callback) const override;

    static const Ptr<const inet::physicallayer::Ieee80211PhyHeader> popIeee80211PhyHeader(Packet *packet, const inet::physicallayer::IIeee80211Mode *mode);
};

} // namespace inet

#endif // __INET_IEEE80211PHYDISSECTOR_H_
