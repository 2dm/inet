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


#include "inet/common/ProtocolGroup.h"
#include "inet/common/ProtocolTag_m.h"
#include "inet/common/packet/chunk/BitCountChunk.h"
#include "inet/common/packet/dissector/ProtocolDissectorRegistry.h"
#include "inet/physicallayer/ieee80211/packetlevel/Ieee80211PhyHeader_m.h"
#include "inet/physicallayer/ieee80211/packetlevel/Ieee80211PhyProtocolDissector.h"
#include "inet/physicallayer/ieee80211/packetlevel/Ieee80211Tag_m.h"

namespace inet {

Register_Protocol_Dissector(&Protocol::ieee80211Phy, Ieee80211PhyProtocolDissector);

void Ieee80211PhyProtocolDissector::dissect(Packet *packet, const Protocol *protocol, ICallback& callback) const
{
    callback.startProtocolDataUnit(&Protocol::ieee80211Phy);
    auto originalBackOffset = packet->getBackOffset();
    auto payloadEndOffset = packet->getFrontOffset();
    auto mode = packet->getTag<inet::physicallayer::Ieee80211ModeInd>()->getMode();
    const auto& header = popIeee80211PhyHeader(packet, mode);
    callback.visitChunk(header, &Protocol::ieee80211Phy);
    payloadEndOffset += header->getChunkLength() + B(header->getLengthField());
    bool incorrect = (payloadEndOffset > originalBackOffset || header->getLengthField() < header->getChunkLength());
    if (incorrect) {
        callback.markIncorrect();
        payloadEndOffset = originalBackOffset;
    }
    packet->setBackOffset(payloadEndOffset);
    callback.dissectPacket(packet, &Protocol::ieee80211Mac);
    packet->setBackOffset(originalBackOffset);
    auto paddingLength = packet->getDataLength();
    if (paddingLength > b(0)) {
        const auto& padding = packet->popAtFront(paddingLength);
        callback.visitChunk(padding, &Protocol::ieee80211Phy);
    }
    callback.endProtocolDataUnit(&Protocol::ieee80211Phy);
}

const Ptr<const inet::physicallayer::Ieee80211PhyHeader> Ieee80211PhyProtocolDissector::popIeee80211PhyHeader(Packet *packet, const inet::physicallayer::IIeee80211Mode *mode)
{
    if (dynamic_cast<const inet::physicallayer::Ieee80211DsssMode*>(mode)) {
        return packet->popAtFront<inet::physicallayer::Ieee80211DsssPhyHeader>(b(-1), Chunk::PF_ALLOW_INCORRECT);
    }
    else if (dynamic_cast<const inet::physicallayer::Ieee80211DsssOfdmMode*>(mode)) {
        return packet->popAtFront<inet::physicallayer::Ieee80211DsssPhyHeader>(b(-1), Chunk::PF_ALLOW_INCORRECT);
    }
    else if (dynamic_cast<const inet::physicallayer::Ieee80211ErpOfdmMode*>(mode)) {
        return packet->popAtFront<inet::physicallayer::Ieee80211ErpOfdmPhyHeader>(b(-1), Chunk::PF_ALLOW_INCORRECT);
    }
    else if (dynamic_cast<const inet::physicallayer::Ieee80211FhssMode*>(mode)) {
        return packet->popAtFront<inet::physicallayer::Ieee80211FhssPhyHeader>(b(-1), Chunk::PF_ALLOW_INCORRECT);
    }
    else if (dynamic_cast<const inet::physicallayer::Ieee80211HrDsssMode*>(mode)) {
        return packet->popAtFront<inet::physicallayer::Ieee80211HrDsssPhyHeader>(b(-1), Chunk::PF_ALLOW_INCORRECT);
    }
    else if (dynamic_cast<const inet::physicallayer::Ieee80211HtMode*>(mode)) {
        return packet->popAtFront<inet::physicallayer::Ieee80211HtPhyHeader>(b(-1), Chunk::PF_ALLOW_INCORRECT);
    }
    else if (dynamic_cast<const inet::physicallayer::Ieee80211IrMode*>(mode)) {
        return packet->popAtFront<inet::physicallayer::Ieee80211IrPhyHeader>(b(-1), Chunk::PF_ALLOW_INCORRECT);
    }
    else if (dynamic_cast<const inet::physicallayer::Ieee80211OfdmMode*>(mode)) {
        return packet->popAtFront<inet::physicallayer::Ieee80211OfdmPhyHeader>(b(-1), Chunk::PF_ALLOW_INCORRECT);
    }
    else if (dynamic_cast<const inet::physicallayer::Ieee80211VhtMode*>(mode)) {
        return packet->popAtFront<inet::physicallayer::Ieee80211VhtPhyHeader>(b(-1), Chunk::PF_ALLOW_INCORRECT);
    }
    else
        throw cRuntimeError("Invalid IEEE 802.11 PHY mode.");
}

} // namespace inet

