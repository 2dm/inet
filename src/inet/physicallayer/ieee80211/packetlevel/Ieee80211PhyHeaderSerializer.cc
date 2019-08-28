//
// Copyright (C) 2014 OpenSim Ltd.
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

#include "inet/common/packet/serializer/ChunkSerializerRegistry.h"
#include "inet/physicallayer/ieee80211/packetlevel/Ieee80211PhyHeader_m.h"
#include "inet/physicallayer/ieee80211/packetlevel/Ieee80211PhyHeaderSerializer.h"

namespace inet {

namespace  physicallayer {

Register_Serializer(Ieee80211PhyHeader, Ieee80211PhyHeaderSerializer);
Register_Serializer(Ieee80211FhssPhyHeader, Ieee80211PhyHeaderSerializer);
Register_Serializer(Ieee80211IrPhyHeader, Ieee80211PhyHeaderSerializer);
Register_Serializer(Ieee80211DsssPhyHeader, Ieee80211PhyHeaderSerializer);
Register_Serializer(Ieee80211HrDsssPhyHeader, Ieee80211PhyHeaderSerializer);
Register_Serializer(Ieee80211OfdmPhyHeader, Ieee80211PhyHeaderSerializer);
Register_Serializer(Ieee80211HtPhyHeader, Ieee80211PhyHeaderSerializer);
Register_Serializer(Ieee80211VhtPhyHeader, Ieee80211PhyHeaderSerializer);

void Ieee80211PhyHeaderSerializer::serialize(MemoryOutputStream& stream, const Ptr<const Chunk>& chunk) const
{
    if (auto ofdmPhyHeader = dynamicPtrCast<const Ieee80211OfdmPhyHeader>(chunk)) {
        stream.writeUint4(ofdmPhyHeader->getRate());
        stream.writeBit(ofdmPhyHeader->getReserved());
        stream.writeNBitsOfUint64Be(B(ofdmPhyHeader->getLengthField()).get(), 12);
        stream.writeBit(ofdmPhyHeader->getParity());
        stream.writeNBitsOfUint64Be(ofdmPhyHeader->getTail(), 6);
        stream.writeUint16Be(ofdmPhyHeader->getService());
    }
    else if (auto dsssPhyHeader = dynamicPtrCast<const Ieee80211DsssPhyHeader>(chunk)) {
        stream.writeByte(dsssPhyHeader->getSignal());
        stream.writeByte(dsssPhyHeader->getService());
        stream.writeUint16Be(B(dsssPhyHeader->getLengthField()).get());
    }
    else if (auto fhssPhyHeader = dynamicPtrCast<const Ieee80211FhssPhyHeader>(chunk)) {
        stream.writeNBitsOfUint64Be(fhssPhyHeader->getPlw(), 12);
        stream.writeUint4(fhssPhyHeader->getPsf());
        stream.writeUint16Be(fhssPhyHeader->getCrc());
    }
    else
        throw cRuntimeError("Ieee80211PhyHeaderSerializer: cannot serialize the frame, serializer not implemented yet.");
}

const Ptr<Chunk> Ieee80211PhyHeaderSerializer::deserialize(MemoryInputStream& stream) const
{
    if (true) {
        // TODO: KLUDGE (could be Ieee80211FhssPhyHeader as well)
        auto dsssPhyHeader = makeShared<Ieee80211DsssPhyHeader>();
        dsssPhyHeader->setSignal(stream.readByte());
        dsssPhyHeader->setService(stream.readByte());
        dsssPhyHeader->setLengthField(B(stream.readUint16Be()));
        return dsssPhyHeader;
    }
    else if (true) { // TODO: KLUDGE:
        auto ofdmPhyHeader = makeShared<Ieee80211OfdmPhyHeader>();
        ofdmPhyHeader->setRate(stream.readUint4());
        ofdmPhyHeader->setReserved(stream.readBit());
        ofdmPhyHeader->setLengthField(B(stream.readNBitsToUint64Be(12)));
        ofdmPhyHeader->setParity(stream.readBit());
        ofdmPhyHeader->setTail(stream.readNBitsToUint64Be(6));
        ofdmPhyHeader->setService(stream.readUint16Be());
        return ofdmPhyHeader;
    }
    else {
        auto phyHeader = makeShared<Ieee80211PhyHeader>();
        // TODO: KLUDGE:
        phyHeader->setChunkLength(b(192));
        stream.readByteRepeatedly('?', B(phyHeader->getChunkLength()).get());
        return phyHeader;
    }
}

} // namespace physicallayer

} // namespace inet

