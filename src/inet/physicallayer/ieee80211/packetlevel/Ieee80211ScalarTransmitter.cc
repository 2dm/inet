//
// Copyright (C) 2013 OpenSim Ltd.
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

#include "inet/mobility/contract/IMobility.h"
#include "inet/physicallayer/contract/packetlevel/IRadio.h"
#include "inet/physicallayer/contract/packetlevel/RadioControlInfo_m.h"
#include "inet/physicallayer/ieee80211/packetlevel/Ieee80211PhyHeader_m.h"
#include "inet/physicallayer/ieee80211/packetlevel/Ieee80211ScalarTransmission.h"
#include "inet/physicallayer/ieee80211/packetlevel/Ieee80211ScalarTransmitter.h"

namespace inet {

namespace physicallayer {

Define_Module(Ieee80211ScalarTransmitter);

Ieee80211ScalarTransmitter::Ieee80211ScalarTransmitter() :
    Ieee80211TransmitterBase()
{
}

std::ostream& Ieee80211ScalarTransmitter::printToStream(std::ostream& stream, int level) const
{
    stream << "Ieee80211ScalarTransmitter";
    return Ieee80211TransmitterBase::printToStream(stream, level);
}

const ITransmission *Ieee80211ScalarTransmitter::createTransmission(const IRadio *transmitter, const Packet *packet, simtime_t startTime) const
{
    const IIeee80211Mode *transmissionMode = computeTransmissionMode(packet);
    auto phyHeader = peekIeee80211PhyHeader(packet, transmissionMode);
    const Ieee80211Channel *transmissionChannel = computeTransmissionChannel(packet);
    W transmissionPower = computeTransmissionPower(packet);
    Hz transmissionBandwidth = transmissionMode->getDataMode()->getBandwidth();
    bps transmissionBitrate = transmissionMode->getDataMode()->getNetBitrate();
    if (transmissionMode->getDataMode()->getNumberOfSpatialStreams() > transmitter->getAntenna()->getNumAntennas())
        throw cRuntimeError("Number of spatial streams is higher than the number of antennas");
    const simtime_t duration = transmissionMode->getDuration(B(phyHeader->getLengthField()));
    const simtime_t endTime = startTime + duration;
    IMobility *mobility = transmitter->getAntenna()->getMobility();
    const Coord startPosition = mobility->getCurrentPosition();
    const Coord endPosition = mobility->getCurrentPosition();
    const Quaternion startOrientation = mobility->getCurrentAngularPosition();
    const Quaternion endOrientation = mobility->getCurrentAngularPosition();
    auto headerLength = b(transmissionMode->getHeaderMode()->getLength());
    auto dataLength = b(transmissionMode->getDataMode()->getCompleteLength(B(phyHeader->getLengthField())));
    const simtime_t preambleDuration = transmissionMode->getPreambleMode()->getDuration();
    const simtime_t headerDuration = transmissionMode->getHeaderMode()->getDuration();
    const simtime_t dataDuration = duration - headerDuration - preambleDuration;
    return new Ieee80211ScalarTransmission(transmitter, packet, startTime, endTime, preambleDuration, headerDuration, dataDuration, startPosition, endPosition, startOrientation, endOrientation, modulation, headerLength, dataLength, carrierFrequency, transmissionBandwidth, transmissionBitrate, transmissionPower, transmissionMode, transmissionChannel);
}

const Ptr<const Ieee80211PhyHeader> Ieee80211ScalarTransmitter::peekIeee80211PhyHeader(const Packet *packet, const IIeee80211Mode *mode)
{
    if (dynamic_cast<const Ieee80211DsssMode*>(mode)) {
        return packet->peekAtFront<Ieee80211DsssPhyHeader>();
    }
    else if (dynamic_cast<const Ieee80211DsssOfdmMode*>(mode)) {
        return packet->peekAtFront<Ieee80211DsssPhyHeader>();
    }
    else if (dynamic_cast<const Ieee80211ErpOfdmMode*>(mode)) {
        return packet->peekAtFront<Ieee80211ErpOfdmPhyHeader>();
    }
    else if (dynamic_cast<const Ieee80211FhssMode*>(mode)) {
        return packet->peekAtFront<Ieee80211FhssPhyHeader>();
    }
    else if (dynamic_cast<const Ieee80211HrDsssMode*>(mode)) {
        return packet->peekAtFront<Ieee80211HrDsssPhyHeader>();
    }
    else if (dynamic_cast<const Ieee80211HtMode*>(mode)) {
        return packet->peekAtFront<Ieee80211HtPhyHeader>();
    }
    else if (dynamic_cast<const Ieee80211IrMode*>(mode)) {
        return packet->peekAtFront<Ieee80211IrPhyHeader>();
    }
    else if (dynamic_cast<const Ieee80211OfdmMode*>(mode)) {
        return packet->peekAtFront<Ieee80211OfdmPhyHeader>();
    }
    else if (dynamic_cast<const Ieee80211VhtMode*>(mode)) {
        return packet->peekAtFront<Ieee80211VhtPhyHeader>();
    }
    else
        throw cRuntimeError("Invalid IEEE 802.11 PHY mode.");
}

} // namespace physicallayer

} // namespace inet

