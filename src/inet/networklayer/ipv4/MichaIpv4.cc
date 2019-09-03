//
// Copyright (C) 2004 Andras Varga
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

#include <stdlib.h>
#include <string.h>
#include <cmath>
#include "inet/applications/common/SocketTag_m.h"
#include "inet/common/INETUtils.h"
#include "inet/common/IProtocolRegistrationListener.h"
#include "inet/common/LayeredProtocolBase.h"
#include "inet/common/lifecycle/NodeOperations.h"
#include "inet/common/lifecycle/NodeStatus.h"
#include "inet/common/ModuleAccess.h"
#include "inet/common/packet/Message.h"
#include "inet/common/ProtocolTag_m.h"
#include "inet/common/checksum/TcpIpChecksum.h"
#include "inet/linklayer/common/InterfaceTag_m.h"
#include "inet/linklayer/common/MacAddressTag_m.h"
#include "inet/networklayer/arp/ipv4/ArpPacket_m.h"
#include "inet/networklayer/common/DscpTag_m.h"
#include "inet/networklayer/common/EcnTag_m.h"
#include "inet/networklayer/common/FragmentationTag_m.h"
#include "inet/networklayer/common/HopLimitTag_m.h"
#include "inet/networklayer/common/L3AddressTag_m.h"
#include "inet/networklayer/common/L3Tools.h"
#include "inet/networklayer/common/MulticastTag_m.h"
#include "inet/networklayer/common/NextHopAddressTag_m.h"
#include "inet/networklayer/contract/IArp.h"
#include "inet/networklayer/contract/IInterfaceTable.h"
#include "inet/networklayer/contract/ipv4/Ipv4SocketCommand_m.h"
#include "inet/networklayer/ipv4/IcmpHeader_m.h"
#include "inet/networklayer/ipv4/IIpv4RoutingTable.h"
//#include "inet/networklayer/ipv4/Ipv4.h"
#include "inet/networklayer/ipv4/MichaIpv4.h"
#include "inet/networklayer/ipv4/Ipv4Header_m.h"
#include "inet/networklayer/ipv4/Ipv4InterfaceData.h"
//#include "inet/common/queue/MichaDropTailQueue.h"
#include "inet/common/queue/DropTailQueue.h"
#include "inet/transportlayer/tcp/TcpConnection.h"


namespace inet {

Define_Module(MichaIpv4);

//TODO TRANSLATE
// a multicast cimek eseten hianyoznak bizonyos NetFilter hook-ok
// a local interface-k hasznalata eseten szinten hianyozhatnak bizonyos NetFilter hook-ok

MichaIpv4::MichaIpv4() :
    isUp(true)
{
}

MichaIpv4::~MichaIpv4()
{
	//delete sarsa;
	delete cancelEvent(rlStatTimerMsg);
    for (auto it : socketIdToSocketDescriptor)
        delete it.second;
    if (choosenActions) {
    	delete choosenActions;
    }
    if (sentBytesVec) {
        delete sentBytesVec;
    }
    flush();
}

void MichaIpv4::initialize(int stage)
{
    if (stage == INITSTAGE_LOCAL) {
        QueueBase::initialize();

        ift = getModuleFromPar<IInterfaceTable>(par("interfaceTableModule"), this);
        rt = getModuleFromPar<IIpv4RoutingTable>(par("routingTableModule"), this);
        arp = getModuleFromPar<IArp>(par("arpModule"), this);
        icmp = getModuleFromPar<Icmp>(par("icmpModule"), this);

        transportInGateBaseId = gateBaseId("transportIn");

        const char *crcModeString = par("crcMode");
        if (!strcmp(crcModeString, "declared"))
            crcMode = CRC_DECLARED_CORRECT;
        else if (!strcmp(crcModeString, "computed"))
            crcMode = CRC_COMPUTED;
        else
            throw cRuntimeError("Unknown crc mode: '%s'", crcModeString);

        defaultTimeToLive = par("timeToLive");
        defaultMCTimeToLive = par("multicastTimeToLive");
        fragmentTimeoutTime = par("fragmentTimeout");
        forceBroadcast = par("forceBroadcast");
        useProxyARP = par("useProxyARP");

        curFragmentId = 0;
        lastCheckTime = 0;

        numMulticast = numLocalDeliver = numDropped = numUnroutable = numForwarded = 0;

        // NetFilter:
        hooks.clear();
        queuedDatagramsForHooks.clear();

        pendingPackets.clear();
        cModule *arpModule = check_and_cast<cModule *>(arp);
        arpModule->subscribe(IArp::arpResolutionCompletedSignal, this);
        arpModule->subscribe(IArp::arpResolutionFailedSignal, this);



        //cIListener *listener =
        //getSimulation()->getSystemModule()->subscribe("queueLength", listener);

        //sarsa = new RL_Sarsa();
        sarsa = getModuleFromPar<RL_Sarsa>(par("rl_SarsaModule"), this);
        choosedAction = actions::nothing;
        choosenActions = new cOutVector("ipChoosenActionsVec");
        sentBytesVec = new cOutVector("ipSentBytesVec");
        ecn_threshold = par("ecn_threshold");
        regularRun = par("regularRun");

        sourceIdFilter = par("sourceIdFilter");
        dstAddrFilter = par("dstAddrFilter");

        //cModule *host = getContainingNode(this);
        queueLengthSignalId = registerSignal("queueLength");
		getSimulation()->getSystemModule()->subscribe(queueLengthSignalId, this);

		packetDequeuedSignalId = registerSignal("packetDequeued");
		getSimulation()->getSystemModule()->subscribe(packetDequeuedSignalId, this);

		queueingTimeSignalId = registerSignal("queueingTime");
		getSimulation()->getSystemModule()->subscribe(queueingTimeSignalId, this);

		packetDroppedSignalId = registerSignal("packetDropped");
		getSimulation()->getSystemModule()->subscribe(packetDroppedSignalId, this);

		packetEnqueuedSignalId = registerSignal("packetEnqueued");
		getSimulation()->getSystemModule()->subscribe(packetEnqueuedSignalId, this);

		tcpConnectionAddedSignalId = registerSignal("tcpConnectionAdded");
		getSimulation()->getSystemModule()->subscribe(tcpConnectionAddedSignalId, this);

		tcpConnectionRemovedSignalId = registerSignal("tcpConnectionRemoved");
		getSimulation()->getSystemModule()->subscribe(tcpConnectionRemovedSignalId, this);


		rlStatTimerMsg  = new cMessage("rlStatisticsTimerMsg");
		timerDelta =  300e-6;	//10 usec

        //host->subscribe(DropTailQueue::queueLengthSignal, this);

        WATCH(numMulticast);
        WATCH(numLocalDeliver);
        WATCH(numDropped);
        WATCH(numUnroutable);
        WATCH(numForwarded);
        WATCH_MAP(pendingPackets);
        WATCH_MAP(socketIdToSocketDescriptor);

        WATCH(packetDroppedAccumDbg);
    }
    else if (stage == INITSTAGE_NETWORK_LAYER) {
        isUp = isNodeUp();
        registerService(Protocol::ipv4, gate("transportIn"), gate("queueIn"));
        registerProtocol(Protocol::ipv4, gate("queueOut"), gate("transportOut"));
    }
}

void MichaIpv4::handleRegisterService(const Protocol& protocol, cGate *out, ServicePrimitive servicePrimitive)
{
    Enter_Method("handleRegisterService");
}

void MichaIpv4::handleRegisterProtocol(const Protocol& protocol, cGate *in, ServicePrimitive servicePrimitive)
{
    Enter_Method("handleRegisterProtocol");
    if (in->isName("transportIn"))
            upperProtocols.insert(&protocol);
}

void MichaIpv4::refreshDisplay() const
{
    char buf[80] = "";
    if (numForwarded > 0)
        sprintf(buf + strlen(buf), "fwd:%d ", numForwarded);
    if (numLocalDeliver > 0)
        sprintf(buf + strlen(buf), "up:%d ", numLocalDeliver);
    if (numMulticast > 0)
        sprintf(buf + strlen(buf), "mcast:%d ", numMulticast);
    if (numDropped > 0)
        sprintf(buf + strlen(buf), "DROP:%d ", numDropped);
    if (numUnroutable > 0)
        sprintf(buf + strlen(buf), "UNROUTABLE:%d ", numUnroutable);
    getDisplayString().setTagArg("t", 0, buf);
}

void MichaIpv4::handleMessage(cMessage *msg)
{
	if ( msg->isSelfMessage() ) {
		const char *name = msg->getName();

		if (name == std::string("rlStatisticsTimerMsg")) {
			doSarsaStuff();
			scheduleAt(simTime() + timerDelta, msg);
			return;
		} else {
			return;
		}
	}
    auto request = dynamic_cast<Request *>(msg);
    if (Ipv4SocketBindCommand *command = dynamic_cast<Ipv4SocketBindCommand *>(msg->getControlInfo())) {
        int socketId = request->getTag<SocketReq>()->getSocketId();
        SocketDescriptor *descriptor = new SocketDescriptor(socketId, command->getProtocol()->getId(), command->getLocalAddress());
        socketIdToSocketDescriptor[socketId] = descriptor;
        delete msg;
    }
    else if (Ipv4SocketConnectCommand *command = dynamic_cast<Ipv4SocketConnectCommand *>(msg->getControlInfo())) {
        int socketId = request->getTag<SocketReq>()->getSocketId();
        if (socketIdToSocketDescriptor.find(socketId) == socketIdToSocketDescriptor.end())
            throw cRuntimeError("Ipv4Socket: should use bind() before connect()");
        socketIdToSocketDescriptor[socketId]->remoteAddress = command->getRemoteAddress();
        delete msg;
    }
    else if (dynamic_cast<Ipv4SocketCloseCommand *>(msg->getControlInfo()) != nullptr) {
        int socketId = 0; request->getTag<SocketReq>()->getSocketId();
        auto it = socketIdToSocketDescriptor.find(socketId);
        if (it != socketIdToSocketDescriptor.end()) {
            delete it->second;
            socketIdToSocketDescriptor.erase(it);
        }
        delete msg;
    }
    else
        QueueBase::handleMessage(msg);
}

void MichaIpv4::endService(cPacket *packet)
{
    if (!isUp) {
        EV_ERROR << "Ipv4 is down -- discarding message\n";
        delete packet;
        return;
    }
    if (packet->getArrivalGate()->isName("transportIn")) {    //TODO packet->getArrivalGate()->getBaseId() == transportInGateBaseId
        handlePacketFromHL(check_and_cast<Packet*>(packet));
    }
    else {    // from network
        EV_INFO << "Received " << packet << " from network.\n";
        handleIncomingDatagram(check_and_cast<Packet*>(packet));
    }
}

bool MichaIpv4::verifyCrc(const Ptr<const Ipv4Header>& ipv4Header)
{
    switch (ipv4Header->getCrcMode()) {
        case CRC_DECLARED_CORRECT: {
            // if the CRC mode is declared to be correct, then the check passes if and only if the chunk is correct
            return ipv4Header->isCorrect();
        }
        case CRC_DECLARED_INCORRECT:
            // if the CRC mode is declared to be incorrect, then the check fails
            return false;
        case CRC_COMPUTED: {
            if (ipv4Header->isCorrect()) {
                // compute the CRC, the check passes if the result is 0xFFFF (includes the received CRC) and the chunks are correct
                MemoryOutputStream ipv4HeaderStream;
                Chunk::serialize(ipv4HeaderStream, ipv4Header);
                uint16_t computedCrc = TcpIpChecksum::checksum(ipv4HeaderStream.getData());
                return computedCrc == 0;
            }
            else {
                return false;
            }
        }
        default:
            throw cRuntimeError("Unknown CRC mode");
    }
}

const InterfaceEntry *MichaIpv4::getSourceInterface(Packet *packet)
{
    auto tag = packet->findTag<InterfaceInd>();
    return tag != nullptr ? ift->getInterfaceById(tag->getInterfaceId()) : nullptr;
}

const InterfaceEntry *MichaIpv4::getDestInterface(Packet *packet)
{
    auto tag = packet->findTag<InterfaceReq>();
    return tag != nullptr ? ift->getInterfaceById(tag->getInterfaceId()) : nullptr;
}

Ipv4Address MichaIpv4::getNextHop(Packet *packet)
{
    auto tag = packet->findTag<NextHopAddressReq>();
    return tag != nullptr ? tag->getNextHopAddress().toIpv4() : Ipv4Address::UNSPECIFIED_ADDRESS;
}

void MichaIpv4::handleIncomingDatagram(Packet *packet)
{
    ASSERT(packet);
    int interfaceId = packet->getTag<InterfaceInd>()->getInterfaceId();
    emit(packetReceivedFromLowerSignal, packet);

    //
    // "Prerouting"
    //

    const auto& ipv4Header = packet->peekAtFront<Ipv4Header>();
    packet->addTagIfAbsent<NetworkProtocolInd>()->setProtocol(&Protocol::ipv4);
    packet->addTagIfAbsent<NetworkProtocolInd>()->setNetworkProtocolHeader(ipv4Header);

    if (!verifyCrc(ipv4Header)) {
        EV_WARN << "CRC error found, drop packet\n";
        PacketDropDetails details;
        details.setReason(INCORRECTLY_RECEIVED);
        emit(packetDroppedSignal, packet, &details);
        delete packet;
        return;
    }

    if (ipv4Header->getTotalLengthField() > packet->getDataLength()) {
        EV_WARN << "length error found, sending ICMP_PARAMETER_PROBLEM\n";
        sendIcmpError(packet, interfaceId, ICMP_PARAMETER_PROBLEM, 0);
        return;
    }

    // remove lower layer paddings:
    if (ipv4Header->getTotalLengthField() < packet->getDataLength()) {
        packet->setBackOffset(packet->getFrontOffset() + ipv4Header->getTotalLengthField());
    }

    // check for header biterror
    if (packet->hasBitError()) {
        // probability of bit error in header = size of header / size of total message
        // (ignore bit error if in payload)
        double relativeHeaderLength = B(ipv4Header->getHeaderLength()).get() / (double)B(ipv4Header->getChunkLength()).get();
        if (dblrand() <= relativeHeaderLength) {
            EV_WARN << "bit error found, sending ICMP_PARAMETER_PROBLEM\n";
            sendIcmpError(packet, interfaceId, ICMP_PARAMETER_PROBLEM, 0);
            return;
        }
    }

    EV_DETAIL << "Received datagram `" << ipv4Header->getName() << "' with dest=" << ipv4Header->getDestAddress() << "\n";

    if (datagramPreRoutingHook(packet) == INetfilter::IHook::ACCEPT)
        preroutingFinish(packet);
}

Packet *MichaIpv4::prepareForForwarding(Packet *packet) const
{
    const auto& ipv4Header = removeNetworkProtocolHeader<Ipv4Header>(packet);
    ipv4Header->setTimeToLive(ipv4Header->getTimeToLive() - 1);
    insertNetworkProtocolHeader(packet, Protocol::ipv4, ipv4Header);
    return packet;
}

void MichaIpv4::preroutingFinish(Packet *packet)
{
    const InterfaceEntry *fromIE = ift->getInterfaceById(packet->getTag<InterfaceInd>()->getInterfaceId());
    Ipv4Address nextHopAddr = getNextHop(packet);

    const auto& ipv4Header = packet->peekAtFront<Ipv4Header>();
    ASSERT(ipv4Header);
    Ipv4Address destAddr = ipv4Header->getDestAddress();

    // route packet

    if (fromIE->isLoopback()) {
        reassembleAndDeliver(packet);
    }
    else if (destAddr.isMulticast()) {
        // check for local delivery
        // Note: multicast routers will receive IGMP datagrams even if their interface is not joined to the group
        if (fromIE->ipv4Data()->isMemberOfMulticastGroup(destAddr) ||
            (rt->isMulticastForwardingEnabled() && ipv4Header->getProtocolId() == IP_PROT_IGMP))
            reassembleAndDeliver(packet->dup());
        else
            EV_WARN << "Skip local delivery of multicast datagram (input interface not in multicast group)\n";

        // don't forward if IP forwarding is off, or if dest address is link-scope
        if (!rt->isMulticastForwardingEnabled()) {
            EV_WARN << "Skip forwarding of multicast datagram (forwarding disabled)\n";
            delete packet;
        }
        else if (destAddr.isLinkLocalMulticast()) {
            EV_WARN << "Skip forwarding of multicast datagram (packet is link-local)\n";
            delete packet;
        }
        else if (ipv4Header->getTimeToLive() <= 1) {      // TTL before decrement
            EV_WARN << "Skip forwarding of multicast datagram (TTL reached 0)\n";
            delete packet;
        }
        else
            forwardMulticastPacket(prepareForForwarding(packet));
    }
    else {
        const InterfaceEntry *broadcastIE = nullptr;

        // check for local delivery; we must accept also packets coming from the interfaces that
        // do not yet have an IP address assigned. This happens during DHCP requests.
        bool flag1 = rt->isLocalAddress(destAddr);
        bool flag2 = fromIE->ipv4Data()->getIPAddress().isUnspecified();
        if (flag1 || flag2) {
            reassembleAndDeliver(packet);
        }
        else if (destAddr.isLimitedBroadcastAddress() || (broadcastIE = rt->findInterfaceByLocalBroadcastAddress(destAddr))) {
            // broadcast datagram on the target subnet if we are a router
            if (broadcastIE && fromIE != broadcastIE && rt->isForwardingEnabled()) {
                auto packetCopy = prepareForForwarding(packet->dup());
                packetCopy->addTagIfAbsent<InterfaceReq>()->setInterfaceId(broadcastIE->getInterfaceId());
                packetCopy->addTagIfAbsent<NextHopAddressReq>()->setNextHopAddress(Ipv4Address::ALLONES_ADDRESS);
                fragmentPostRouting(packetCopy);
            }

            EV_INFO << "Broadcast received\n";
            reassembleAndDeliver(packet);
        }
        else if (!rt->isForwardingEnabled()) {
            EV_WARN << "forwarding off, dropping packet\n";
            numDropped++;
            PacketDropDetails details;
            details.setReason(FORWARDING_DISABLED);
            emit(packetDroppedSignal, packet, &details);
            delete packet;
        }
        else {
            packet->addTagIfAbsent<NextHopAddressReq>()->setNextHopAddress(nextHopAddr);
            routeUnicastPacket(prepareForForwarding(packet));
        }
    }
}

void MichaIpv4::handlePacketFromHL(Packet *packet)
{
    EV_INFO << "Received " << packet << " from upper layer.\n";
    emit(packetReceivedFromUpperSignal, packet);

    // if no interface exists, do not send datagram
    if (ift->getNumInterfaces() == 0) {
        EV_ERROR << "No interfaces exist, dropping packet\n";
        numDropped++;
        PacketDropDetails details;
        details.setReason(NO_INTERFACE_FOUND);
        emit(packetDroppedSignal, packet, &details);
        delete packet;
        return;
    }

    // encapsulate
    encapsulate(packet);

    // TODO:
    L3Address nextHopAddr(Ipv4Address::UNSPECIFIED_ADDRESS);
    if (datagramLocalOutHook(packet) == INetfilter::IHook::ACCEPT)
        datagramLocalOut(packet);
}

void MichaIpv4::datagramLocalOut(Packet *packet)
{
    const InterfaceEntry *destIE = getDestInterface(packet);
    Ipv4Address requestedNextHopAddress = getNextHop(packet);

    const auto& ipv4Header = packet->peekAtFront<Ipv4Header>();
    bool multicastLoop = false;
    MulticastReq *mcr = packet->findTag<MulticastReq>();
    if (mcr != nullptr) {
        multicastLoop = mcr->getMulticastLoop();
    }

    // send
    Ipv4Address destAddr = ipv4Header->getDestAddress();

    EV_DETAIL << "Sending datagram '" << packet->getName() << "' with destination = " << destAddr << "\n";

    if (ipv4Header->getDestAddress().isMulticast()) {
        destIE = determineOutgoingInterfaceForMulticastDatagram(ipv4Header, destIE);
        packet->addTagIfAbsent<InterfaceReq>()->setInterfaceId(destIE ? destIE->getInterfaceId() : -1);

        // loop back a copy
        if (multicastLoop && (!destIE || !destIE->isLoopback())) {
            const InterfaceEntry *loopbackIF = ift->getFirstLoopbackInterface();
            if (loopbackIF) {
                auto packetCopy = packet->dup();
                packetCopy->addTagIfAbsent<InterfaceReq>()->setInterfaceId(loopbackIF->getInterfaceId());
                packetCopy->addTagIfAbsent<NextHopAddressReq>()->setNextHopAddress(destAddr);
                fragmentPostRouting(packetCopy);
            }
        }

        if (destIE) {
            numMulticast++;
            packet->addTagIfAbsent<InterfaceReq>()->setInterfaceId(destIE->getInterfaceId());        //FIXME KLUDGE is it needed?
            packet->addTagIfAbsent<NextHopAddressReq>()->setNextHopAddress(destAddr);
            fragmentPostRouting(packet);
        }
        else {
            EV_ERROR << "No multicast interface, packet dropped\n";
            numUnroutable++;
            PacketDropDetails details;
            details.setReason(NO_INTERFACE_FOUND);
            emit(packetDroppedSignal, packet, &details);
            delete packet;
        }
    }
    else {    // unicast and broadcast
              // check for local delivery
        if (rt->isLocalAddress(destAddr)) {
            EV_INFO << "Delivering " << packet << " locally.\n";
            if (destIE && !destIE->isLoopback()) {
                EV_DETAIL << "datagram destination address is local, ignoring destination interface specified in the control info\n";
                destIE = nullptr;
                packet->addTagIfAbsent<InterfaceReq>()->setInterfaceId(-1);
            }
            if (!destIE) {
                destIE = ift->getFirstLoopbackInterface();
                packet->addTagIfAbsent<InterfaceReq>()->setInterfaceId(destIE ? destIE->getInterfaceId() : -1);
            }
            ASSERT(destIE);
            packet->addTagIfAbsent<NextHopAddressReq>()->setNextHopAddress(destAddr);
            routeUnicastPacket(packet);
        }
        else if (destAddr.isLimitedBroadcastAddress() || rt->isLocalBroadcastAddress(destAddr))
            routeLocalBroadcastPacket(packet);
        else {
            packet->addTagIfAbsent<NextHopAddressReq>()->setNextHopAddress(requestedNextHopAddress);
            routeUnicastPacket(packet);
        }
    }
}

/* Choose the outgoing interface for the muticast datagram:
 *   1. use the interface specified by MULTICAST_IF socket option (received in the control info)
 *   2. lookup the destination address in the routing table
 *   3. if no route, choose the interface according to the source address
 *   4. or if the source address is unspecified, choose the first MULTICAST interface
 */
const InterfaceEntry *MichaIpv4::determineOutgoingInterfaceForMulticastDatagram(const Ptr<const Ipv4Header>& ipv4Header, const InterfaceEntry *multicastIFOption)
{
    const InterfaceEntry *ie = nullptr;
    if (multicastIFOption) {
        ie = multicastIFOption;
        EV_DETAIL << "multicast packet routed by socket option via output interface " << ie->getInterfaceName() << "\n";
    }
    if (!ie) {
        Ipv4Route *route = rt->findBestMatchingRoute(ipv4Header->getDestAddress());
        if (route)
            ie = route->getInterface();
        if (ie)
            EV_DETAIL << "multicast packet routed by routing table via output interface " << ie->getInterfaceName() << "\n";
    }
    if (!ie) {
        ie = rt->getInterfaceByAddress(ipv4Header->getSrcAddress());
        if (ie)
            EV_DETAIL << "multicast packet routed by source address via output interface " << ie->getInterfaceName() << "\n";
    }
    if (!ie) {
        ie = ift->getFirstMulticastInterface();
        if (ie)
            EV_DETAIL << "multicast packet routed via the first multicast interface " << ie->getInterfaceName() << "\n";
    }
    return ie;
}

void MichaIpv4::routeUnicastPacket(Packet *packet)
{
    const InterfaceEntry *fromIE = getSourceInterface(packet);
    const InterfaceEntry *destIE = getDestInterface(packet);
    Ipv4Address nextHopAddress = getNextHop(packet);

    const auto& ipv4Header = packet->peekAtFront<Ipv4Header>();
    Ipv4Address destAddr = ipv4Header->getDestAddress();
    EV_INFO << "Routing " << packet << " with destination = " << destAddr << ", ";

    // if output port was explicitly requested, use that, otherwise use Ipv4 routing
    if (destIE) {
        EV_DETAIL << "using manually specified output interface " << destIE->getInterfaceName() << "\n";
        // and nextHopAddr remains unspecified
        if (!nextHopAddress.isUnspecified()) {
            // do nothing, next hop address already specified
        }
        // special case ICMP reply
        else if (destIE->isBroadcast()) {
            // if the interface is broadcast we must search the next hop
            const Ipv4Route *re = rt->findBestMatchingRoute(destAddr);
            if (re && re->getInterface() == destIE) {
                packet->addTagIfAbsent<NextHopAddressReq>()->setNextHopAddress(re->getGateway());
            }
        }
    }
    else {
        // use Ipv4 routing (lookup in routing table)
        const Ipv4Route *re = rt->findBestMatchingRoute(destAddr);
        if (re) {
            destIE = re->getInterface();
            packet->addTagIfAbsent<InterfaceReq>()->setInterfaceId(destIE->getInterfaceId());
            packet->addTagIfAbsent<NextHopAddressReq>()->setNextHopAddress(re->getGateway());
        }
    }

    if (!destIE) {    // no route found
        EV_WARN << "unroutable, sending ICMP_DESTINATION_UNREACHABLE, dropping packet\n";
        numUnroutable++;
        PacketDropDetails details;
        details.setReason(NO_ROUTE_FOUND);
        emit(packetDroppedSignal, packet, &details);
        sendIcmpError(packet, fromIE ? fromIE->getInterfaceId() : -1, ICMP_DESTINATION_UNREACHABLE, 0);
    }
    else {    // fragment and send
        if (fromIE != nullptr) {
            if (datagramForwardHook(packet) != INetfilter::IHook::ACCEPT)
                return;
        }

        routeUnicastPacketFinish(packet);
    }
}

void MichaIpv4::routeUnicastPacketFinish(Packet *packet)
{
    EV_INFO << "output interface = " << getDestInterface(packet)->getInterfaceName() << ", next hop address = " << getNextHop(packet) << "\n";
    numForwarded++;
    fragmentPostRouting(packet);
}

void MichaIpv4::routeLocalBroadcastPacket(Packet *packet)
{
    auto interfaceReq = packet->findTag<InterfaceReq>();
    const InterfaceEntry *destIE = interfaceReq != nullptr ? ift->getInterfaceById(interfaceReq->getInterfaceId()) : nullptr;
    // The destination address is 255.255.255.255 or local subnet broadcast address.
    // We always use 255.255.255.255 as nextHopAddress, because it is recognized by ARP,
    // and mapped to the broadcast MAC address.
    if (destIE != nullptr) {
        packet->addTagIfAbsent<InterfaceReq>()->setInterfaceId(destIE->getInterfaceId());    //FIXME KLUDGE is it needed?
        packet->addTagIfAbsent<NextHopAddressReq>()->setNextHopAddress(Ipv4Address::ALLONES_ADDRESS);
        fragmentPostRouting(packet);
    }
    else if (forceBroadcast) {
        // forward to each interface including loopback
        for (int i = 0; i < ift->getNumInterfaces(); i++) {
            const InterfaceEntry *ie = ift->getInterface(i);
            auto packetCopy = packet->dup();
            packetCopy->addTagIfAbsent<InterfaceReq>()->setInterfaceId(ie->getInterfaceId());
            packetCopy->addTagIfAbsent<NextHopAddressReq>()->setNextHopAddress(Ipv4Address::ALLONES_ADDRESS);
            fragmentPostRouting(packetCopy);
        }
        delete packet;
    }
    else {
        numDropped++;
        PacketDropDetails details;
        details.setReason(NO_INTERFACE_FOUND);
        emit(packetDroppedSignal, packet, &details);
        delete packet;
    }
}

const InterfaceEntry *MichaIpv4::getShortestPathInterfaceToSource(const Ptr<const Ipv4Header>& ipv4Header) const
{
    return rt->getInterfaceForDestAddr(ipv4Header->getSrcAddress());
}

void MichaIpv4::forwardMulticastPacket(Packet *packet)
{
    const InterfaceEntry *fromIE = ift->getInterfaceById(packet->getTag<InterfaceInd>()->getInterfaceId());
    const auto& ipv4Header = packet->peekAtFront<Ipv4Header>();
    const Ipv4Address& srcAddr = ipv4Header->getSrcAddress();
    const Ipv4Address& destAddr = ipv4Header->getDestAddress();
    ASSERT(destAddr.isMulticast());
    ASSERT(!destAddr.isLinkLocalMulticast());

    EV_INFO << "Forwarding multicast datagram `" << packet->getName() << "' with dest=" << destAddr << "\n";

    numMulticast++;

    const Ipv4MulticastRoute *route = rt->findBestMatchingMulticastRoute(srcAddr, destAddr);
    if (!route) {
        EV_WARN << "Multicast route does not exist, try to add.\n";
        // TODO: no need to emit fromIE when tags will be used in place of control infos
        emit(ipv4NewMulticastSignal, ipv4Header.get(), const_cast<InterfaceEntry *>(fromIE));

        // read new record
        route = rt->findBestMatchingMulticastRoute(srcAddr, destAddr);

        if (!route) {
            EV_ERROR << "No route, packet dropped.\n";
            numUnroutable++;
            PacketDropDetails details;
            details.setReason(NO_ROUTE_FOUND);
            emit(packetDroppedSignal, packet, &details);
            delete packet;
            return;
        }
    }

    if (route->getInInterface() && fromIE != route->getInInterface()->getInterface()) {
        EV_ERROR << "Did not arrive on input interface, packet dropped.\n";
        // TODO: no need to emit fromIE when tags will be used in place of control infos
        emit(ipv4DataOnNonrpfSignal, ipv4Header.get(), const_cast<InterfaceEntry *>(fromIE));
        numDropped++;
        PacketDropDetails details;
        emit(packetDroppedSignal, packet, &details);
        delete packet;
    }
    // backward compatible: no parent means shortest path interface to source (RPB routing)
    else if (!route->getInInterface() && fromIE != getShortestPathInterfaceToSource(ipv4Header)) {
        EV_ERROR << "Did not arrive on shortest path, packet dropped.\n";
        numDropped++;
        PacketDropDetails details;
        emit(packetDroppedSignal, packet, &details);
        delete packet;
    }
    else {
        // TODO: no need to emit fromIE when tags will be used in place of control infos
        emit(ipv4DataOnRpfSignal, ipv4Header.get(), const_cast<InterfaceEntry *>(fromIE));    // forwarding hook

        numForwarded++;
        // copy original datagram for multiple destinations
        for (unsigned int i = 0; i < route->getNumOutInterfaces(); i++) {
            Ipv4MulticastRoute::OutInterface *outInterface = route->getOutInterface(i);
            const InterfaceEntry *destIE = outInterface->getInterface();
            if (destIE != fromIE && outInterface->isEnabled()) {
                int ttlThreshold = destIE->ipv4Data()->getMulticastTtlThreshold();
                if (ipv4Header->getTimeToLive() <= ttlThreshold)
                    EV_WARN << "Not forwarding to " << destIE->getInterfaceName() << " (ttl treshold reached)\n";
                else if (outInterface->isLeaf() && !destIE->ipv4Data()->hasMulticastListener(destAddr))
                    EV_WARN << "Not forwarding to " << destIE->getInterfaceName() << " (no listeners)\n";
                else {
                    EV_DETAIL << "Forwarding to " << destIE->getInterfaceName() << "\n";
                    auto packetCopy = packet->dup();
                    packetCopy->addTagIfAbsent<InterfaceReq>()->setInterfaceId(destIE->getInterfaceId());
                    packetCopy->addTagIfAbsent<NextHopAddressReq>()->setNextHopAddress(destAddr);
                    fragmentPostRouting(packetCopy);
                }
            }
        }

        // TODO: no need to emit fromIE when tags will be use, d in place of control infos
        emit(ipv4MdataRegisterSignal, packet, const_cast<InterfaceEntry *>(fromIE));    // postRouting hook

        // only copies sent, delete original packet
        delete packet;
    }
}

void MichaIpv4::reassembleAndDeliver(Packet *packet)
{
    EV_INFO << "Delivering " << packet << " locally.\n";

    const auto& ipv4Header = packet->peekAtFront<Ipv4Header>();
    if (ipv4Header->getSrcAddress().isUnspecified())
        EV_WARN << "Received datagram '" << packet->getName() << "' without source address filled in\n";

    // reassemble the packet (if fragmented)
    if (ipv4Header->getFragmentOffset() != 0 || ipv4Header->getMoreFragments()) {
        EV_DETAIL << "Datagram fragment: offset=" << ipv4Header->getFragmentOffset()
                  << ", MORE=" << (ipv4Header->getMoreFragments() ? "true" : "false") << ".\n";

        // erase timed out fragments in fragmentation buffer; check every 10 seconds max
        if (simTime() >= lastCheckTime + 10) {
            lastCheckTime = simTime();
            fragbuf.purgeStaleFragments(icmp, simTime() - fragmentTimeoutTime);
        }

        packet = fragbuf.addFragment(packet, simTime());
        if (!packet) {
            EV_DETAIL << "No complete datagram yet.\n";
            return;
        }
        if (packet->peekAtFront<Ipv4Header>()->getCrcMode() == CRC_COMPUTED) {
            auto ipv4Header = removeNetworkProtocolHeader<Ipv4Header>(packet);
            setComputedCrc(ipv4Header);
            insertNetworkProtocolHeader(packet, Protocol::ipv4, ipv4Header);
        }
        EV_DETAIL << "This fragment completes the datagram.\n";
    }

    if (datagramLocalInHook(packet) == INetfilter::IHook::ACCEPT)
        reassembleAndDeliverFinish(packet);
}

void MichaIpv4::reassembleAndDeliverFinish(Packet *packet)
{
    auto ipv4HeaderPosition = packet->getFrontOffset();
    const auto& ipv4Header = packet->peekAtFront<Ipv4Header>();
    const Protocol *protocol = ipv4Header->getProtocol();
    auto remoteAddress(ipv4Header->getSrcAddress());
    auto localAddress(ipv4Header->getDestAddress());
    auto hasEcn = ipv4Header->getExplicitCongestionNotification();
    if (hasEcn) {
       // EV_INFO << "\n\n\n\n\n\n\n\n GOT IP CE <--------------------------------------------------\n\n\n\n\n\n\n\n";
        packet->addTagIfAbsent<EcnReq>()->setExplicitCongestionNotification(hasEcn);
    }
    
    

    decapsulate(packet);
    bool hasSocket = false;
    for (const auto &elem: socketIdToSocketDescriptor) {
        if (elem.second->protocolId == protocol->getId()
                && (elem.second->localAddress.isUnspecified() || elem.second->localAddress == localAddress)
                && (elem.second->remoteAddress.isUnspecified() || elem.second->remoteAddress == remoteAddress)) {
            auto *packetCopy = packet->dup();
            packetCopy->addTagIfAbsent<SocketInd>()->setSocketId(elem.second->socketId);
            EV_INFO << "Passing up to socket " << elem.second->socketId << "\n";
            emit(packetSentToUpperSignal, packetCopy);
            send(packetCopy, "transportOut");
            hasSocket = true;
        }
    }
    if (upperProtocols.find(protocol) != upperProtocols.end()) {
        EV_INFO << "Passing up to protocol " << protocol << "\n";
        emit(packetSentToUpperSignal, packet);
        send(packet, "transportOut");
        numLocalDeliver++;
    }
    else if (hasSocket) {
        delete packet;
    }
    else {
        EV_ERROR << "Transport protocol '" << protocol->getName() << "' not connected, discarding packet\n";
        packet->setFrontOffset(ipv4HeaderPosition);
        const InterfaceEntry* fromIE = getSourceInterface(packet);
        sendIcmpError(packet, fromIE ? fromIE->getInterfaceId() : -1, ICMP_DESTINATION_UNREACHABLE, ICMP_DU_PROTOCOL_UNREACHABLE);
    }
}

void MichaIpv4::decapsulate(Packet *packet)
{
    // decapsulate transport packet
    const auto& ipv4Header = packet->popAtFront<Ipv4Header>();

    // create and fill in control info
    packet->addTagIfAbsent<DscpInd>()->setDifferentiatedServicesCodePoint(ipv4Header->getDiffServCodePoint());
    //packet->addTagIfAbsent<EcnInd>()->setExplicitCongestionNotification(ipv4Header->getExplicitCongestionNotification());

    /*double P = (double)rand() / (double)RAND_MAX;
    if ( P <= (double)0.1 ) {
         auto EcnTagReq = packet->addTagIfAbsent<EcnInd>();
         EcnTagReq->setExplicitCongestionNotification(true);
         EcnTagReq->getExplicitCongestionNotification();

        EV_INFO << "\n\n\n\n\n\n\n\n SET IP CE <--------------------------------------------------\n\n\n\n\n\n\n\n";
    }*/

    // original Ipv4 datagram might be needed in upper layers to send back ICMP error message

    auto transportProtocol = ProtocolGroup::ipprotocol.getProtocol(ipv4Header->getProtocolId());
    packet->addTagIfAbsent<PacketProtocolTag>()->setProtocol(transportProtocol);
    packet->addTagIfAbsent<DispatchProtocolReq>()->setProtocol(transportProtocol);
    auto l3AddressInd = packet->addTagIfAbsent<L3AddressInd>();
    l3AddressInd->setSrcAddress(ipv4Header->getSrcAddress());
    l3AddressInd->setDestAddress(ipv4Header->getDestAddress());
    packet->addTagIfAbsent<HopLimitInd>()->setHopLimit(ipv4Header->getTimeToLive());
}

void MichaIpv4::fragmentPostRouting(Packet *packet)
{
    const InterfaceEntry *destIE = ift->getInterfaceById(packet->getTag<InterfaceReq>()->getInterfaceId());
    // fill in source address
    if (packet->peekAtFront<Ipv4Header>()->getSrcAddress().isUnspecified()) {
        auto ipv4Header = removeNetworkProtocolHeader<Ipv4Header>(packet);
        ipv4Header->setSrcAddress(destIE->ipv4Data()->getIPAddress());
        insertNetworkProtocolHeader(packet, Protocol::ipv4, ipv4Header);
    }
    if (datagramPostRoutingHook(packet) == INetfilter::IHook::ACCEPT)
        fragmentAndSend(packet);
}

void MichaIpv4::setComputedCrc(Ptr<Ipv4Header>& ipv4Header)
{
    ASSERT(crcMode == CRC_COMPUTED);
    ipv4Header->setCrc(0);
    MemoryOutputStream ipv4HeaderStream;
    Chunk::serialize(ipv4HeaderStream, ipv4Header);
    // compute the CRC
    uint16_t crc = TcpIpChecksum::checksum(ipv4HeaderStream.getData());
    ipv4Header->setCrc(crc);
}

void MichaIpv4::fragmentAndSend(Packet *packet)
{
    const InterfaceEntry *destIE = ift->getInterfaceById(packet->getTag<InterfaceReq>()->getInterfaceId());
    Ipv4Address nextHopAddr = getNextHop(packet);
    if (nextHopAddr.isUnspecified()) {
        Ipv4InterfaceData *ipv4Data = destIE->ipv4Data();
        const auto& ipv4Header = packet->peekAtFront<Ipv4Header>();
        Ipv4Address destAddress = ipv4Header->getDestAddress();
        if (Ipv4Address::maskedAddrAreEqual(destAddress, ipv4Data->getIPAddress(), ipv4Data->getNetmask()))
            nextHopAddr = destAddress;
        else if (useProxyARP) {
            nextHopAddr = destAddress;
            EV_WARN << "no next-hop address, using destination address " << nextHopAddr << " (proxy ARP)\n";
        }
        else
            throw cRuntimeError(packet, "Cannot send datagram on broadcast interface: no next-hop address and Proxy ARP is disabled");
        packet->addTagIfAbsent<NextHopAddressReq>()->setNextHopAddress(nextHopAddr);
    }

    const auto& ipv4Header = packet->peekAtFront<Ipv4Header>();

    // hop counter check
    if (ipv4Header->getTimeToLive() <= 0) {
        // drop datagram, destruction responsibility in ICMP
        PacketDropDetails details;
        details.setReason(HOP_LIMIT_REACHED);
        emit(packetDroppedSignal, packet, &details);
        EV_WARN << "datagram TTL reached zero, sending ICMP_TIME_EXCEEDED\n";
        sendIcmpError(packet, -1    /*TODO*/, ICMP_TIME_EXCEEDED, 0);
        numDropped++;
        return;
    }

//	if (QLength == 9) {
//		markEcn = true;
//	}
//	else if (QLength < 7) {
//		markEcn = false;
//	}
//	if (markEcn) {
//		auto ipv4Header_ds = removeNetworkProtocolHeader<Ipv4Header>(packet);
//		ipv4Header_ds->setExplicitCongestionNotification(true);
//		insertNetworkProtocolHeader(packet, Protocol::ipv4, ipv4Header_ds);
//		EV_INFO << "\n\n\n\n\n\n\n\n SET IP CE <--------------------------------------------------\n\n\n\n\n\n\n\n";
//	}



/************************************* RED ECN ****************************************************/
/*    double thresh = 6;			// 1 Node - 6      2Nodes - 15
    double qCapcity = 10;		// 1 Node - 10     2Nodes - 23

    if ( QLength > thresh )
    {

    	double P = (double)rand() / (double)RAND_MAX;
    	double T = (double)(QLength-thresh) / (qCapcity-thresh);

    	if ( P <= T )
    	{
    		doMarkWithEcn = true;
    	}
    	int addr = packet->peekAtFront<Ipv4Header>()->getDestAddress().getInt();

    	if ( doMarkWithEcn && (addr==167772165))		//1Node - 167772165    2Nodes - dstAddrFilter
    	{
    		auto ipv4Header_ds = removeNetworkProtocolHeader<Ipv4Header>(packet);
    	    ipv4Header_ds->setExplicitCongestionNotification(true);
    	    insertNetworkProtocolHeader(packet, Protocol::ipv4, ipv4Header_ds);
    	    EV_INFO << "\n\n\n\n\n\n\n\n SET IP CE <--------------------------------------------------\n\n\n\n\n\n\n\n";
    	    //QLength = 0;
    	}
    } else
    {
    	doMarkWithEcn = false;
    }

*/

    /************************************* RL ****************************************************/

    int addr = packet->peekAtFront<Ipv4Header>()->getDestAddress().getInt();

	if ( choosedAction == actions::markEcn && (addr==dstAddrFilter))		//1Node - 167772165    2Nodes - dstAddrFilter
    {
    	auto ipv4Header_ds = removeNetworkProtocolHeader<Ipv4Header>(packet);
        ipv4Header_ds->setExplicitCongestionNotification(true);
        insertNetworkProtocolHeader(packet, Protocol::ipv4, ipv4Header_ds);
        EV_INFO << "\n\n\n\n\n\n\n\n SET IP CE BY RL <--------------------------------------------------\n\n\n\n\n\n\n\n";
   	}

	if ( choosedAction == actions::drop && (addr==dstAddrFilter))		//1Node - 167772165    2Nodes - dstAddrFilter
	{
		 PacketDropDetails details;
		 //details.setReason(HOP_LIMIT_REACHED);
		 emit(packetDroppedSignal, packet, &details);
		 delete packet;
		 numDropped++;
		 packetDropped++;
		 packetDroppedAccumDbg++;
		 EV_INFO << "\n\n\n\n\n\n\n\n DROPED BY RL <--------------------------------------------------\n\n\n\n\n\n\n\n";
		 return;
	}
	if ( choosedAction == actions::drop && (addr==dstAddrFilter))		//1Node - 167772165    2Nodes - dstAddrFilter
	{
		EV_INFO << "\n\n\n\n\n\n\n\n Nothing BY RL <--------------------------------------------------\n\n\n\n\n\n\n\n";
	}


	if (choosenActions)
	{
		choosenActions->record(choosedAction);
	}


    // RAND option
//    double P = (double)rand() / (double)RAND_MAX;
//    if ( P <= (double)0.01 )
//    {
//        auto ipv4Header_ds = removeNetworkProtocolHeader<Ipv4Header>(packet);
//        ipv4Header_ds->setExplicitCongestionNotification(true);
//        insertNetworkProtocolHeader(packet, Protocol::ipv4, ipv4Header_ds);
//        EV_INFO << "\n\n\n\n\n\n\n\n SET IP CE <--------------------------------------------------\n\n\n\n\n\n\n\n";
//    }

    int mtu = destIE->getMtu();

    // send datagram straight out if it doesn't require fragmentation (note: mtu==0 means infinite mtu)
    if (mtu == 0 || packet->getByteLength() <= mtu) {
        if (crcMode == CRC_COMPUTED) {
            auto ipv4Header = removeNetworkProtocolHeader<Ipv4Header>(packet);
            setComputedCrc(ipv4Header);
            insertNetworkProtocolHeader(packet, Protocol::ipv4, ipv4Header);
        }
        sendDatagramToOutput(packet);
        return;
    }

    // if "don't fragment" bit is set, throw datagram away and send ICMP error message
    if (ipv4Header->getDontFragment()) {
        PacketDropDetails details;
        emit(packetDroppedSignal, packet, &details);
        EV_WARN << "datagram larger than MTU and don't fragment bit set, sending ICMP_DESTINATION_UNREACHABLE\n";
        sendIcmpError(packet, -1    /*TODO*/, ICMP_DESTINATION_UNREACHABLE,
                ICMP_DU_FRAGMENTATION_NEEDED);
        numDropped++;
        return;
    }

    // FIXME some IP options should not be copied into each fragment, check their COPY bit
    int headerLength = B(ipv4Header->getHeaderLength()).get();
    int payloadLength = B(packet->getDataLength()).get() - headerLength;
    int fragmentLength = ((mtu - headerLength) / 8) * 8;    // payload only (without header)
    int offsetBase = ipv4Header->getFragmentOffset();
    if (fragmentLength <= 0)
        throw cRuntimeError("Cannot fragment datagram: MTU=%d too small for header size (%d bytes)", mtu, headerLength); // exception and not ICMP because this is likely a simulation configuration error, not something one wants to simulate

    int noOfFragments = (payloadLength + fragmentLength - 1) / fragmentLength;
    EV_DETAIL << "Breaking datagram into " << noOfFragments << " fragments\n";

    // create and send fragments
    std::string fragMsgName = packet->getName();
    fragMsgName += "-frag-";

    int offset = 0;
    while (offset < payloadLength) {
        bool lastFragment = (offset + fragmentLength >= payloadLength);
        // length equal to fragmentLength, except for last fragment;
        int thisFragmentLength = lastFragment ? payloadLength - offset : fragmentLength;

        std::string curFragName = fragMsgName + std::to_string(offset);
        if (lastFragment)
            curFragName += "-last";
        Packet *fragment = new Packet(curFragName.c_str());     //TODO add offset or index to fragment name

        //copy Tags from packet to fragment
        fragment->copyTags(*packet);

        ASSERT(fragment->getByteLength() == 0);
        auto fraghdr = staticPtrCast<Ipv4Header>(ipv4Header->dupShared());
        const auto& fragData = packet->peekDataAt(B(headerLength + offset), B(thisFragmentLength));
        ASSERT(fragData->getChunkLength() == B(thisFragmentLength));
        fragment->insertAtBack(fragData);

        // "more fragments" bit is unchanged in the last fragment, otherwise true
        if (!lastFragment)
            fraghdr->setMoreFragments(true);

        fraghdr->setFragmentOffset(offsetBase + offset);
        fraghdr->setTotalLengthField(B(headerLength + thisFragmentLength));
        if (crcMode == CRC_COMPUTED)
            setComputedCrc(fraghdr);

        fragment->insertAtFront(fraghdr);
        ASSERT(fragment->getByteLength() == headerLength + thisFragmentLength);
        sendDatagramToOutput(fragment);
        offset += thisFragmentLength;
    }

    delete packet;
}

void MichaIpv4::encapsulate(Packet *transportPacket)
{
    const auto& ipv4Header = makeShared<Ipv4Header>();

    auto l3AddressReq = transportPacket->removeTag<L3AddressReq>();
    Ipv4Address src = l3AddressReq->getSrcAddress().toIpv4();
    Ipv4Address dest = l3AddressReq->getDestAddress().toIpv4();
    delete l3AddressReq;

    ipv4Header->setProtocolId((IpProtocolId)ProtocolGroup::ipprotocol.getProtocolNumber(transportPacket->getTag<PacketProtocolTag>()->getProtocol()));

    auto hopLimitReq = transportPacket->removeTagIfPresent<HopLimitReq>();
    short ttl = (hopLimitReq != nullptr) ? hopLimitReq->getHopLimit() : -1;
    delete hopLimitReq;
    bool dontFragment = false;
    if (auto dontFragmentReq = transportPacket->removeTagIfPresent<FragmentationReq>()) {
        dontFragment = dontFragmentReq->getDontFragment();
        delete dontFragmentReq;
    }

    // set source and destination address
    ipv4Header->setDestAddress(dest);

    // when source address was given, use it; otherwise it'll get the address
    // of the outgoing interface after routing
    if (!src.isUnspecified()) {
        // if interface parameter does not match existing interface, do not send datagram
        if (rt->getInterfaceByAddress(src) == nullptr)
            throw cRuntimeError("Wrong source address %s in (%s)%s: no interface with such address",
                    src.str().c_str(), transportPacket->getClassName(), transportPacket->getFullName());

        ipv4Header->setSrcAddress(src);
    }

    // set other fields
    if (DscpReq *dscpReq = transportPacket->removeTagIfPresent<DscpReq>()) {
        ipv4Header->setDiffServCodePoint(dscpReq->getDifferentiatedServicesCodePoint());
        delete dscpReq;
    }
    if (EcnReq *ecnReq = transportPacket->removeTagIfPresent<EcnReq>()) {
        ipv4Header->setExplicitCongestionNotification(ecnReq->getExplicitCongestionNotification());
        delete ecnReq;
    }

    ipv4Header->setIdentification(curFragmentId++);
    ipv4Header->setMoreFragments(false);
    ipv4Header->setDontFragment(dontFragment);
    ipv4Header->setFragmentOffset(0);

    if (ttl != -1) {
        ASSERT(ttl > 0);
    }
    else if (ipv4Header->getDestAddress().isLinkLocalMulticast())
        ttl = 1;
    else if (ipv4Header->getDestAddress().isMulticast())
        ttl = defaultMCTimeToLive;
    else
        ttl = defaultTimeToLive;
    ipv4Header->setTimeToLive(ttl);
    ipv4Header->setTotalLengthField(ipv4Header->getChunkLength() + transportPacket->getDataLength());
    ipv4Header->setCrcMode(crcMode);
    ipv4Header->setCrc(0);
    switch (crcMode) {
        case CRC_DECLARED_CORRECT:
            // if the CRC mode is declared to be correct, then set the CRC to an easily recognizable value
            ipv4Header->setCrc(0xC00D);
            break;
        case CRC_DECLARED_INCORRECT:
            // if the CRC mode is declared to be incorrect, then set the CRC to an easily recognizable value
            ipv4Header->setCrc(0xBAAD);
            break;
        case CRC_COMPUTED: {
            ipv4Header->setCrc(0);
            // crc will be calculated in fragmentAndSend()
            break;
        }
        default:
            throw cRuntimeError("Unknown CRC mode");
    }
    insertNetworkProtocolHeader(transportPacket, Protocol::ipv4, ipv4Header);
    // setting MichaIpv4 options is currently not supported
}

void MichaIpv4::sendDatagramToOutput(Packet *packet)
{
    const InterfaceEntry *ie = ift->getInterfaceById(packet->getTag<InterfaceReq>()->getInterfaceId());
    auto nextHopAddressReq = packet->removeTag<NextHopAddressReq>();
    Ipv4Address nextHopAddr = nextHopAddressReq->getNextHopAddress().toIpv4();
    delete nextHopAddressReq;
    if (!ie->isBroadcast() || ie->getMacAddress().isUnspecified()) // we can't do ARP
        sendPacketToNIC(packet);
    else {
        MacAddress nextHopMacAddr = resolveNextHopMacAddress(packet, nextHopAddr, ie);
        if (nextHopMacAddr.isUnspecified()) {
            EV_INFO << "Pending " << packet << " to ARP resolution.\n";
            pendingPackets[nextHopAddr].insert(packet);
        }
        else {
            ASSERT2(pendingPackets.find(nextHopAddr) == pendingPackets.end(), "Ipv4-ARP error: nextHopAddr found in ARP table, but Ipv4 queue for nextHopAddr not empty");
            packet->addTagIfAbsent<MacAddressReq>()->setDestAddress(nextHopMacAddr);
            sendPacketToNIC(packet);
        }
    }
}

void MichaIpv4::arpResolutionCompleted(IArp::Notification *entry)
{
    if (entry->l3Address.getType() != L3Address::IPv4)
        return;
    auto it = pendingPackets.find(entry->l3Address.toIpv4());
    if (it != pendingPackets.end()) {
        cPacketQueue& packetQueue = it->second;
        EV << "ARP resolution completed for " << entry->l3Address << ". Sending " << packetQueue.getLength()
           << " waiting packets from the queue\n";

        while (!packetQueue.isEmpty()) {
            Packet *packet = check_and_cast<Packet *>(packetQueue.pop());
            EV << "Sending out queued packet " << packet << "\n";
            packet->addTagIfAbsent<InterfaceReq>()->setInterfaceId(entry->ie->getInterfaceId());
            packet->addTagIfAbsent<MacAddressReq>()->setDestAddress(entry->macAddress);
            sendPacketToNIC(packet);
        }
        pendingPackets.erase(it);
    }
}

void MichaIpv4::arpResolutionTimedOut(IArp::Notification *entry)
{
    if (entry->l3Address.getType() != L3Address::IPv4)
        return;
    auto it = pendingPackets.find(entry->l3Address.toIpv4());
    if (it != pendingPackets.end()) {
        cPacketQueue& packetQueue = it->second;
        EV << "ARP resolution failed for " << entry->l3Address << ",  dropping " << packetQueue.getLength() << " packets\n";
        for (int i = 0; i < packetQueue.getLength(); i++) {
            auto packet = packetQueue.get(i);
            PacketDropDetails details;
            details.setReason(ADDRESS_RESOLUTION_FAILED);
            emit(packetDroppedSignal, packet, &details);
        }
        packetQueue.clear();
        pendingPackets.erase(it);
    }
}

MacAddress MichaIpv4::resolveNextHopMacAddress(cPacket *packet, Ipv4Address nextHopAddr, const InterfaceEntry *destIE)
{
    if (nextHopAddr.isLimitedBroadcastAddress() || nextHopAddr == destIE->ipv4Data()->getNetworkBroadcastAddress()) {
        EV_DETAIL << "destination address is broadcast, sending packet to broadcast MAC address\n";
        return MacAddress::BROADCAST_ADDRESS;
    }

    if (nextHopAddr.isMulticast()) {
        MacAddress macAddr = MacAddress::makeMulticastAddress(nextHopAddr);
        EV_DETAIL << "destination address is multicast, sending packet to MAC address " << macAddr << "\n";
        return macAddr;
    }

    return arp->resolveL3Address(nextHopAddr, destIE);
}

void MichaIpv4::sendPacketToNIC(Packet *packet)
{
    EV_INFO << "Sending " << packet << " to output interface = " << ift->getInterfaceById(packet->getTag<InterfaceReq>()->getInterfaceId())->getInterfaceName() << ".\n";
    packet->addTagIfAbsent<PacketProtocolTag>()->setProtocol(&Protocol::ipv4);
    packet->addTagIfAbsent<DispatchProtocolInd>()->setProtocol(&Protocol::ipv4);
    delete packet->removeTagIfPresent<DispatchProtocolReq>();
    ASSERT(packet->findTag<InterfaceReq>() != nullptr);

    // MICHA - measure here? decide drop here?
//    double alpha = 1;
//    double beta = 1;
//    double gamma = 1;
//    double U = alpha*throuput -beta*delay
//    Packet tmpPacket = *packet; //use new?
//    decapsulate(tmpPacket);
//    tmpPacket.



    send(packet, "queueOut");
}

// NetFilter:

void MichaIpv4::registerHook(int priority, INetfilter::IHook *hook)
{
    Enter_Method("registerHook()");
    NetfilterBase::registerHook(priority, hook);
}

void MichaIpv4::unregisterHook(INetfilter::IHook *hook)
{
    Enter_Method("unregisterHook()");
    NetfilterBase::unregisterHook(hook);
}

void MichaIpv4::dropQueuedDatagram(const Packet *packet)
{
    Enter_Method("dropQueuedDatagram()");
    for (auto iter = queuedDatagramsForHooks.begin(); iter != queuedDatagramsForHooks.end(); iter++) {
        if (iter->packet == packet) {
            delete packet;
            queuedDatagramsForHooks.erase(iter);
            return;
        }
    }
}

void MichaIpv4::reinjectQueuedDatagram(const Packet *packet)
{
    Enter_Method("reinjectDatagram()");
    for (auto iter = queuedDatagramsForHooks.begin(); iter != queuedDatagramsForHooks.end(); iter++) {
        if (iter->packet == packet) {
            auto *qPacket = iter->packet;
            take(qPacket);
            switch (iter->hookType) {
                case INetfilter::IHook::LOCALOUT:
                    datagramLocalOut(qPacket);
                    break;

                case INetfilter::IHook::PREROUTING:
                    preroutingFinish(qPacket);
                    break;

                case INetfilter::IHook::POSTROUTING:
                    fragmentAndSend(qPacket);
                    break;

                case INetfilter::IHook::LOCALIN:
                    reassembleAndDeliverFinish(qPacket);
                    break;

                case INetfilter::IHook::FORWARD:
                    routeUnicastPacketFinish(qPacket);
                    break;

                default:
                    throw cRuntimeError("Unknown hook ID: %d", (int)(iter->hookType));
                    break;
            }
            queuedDatagramsForHooks.erase(iter);
            return;
        }
    }
}

INetfilter::IHook::Result MichaIpv4::datagramPreRoutingHook(Packet *packet)
{
    for (auto & elem : hooks) {
        IHook::Result r = elem.second->datagramPreRoutingHook(packet);
        switch (r) {
            case INetfilter::IHook::ACCEPT:
                break;    // continue iteration

            case INetfilter::IHook::DROP:
                delete packet;
                return r;

            case INetfilter::IHook::QUEUE:
                queuedDatagramsForHooks.push_back(QueuedDatagramForHook(packet, INetfilter::IHook::PREROUTING));
                return r;

            case INetfilter::IHook::STOLEN:
                return r;

            default:
                throw cRuntimeError("Unknown Hook::Result value: %d", (int)r);
        }
    }
    return INetfilter::IHook::ACCEPT;
}

INetfilter::IHook::Result MichaIpv4::datagramForwardHook(Packet *packet)
{
    for (auto & elem : hooks) {
        IHook::Result r = elem.second->datagramForwardHook(packet);
        switch (r) {
            case INetfilter::IHook::ACCEPT:
                break;    // continue iteration

            case INetfilter::IHook::DROP:
                delete packet;
                return r;

            case INetfilter::IHook::QUEUE:
                queuedDatagramsForHooks.push_back(QueuedDatagramForHook(packet, INetfilter::IHook::FORWARD));
                return r;

            case INetfilter::IHook::STOLEN:
                return r;

            default:
                throw cRuntimeError("Unknown Hook::Result value: %d", (int)r);
        }
    }
    return INetfilter::IHook::ACCEPT;
}

INetfilter::IHook::Result MichaIpv4::datagramPostRoutingHook(Packet *packet)
{
    for (auto & elem : hooks) {
        IHook::Result r = elem.second->datagramPostRoutingHook(packet);
        switch (r) {
            case INetfilter::IHook::ACCEPT:
                break;    // continue iteration

            case INetfilter::IHook::DROP:
                delete packet;
                return r;

            case INetfilter::IHook::QUEUE:
                queuedDatagramsForHooks.push_back(QueuedDatagramForHook(packet, INetfilter::IHook::POSTROUTING));
                return r;

            case INetfilter::IHook::STOLEN:
                return r;

            default:
                throw cRuntimeError("Unknown Hook::Result value: %d", (int)r);
        }
    }
    return INetfilter::IHook::ACCEPT;
}

bool MichaIpv4::handleOperationStage(LifecycleOperation *operation, int stage, IDoneCallback *doneCallback)
{
    Enter_Method_Silent();
    if (dynamic_cast<NodeStartOperation *>(operation)) {
        if (static_cast<NodeStartOperation::Stage>(stage) == NodeStartOperation::STAGE_NETWORK_LAYER)
            start();
    }
    else if (dynamic_cast<NodeShutdownOperation *>(operation)) {
        if (static_cast<NodeShutdownOperation::Stage>(stage) == NodeShutdownOperation::STAGE_NETWORK_LAYER)
            stop();
    }
    else if (dynamic_cast<NodeCrashOperation *>(operation)) {
        if (static_cast<NodeCrashOperation::Stage>(stage) == NodeCrashOperation::STAGE_CRASH)
            stop();
    }
    return true;
}

void MichaIpv4::start()
{
    ASSERT(queue.isEmpty());
    isUp = true;
}

void MichaIpv4::stop()
{
    isUp = false;
    delete cancelEvent(rlStatTimerMsg);
    flush();
}

void MichaIpv4::flush()
{
    delete cancelService();
    EV_DEBUG << "Ipv4::flush(): packets in queue: " << queue.str() << endl;
    queue.clear();

    EV_DEBUG << "Ipv4::flush(): pending packets:\n";
    for (auto & elem : pendingPackets) {
        EV_DEBUG << "Ipv4::flush():    " << elem.first << ": " << elem.second.str() << endl;
        elem.second.clear();
    }
    pendingPackets.clear();

    EV_DEBUG << "Ipv4::flush(): packets in hooks: " << queuedDatagramsForHooks.size() << endl;
    for (auto & elem : queuedDatagramsForHooks) {
        delete elem.packet;
    }
    queuedDatagramsForHooks.clear();

    fragbuf.flush();
}

bool MichaIpv4::isNodeUp()
{
    NodeStatus *nodeStatus = dynamic_cast<NodeStatus *>(findContainingNode(this)->getSubmodule("status"));
    return !nodeStatus || nodeStatus->getState() == NodeStatus::UP;
}

INetfilter::IHook::Result MichaIpv4::datagramLocalInHook(Packet *packet)
{
    for (auto & elem : hooks) {
        IHook::Result r = elem.second->datagramLocalInHook(packet);
        switch (r) {
            case INetfilter::IHook::ACCEPT:
                break;    // continue iteration

            case INetfilter::IHook::DROP:
                delete packet;
                return r;

            case INetfilter::IHook::QUEUE: {
                if (packet->getOwner() != this)
                    throw cRuntimeError("Model error: netfilter hook changed the owner of queued datagram '%s'", packet->getFullName());
                queuedDatagramsForHooks.push_back(QueuedDatagramForHook(packet, INetfilter::IHook::LOCALIN));
                return r;
            }

            case INetfilter::IHook::STOLEN:
                return r;

            default:
                throw cRuntimeError("Unknown Hook::Result value: %d", (int)r);
        }
    }
    return INetfilter::IHook::ACCEPT;
}

INetfilter::IHook::Result MichaIpv4::datagramLocalOutHook(Packet *packet)
{
    for (auto & elem : hooks) {
        IHook::Result r = elem.second->datagramLocalOutHook(packet);
        switch (r) {
            case INetfilter::IHook::ACCEPT:
                break;    // continue iteration

            case INetfilter::IHook::DROP:
                delete packet;
                return r;

            case INetfilter::IHook::QUEUE:
                queuedDatagramsForHooks.push_back(QueuedDatagramForHook(packet, INetfilter::IHook::LOCALOUT));
                return r;

            case INetfilter::IHook::STOLEN:
                return r;

            default:
                throw cRuntimeError("Unknown Hook::Result value: %d", (int)r);
        }
    }
    return INetfilter::IHook::ACCEPT;
}

void MichaIpv4::receiveSignal(cComponent *source, simsignal_t signalID, cObject *obj, cObject *details)
{
    Enter_Method_Silent();

    if (signalID == IArp::arpResolutionCompletedSignal) {
        arpResolutionCompleted(check_and_cast<IArp::Notification *>(obj));
    }
    if (signalID == IArp::arpResolutionFailedSignal) {
        arpResolutionTimedOut(check_and_cast<IArp::Notification *>(obj));
    }

    if (signalID == tcpConnectionAddedSignalId) {
        auto sourceId = source->getId();

//        tcp::TcpConnection *conn = check_and_cast<tcp::TcpConnection *>(obj);;
//        auto tcpSockId = conn->getSocketId(); //check for SERVERS connection closing (because it receives ack on fin and nodes wait)
        // node[0] socketId = 14; node[1] socketId = 15; node[2] socketId = 16
        // servers: node[0]socketId = 17; node[1]socketId = 18; node[2]socketId = 19;
        if ((sourceId == 24) || (sourceId == 58) || (sourceId == 92)) //24 = node[1] 58=node[2] 92=node[3]
        {
            ++tcpConnCounter;
            if (tcpConnCounter == 1) {
                simtime_t tmp = simTime();
                scheduleAt(tmp + timerDelta, rlStatTimerMsg);
            }
        }
    }

    if (signalID == tcpConnectionRemovedSignalId) {
//        auto sourceId = source->getId();
//        if ((sourceId == 24) || (sourceId == 58) || (sourceId == 92)) //24 = node[1] 58=node[2] 92=node[3]
        tcp::TcpConnection *conn = check_and_cast<tcp::TcpConnection *>(obj);;
        auto tcpSockId = conn->getSocketId(); //check for SERVERS connection closing (because it receives ack on fin and nodes wait)
        // node[0] socketId = 14; node[1] socketId = 15; node[2] socketId = 16
        // servers: node[0]socketId = 17; node[1]socketId = 18; node[2]socketId = 19;
        if ((tcpSockId == 17) || (tcpSockId == 18) || (tcpSockId == 19))
        {
            --tcpConnCounter;
            if (tcpConnCounter == 0) {
                cancelEvent(rlStatTimerMsg);
            }
        }
    }

    if (signalID == packetEnqueuedSignalId) {
    	auto sourceId = source->getId();
    	if (sourceId != sourceIdFilter) {return;}

    	//doSarsaStuff();
    }

    if (signalID == packetDequeuedSignalId) {
    	/*auto signalOwner = check_and_cast<InterfaceEntry *>(source->getOwner());
    	auto sourceAddress = signalOwner->getIpv4Address().getInt();
    	if (sourceAddress != 167772165)
    	{
    		return;
    	}*/

    	auto sourceId = source->getId();
    	if (sourceId != sourceIdFilter) {return;}

    	Packet *packet = check_and_cast<Packet *>(obj);
    	/*auto destAddress = packet->peekAtFront<Ipv4Header>()->getDestAddress().getInt();
    	auto sourceAddress = packet->peekAtFront<Ipv4Header>()->getSrcAddress().getInt();
    	/if ( (sourceAddress != 167772161) || (destAddress != 167772165) )
    	{
    		return;
    	}*/

    	bytesSent += packet->getByteLength();
    	if (sentBytesVec)
    	{
    	    sentBytesVec->record(bytesSent);
    	}
    	//EV_INFO << "\n\n\n\n\n\n\n\n bytesSent = " << bytesSent << "<--------------------------------------------------\n\n\n\n\n\n\n\n";
    	//doSarsaStuff();
    }


    if (signalID == packetDroppedSignalId) {
    	auto sourceId = source->getId();
    	if (sourceId != sourceIdFilter) {return;}
    	if (check_and_cast<PacketDropDetails *>(details)->getReason() == QUEUE_OVERFLOW) {
    		packetDropped++;
    		packetDroppedAccumDbg++;
    		//EV_INFO << "\n\n\n\n\n\n\n\n packetDropped = " << packetDropped << "<--------------------------------------------------\n\n\n\n\n\n\n\n";
    	}

    }


//	if (signalID == lengthSignalId) {
//        //MichaQlengthSignal *qL = check_and_cast<MichaQlengthSignal *>(obj);
//
//        //int* ql = check_and_cast<int *>(obj);
//        //QLength = *ql;
//        EV_INFO << "\n\n\n\n\n\n\n\n QLength = " << QLength << "<--------------------------------------------------\n\n\n\n\n\n\n\n";
//
//        //if (qL->qLength >= 9) {
//        //	QLength = 1;
//		//}
//
//    }
}

void MichaIpv4::receiveSignal(cComponent *source, simsignal_t signalID, long value, cObject *details)
{
	if (signalID == queueLengthSignalId) {
		auto sourceId = source->getId();
		if (sourceId != sourceIdFilter) {return;} // 1node = 99 2node = sourceIdFilter
		QLength = value;
		//EV_INFO << "\n\n\n\n\n\n\n\n QLength = " << QLength << "<--------------------------------------------------\n\n\n\n\n\n\n\n";
	}


}

void MichaIpv4::receiveSignal(cComponent *source, simsignal_t signalID, const SimTime& t, cObject *details) {
	if (signalID == queueingTimeSignalId) {
		auto sourceId = source->getId();
		if (sourceId != sourceIdFilter) {return;}
		queuingTimeAccum += t;
		//EV_INFO << "\n\n\n\n\n\n\n\n queuingTimeAccum = " << 100000*queuingTimeAccum.dbl() <<  " t = " << t << " t.raw = " << t.raw() << "<--------------------------------------------------\n\n\n\n\n\n\n\n";

	}
}



void MichaIpv4::sendIcmpError(Packet *origPacket, int inputInterfaceId, IcmpType type, IcmpCode code)
{
    icmp->sendErrorMessage(origPacket, inputInterfaceId, type, code);
}

void MichaIpv4::doSarsaStuff() {

    actions nextAction;

    double a_bytes = 10;
    double a_drops = -2000;
    double a_timePassed = -1000; // -1;

    double r_bytes = (a_bytes*bytesSent/100);
    double r_drops = (a_drops*packetDropped);
    double reward = r_bytes + r_drops + a_timePassed;

    if (!regularRun) {
        if (ecn_threshold > 0) {

            if (QLength >= ecn_threshold) {
                nextAction = actions::markEcn;
            } else {
                nextAction = actions::nothing;
            }

        } else {

            // Get next action from RL agent
            nextAction = sarsa->chooseAction(bytesSent/100, QLength, (uint64_t) packetDropped);

        }
    }

    // Update Q function values. MUST do out of else-block so reward.txt will be updated
    sarsa->udpateQ(reward, bytesSent, QLength, packetDropped, nextAction);


	bytesSent = 0;
	queuingTimeAccum = 0;
	packetDropped = 0;
	choosedAction = nextAction;
}



} // namespace inet
