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
#include "inet/linklayer/ieee80211/mac/Ieee80211MacHeaderSerializer.h"

namespace inet {

namespace ieee80211 {

Register_Serializer(Ieee80211MacHeader, Ieee80211MacHeaderSerializer);
Register_Serializer(Ieee80211DataOrMgmtHeader, Ieee80211MacHeaderSerializer);
Register_Serializer(Ieee80211DataHeader, Ieee80211MacHeaderSerializer);
Register_Serializer(Ieee80211MgmtHeader, Ieee80211MacHeaderSerializer);
Register_Serializer(Ieee80211MsduSubframeHeader, Ieee80211MacHeaderSerializer);
Register_Serializer(Ieee80211MpduSubframeHeader, Ieee80211MacHeaderSerializer);

Register_Serializer(Ieee80211AckFrame, Ieee80211MacHeaderSerializer);
Register_Serializer(Ieee80211RtsFrame, Ieee80211MacHeaderSerializer);
Register_Serializer(Ieee80211CtsFrame, Ieee80211MacHeaderSerializer);

Register_Serializer(Ieee80211BasicBlockAckReq, Ieee80211MacHeaderSerializer);
Register_Serializer(Ieee80211CompressedBlockAckReq, Ieee80211MacHeaderSerializer);
Register_Serializer(Ieee80211MultiTidBlockAckReq, Ieee80211MacHeaderSerializer);
Register_Serializer(Ieee80211BasicBlockAck, Ieee80211MacHeaderSerializer);
Register_Serializer(Ieee80211CompressedBlockAck, Ieee80211MacHeaderSerializer);
Register_Serializer(Ieee80211MultiTidBlockAck, Ieee80211MacHeaderSerializer);

Register_Serializer(Ieee80211MacTrailer, Ieee80211MacTrailerSerializer);

void Ieee80211MacHeaderSerializer::serialize(MemoryOutputStream& stream, const Ptr<const Chunk>& chunk) const
{

    if (auto msduSubframe = dynamicPtrCast<const Ieee80211MsduSubframeHeader>(chunk))
    {
        stream.writeMacAddress(msduSubframe->getDa());
        stream.writeMacAddress(msduSubframe->getSa());
        stream.writeUint16Be(msduSubframe->getLength());
    }
    else if (auto mpduSubframe = dynamicPtrCast<const Ieee80211MpduSubframeHeader>(chunk))
    {
        stream.writeUint4(0);
        stream.writeUint4(mpduSubframe->getLength() >> 8);
        stream.writeUint8(mpduSubframe->getLength() & 0xFF);
        stream.writeByte(0);
        stream.writeByte(0x4E);
    }
    else {
        auto macHeader = dynamicPtrCast<const Ieee80211MacHeader>(chunk);
        stream.writeNBitsOfUint64Be(macHeader->getSubType(), 4);
        stream.writeNBitsOfUint64Be(macHeader->getFrameType(), 2);
        stream.writeNBitsOfUint64Be(macHeader->getProtocolVersion(), 2);
        stream.writeBit(macHeader->getOrder());
        stream.writeBit(macHeader->getProtectedFrame());
        stream.writeBit(macHeader->getMoreData());
        stream.writeBit(macHeader->getPowerMgmt());
        stream.writeBit(macHeader->getRetry());
        stream.writeBit(macHeader->getMoreFragments());
        stream.writeBit(macHeader->getFromDS());
        stream.writeBit(macHeader->getToDS());
        Ieee80211FrameType type = macHeader->getType();
        switch (type) {
            case ST_ASSOCIATIONREQUEST:
            case ST_ASSOCIATIONRESPONSE:
            case ST_REASSOCIATIONREQUEST:
            case ST_REASSOCIATIONRESPONSE:
            case ST_PROBEREQUEST:
            case ST_PROBERESPONSE:
            case ST_BEACON:
            case ST_ATIM:
            case ST_DISASSOCIATION:
            case ST_AUTHENTICATION:
            case ST_DEAUTHENTICATION:
            case ST_NOACKACTION: {
                auto mgmtHeader = dynamicPtrCast<const Ieee80211MgmtHeader>(chunk);
                stream.writeUint16Be(mgmtHeader->getDurationField().inUnit(SIMTIME_US));
                stream.writeMacAddress(mgmtHeader->getReceiverAddress());
                stream.writeMacAddress(mgmtHeader->getTransmitterAddress());
                stream.writeMacAddress(mgmtHeader->getAddress3());
                stream.writeNBitsOfUint64Be(mgmtHeader->getSequenceNumber().getRaw(), 4);
                stream.writeNBitsOfUint64Be(mgmtHeader->getFragmentNumber(), 12);
                break;
            }
            case ST_ACTION: {
                auto actionFrame = dynamicPtrCast<const Ieee80211ActionFrame>(chunk);
                stream.writeUint16Be(actionFrame->getDurationField().inUnit(SIMTIME_US));
                stream.writeMacAddress(actionFrame->getReceiverAddress());
                stream.writeMacAddress(actionFrame->getTransmitterAddress());
                stream.writeMacAddress(actionFrame->getAddress3());
                stream.writeNBitsOfUint64Be(actionFrame->getSequenceNumber().getRaw(), 4);
                stream.writeNBitsOfUint64Be(actionFrame->getFragmentNumber(), 12);
                switch (actionFrame->getCategory()) {
                case 1: {
                    throw cRuntimeError("Ieee80211Serializer: cannot serialize the Ieee80211ActionFrame frame, category 1 not supported.");
                    break;
                }
                case 2: {
                    throw cRuntimeError("Ieee80211Serializer: cannot serialize the Ieee80211ActionFrame frame, category 2 not supported.");
                    break;
                }
                case 3: {
                    stream.writeByte(actionFrame->getCategory());
                    switch (actionFrame->getBlockAckAction()) {
                    case 0: {
                        auto addbaRequest = dynamicPtrCast<const Ieee80211AddbaRequest>(chunk);
                        stream.writeByte(addbaRequest->getBlockAckAction());
                        stream.writeByte(addbaRequest->getDialogToken());
                        stream.writeBit(addbaRequest->getAMsduSupported());
                        stream.writeBit(addbaRequest->getBlockAckPolicy());
                        stream.writeNBitsOfUint64Be(addbaRequest->getTid(), 4);
                        stream.writeNBitsOfUint64Be(addbaRequest->getBufferSize(), 10);
                        stream.writeUint16Be(addbaRequest->getBlockAckTimeoutValue().inUnit(SIMTIME_US) / 1024);
                        stream.writeNBitsOfUint64Be(addbaRequest->get_fragmentNumber(), 4);
                        stream.writeNBitsOfUint64Be(addbaRequest->getSequenceNumber().getRaw(), 12);
                        break;
                    }
                    case 1: {
                        auto addbaResponse = dynamicPtrCast<const Ieee80211AddbaResponse>(chunk);
                        stream.writeByte(addbaResponse->getBlockAckAction());
                        stream.writeByte(addbaResponse->getDialogToken());
                        stream.writeUint16Be(addbaResponse->getStatusCode());
                        stream.writeBit(addbaResponse->getAMsduSupported());
                        stream.writeBit(addbaResponse->getBlockAckPolicy());
                        stream.writeNBitsOfUint64Be(addbaResponse->getTid(), 4);
                        stream.writeNBitsOfUint64Be(addbaResponse->getBufferSize(), 10);
                        stream.writeUint16Be(addbaResponse->getBlockAckTimeoutValue().inUnit(SIMTIME_US) / 1024);
                        break;
                    }
                    case 2: {
                        auto delba = dynamicPtrCast<const Ieee80211Delba>(chunk);
                        stream.writeByte(delba->getBlockAckAction());
                        stream.writeNBitsOfUint64Be(delba->getReserved(), 11);
                        stream.writeBit(delba->getInitiator());
                        stream.writeNBitsOfUint64Be(delba->getTid(), 4);
                        stream.writeUint16Be(delba->getReasonCode());
                        break;
                    }
                    default:
                        throw cRuntimeError("Ieee80211Serializer: cannot serialize the Ieee80211ActionFrame frame, blockAckAction %d not supported.", actionFrame->getBlockAckAction());
                    }
                    break;
                }
                }
                break;
            }
            case ST_RTS: {
                auto rtsFrame = dynamicPtrCast<const Ieee80211RtsFrame>(chunk);
                stream.writeUint16Be(rtsFrame->getDurationField().inUnit(SIMTIME_US));
                stream.writeMacAddress(rtsFrame->getReceiverAddress());
                stream.writeMacAddress(rtsFrame->getTransmitterAddress());
                break;
            }
            case ST_CTS: {
                auto ctsFrame = dynamicPtrCast<const Ieee80211CtsFrame>(chunk);
                stream.writeUint16Be(ctsFrame->getDurationField().inUnit(SIMTIME_US));
                stream.writeMacAddress(ctsFrame->getReceiverAddress());
                break;
            }
            case ST_ACK: {
                auto ackFrame = dynamicPtrCast<const Ieee80211AckFrame>(chunk);
                stream.writeUint16Be(ackFrame->getDurationField().inUnit(SIMTIME_US));
                stream.writeMacAddress(ackFrame->getReceiverAddress());
                break;
            }
            case ST_BLOCKACK_REQ: {
                auto blockAckReq = dynamicPtrCast<const Ieee80211BlockAckReq>(chunk);
                stream.writeUint16Be(blockAckReq->getDurationField().inUnit(SIMTIME_US));
                stream.writeMacAddress(blockAckReq->getReceiverAddress());
                stream.writeMacAddress(blockAckReq->getTransmitterAddress());
                stream.writeBit(blockAckReq->getBarAckPolicy());
                bool multiTid = blockAckReq->getMultiTid();
                bool compressedBitmap = blockAckReq->getCompressedBitmap();
                stream.writeBit(multiTid);
                stream.writeBit(compressedBitmap);
                stream.writeNBitsOfUint64Be(blockAckReq->getReserved(), 9);
                if (!multiTid && !compressedBitmap) {
                    auto basicBlockAckReq = dynamicPtrCast<const Ieee80211BasicBlockAckReq>(chunk);
                    stream.writeNBitsOfUint64Be(basicBlockAckReq->getTidInfo(), 4);
                    stream.writeUint32Be(basicBlockAckReq->getFragmentNumber());
                    stream.writeUint64Be(0);
                    stream.writeUint64Be(basicBlockAckReq->getStartingSequenceNumber().getRaw());
                }
                else if (!multiTid && compressedBitmap) {
                    auto compressedBlockAckReq = dynamicPtrCast<const Ieee80211CompressedBlockAckReq>(chunk);
                    stream.writeNBitsOfUint64Be(compressedBlockAckReq->getTidInfo(), 4);
                    stream.writeUint32Be(compressedBlockAckReq->getFragmentNumber());
                    stream.writeUint64Be(0);
                    stream.writeUint64Be(compressedBlockAckReq->getStartingSequenceNumber().getRaw());
                }
                else if (multiTid && compressedBitmap) {
                    throw cRuntimeError("Ieee80211Serializer: cannot serialize the frame, Ieee80211MultiTidBlockAckReq unimplemented.");
                }
                else
                    throw cRuntimeError("Ieee80211Serializer: cannot serialize the frame, multiTid = 1 && compressedBitmap = 0 is reserved.");
                break;
            }
            case ST_BLOCKACK: {
                auto blockAck = dynamicPtrCast<const Ieee80211BlockAck>(chunk);
                stream.writeUint16Be(blockAck->getDurationField().inUnit(SIMTIME_US));
                stream.writeMacAddress(blockAck->getReceiverAddress());
                stream.writeMacAddress(blockAck->getTransmitterAddress());
                stream.writeBit(blockAck->getBlockAckPolicy());
                bool multiTid = blockAck->getMultiTid();
                bool compressedBitmap = blockAck->getCompressedBitmap();
                stream.writeBit(multiTid);
                stream.writeBit(compressedBitmap);
                stream.writeNBitsOfUint64Be(blockAck->getReserved(), 9);
                if (!multiTid && !compressedBitmap) {
                    auto basicBlockAck = dynamicPtrCast<const Ieee80211BasicBlockAck>(chunk);
                    stream.writeNBitsOfUint64Be(basicBlockAck->getTidInfo(), 4);
                    stream.writeUint16Be(basicBlockAck->getStartingSequenceNumber().getRaw());
                    for (size_t i = 0; i < 64; ++i) {
                        stream.writeByte(basicBlockAck->getBlockAckBitmap(i).getBytes()[0]);
                        stream.writeByte(basicBlockAck->getBlockAckBitmap(i).getBytes()[1]);
                    }
                }
                else if (!multiTid && compressedBitmap) {
                    auto compressedBlockAck = dynamicPtrCast<const Ieee80211CompressedBlockAck>(chunk);
                    stream.writeNBitsOfUint64Be(compressedBlockAck->getTidInfo(), 4);
                    stream.writeUint16Be(compressedBlockAck->getStartingSequenceNumber().getRaw());
                    for (size_t i = 0; i < 8; ++i) {
                        stream.writeByte(compressedBlockAck->getBlockAckBitmap().getBytes()[i]);
                    }
                }
                else if (multiTid && compressedBitmap) {
                    throw cRuntimeError("Ieee80211Serializer: cannot serialize the frame, Ieee80211MultiTidBlockAck unimplemented.");
                }
                else {
                    throw cRuntimeError("Ieee80211Serializer: cannot serialize the frame, multiTid = 1 && compressedBitmap = 0 is reserved.");
                }
                break;

            }
            case ST_DATA_WITH_QOS:
            case ST_DATA: {
                auto dataHeader = dynamicPtrCast<const Ieee80211DataHeader>(chunk);
                stream.writeUint16Be(dataHeader->getDurationField().inUnit(SIMTIME_US));
                stream.writeMacAddress(dataHeader->getReceiverAddress());
                stream.writeMacAddress(dataHeader->getTransmitterAddress());
                stream.writeMacAddress(dataHeader->getAddress3());
                stream.writeNBitsOfUint64Be(dataHeader->getSequenceNumber().getRaw(), 4);
                stream.writeNBitsOfUint64Be(dataHeader->getFragmentNumber(), 12);
                if (dataHeader->getFromDS() && dataHeader->getToDS())
                    stream.writeMacAddress(dataHeader->getAddress4());
                if (type == ST_DATA_WITH_QOS) {
                    stream.writeNBitsOfUint64Be(dataHeader->getTid(), 4);
                    stream.writeBit(true);
                    stream.writeNBitsOfUint64Be(dataHeader->getAckPolicy(), 2);
                    stream.writeBit(dataHeader->getAMsduPresent());
                }
                break;
            }
            case ST_PSPOLL:
            case ST_LBMS_REQUEST:
            case ST_LBMS_REPORT: {
                break;
            }
            default:
                throw cRuntimeError("Ieee80211Serializer: cannot serialize the frame, type %d not supported.", type);
        }
    }
}

const Ptr<Chunk> Ieee80211MacHeaderSerializer::deserialize(MemoryInputStream& stream) const
{
    if (B(stream.getRemainingLength()) == B(14)) {
        auto msduSubframe = makeShared<Ieee80211MsduSubframeHeader>();
        msduSubframe->setDa(stream.readMacAddress());
        msduSubframe->setSa(stream.readMacAddress());
        msduSubframe->setLength(stream.readUint16Be());
        return msduSubframe;
    }
    else if (B(stream.getRemainingLength()) == B(4))
    {
        auto mpduSubframe = makeShared<Ieee80211MpduSubframeHeader>();
        stream.readUint4();
        mpduSubframe->setLength(stream.readUint4() >> 8);
        mpduSubframe->setLength(stream.readUint8());
        stream.readByte();
        stream.readByte();
        return mpduSubframe;
    }
    else {
        auto macHeader = makeShared<Ieee80211MacHeader>();
        uint8_t subType = stream.readNBitsToUint64Be(4);
        uint8_t frameType = stream.readNBitsToUint64Be(2);
        uint8_t protocolVersion = stream.readNBitsToUint64Be(2);
        macHeader->setType(protocolVersion, frameType, subType);
        bool order = stream.readBit();
        bool protectedFrame = stream.readBit();
        bool moreData = stream.readBit();
        bool powerMgmt = stream.readBit();
        bool retry = stream.readBit();
        bool moreFragments = stream.readBit();
        bool fromDS = stream.readBit();
        bool toDS = stream.readBit();
        Ieee80211FrameType type = macHeader->getType();
        switch (type) {
            case ST_ASSOCIATIONREQUEST:
            case ST_ASSOCIATIONRESPONSE:
            case ST_REASSOCIATIONREQUEST:
            case ST_REASSOCIATIONRESPONSE:
            case ST_PROBEREQUEST:
            case ST_PROBERESPONSE:
            case ST_BEACON:
            case ST_ATIM:
            case ST_DISASSOCIATION:
            case ST_AUTHENTICATION:
            case ST_DEAUTHENTICATION:
            case ST_NOACKACTION: {
                auto mgmtHeader = makeShared<Ieee80211MgmtHeader>();
                mgmtHeader->setType(type);
                mgmtHeader->setOrder(order);
                mgmtHeader->setProtectedFrame(protectedFrame);
                mgmtHeader->setMoreData(moreData);
                mgmtHeader->setPowerMgmt(powerMgmt);
                mgmtHeader->setRetry(retry);
                mgmtHeader->setMoreFragments(moreFragments);
                mgmtHeader->setFromDS(fromDS);
                mgmtHeader->setToDS(toDS);
                mgmtHeader->setDurationField(SimTime(stream.readUint16Be(), SIMTIME_US));
                mgmtHeader->setReceiverAddress(stream.readMacAddress());
                mgmtHeader->setTransmitterAddress(stream.readMacAddress());
                mgmtHeader->setAddress3(stream.readMacAddress());
                mgmtHeader->setSequenceNumber(SequenceNumber(stream.readNBitsToUint64Be(4)));
                mgmtHeader->setFragmentNumber(stream.readNBitsToUint64Be(12));
                return mgmtHeader;
            }
            case ST_ACTION: {
                auto actionFrame = makeShared<Ieee80211ActionFrame>();
                actionFrame->setType(type);
                actionFrame->setOrder(order);
                actionFrame->setProtectedFrame(protectedFrame);
                actionFrame->setMoreData(moreData);
                actionFrame->setPowerMgmt(powerMgmt);
                actionFrame->setRetry(retry);
                actionFrame->setMoreFragments(moreFragments);
                actionFrame->setFromDS(fromDS);
                actionFrame->setToDS(toDS);
                actionFrame->setDurationField(SimTime(stream.readUint16Be(), SIMTIME_US));
                actionFrame->setReceiverAddress(stream.readMacAddress());
                actionFrame->setTransmitterAddress(stream.readMacAddress());
                actionFrame->setAddress3(stream.readMacAddress());
                actionFrame->setSequenceNumber(SequenceNumber(stream.readNBitsToUint64Be(4)));
                actionFrame->setFragmentNumber(stream.readNBitsToUint64Be(12));
                actionFrame->setCategory(stream.readByte());
                switch (actionFrame->getCategory()) {
                    case 1: {
                        actionFrame->markIncorrect();
                        return actionFrame;
                    }
                    case 2: {
                        actionFrame->markIncorrect();
                        return actionFrame;
                    }
                    case 3: {
                        uint8_t blockAckAction = stream.readByte();
                        switch (blockAckAction) {
                        case 0: {
                            auto addbaRequest = makeShared<Ieee80211AddbaRequest>();
                            addbaRequest->setType(type);
                            addbaRequest->setOrder(order);
                            addbaRequest->setProtectedFrame(protectedFrame);
                            addbaRequest->setMoreData(moreData);
                            addbaRequest->setPowerMgmt(powerMgmt);
                            addbaRequest->setRetry(retry);
                            addbaRequest->setMoreFragments(moreFragments);
                            addbaRequest->setFromDS(fromDS);
                            addbaRequest->setToDS(toDS);
                            addbaRequest->setDurationField(actionFrame->getDurationField());
                            addbaRequest->setReceiverAddress(actionFrame->getReceiverAddress());
                            addbaRequest->setTransmitterAddress(actionFrame->getTransmitterAddress());
                            addbaRequest->setAddress3(actionFrame->getAddress3());
                            addbaRequest->setSequenceNumber(actionFrame->getSequenceNumber());
                            addbaRequest->setFragmentNumber(actionFrame->getFragmentNumber());
                            addbaRequest->setCategory(actionFrame->getCategory());
                            addbaRequest->setBlockAckAction(blockAckAction);

                            addbaRequest->setDialogToken(stream.readByte());
                            addbaRequest->setAMsduSupported(stream.readBit());
                            addbaRequest->setBlockAckPolicy(stream.readBit());
                            addbaRequest->setTid(stream.readNBitsToUint64Be(4));
                            addbaRequest->setBufferSize(stream.readNBitsToUint64Be(10));
                            addbaRequest->setBlockAckTimeoutValue(SimTime(stream.readUint16Be() * 1024, SIMTIME_US));
                            addbaRequest->set_fragmentNumber(stream.readNBitsToUint64Be(4));
                            addbaRequest->setSequenceNumber(SequenceNumber(stream.readNBitsToUint64Be(12)));
                            return addbaRequest;
                        }
                        case 1: {
                            auto addbaResponse = makeShared<Ieee80211AddbaResponse>();
                            addbaResponse->setType(type);
                            addbaResponse->setOrder(order);
                            addbaResponse->setProtectedFrame(protectedFrame);
                            addbaResponse->setMoreData(moreData);
                            addbaResponse->setPowerMgmt(powerMgmt);
                            addbaResponse->setRetry(retry);
                            addbaResponse->setMoreFragments(moreFragments);
                            addbaResponse->setFromDS(fromDS);
                            addbaResponse->setToDS(toDS);
                            addbaResponse->setDurationField(actionFrame->getDurationField());
                            addbaResponse->setReceiverAddress(actionFrame->getReceiverAddress());
                            addbaResponse->setTransmitterAddress(actionFrame->getTransmitterAddress());
                            addbaResponse->setAddress3(actionFrame->getAddress3());
                            addbaResponse->setSequenceNumber(actionFrame->getSequenceNumber());
                            addbaResponse->setFragmentNumber(actionFrame->getFragmentNumber());
                            addbaResponse->setCategory(actionFrame->getCategory());
                            addbaResponse->setBlockAckAction(blockAckAction);

                            addbaResponse->setDialogToken(stream.readByte());
                            addbaResponse->setStatusCode(stream.readUint16Be());
                            addbaResponse->setAMsduSupported(stream.readBit());
                            addbaResponse->setBlockAckPolicy(stream.readBit());
                            addbaResponse->setTid(stream.readNBitsToUint64Be(4));
                            addbaResponse->setBufferSize(stream.readNBitsToUint64Be(10));
                            addbaResponse->setBlockAckTimeoutValue(SimTime(stream.readUint16Be() * 1024, SIMTIME_US));
                            return addbaResponse;
                        }
                        case 2: {
                            auto delba = makeShared<Ieee80211Delba>();
                            delba->setType(type);
                            delba->setOrder(order);
                            delba->setProtectedFrame(protectedFrame);
                            delba->setMoreData(moreData);
                            delba->setPowerMgmt(powerMgmt);
                            delba->setRetry(retry);
                            delba->setMoreFragments(moreFragments);
                            delba->setFromDS(fromDS);
                            delba->setToDS(toDS);
                            delba->setDurationField(actionFrame->getDurationField());
                            delba->setReceiverAddress(actionFrame->getReceiverAddress());
                            delba->setTransmitterAddress(actionFrame->getTransmitterAddress());
                            delba->setAddress3(actionFrame->getAddress3());
                            delba->setSequenceNumber(actionFrame->getSequenceNumber());
                            delba->setFragmentNumber(actionFrame->getFragmentNumber());
                            delba->setCategory(actionFrame->getCategory());
                            delba->setBlockAckAction(blockAckAction);

                            delba->setReserved(stream.readNBitsToUint64Be(11));
                            delba->setInitiator(stream.readBit());
                            delba->setTid(stream.readNBitsToUint64Be(4));
                            delba->setReasonCode(stream.readUint16Be());
                            return delba;
                        }
                        default:
                            actionFrame->markIncorrect();
                            return actionFrame;
                        }
                        break;
                    }
                }
                break;
            }
            case ST_RTS: {
                auto rtsFrame = makeShared<Ieee80211RtsFrame>();
                rtsFrame->setType(type);
                rtsFrame->setOrder(order);
                rtsFrame->setProtectedFrame(protectedFrame);
                rtsFrame->setMoreData(moreData);
                rtsFrame->setPowerMgmt(powerMgmt);
                rtsFrame->setRetry(retry);
                rtsFrame->setMoreFragments(moreFragments);
                rtsFrame->setFromDS(fromDS);
                rtsFrame->setToDS(toDS);
                rtsFrame->setDurationField(SimTime(stream.readUint16Be(), SIMTIME_US));
                rtsFrame->setReceiverAddress(stream.readMacAddress());
                rtsFrame->setTransmitterAddress(stream.readMacAddress());
                return rtsFrame;
            }
            case ST_CTS: {
                auto ctsFrame = makeShared<Ieee80211CtsFrame>();
                ctsFrame->setType(type);
                ctsFrame->setOrder(order);
                ctsFrame->setProtectedFrame(protectedFrame);
                ctsFrame->setMoreData(moreData);
                ctsFrame->setPowerMgmt(powerMgmt);
                ctsFrame->setRetry(retry);
                ctsFrame->setMoreFragments(moreFragments);
                ctsFrame->setFromDS(fromDS);
                ctsFrame->setToDS(toDS);
                ctsFrame->setDurationField(SimTime(stream.readUint16Be(), SIMTIME_US));
                ctsFrame->setReceiverAddress(stream.readMacAddress());
                return ctsFrame;
            }
            case ST_ACK: {
                auto ackFrame = makeShared<Ieee80211AckFrame>();
                ackFrame->setType(type);
                ackFrame->setOrder(order);
                ackFrame->setProtectedFrame(protectedFrame);
                ackFrame->setMoreData(moreData);
                ackFrame->setPowerMgmt(powerMgmt);
                ackFrame->setRetry(retry);
                ackFrame->setMoreFragments(moreFragments);
                ackFrame->setFromDS(fromDS);
                ackFrame->setToDS(toDS);
                ackFrame->setDurationField(SimTime(stream.readUint16Be(), SIMTIME_US));
                ackFrame->setReceiverAddress(stream.readMacAddress());
                return ackFrame;
            }
            case ST_BLOCKACK_REQ: {
                auto blockAckReq = makeShared<Ieee80211BlockAckReq>();
                blockAckReq->setType(type);
                blockAckReq->setOrder(order);
                blockAckReq->setProtectedFrame(protectedFrame);
                blockAckReq->setMoreData(moreData);
                blockAckReq->setPowerMgmt(powerMgmt);
                blockAckReq->setRetry(retry);
                blockAckReq->setMoreFragments(moreFragments);
                blockAckReq->setFromDS(fromDS);
                blockAckReq->setToDS(toDS);
                blockAckReq->setDurationField(SimTime(stream.readUint16Be(), SIMTIME_US));
                blockAckReq->setReceiverAddress(stream.readMacAddress());
                blockAckReq->setTransmitterAddress(stream.readMacAddress());
                blockAckReq->setBarAckPolicy(stream.readBit());
                bool multiTid = stream.readBit();
                bool compressedBitmap = stream.readBit();
                blockAckReq->setMultiTid(multiTid);
                blockAckReq->setCompressedBitmap(compressedBitmap);
                blockAckReq->setReserved(stream.readNBitsToUint64Be(9));
                if (!multiTid && !compressedBitmap) {
                    auto basicBlockAckReq = makeShared<Ieee80211BasicBlockAckReq>();
                    basicBlockAckReq->setType(type);
                    basicBlockAckReq->setOrder(order);
                    basicBlockAckReq->setProtectedFrame(protectedFrame);
                    basicBlockAckReq->setMoreData(moreData);
                    basicBlockAckReq->setPowerMgmt(powerMgmt);
                    basicBlockAckReq->setRetry(retry);
                    basicBlockAckReq->setMoreFragments(moreFragments);
                    basicBlockAckReq->setFromDS(fromDS);
                    basicBlockAckReq->setToDS(toDS);
                    basicBlockAckReq->setDurationField(blockAckReq->getDurationField());
                    basicBlockAckReq->setReceiverAddress(blockAckReq->getReceiverAddress());
                    basicBlockAckReq->setTransmitterAddress(blockAckReq->getTransmitterAddress());
                    basicBlockAckReq->setBarAckPolicy(blockAckReq->getBarAckPolicy());
                    basicBlockAckReq->setMultiTid(multiTid);
                    basicBlockAckReq->setCompressedBitmap(compressedBitmap);
                    basicBlockAckReq->setReserved(blockAckReq->getReserved());

                    basicBlockAckReq->setTidInfo(stream.readNBitsToUint64Be(4));
                    basicBlockAckReq->setFragmentNumber(stream.readUint32Be());
                    stream.readUint64Be();
                    basicBlockAckReq->setStartingSequenceNumber(SequenceNumber(stream.readUint64Be()));
                    return basicBlockAckReq;
                }
                else if (!multiTid && compressedBitmap) {
                    auto compressedBlockAckReq = makeShared<Ieee80211CompressedBlockAckReq>();
                    compressedBlockAckReq->setType(type);
                    compressedBlockAckReq->setOrder(order);
                    compressedBlockAckReq->setProtectedFrame(protectedFrame);
                    compressedBlockAckReq->setMoreData(moreData);
                    compressedBlockAckReq->setPowerMgmt(powerMgmt);
                    compressedBlockAckReq->setRetry(retry);
                    compressedBlockAckReq->setMoreFragments(moreFragments);
                    compressedBlockAckReq->setFromDS(fromDS);
                    compressedBlockAckReq->setToDS(toDS);
                    compressedBlockAckReq->setDurationField(blockAckReq->getDurationField());
                    compressedBlockAckReq->setReceiverAddress(blockAckReq->getReceiverAddress());
                    compressedBlockAckReq->setTransmitterAddress(blockAckReq->getTransmitterAddress());
                    compressedBlockAckReq->setBarAckPolicy(blockAckReq->getBarAckPolicy());
                    compressedBlockAckReq->setMultiTid(multiTid);
                    compressedBlockAckReq->setCompressedBitmap(compressedBitmap);
                    compressedBlockAckReq->setReserved(blockAckReq->getReserved());

                    compressedBlockAckReq->setTidInfo(stream.readNBitsToUint64Be(4));
                    compressedBlockAckReq->setFragmentNumber(stream.readUint32Be());
                    stream.readUint64Be();
                    compressedBlockAckReq->setStartingSequenceNumber(SequenceNumber(stream.readUint64Be()));
                    return compressedBlockAckReq;
                }
                else
                    blockAckReq->markIncorrect();
                return blockAckReq;
                break;
            }
            case ST_BLOCKACK: {
                auto blockAck = makeShared<Ieee80211BlockAck>();
                blockAck->setType(type);
                blockAck->setOrder(order);
                blockAck->setProtectedFrame(protectedFrame);
                blockAck->setMoreData(moreData);
                blockAck->setPowerMgmt(powerMgmt);
                blockAck->setRetry(retry);
                blockAck->setMoreFragments(moreFragments);
                blockAck->setFromDS(fromDS);
                blockAck->setToDS(toDS);
                blockAck->setDurationField(SimTime(stream.readUint16Be(), SIMTIME_US));
                blockAck->setReceiverAddress(stream.readMacAddress());
                blockAck->setTransmitterAddress(stream.readMacAddress());
                blockAck->setBlockAckPolicy(stream.readBit());
                bool multiTid = stream.readBit();
                bool compressedBitmap = stream.readBit();
                blockAck->setMultiTid(multiTid);
                blockAck->setCompressedBitmap(compressedBitmap);
                blockAck->setReserved(stream.readNBitsToUint64Be(9));
                if (!multiTid && !compressedBitmap) {
                    auto basicBlockAck = makeShared<Ieee80211BasicBlockAck>();
                    basicBlockAck->setType(type);
                    basicBlockAck->setOrder(order);
                    basicBlockAck->setProtectedFrame(protectedFrame);
                    basicBlockAck->setMoreData(moreData);
                    basicBlockAck->setPowerMgmt(powerMgmt);
                    basicBlockAck->setRetry(retry);
                    basicBlockAck->setMoreFragments(moreFragments);
                    basicBlockAck->setFromDS(fromDS);
                    basicBlockAck->setToDS(toDS);
                    basicBlockAck->setDurationField(blockAck->getDurationField());
                    basicBlockAck->setReceiverAddress(blockAck->getReceiverAddress());
                    basicBlockAck->setTransmitterAddress(blockAck->getTransmitterAddress());
                    basicBlockAck->setBlockAckPolicy(blockAck->getBlockAckPolicy());
                    basicBlockAck->setMultiTid(multiTid);
                    basicBlockAck->setCompressedBitmap(compressedBitmap);
                    basicBlockAck->setReserved(blockAck->getReserved());

                    basicBlockAck->setTidInfo(stream.readNBitsToUint64Be(4));
                    basicBlockAck->setStartingSequenceNumber(SequenceNumber(stream.readUint16Be()));
                    for (size_t i = 0; i < 64; ++i) {
                        std::vector<uint8_t> bytes;
                        bytes.push_back(stream.readByte());
                        bytes.push_back(stream.readByte());
                        BitVector* blockAckBitmap = new BitVector(bytes);
                        basicBlockAck->setBlockAckBitmap(i, *blockAckBitmap);
                    }
                    return basicBlockAck;
                }
                else if (!multiTid && compressedBitmap) {
                    auto compressedBlockAck = makeShared<Ieee80211CompressedBlockAck>();
                    compressedBlockAck->setType(type);
                    compressedBlockAck->setOrder(order);
                    compressedBlockAck->setProtectedFrame(protectedFrame);
                    compressedBlockAck->setMoreData(moreData);
                    compressedBlockAck->setPowerMgmt(powerMgmt);
                    compressedBlockAck->setRetry(retry);
                    compressedBlockAck->setMoreFragments(moreFragments);
                    compressedBlockAck->setFromDS(fromDS);
                    compressedBlockAck->setToDS(toDS);
                    compressedBlockAck->setDurationField(blockAck->getDurationField());
                    compressedBlockAck->setReceiverAddress(blockAck->getReceiverAddress());
                    compressedBlockAck->setTransmitterAddress(blockAck->getTransmitterAddress());
                    compressedBlockAck->setBlockAckPolicy(blockAck->getBlockAckPolicy());
                    compressedBlockAck->setMultiTid(multiTid);
                    compressedBlockAck->setCompressedBitmap(compressedBitmap);
                    compressedBlockAck->setReserved(blockAck->getReserved());

                    compressedBlockAck->setTidInfo(stream.readNBitsToUint64Be(4));
                    compressedBlockAck->setStartingSequenceNumber(SequenceNumber(stream.readUint16Be()));
                    std::vector<uint8_t> bytes;
                    for (size_t i = 0; i < 8; ++i) {
                        bytes.push_back(stream.readByte());
                    }
                    compressedBlockAck->setBlockAckBitmap(*(new BitVector(bytes)));
                    return compressedBlockAck;
                }
                else {
                    blockAck->markIncorrect();
                    return blockAck;
                }
                break;

            }
            case ST_DATA_WITH_QOS:
            case ST_DATA: {
                auto dataHeader = makeShared<Ieee80211DataHeader>();
                dataHeader->setType(type);
                dataHeader->setOrder(order);
                dataHeader->setProtectedFrame(protectedFrame);
                dataHeader->setMoreData(moreData);
                dataHeader->setPowerMgmt(powerMgmt);
                dataHeader->setRetry(retry);
                dataHeader->setMoreFragments(moreFragments);
                dataHeader->setFromDS(fromDS);
                dataHeader->setToDS(toDS);
                dataHeader->setDurationField(SimTime(stream.readUint16Be(), SIMTIME_US));
                dataHeader->setReceiverAddress(stream.readMacAddress());
                dataHeader->setTransmitterAddress(stream.readMacAddress());
                dataHeader->setAddress3(stream.readMacAddress());
                dataHeader->setSequenceNumber(SequenceNumber(stream.readNBitsToUint64Be(4)));
                dataHeader->setFragmentNumber(stream.readNBitsToUint64Be(12));
                if (dataHeader->getFromDS() && dataHeader->getToDS())
                    dataHeader->setAddress4(stream.readMacAddress());
                if (type == ST_DATA_WITH_QOS) {
                    dataHeader->setTid(stream.readNBitsToUint64Be(4));
                    stream.readBit();
                    dataHeader->setAckPolicy(static_cast<AckPolicy>(stream.readNBitsToUint64Be(2)));
                    dataHeader->setAMsduPresent(stream.readBit());
                }
                return dataHeader;
            }
            case ST_PSPOLL:
            case ST_LBMS_REQUEST:
            case ST_LBMS_REPORT: {
                return macHeader;
            }
            default: {
                macHeader->markIncorrect();
                return macHeader;
            }
        }
    }
}

void Ieee80211MacTrailerSerializer::serialize(MemoryOutputStream& stream, const Ptr<const Chunk>& chunk) const
{
    const auto& macTrailer = dynamicPtrCast<const Ieee80211MacTrailer>(chunk);
    auto fcsMode = macTrailer->getFcsMode();
    if (fcsMode != FCS_COMPUTED)
        throw cRuntimeError("Cannot serialize Ieee80211FcsTrailer without properly computed FCS, try changing the value of the fcsMode parameter (e.g. in the Ieee80211Mac module)");
    stream.writeUint32Be(macTrailer->getFcs());
}

const Ptr<Chunk> Ieee80211MacTrailerSerializer::deserialize(MemoryInputStream& stream) const
{
    auto macTrailer = makeShared<Ieee80211MacTrailer>();
    auto fcs = stream.readUint32Be();
    macTrailer->setFcs(fcs);
    macTrailer->setFcsMode(FCS_COMPUTED);
    return macTrailer;
}

} // namespace ieee80211

} // namespace inet

