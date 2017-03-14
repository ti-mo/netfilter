package netfilter

import (
	"github.com/mdlayher/netlink"
	"fmt"
	"log"
)

// Get the Netfilter Subsystem ID from the Netlink header type
// This determines which Netfilter family the Netlink message belongs to
// All Netfilter types are defined in Linux/include/uapi/linux/netfilter/nfnetlink.h,
// along with the definitions of their respective transformations (NFNL_SUBSYS_ID, NFNL_MSG_TYPE)
func getSubsystemID(nlht NetlinkType) SubsystemID {
	return SubsystemID(uint16(nlht) & 0xff00 >> 8)
}

// Get the Netfilter Message Type from the Netlink header type
// The MessageType is used in combination with netlink.HeaderFlags
// to obtain information about the payload contained in the message.
func getMessageType(nlht NetlinkType) MessageType {
	return MessageType(uint16(nlht) & 0x00ff)
}

// Extract Netfilter-specific information from the Netlink NetlinkType
// Parses netlink.HeaderType into SubsystemID and MessageType
func ParseNetlinkHeaderType(nlht netlink.HeaderType) (SubsystemID, MessageType) {
	// Convert the netlink.NetlinkType into our netfilter.NetlinkType (different String())
	return getSubsystemID(NetlinkType(nlht)), getMessageType(NetlinkType(nlht))
}

// The Netlink header type is subtyped here because Netfilter splits this field in two: SubsystemID and Message Type
type NetlinkType netlink.HeaderType

// Parse the SubsystemID and Message Type to give correct
// string representation of the Header Type in Netfilter context
func (ht NetlinkType) String() string {
	return fmt.Sprintf("%s|%d", getSubsystemID(ht), getMessageType(ht))
}

// Given a Netlink message payload, instantiate and return a Netfilter header
// The header is in the first 4 bytes of the Netlink payload
func DecodeHeader(nlMsg netlink.Message) Header {
	var hdr Header

	err := hdr.UnmarshalBinary(nlMsg.Data[0:4])
	if err != nil {
		log.Fatalf("failed to decode netlink message into netfilter header: %v", err)
	}

	return hdr
}
