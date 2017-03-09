package netfilter

import (
	"github.com/mdlayher/netlink"
	"fmt"
)

// Get the Netfilter Subsystem ID from the Netlink header type
// This determines which Netfilter family the Netlink message belongs to
// All Netfilter types are defined in Linux/include/uapi/linux/netfilter/nfnetlink.h,
// along with the definitions of their respective transformations (NFNL_SUBSYS_ID, NFNL_MSG_TYPE)
func getSubsystemID(nlht HeaderType) SubsystemID {
	return SubsystemID(uint16(nlht) & 0xff00 >> 8)
}

// Get the Netfilter Message Type from the Netlink header type
// The MessageType is used in combination with netlink.HeaderFlags
// to obtain information about the payload contained in the message.
func getMessageType(nlht HeaderType) MessageType {
	return MessageType(uint16(nlht) & 0x00ff)
}

// Extract Netfilter-specific information from the Netlink HeaderType
// Parses netlink.HeaderType into SubsystemID and MessageType
func ParseHeaderType(nlht netlink.HeaderType) (SubsystemID, MessageType) {
	// Convert the netlink.HeaderType into our netfilter.HeaderType (different String())
	return getSubsystemID(HeaderType(nlht)), getMessageType(HeaderType(nlht))
}

// The Netlink header type is subtyped here because Netfilter splits this field in two: SubsystemID and Message Type
type HeaderType netlink.HeaderType

// Parse the SubsystemID and Message Type to give correct
// string representation of the Header Type in Netfilter context
func (ht HeaderType) String() string {
	return fmt.Sprintf("%s|%d", getSubsystemID(ht), getMessageType(ht))
}
