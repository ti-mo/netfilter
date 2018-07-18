package netfilter

import (
	"fmt"

	"github.com/mdlayher/netlink"
)

// HeaderType is a field found in the Netlink header, but Netfilter subsystems divide
// this uint16 into two bytes: the most significant byte is the subsystem ID and the
// least significant is the message type.
//
// The significance of the MessageType field is fully dependent on the subsystem
// the message is for. This package only splits the field into two bytes and provides
// a list of known SubsystemIDs. Subpackages (for subsystems like Conntrack) then make
// further use of the MessageType fields to interpret messages accordingly.
type HeaderType struct {
	SubsystemID SubsystemID
	MessageType MessageType
}

// UnmarshalNetlinkHeaderType unmarshals a netlink.HeaderType into a netfilter.HeaderType.
// The most significant byte is the subsystem ID and the least significant is the message type.
func UnmarshalNetlinkHeaderType(nlht netlink.HeaderType) HeaderType {
	ht := HeaderType{
		SubsystemID: SubsystemID(uint16(nlht) & 0xff00 >> 8),
		MessageType: MessageType(uint16(nlht) & 0x00ff),
	}

	return ht
}

// MarshalNetlinkHeaderType marshals a netfilter.HeaderType into a netlink.HeaderType.
// It joins the SubsystemID and MessageType fields back together into a uint16 to be placed
// into the Netlink header.
func MarshalNetlinkHeaderType(ht HeaderType) netlink.HeaderType {
	return netlink.HeaderType(uint16(ht.SubsystemID)<<8 | uint16(ht.MessageType))
}

// String representation of the HeaderType in Netfilter context, for debugging purposes.
func (ht HeaderType) String() string {
	return fmt.Sprintf("%s|%d", ht.SubsystemID, ht.MessageType)
}

// UnmarshalMessage unmarshals the first 4 bytes of a netlink.Message into a netfilter.Header.
// It safely calls Header.UnmarshalBinary with the correct offset on the Netlink message's Data field.
func (h *Header) UnmarshalMessage(msg netlink.Message) error {

	err := h.UnmarshalBinary(msg.Data[:nfHeaderLen])
	if err != nil {
		return err
	}

	return nil
}

// MarshalMessage safely marshals a netfilter.Header into the correct offset of a netlink.Message's Data field.
func (h *Header) MarshalMessage(msg *netlink.Message) error {

	hb, err := h.MarshalBinary()
	if err != nil {
		return err
	}

	copy(msg.Data[:nfHeaderLen], hb)

	return nil
}
