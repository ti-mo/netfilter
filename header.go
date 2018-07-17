package netfilter

import (
	"fmt"

	"github.com/mdlayher/netlink"
)

// HeaderType is a Netfilter-specific representation of a Netlink header.
// Netfilter splits this field in two; Subsystem ID and Message Type.
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
func MarshalNetlinkHeaderType(ht HeaderType) netlink.HeaderType {
	return netlink.HeaderType(uint16(ht.SubsystemID)<<8 | uint16(ht.MessageType))
}

// Parse the SubsystemID and Message Type to give correct
// string representation of the Header Type in Netfilter context.
func (ht HeaderType) String() string {
	return fmt.Sprintf("%s|%d", ht.SubsystemID, ht.MessageType)
}

// UnmarshalMessage unmarshals the first 4 bytes of a netlink.Message into a netfilter.Header.
func (h *Header) UnmarshalMessage(msg netlink.Message) error {
	err := h.UnmarshalBinary(msg.Data[:nfHeaderLen])
	if err != nil {
		return err
	}

	return nil
}

// MarshalMessage marshals a nefilter.Header into the first 4 bytes of a netlink.Message's Data attribute.
func (h Header) MarshalMessage(msg *netlink.Message) error {
	hb, err := h.MarshalBinary()
	if err != nil {
		return err
	}

	copy(msg.Data[:nfHeaderLen], hb)

	return nil
}
