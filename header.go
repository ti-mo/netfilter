package netfilter

import (
	"github.com/mdlayher/netlink"
	"fmt"
)

// The Netlink header type is subtyped here because Netfilter splits this field in two:
// SubsystemID and Message Type.
type HeaderType struct {
	SubsystemID SubsystemID
	MessageType MessageType
}

// UnmarshalNetlink unmarshals a netlink.HeaderType into a netfilter.HeaderType.
func UnmarshalNetlinkHeaderType(nlht netlink.HeaderType) HeaderType {
	ht := HeaderType{
		SubsystemID: SubsystemID(uint16(nlht) & 0xff00 >> 8),
		MessageType: MessageType(uint16(nlht) & 0x00ff),
	}

	return ht
}

// MarshalNetlink marshals a netfilter.HeaderType into a netlink.HeaderType.
func MarshalNetlinkHeaderType(ht HeaderType) netlink.HeaderType {
	return netlink.HeaderType(uint16(ht.SubsystemID) << 8 | uint16(ht.MessageType))
}

// Parse the SubsystemID and Message Type to give correct
// string representation of the Header Type in Netfilter context.
func (ht HeaderType) String() string {
	return fmt.Sprintf("%s|%d", ht.SubsystemID, ht.MessageType)
}

// UnmarshalMessage unmarshals a netlink.Message into a netfilter.Header.
func (h *Header) UnmarshalMessage(msg netlink.Message) error {
	err := h.UnmarshalBinary(msg.Data[:nfHeaderLen])
	if err != nil {
		return err
	}

	return nil
}

// MarshalMessage marshals a nefilter.Header into a netlink.Message's Data attribute.
func (h Header) MarshalMessage(msg *netlink.Message) error {
	hb, err := h.MarshalBinary()
	if err != nil {
		return err
	}

	copy(msg.Data[:nfHeaderLen], hb)

	return nil
}
