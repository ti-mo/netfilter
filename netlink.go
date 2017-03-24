package netfilter

import (
	"github.com/mdlayher/netlink"
	"fmt"
)

// The Netlink header type is subtyped here because Netfilter splits this field in two:
// SubsystemID and Message Type
type HeaderType struct {
	MessageType MessageType
	SubsystemID SubsystemID
}

// An Attribute is a netlink.Attribute that can be nested.
type Attribute struct {
	netlink.Attribute
	Children []Attribute
}

// UnmarshalNetlink unmarshals a netlink.HeaderType into a netfilter.HeaderType
func (ht *HeaderType) UnmarshalNetlink(nlht netlink.HeaderType) error {
	ht.SubsystemID = SubsystemID(uint16(nlht) & 0xff00 >> 8)
	ht.MessageType = MessageType(uint16(nlht) & 0x00ff)

	return nil
}

// MarshalNetlink marshals a netfilter.HeaderType into a netlink.HeaderType
func (ht HeaderType) MarshalNetlink(nlht *netlink.HeaderType) error {
	*nlht = netlink.HeaderType(uint16(ht.SubsystemID) << 8 | uint16(ht.MessageType))

	return nil
}

// Parse the SubsystemID and Message Type to give correct
// string representation of the Header Type in Netfilter context
func (ht HeaderType) String() string {
	return fmt.Sprintf("%s|%d", ht.SubsystemID, ht.MessageType)
}

// UnmarshalMessage unmarshals a netlink.Message into a netfilter.Header
func (h *Header) UnmarshalMessage(msg netlink.Message) error {

	err := h.UnmarshalBinary(msg.Data[:nfHeaderLen])
	if err != nil {
		return err
	}

	return nil
}

// MarshalMessage marshals a nefilter.Header into a netlink.Message's Data attribute
func (h Header) MarshalMessage(msg *netlink.Message) error {
	hb, err := h.MarshalBinary()
	if err != nil {
		return err
	}

	copy(msg.Data[:nfHeaderLen], hb)

	return nil
}

// UnmarshalAttributes unmarshals a netlink.Attribute's binary contents into
// a nested structure of netfilter.Attributes.
func UnmarshalAttributes(b []byte) ([]Attribute, error) {

	var ra []Attribute

	attrs, err := netlink.UnmarshalAttributes(b)
	if err != nil {
		return nil, err
	}

	for _, nla := range attrs {
		// Wrap a netlink.Attribute into a netfilter.Attribute
		nfa := Attribute{Attribute: nla}

		if nla.Nested {
			// Recursive Unmarshal
			nfattrs, err := UnmarshalAttributes(nla.Data); if err != nil {
				return nil, err
			}

			nfa.Children = nfattrs
		}

		ra = append(ra, nfa)
	}

	return ra, nil
}

// MarshalAttributes marshals a nested attribute structure
// into its binary representation.
func MarshalAttributes(attrs []Attribute) ([]byte, error) {

	var rb []byte

	for _, nfa := range attrs {
		if nfa.Nested {
			// Recursive Marshal
			nfnab, err := MarshalAttributes(nfa.Children)
			if err != nil {
				return nil, err
			}

			nfa.Data = append(nfa.Data, nfnab...)
		}

		nfab, err := nfa.MarshalBinary()
		if err != nil {
			return nil, err
		}

		rb = append(rb, nfab...)
	}

	return rb, nil
}
