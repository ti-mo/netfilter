package netfilter

import (
	"github.com/mdlayher/netlink"
	"fmt"
)

// An Attribute is a netlink.Attribute that can be nested.
type Attribute struct {
	netlink.Attribute
	Children []Attribute
}

func (a Attribute) String() string {
	if a.Nested {
		return fmt.Sprintf("<Length %v, Type %v, Nested %v, %d Children (%v)>", a.Length, a.Type, a.Nested, len(a.Children), a.Children)
	} else {
		return fmt.Sprintf("<Length %v, Type %v, Nested %v, NetByteOrder %v, %v>", a.Length, a.Type, a.Nested, a.NetByteOrder, a.Data)
	}
}

// UnmarshalMessage unmarshals the correct offset of a netlink.Message into a
// list of netfilter.Attributes.
func UnmarshalMessage(msg netlink.Message) ([]Attribute, error) {
	// If there is no valid header present, initialize it
	if len(msg.Data) < nfHeaderLen {
		msg.Data = make([]byte, nfHeaderLen)
	}

	return UnmarshalAttributes(msg.Data[nfHeaderLen:])
}

// MarshalNessage marshals a list of netfilter.Attributes into a netlink.Message
// at the correct offset. Discards existing data past nfHeaderLen.
func MarshalMessage(msg *netlink.Message, attrs []Attribute) error {
	ba, err := MarshalAttributes(attrs)
	if err != nil {
		return err
	}

	// If there is no valid header present, initialize it
	if len(msg.Data) < nfHeaderLen {
		msg.Data = make([]byte, nfHeaderLen)
	}

	msg.Data = append(msg.Data[:nfHeaderLen], ba...)

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
