package netfilter

import (
	"encoding/binary"
	"fmt"

	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
)

// An Attribute is a netlink.Attribute that can be nested.
type Attribute struct {
	netlink.Attribute

	// Whether the attribute's data contains nested attributes.
	Nested   bool
	Children []Attribute

	// Whether the attribute's data is in network (true) or native (false) byte order.
	NetByteOrder bool
}

// Constants defined in include/uapi/linux/netlink.h
const nlaNested uint16 = 0x8000                    // NLA_F_NESTED
const nlaNetByteOrder uint16 = 0x4000              // NLA_F_NET_BYTE_ORDER
const nlaTypeMask = ^(nlaNested | nlaNetByteOrder) // NLA_TYPE_MASK

func (a Attribute) String() string {
	if a.Nested {
		return fmt.Sprintf("<Length %v, Type %v, Nested %v, %d Children (%v)>", a.Length, a.Type, a.Nested, len(a.Children), a.Children)
	}

	return fmt.Sprintf("<Length %v, Type %v, Nested %v, NetByteOrder %v, %v>", a.Length, a.Type, a.Nested, a.NetByteOrder, a.Data)

}

// Uint16 interprets a non-nested Netfilter attribute in network byte order as a uint16.
func (a Attribute) Uint16() uint16 {

	if a.Nested {
		panic("Uint16: unexpected Nested attribute")
	}

	if l := len(a.Data); l != 2 {
		panic(fmt.Sprintf("Uint16: unexpected byte slice length: %d", l))
	}

	return binary.BigEndian.Uint16(a.Data)
}

// Int16 converts the result of Uint16() to an int16.
func (a Attribute) Int16() int16 {
	return int16(a.Uint16())
}

// Uint32 interprets a non-nested Netfilter attribute in network byte order as a uint32.
func (a Attribute) Uint32() uint32 {

	if a.Nested {
		panic("Uint32: unexpected Nested attribute")
	}

	if l := len(a.Data); l != 4 {
		panic(fmt.Sprintf("Uint32: unexpected byte slice length: %d", l))
	}

	return binary.BigEndian.Uint32(a.Data)
}

// Int32 converts the result of Uint16() to an int32.
func (a Attribute) Int32() int32 {
	return int32(a.Uint32())
}

// Uint64 interprets a non-nested Netfilter attribute in network byte order as a uint64.
func (a Attribute) Uint64() uint64 {

	if a.Nested {
		panic("Uint64: unexpected Nested attribute")
	}

	if l := len(a.Data); l != 8 {
		panic(fmt.Sprintf("Uint64: unexpected byte slice length: %d", l))
	}

	return binary.BigEndian.Uint64(a.Data)
}

// Int64 converts the result of Uint16() to an int64.
func (a Attribute) Int64() int64 {
	return int64(a.Uint64())
}

// UnmarshalMessage unmarshals the correct offset of a netlink.Message into a
// list of netfilter.Attributes.
func UnmarshalMessage(msg netlink.Message) ([]Attribute, error) {

	// TODO: Is this correct? Function should just return nothing if there's
	// less than a header's worth of data.
	if len(msg.Data) < nfHeaderLen {
		msg.Data = make([]byte, nfHeaderLen)
	}

	return UnmarshalAttributes(msg.Data[nfHeaderLen:])
}

// MarshalMessage marshals a list of netfilter.Attributes into a netlink.Message
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

// UnmarshalAttributes unmarshals a netlink.Attribute's data payload into a
// list of netfilter.Attributes.
func UnmarshalAttributes(b []byte) ([]Attribute, error) {

	var ra []Attribute

	// Obtain a list of parsed netlink attributes possibly holding
	// nested Netfilter attributes in their binary Data field.
	attrs, err := netlink.UnmarshalAttributes(b)
	if err != nil {
		return nil, err
	}

	// Wrap all netlink.Attributes into netfilter.Attributes to support nesting
	for _, nla := range attrs {

		nfa := Attribute{Attribute: nla}

		// Only consider the rightmost 14 bits for Type
		nla.Type = nlenc.Uint16(b[2:4]) & nlaTypeMask

		// Boolean flags extracted from the two leftmost bits of Type
		nfa.Nested = (nlenc.Uint16(b[2:4]) & nlaNested) > 0
		nfa.NetByteOrder = (nlenc.Uint16(b[2:4]) & nlaNetByteOrder) > 0

		if nfa.NetByteOrder && nfa.Nested {
			return nil, errInvalidAttributeFlags
		}

		// Unmarshal recursively if the netlink Nested flag is set
		if nfa.Nested {
			if nfa.Children, err = UnmarshalAttributes(nla.Data); err != nil {
				return nil, err
			}
		}

		ra = append(ra, nfa)
	}

	return ra, nil
}

// MarshalAttributes marshals a nested attribute structure into a byte slice.
func MarshalAttributes(attrs []Attribute) ([]byte, error) {

	var rb []byte

	for _, nfa := range attrs {

		if nfa.NetByteOrder && nfa.Nested {
			return nil, errInvalidAttributeFlags
		}

		// Save nested or byte order flags back to the netlink.Attribute's
		// Type field to include it in the marshaling operation
		switch {
		case nfa.Nested:
			nfa.Type = nfa.Type | nlaNested
		case nfa.NetByteOrder:
			nfa.Type = nfa.Type | nlaNetByteOrder
		}

		// Recursively marshal the attribute's children
		if nfa.Nested {
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
