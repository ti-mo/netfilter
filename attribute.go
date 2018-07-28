package netfilter

import (
	"encoding/binary"
	"fmt"

	"github.com/mdlayher/netlink"
	"github.com/pkg/errors"
)

// An Attribute is a copy of a netlink.Attribute that can be nested.
type Attribute struct {

	// Length of an Attribute, including this field and Type.
	Length uint16

	// The type of this Attribute, typically matched to a constant.
	Type uint16

	// An arbitrary payload which is specified by Type.
	Data []byte

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
		return fmt.Sprintf("<Length %d, Type %d, Nested %t, %d Children (%v)>", a.Length, a.Type, a.Nested, len(a.Children), a.Children)
	}

	return fmt.Sprintf("<Length %d, Type %d, Nested %t, NetByteOrder %t, %v>", a.Length, a.Type, a.Nested, a.NetByteOrder, a.Data)

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

// AttributesFromNetlink unmarshals the correct offset of a netlink.Message into a
// list of netfilter.Attributes.
func AttributesFromNetlink(msg netlink.Message) ([]Attribute, error) {

	if len(msg.Data) < nfHeaderLen {
		return nil, errShortMessage
	}

	return UnmarshalAttributes(msg.Data[nfHeaderLen:])
}

// AttributesToNetlink marshals a list of netfilter.Attributes into a netlink.Message
// at the correct offset. Overwrites existing data past nfHeaderLen in the netlink.Message.
func AttributesToNetlink(attrs []Attribute, msg *netlink.Message) error {

	ba, err := MarshalAttributes(attrs)
	if err != nil {
		return err
	}

	// Initiate the message buffer to at least the length of a Netfilter header.
	if len(msg.Data) < nfHeaderLen {
		msg.Data = make([]byte, nfHeaderLen)
	}

	msg.Data = append(msg.Data[:nfHeaderLen], ba...)

	return nil
}

// UnmarshalAttributes returns an array of netfilter.Attributes decoded from
// a byte array. This byte array should be taken from the netlink.Message's
// Data payload after the nfHeaderLen offset.
func UnmarshalAttributes(b []byte) ([]Attribute, error) {

	var ra []Attribute

	// Obtain a list of parsed netlink attributes possibly holding
	// nested Netfilter attributes in their binary Data field.
	attrs, err := netlink.UnmarshalAttributes(b)
	if err != nil {
		return nil, errors.Wrap(err, errWrapNetlinkUnmarshalAttrs)
	}

	// Wrap all netlink.Attributes into netfilter.Attributes to support nesting
	for _, nla := range attrs {

		// Copy the netlink attribute's fields into the netfilter attribute.
		nfa := Attribute{
			Length: nla.Length,
			Type:   nla.Type,
			Data:   nla.Data,
		}

		// Only consider the rightmost 14 bits for Type
		// Overwrite the value on the copied nested structure
		nfa.Type = nla.Type & nlaTypeMask

		// Boolean flags extracted from the two leftmost bits of Type
		nfa.Nested = (nla.Type & nlaNested) != 0
		nfa.NetByteOrder = (nla.Type & nlaNetByteOrder) != 0

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
// This byte slice can then be copied into a netlink.Message's Data field after
// the nfHeaderLen offset.
func MarshalAttributes(attrs []Attribute) ([]byte, error) {

	var rb []byte

	// netlink.Attribute to use for MarshalBinary()
	// Used as scratch buffer, so only requires a single allocation
	nla := netlink.Attribute{}

	for _, nfa := range attrs {

		if nfa.NetByteOrder && nfa.Nested {
			return nil, errInvalidAttributeFlags
		}

		// Save nested or byte order flags back to the netlink.Attribute's
		// Type field to include it in the marshaling operation
		nla.Type = nfa.Type

		switch {
		case nfa.Nested:
			nla.Type = nla.Type | nlaNested
		case nfa.NetByteOrder:
			nla.Type = nla.Type | nlaNetByteOrder
		}

		// Recursively marshal the attribute's children
		if nfa.Nested {
			nfnab, err := MarshalAttributes(nfa.Children)
			if err != nil {
				return nil, err
			}

			nla.Data = append(nla.Data, nfnab...)
		} else {
			nla.Data = nfa.Data
		}

		// Automatically set length attribute based on payload length.
		// Alternatively, copy length to the netlink Attribute, since that's the
		// one considered for marshaling.
		if nfa.Length == 0 {
			nla.Length = uint16(nlaHeaderLen + len(nla.Data))
		} else {
			nla.Length = nfa.Length
		}

		nlab, err := nla.MarshalBinary()
		if err != nil {
			return nil, errors.Wrap(err, errWrapNetlinkMarshalAttrs)
		}

		rb = append(rb, nlab...)
	}

	return rb, nil
}
