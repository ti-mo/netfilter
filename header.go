package netfilter

import (
	"fmt"

	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
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

// SubsystemID denotes the Netfilter Subsystem ID the message is for. It is a const that
// is defined in the kernel at uapi/linux/netfilter/nfnetlink.h.
//go:generate stringer -type=SubsystemID
type SubsystemID uint8

// MessageType denotes the message type specific to the subsystem. Its meaning can only
// be determined after decoding the Netfilter Subsystem type, because it only has meaning
// in that context. Possible values and string representations need to be implemented in
// a subsystem-specific package.
type MessageType uint8

// FromNetlinkHeader unmarshals a netlink.HeaderType into a netfilter.HeaderType.
// The most significant byte is the subsystem ID and the least significant is the message type.
func (ht *HeaderType) FromNetlinkHeader(nlh netlink.Header) {
	ht.SubsystemID = SubsystemID(uint16(nlh.Type) & 0xff00 >> 8)
	ht.MessageType = MessageType(uint16(nlh.Type) & 0x00ff)
}

// ToNetlinkHeader marshals a Netfilter HeaderType into a Netlink header's Type field.
// It joins the SubsystemID and MessageType fields back together into a uint16.
func (ht *HeaderType) ToNetlinkHeader(nlh *netlink.Header) {
	nlh.Type = netlink.HeaderType(uint16(ht.SubsystemID)<<8 | uint16(ht.MessageType))
}

// String representation of the HeaderType in Netfilter context, for debugging purposes.
func (ht HeaderType) String() string {
	return fmt.Sprintf("%s|%d", ht.SubsystemID, ht.MessageType)
}

// Header represents a Netfilter Netlink protocol header.
// Also known as 'nfgenmsg' at Linux/include/uapi/linux/netfilter/nfnetlink.h.
// Holds the family, version and resource ID of the Netfilter message.
// -----------------------------------------------------
// | Family (1B) | Version (1B) | ResourceID (2 Bytes) |
// -----------------------------------------------------
type Header struct {
	Family     uint8
	Version    uint8
	ResourceID uint16
}

// Size of a Netfilter header (4 Bytes)
const nfHeaderLen = 4

// FromNetlinkMessage is a convenience method that unmarshals the first 4 bytes of a
// netlink.Message into a netfilter.Header. It safely calls Header.UnmarshalBinary
// with the correct offset on the Netlink message's Data field.
func (h *Header) FromNetlinkMessage(msg netlink.Message) error {

	err := h.UnmarshalBinary(msg.Data[:nfHeaderLen])
	if err != nil {
		return err
	}

	return nil
}

// ToNetlinkMessage is a convenience method that safely marshals a netfilter.Header into the
// correct offset of a netlink.Message's Data field.
func (h *Header) ToNetlinkMessage(msg *netlink.Message) error {

	hb, err := h.MarshalBinary()
	if err != nil {
		return err
	}

	copy(msg.Data[:nfHeaderLen], hb)

	return nil
}

// UnmarshalBinary unmarshals the contents of the first <nfHeaderLen> bytes of a
// byte slice into a netfilter.Header structure.
func (h *Header) UnmarshalBinary(b []byte) error {

	if len(b) < nfHeaderLen {
		return errShortMessage
	}

	h.Family = b[0]
	h.Version = b[1]
	h.ResourceID = nlenc.Uint16(b[2:4])

	return nil
}

// MarshalBinary marshals a netfilter.Header into a byte slice.
func (h *Header) MarshalBinary() ([]byte, error) {

	b := make([]byte, nfHeaderLen)

	b[0] = h.Family
	b[1] = h.Version
	nlenc.PutUint16(b[2:4], h.ResourceID)

	return b, nil
}
