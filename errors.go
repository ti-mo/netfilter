package netfilter

import "errors"

const (
	errWrapNetlinkUnmarshalAttrs = "error unmarshaling netlink attributes"
	errWrapNetlinkMarshalAttrs   = "error marshaling netlink attributes"
)

var (
	// errInvalidAttributeFlags specifies if an Attribute's flag configuration is invalid.
	// From a comment in Linux/include/uapi/linux/netlink.h, Nested and NetByteOrder are mutually exclusive.
	errInvalidAttributeFlags = errors.New("invalid attribute; type cannot have both nested and net byte order flags")

	errShortMessage = errors.New("cannot parse netfilter message because it is too short")
	errExistingData = errors.New("netlink message already contains Data payload")

	errConnIsMulticast = errors.New("Conn is attached to one or more multicast groups and can no longer be used for bidirectional traffic")
)
