package netfilter

import (
	"github.com/mdlayher/netlink"
)

// Conn represents a Netlink connection to the Netfilter subsystem.
type Conn struct {
	conn *netlink.Conn

	// Marks the Conn as being attached to one or more multicast groups,
	// it can no longer be used for any queries for its remaining lifetime.
	isMulticast bool
}

// Open opens a new Netlink connection to the Netfilter subsystem
// and returns it wrapped in a Conn structure.
func Open() (*Conn, error) {
	var c Conn
	var err error

	c.conn, err = netlink.Dial(NLNetfilter, nil)
	if err != nil {
		return nil, err
	}

	return &c, nil
}

// Close closes a Conn.
func (c *Conn) Close() error {
	return c.conn.Close()
}

// Query sends a Netfilter message over Netlink and validates the response.
// The call will fail if the Conn is marked as Multicast.
func (c *Conn) Query(nlm netlink.Message) ([]netlink.Message, error) {

	if c.isMulticast {
		return nil, errConnIsMulticast
	}

	ret, err := c.conn.Execute(nlm)
	if err != nil {
		return nil, err
	}

	// Check the Netlink response for non-zero error code
	if err := CheckNetlinkError(ret); err != nil {
		return nil, err
	}

	return ret, nil
}

// JoinGroups attaches the Netlink socket to one or more Netfilter multicast groups.
// Marks the Conn as Multicast, meaning it can no longer be used for any queries.
func (c *Conn) JoinGroups(groups []NetlinkGroup) error {

	for _, group := range groups {
		err := c.conn.JoinGroup(uint32(group))
		if err != nil {
			return err
		}
	}

	// Mark the Conn as being attached to a multicast group
	c.isMulticast = true

	return nil
}

// LeaveGroups detaches the Netlink socket from one or more Netfilter multicast groups.
// Does not remove the Multicast flag, open a separate Conn for making queries instead.
func (c *Conn) LeaveGroups(groups []NetlinkGroup) error {

	for _, group := range groups {
		err := c.conn.LeaveGroup(uint32(group))
		if err != nil {
			return err
		}
	}

	return nil
}

// Receive executes a blocking read on the underlying Netlink socket and returns a Message.
func (c *Conn) Receive() ([]netlink.Message, error) {
	return c.conn.Receive()
}

// IsMulticast returns the Conn's Multicast flag. It is set by calling Listen().
func (c Conn) IsMulticast() bool {
	return c.isMulticast
}
