package netfilter

import (
	"github.com/mdlayher/netlink"
)

// Conn represents a Netlink connection to the Netfilter subsystem.
type Conn struct {
	conn *netlink.Conn
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

// Query sends a Netfilter message over Netlink, expects
// and validates a response and returns the result.
func (c *Conn) Query(nlm netlink.Message) ([]netlink.Message, error) {

	req, err := c.conn.Send(nlm)
	if err != nil {
		return nil, err
	}

	if err := netlink.Validate(nlm, []netlink.Message{req}); err != nil {
		return nil, err
	}

	resp, err := c.conn.Receive()
	if err != nil {
		return nil, err
	}

	return resp, nil
}
