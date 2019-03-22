package netfilter

import (
	"testing"

	"github.com/pkg/errors"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
)

var (
	errNetlinkTest = "synthetic test error"

	nlMsgReqAck = netlink.Message{
		Header: netlink.Header{
			Flags: netlink.Request | netlink.Acknowledge,
		},
	}

	// Dummy connection that simply returns the input payload, with
	// length and PID attributes automatically filled by the netlink library.
	nlConnEcho = nltest.Dial(func(req []netlink.Message) ([]netlink.Message, error) { return req, nil })
	connEcho   = Conn{conn: nlConnEcho}

	// Connection that returns error on any send.
	nlConnError = nltest.Dial(func(req []netlink.Message) ([]netlink.Message, error) { return nil, errors.New(errNetlinkTest) })
	connErr     = Conn{conn: nlConnError}

	// Connection that returns a single message with a nlMsgErr that trips the netlink payload error check.
	nlConnMsgError = nltest.Dial(func(req []netlink.Message) ([]netlink.Message, error) {
		resp := []netlink.Message{
			{
				Header: netlink.Header{Type: netlink.Error},
				Data:   []byte{1, 0, 0, 0},
			},
		}
		return resp, nil
	})
	connErrMsg = Conn{conn: nlConnMsgError}
)

// No CAP_NET_ADMIN needed to simply open and close a netlink socket,
// so always test this, even when the other integration tests don't.
func TestConnDialClose(t *testing.T) {

	c, err := Dial(nil)
	require.NoError(t, err, "opening Conn")

	err = c.Close()
	require.NoError(t, err, "closing Conn")
}

// Attempt to open a Netlink socket into a netns that is highly unlikely
// to exist, so we can catch an error from Dial.
func TestConnDialError(t *testing.T) {

	_, err := Dial(&netlink.Config{NetNS: 1337})
	assert.EqualError(t, err, "setns: bad file descriptor")
}

func TestConnQuery(t *testing.T) {

	// Expect no-op query to be successful.
	_, err := connEcho.Query(nlMsgReqAck)
	assert.NoError(t, err, "query error")

	_, err = connErr.Query(nlMsgReqAck)
	opErr, ok := errors.Cause(err).(*netlink.OpError)
	require.True(t, ok)
	assert.EqualError(t, opErr, "netlink receive: "+errNetlinkTest)

	_, err = connErrMsg.Query(nlMsgReqAck)
	opErr, ok = errors.Cause(err).(*netlink.OpError)
	require.True(t, ok)
	assert.EqualError(t, opErr, "netlink receive: errno -1")
}

func TestConnQueryMulticast(t *testing.T) {

	// Dummy Conn initially marked as Multicast
	connMulticast := Conn{isMulticast: true}

	assert.Equal(t, connMulticast.IsMulticast(), true)

	_, err := connMulticast.Query(nlMsgReqAck)
	assert.EqualError(t, err, errConnIsMulticast.Error())

	err = connMulticast.JoinGroups(nil)
	assert.EqualError(t, err, errNoMulticastGroups.Error())
}

func TestConnReceive(t *testing.T) {

	// Inject a message directly into the nltest connection
	connEcho.conn.Send(nlMsgReqAck)

	// Drain the socket
	_, err := connEcho.Receive()
	if err != nil {
		t.Fatalf("error in Receive: %v", err)
	}
}
