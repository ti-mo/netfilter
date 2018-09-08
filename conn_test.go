package netfilter

import (
	"errors"
	"fmt"
	"testing"

	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
	"github.com/stretchr/testify/assert"
)

var (
	errNetlinkTest = errors.New("synthetic test error")

	nlMsgReqAck = netlink.Message{
		Header: netlink.Header{
			Flags: netlink.HeaderFlagsRequest | netlink.HeaderFlagsAcknowledge,
		},
	}

	// Dummy connection that simply returns the input payload, with
	// length and PID attributes automatically filled by the netlink library.
	nlConnEcho = nltest.Dial(func(req []netlink.Message) ([]netlink.Message, error) { return req, nil })
	connEcho   = Conn{conn: nlConnEcho}

	// Connection that returns error on any send.
	nlConnError = nltest.Dial(func(req []netlink.Message) ([]netlink.Message, error) { return nil, errNetlinkTest })
	connErr     = Conn{conn: nlConnError}

	// Connection that returns a single message with a nlMsgErr that trips the netlink payload error check.
	nlConnMsgError = nltest.Dial(func(req []netlink.Message) ([]netlink.Message, error) {
		resp := []netlink.Message{
			{
				Header: netlink.Header{Type: netlink.HeaderTypeError},
				Data:   []byte{1, 0, 0, 0},
			},
		}
		return resp, nil
	})
	connErrMsg = Conn{conn: nlConnMsgError}
)

func TestConnIntegrationOpenClose(t *testing.T) {

	c, err := Open()
	if err != nil {
		t.Fatalf("error opening Conn: %s", err)
	}

	err = c.Close()
	if err != nil {
		t.Fatalf("error closing Conn: %s", err)
	}
}

func TestConnQuery(t *testing.T) {

	// Expect no-op query to be successful
	if _, err := connEcho.Query(nlMsgReqAck); err != nil {
		t.Fatalf("error from Query: %v", err)
	}

	_, got := connErr.Query(nlMsgReqAck)
	if want := fmt.Sprintf(errNetlinkExecute, errNetlinkTest); want != got.Error() {
		t.Fatalf("unexpected error:\n-  want: %v\n-   got: %v", want, got)
	}

	_, got = connErrMsg.Query(nlMsgReqAck)
	if want := fmt.Sprintf(errNetlinkExecute, "errno -1"); want != got.Error() {
		t.Fatalf("unexpected error:\n-  want: %v\n-   got: %v", want, got)
	}
}

func TestConnQueryMulticast(t *testing.T) {

	// Dummy Conn initially marked as Multicast
	connMulticast := Conn{isMulticast: true}

	assert.Equal(t, connMulticast.IsMulticast(), true)

	_, err := connMulticast.Query(nlMsgReqAck)
	if want, got := errConnIsMulticast, err; want != got {
		t.Fatalf("unexpected error:\n-  want: %v\n-   got: %v", want, got)
	}
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
