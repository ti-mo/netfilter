//+build integration

package netfilter

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mdlayher/netlink"
)

var (
	badGroup = []NetlinkGroup{255}
)

func TestConnIntegrationJoinLeaveGroup(t *testing.T) {
	c, err := Dial(nil)
	require.NoError(t, err, "opening Conn")

	// Join all Conntrack event groups, as an example.
	err = c.JoinGroups(GroupsCT)
	require.NoError(t, err, "JoinGroup")

	err = c.LeaveGroups(GroupsCT)
	require.NoError(t, err, "LeaveGroup")

	err = c.Close()
	require.NoError(t, err, "closing Conn")

}

func TestConnIntegrationBadGroups(t *testing.T) {
	c, err := Dial(nil)
	require.NoError(t, err, "opening Conn")

	err = c.JoinGroups(badGroup)
	require.EqualError(t, err, "netlink join-group: setsockopt: invalid argument")

	err = c.LeaveGroups(badGroup)
	require.EqualError(t, err, "netlink leave-group: setsockopt: invalid argument")

	err = c.Close()
	require.NoError(t, err, "closing Conn")
}

func TestConnIntegrationSetOption(t *testing.T) {
	c, err := Dial(nil)
	require.NoError(t, err, "opening Conn")

	err = c.SetOption(netlink.ListenAllNSID, true)
	require.NoError(t, err, "setting SockOption")

	err = c.Close()
	require.NoError(t, err, "closing Conn")
}
