//+build integration

package netfilter

import (
	"testing"
)

func TestConnIntegrationJoinLeaveGroup(t *testing.T) {
	c, err := Dial(nil)
	if err != nil {
		t.Fatalf("error opening Conn: %s", err)
	}

	// Join all Conntrack event groups, as an example.
	err = c.JoinGroups(GroupsCT)
	if err != nil {
		t.Fatalf("error in JoinGroup: %s", err)
	}

	err = c.LeaveGroups(GroupsCT)
	if err != nil {
		t.Fatalf("error in LeaveGroup: %s", err)
	}

	err = c.Close()
	if err != nil {
		t.Fatalf("error in Close: %s", err)
	}
}
