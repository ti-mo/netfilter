package netfilter

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"

	"github.com/mdlayher/netlink"
)

func TestHeaderMarshalTwoWay(t *testing.T) {

	refHdr := Header{
		SubsystemID: SubsystemID(NFSubsysCTNetlinkTimeout),
		MessageType: MessageType(123),

		Family:     255,
		Version:    1,
		ResourceID: 2,
	}

	refMsg := netlink.Message{Header: netlink.Header{Type: 0x087B}, Data: []byte{255, 1, 0, 2}}

	var gotHdr Header
	gotMsg := netlink.Message{Data: make([]byte, 4)}

	assert.Nil(t, gotHdr.unmarshal(refMsg))

	if diff := cmp.Diff(refHdr, gotHdr); diff != "" {
		t.Fatalf("unexpected netfilter Header (-want, +got):\n %s", diff)
	}

	assert.Nil(t, gotHdr.marshal(&gotMsg))

	if diff := cmp.Diff(refMsg, gotMsg); diff != "" {
		t.Fatalf("unexpected netlink Message (-want, +got):\n %s", diff)
	}

	// unmarshal error
	assert.Equal(t, errMessageLen, gotHdr.unmarshal(netlink.Message{}))

	// marshal error
	assert.Equal(t, errMessageLen, gotHdr.marshal(&netlink.Message{}))
}

func TestHeaderString(t *testing.T) {
	ht := Header{
		SubsystemID: NFSubsysIPSet,
		MessageType: 123,
	}

	want := "<Subsystem: NFSubsysIPSet, Message Type: 123, Family: ProtoUnspec, Version: 0, ResourceID: 0>"

	assert.Equal(t, want, ht.String())
}

func TestProtoFamilyString(t *testing.T) {

	if ProtoFamily(255).String() == "" {
		t.Fatal("ProtoFamily string representation empty - did you run `go generate`?")
	}

	pf := map[ProtoFamily]string{
		ProtoUnspec: "ProtoUnspec",
		ProtoInet:   "ProtoInet",
		ProtoIPv4:   "ProtoIPv4",
		ProtoARP:    "ProtoARP",
		ProtoNetDev: "ProtoNetDev",
		ProtoBridge: "ProtoBridge",
		ProtoIPv6:   "ProtoIPv6",
		ProtoDECNet: "ProtoDECNet",
	}

	for k, v := range pf {
		assert.Equal(t, k.String(), v)
	}
}

func TestSubsystemIDString(t *testing.T) {

	if SubsystemID(255).String() == "" {
		t.Fatal("SubsystemID string representation empty - did you run `go generate`?")
	}
}
