package tls

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"
)

func metadataFixture() TLS12TicketMetadata {
	return TLS12TicketMetadata{
		SessionCreatedAt:       time.Unix(1700000000, 123456789).UTC(),
		SessionAuthenticatedAt: time.Unix(1700000001, 987654321).UTC(),
		TicketReceivedAt:       time.Unix(1700000002, 7).UTC(),
		LifetimeHint:           0x01020304,
		OriginalSessionKnown:   true,
	}
}

func metadataState(extra ...[]byte) *ClientSessionState {
	state := MakeClientSessionState([]byte("metadata-test"), VersionTLS12,
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, nil, nil, nil)
	_, session, _ := state.ResumptionState()
	session.Extra = extra
	return state
}

func TestTLS12TicketMetadataEncoding(t *testing.T) {
	want := metadataFixture()
	encoded, ok := marshalTLS12TicketMetadata(want)
	if !ok {
		t.Fatal("valid full-handshake metadata rejected")
	}

	// Independent schema vector: namespace/version/flags/hint, followed by
	// signed Unix seconds and nanoseconds for each of the four timestamps.
	const vector = "656e6574782f746c7331322d7469636b657400010101020304" +
		"000000006553f100075bcd15" + "000000006553f1013ade68b1" +
		"000000006553f10200000007" + "fffffff1886e090000000000"
	if hex.EncodeToString(encoded) != vector {
		t.Fatalf("metadata bytes differ from version1 schema: %x", encoded)
	}

	for _, hint := range []uint32{0, 1, 7200, ^uint32(0)} {
		for _, resumed := range []bool{false, true} {
			for _, known := range []bool{false, true} {
				if !resumed && !known {
					continue
				}

				info := want
				info.LifetimeHint, info.Resumed, info.OriginalSessionKnown = hint, resumed, known
				if resumed {
					info.PreviousTicketReceivedAtKnown = true
					info.PreviousTicketReceivedAt = time.Unix(1699999999, 123).UTC()
				}

				if !known {
					info.SessionCreatedAt, info.SessionAuthenticatedAt = time.Time{}, time.Time{}
				}

				data, ok := marshalTLS12TicketMetadata(info)
				if !ok {
					t.Fatalf("supported fact combination rejected: hint=%d resumed=%v known=%v", hint, resumed, known)
				}

				state := metadataState(nil, []byte("foreign/v1"), data, []byte{})
				got, ok := state.TLS12TicketMetadata()
				if !ok || got != info {
					t.Fatalf("fact round trip changed metadata: %#v, valid=%v", got, ok)
				}

				state.session.Extra[2][len(data)-1] ^= 1
				if got != info {
					t.Fatal("accessor result aliases mutable Extra bytes")
				}
			}
		}
	}

	// Clock rollback is a policy decision. The codec must retain it faithfully.
	want.PreviousTicketReceivedAt, want.PreviousTicketReceivedAtKnown = want.TicketReceivedAt.Add(time.Hour), true
	want.Resumed = true
	data, ok := marshalTLS12TicketMetadata(want)
	if got, valid := parseTLS12TicketMetadata(data); !ok || !valid || got != want {
		t.Fatal("well-formed backwards-clock facts were lost")
	}

	// A renewed legacy ticket can have known receipt but unknown original age.
	legacy := TLS12TicketMetadata{Resumed: true, TicketReceivedAt: want.TicketReceivedAt}
	data, ok = marshalTLS12TicketMetadata(legacy)
	if got, valid := parseTLS12TicketMetadata(data); !ok || !valid || got != legacy {
		t.Fatal("explicitly unknown legacy lineage became a fresh original age")
	}
}

func TestTLS12TicketMetadataRejectsMalformedFacts(t *testing.T) {
	valid, _ := marshalTLS12TicketMetadata(metadataFixture())
	for size := 0; size < len(valid); size++ {
		if _, ok := parseTLS12TicketMetadata(valid[:size]); ok {
			t.Fatalf("truncated metadata accepted: %d", size)
		}
	}

	invalid := [][]byte{append(bytes.Clone(valid), 0)}
	for _, offset := range []int{0, len(tls12TicketMetadataPrefix)} {
		data := bytes.Clone(valid)
		data[offset] ^= 0xff
		invalid = append(invalid, data)
	}

	for _, flags := range []byte{0, 2, 3, 4, 5, 6, 7, 8, 255} {
		data := bytes.Clone(valid)
		data[len(tls12TicketMetadataPrefix)+1] = flags
		invalid = append(invalid, data)
	}

	for index := range 4 {
		position := len(tls12TicketMetadataPrefix) + 6 + index*12
		for _, seconds := range []int64{-62135596801, 253402300800, -1 << 63, 1<<63 - 1} {
			data := bytes.Clone(valid)
			binary.BigEndian.PutUint64(data[position:], uint64(seconds))
			invalid = append(invalid, data)
		}

		data := bytes.Clone(valid)
		binary.BigEndian.PutUint32(data[position+8:], 1_000_000_000)
		invalid = append(invalid, data)
	}

	for _, data := range invalid {
		if _, ok := parseTLS12TicketMetadata(data); ok {
			t.Fatalf("invalid metadata accepted: %x", data)
		}

		if _, ok := metadataState(data).TLS12TicketMetadata(); ok {
			t.Fatal("accessor accepted malformed owned metadata")
		}
	}

	for _, mutate := range []func(*TLS12TicketMetadata){
		func(m *TLS12TicketMetadata) { m.TicketReceivedAt = time.Time{} },
		func(m *TLS12TicketMetadata) { m.SessionCreatedAt = time.Time{} },
		func(m *TLS12TicketMetadata) { m.SessionAuthenticatedAt = time.Time{} },
		func(m *TLS12TicketMetadata) { m.OriginalSessionKnown = false },
		func(m *TLS12TicketMetadata) { m.PreviousTicketReceivedAtKnown = true },
		func(m *TLS12TicketMetadata) { m.PreviousTicketReceivedAt = m.TicketReceivedAt },
		func(m *TLS12TicketMetadata) { m.SessionCreatedAt = time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC) },
		func(m *TLS12TicketMetadata) { m.SessionAuthenticatedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) },
	} {
		info := metadataFixture()
		mutate(&info)
		if _, ok := marshalTLS12TicketMetadata(info); ok {
			t.Fatal("invalid fact combination was encoded")
		}
	}

	for _, state := range []*ClientSessionState{nil, {}, metadataState(), metadataState([]byte("foreign/v1")), metadataState(valid, valid)} {
		if _, ok := state.TLS12TicketMetadata(); ok {
			t.Fatal("absent or ambiguous provenance accepted")
		}
	}

	state := metadataState(valid)
	for _, version := range []uint16{0, VersionTLS13} {
		state.SetVers(version)
		if _, ok := state.TLS12TicketMetadata(); ok {
			t.Fatal("legacy metadata exposed for a different protocol")
		}
	}
}

func TestLegacyNewSessionTicketPreservesLifetimeHint(t *testing.T) {
	for _, hint := range []uint32{0, 1, 7200, ^uint32(0)} {
		message := newSessionTicketMsg{lifetimeHint: hint, ticket: []byte("ticket")}
		wire, err := message.marshal()
		if err != nil || binary.BigEndian.Uint32(wire[4:8]) != hint {
			t.Fatal("legacy ticket wire hint changed")
		}

		var parsed newSessionTicketMsg
		if !parsed.unmarshal(wire) || parsed.lifetimeHint != hint || !bytes.Equal(parsed.ticket, message.ticket) {
			t.Fatal("valid RFC5077 ticket lost metadata")
		}
	}
}

func TestTLS12MetadataUTCBounds(t *testing.T) {
	for _, stamp := range []time.Time{
		time.Date(1, 1, 1, 0, 0, 0, 0, time.FixedZone("east", 3600)),
		time.Date(9999, 12, 31, 23, 59, 59, 0, time.FixedZone("west", -3600)),
	} {
		info := metadataFixture()
		info.TicketReceivedAt = stamp
		if _, ok := marshalTLS12TicketMetadata(info); ok {
			t.Fatal("civil timestamp outside UTC encoding bounds accepted")
		}
	}

	for _, stamp := range []time.Time{
		time.Date(1, 1, 1, 1, 0, 1, 0, time.FixedZone("east", 3600)),
		time.Date(9999, 12, 31, 23, 59, 59, 0, time.FixedZone("east", 3600)),
	} {
		info := metadataFixture()
		info.TicketReceivedAt = stamp
		data, ok := marshalTLS12TicketMetadata(info)
		if !ok {
			t.Fatal("UTC-representable boundary rejected")
		}

		got, ok := parseTLS12TicketMetadata(data)
		if !ok || !got.TicketReceivedAt.Equal(stamp) {
			t.Fatal("UTC normalization changed the recorded instant")
		}
	}
}
