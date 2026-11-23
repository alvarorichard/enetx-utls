package tls

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	stdtls "crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var metadataHandshakeTime = time.Unix(1800000000, 0).UTC()

// A local CA and a distinct leaf are verified by the client. The peer is the
// standard library, not this fork's TLS server or private handshake helpers.
func metadataHandshakeIdentity(t *testing.T) (stdtls.Certificate, *x509.CertPool) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ca := &x509.Certificate{SerialNumber: big.NewInt(91), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		NotBefore: metadataHandshakeTime.Add(-time.Hour), NotAfter: metadataHandshakeTime.Add(365 * 24 * time.Hour)}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	root, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	leaf := &x509.Certificate{SerialNumber: big.NewInt(92), DNSNames: []string{"ticket.example"},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		NotBefore: ca.NotBefore, NotAfter: ca.NotAfter}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(root)
	return stdtls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey}, roots
}

type metadataHandshakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *metadataHandshakeClock) time() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now
	c.now = c.now.Add(time.Millisecond)
	return now
}

func (c *metadataHandshakeClock) set(now time.Time) {
	c.mu.Lock()
	c.now = now
	c.mu.Unlock()
}

type metadataHandshakeCache struct {
	mu      sync.Mutex
	state   *ClientSessionState
	commits int
}

func (c *metadataHandshakeCache) Get(string) (*ClientSessionState, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state, c.state != nil
}

func (c *metadataHandshakeCache) Put(_ string, state *ClientSessionState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state = state
	if state != nil {
		c.commits++
	}
}

func (c *metadataHandshakeCache) snapshot() (*ClientSessionState, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state, c.commits
}

// metadataTLS12Peer changes only the TLS1.2 NST hint and, when requested, the
// Finished proof. It verifies the standard peer's original Finished, derives
// RFC5246/5288 AES-GCM keys independently, and reauthenticates the changed wire
// transcript. This tests nonzero hints without an engine test hook or trusting
// our marshal/parser/PRF implementations as the oracle. Resumed peers use the
// ordinary unmodified standard server. Zero-hint resumed proof checks can use
// the actual previous session's public MasterSecret without a fresh key log.
type metadataTLS12Peer struct {
	net.Conn
	hint               uint32
	badFinished        bool
	input              []byte
	clientRandom       []byte
	serverRandom       []byte
	secret             []byte
	original           []byte
	wire               []byte
	clientCCS          bool
	clientFinished     []byte
	serverCCS          bool
	seenTicket         bool
	checkedProof       bool
	transform          bool
	stopAfterTicket    bool
	ticketReady        chan struct{}
	finishedGate       chan struct{}
	handshakeContext   context.Context
	ordinaryClient     bool
	clientWriteFailure *metadataFinalWriteFailure
}

func (p *metadataTLS12Peer) keyLog(data []byte) (int, error) {
	fields := strings.Fields(string(data))
	if len(fields) != 3 || fields[0] != "CLIENT_RANDOM" {
		return 0, errors.New("unexpected TLS1.2 key log")
	}

	secret, err := hex.DecodeString(fields[2])
	if err != nil {
		return 0, err
	}
	p.secret = secret
	if len(p.clientFinished) != 0 {
		if _, err := p.finished(p.clientFinished, false); err != nil {
			return 0, err
		}
		p.clientFinished = nil
	}
	return len(data), nil
}

func metadataPeerPRF(secret []byte, label string, seed []byte, length int) []byte {
	input := append([]byte(label), seed...)
	mac := hmac.New(sha256.New, secret)
	mac.Write(input)
	a := mac.Sum(nil)
	var output []byte
	for len(output) < length {
		mac.Reset()
		mac.Write(a)
		mac.Write(input)
		output = append(output, mac.Sum(nil)...)
		mac.Reset()
		mac.Write(a)
		a = mac.Sum(nil)
	}
	return output[:length]
}

func (p *metadataTLS12Peer) gcm(server bool) (cipher.AEAD, []byte, error) {
	if len(p.secret) != 48 || len(p.clientRandom) != 32 || len(p.serverRandom) != 32 {
		return nil, nil, errors.New("peer has no authenticated TLS1.2 key material")
	}

	seed := append(slices.Clone(p.serverRandom), p.clientRandom...)
	keys := metadataPeerPRF(p.secret, "key expansion", seed, 40)
	key, salt := keys[:16], keys[32:36]
	if server {
		key, salt = keys[16:32], keys[36:40]
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	gcm, err := cipher.NewGCM(block)
	return gcm, salt, err
}

func (p *metadataTLS12Peer) finished(record []byte, server bool) ([]byte, error) {
	gcm, salt, err := p.gcm(server)
	if err != nil {
		return nil, err
	}

	if len(record) < 5+8+gcm.Overhead() {
		return nil, errors.New("truncated peer Finished record")
	}

	nonce := append(slices.Clone(salt), record[5:13]...)
	aad := make([]byte, 13) // First encrypted record has sequence number zero.
	copy(aad[8:11], record[:3])
	binary.BigEndian.PutUint16(aad[11:], uint16(len(record)-13-gcm.Overhead()))
	plain, err := gcm.Open(nil, nonce, record[13:], aad)
	if err != nil {
		return nil, err
	}

	if len(plain) != 16 || !bytes.Equal(plain[:4], []byte{20, 0, 0, 12}) {
		return nil, errors.New("peer did not send an ordinary TLS1.2 Finished")
	}

	if !server {
		p.original = append(p.original, plain...)
		p.wire = append(p.wire, plain...)
		return record, nil
	}

	digest := sha256.Sum256(p.original)
	if !hmac.Equal(plain[4:], metadataPeerPRF(p.secret, "server finished", digest[:], 12)) {
		return nil, errors.New("independent peer Finished verification failed")
	}
	p.checkedProof = true
	digest = sha256.Sum256(p.wire)
	copy(plain[4:], metadataPeerPRF(p.secret, "server finished", digest[:], 12))
	if p.badFinished {
		plain[len(plain)-1] ^= 1
	}

	result := slices.Clone(record[:13])
	return gcm.Seal(result, nonce, plain, aad), nil
}

func (p *metadataTLS12Peer) Read(data []byte) (int, error) {
	n, err := p.Conn.Read(data)
	if !p.transform {
		return n, err
	}

	p.input = append(p.input, data[:n]...)
	for len(p.input) >= 5 {
		length := 5 + int(binary.BigEndian.Uint16(p.input[3:5]))
		if len(p.input) < length {
			break
		}

		record := p.input[:length]
		if record[0] == 20 {
			p.clientCCS = true
		} else if record[0] == 22 && !p.clientCCS {
			if len(p.clientRandom) == 0 && len(record) >= 43 && record[5] == 1 {
				p.clientRandom = slices.Clone(record[11:43])
			}
			p.original = append(p.original, record[5:]...)
			p.wire = append(p.wire, record[5:]...)
		} else if record[0] == 22 && p.clientCCS {
			if len(p.secret) == 0 {
				p.clientFinished = slices.Clone(record)
			} else if _, proofErr := p.finished(record, false); proofErr != nil {
				return n, proofErr
			}
		}
		p.input = p.input[length:]
	}
	return n, err
}

func (p *metadataTLS12Peer) Write(data []byte) (int, error) {
	if !p.transform {
		return p.Conn.Write(data)
	}

	originalLength := len(data)
	for len(data) > 0 {
		if len(data) < 5 {
			return 0, errors.New("standard peer wrote a partial record header")
		}

		length := 5 + int(binary.BigEndian.Uint16(data[3:5]))
		if length > len(data) {
			return 0, errors.New("standard peer wrote a partial record body")
		}

		record := slices.Clone(data[:length])
		if record[0] == 20 {
			p.serverCCS = true
		} else if record[0] == 22 && !p.serverCCS {
			if len(p.serverRandom) == 0 && len(record) >= 43 && record[5] == 2 {
				p.serverRandom = slices.Clone(record[11:43])
			}
			p.original = append(p.original, record[5:]...)
			if record[5] == 4 {
				binary.BigEndian.PutUint32(record[9:13], p.hint)
				p.seenTicket = true
				if p.ticketReady != nil {
					close(p.ticketReady)
				}
			}
			p.wire = append(p.wire, record[5:]...)
		} else if record[0] == 22 && p.serverCCS {
			if p.finishedGate != nil {
				<-p.finishedGate
			}
			var err error
			record, err = p.finished(record, true)
			if err != nil {
				return 0, err
			}
		}

		if _, err := p.Conn.Write(record); err != nil {
			return 0, err
		}

		if p.stopAfterTicket && p.seenTicket {
			p.Conn.Close()
			return 0, io.ErrUnexpectedEOF
		}
		data = data[length:]
	}
	return originalLength, nil
}

type metadataHandshakeRun struct {
	client    ConnectionState
	server    stdtls.ConnectionState
	peer      *metadataTLS12Peer
	err       error
	serverErr error
}

type metadataKeyLogWriter struct{ peer *metadataTLS12Peer }

func (w metadataKeyLogWriter) Write(data []byte) (int, error) { return w.peer.keyLog(data) }

type metadataFinalWriteFailure struct {
	net.Conn
	err    error
	armed  atomic.Bool
	failed atomic.Bool
}

func (c *metadataFinalWriteFailure) Write(data []byte) (int, error) {
	if c.armed.Load() {
		c.failed.Store(true)
		return 0, c.err
	}
	return c.Conn.Write(data)
}

func runMetadataHandshake(
	t *testing.T,
	clientConfig *Config,
	serverConfig *stdtls.Config,
	hello ClientHelloID,
	peerOptions metadataTLS12Peer,
) metadataHandshakeRun {
	t.Helper()
	c, s := localPipe(t)
	deadline := time.Now().Add(10 * time.Second)
	c.SetDeadline(deadline)
	s.SetDeadline(deadline)
	peer := &peerOptions
	peer.Conn = s
	var clientConn net.Conn = c
	if peer.clientWriteFailure != nil {
		peer.clientWriteFailure.Conn = c
		clientConn = peer.clientWriteFailure
	}
	serverConfig = serverConfig.Clone()
	if peer.transform {
		serverConfig.KeyLogWriter = metadataKeyLogWriter{peer}
	}

	server := stdtls.Server(peer, serverConfig)
	done := make(chan error, 1)
	go func() {
		err := server.Handshake()
		if err != nil {
			s.Close()
		}
		done <- err
	}()
	ctx := peer.handshakeContext
	if ctx == nil {
		ctx = context.Background()
	}
	var clientState ConnectionState
	var err error
	if peer.ordinaryClient {
		client := Client(clientConn, clientConfig)
		err = client.HandshakeContext(ctx)
		clientState = client.ConnectionState()
	} else {
		client := UClient(clientConn, clientConfig, hello)
		err = client.HandshakeContext(ctx)
		clientState = client.ConnectionState()
	}
	if err != nil {
		c.Close()
		s.Close()
		if peer.finishedGate != nil {
			close(peer.finishedGate)
		}
	}
	serverErr := <-done
	c.Close()
	s.Close()
	return metadataHandshakeRun{client: clientState, server: server.ConnectionState(), peer: peer,
		err: err, serverErr: serverErr}
}

func metadataHandshakeConfigs(t *testing.T) (*Config, *stdtls.Config, *metadataHandshakeCache, *metadataHandshakeClock) {
	t.Helper()
	identity, roots := metadataHandshakeIdentity(t)
	clock := &metadataHandshakeClock{now: metadataHandshakeTime}
	cache := new(metadataHandshakeCache)
	client := &Config{ServerName: "ticket.example", RootCAs: roots, Time: clock.time,
		MinVersion: VersionTLS12, MaxVersion: VersionTLS12, ClientSessionCache: cache}
	server := &stdtls.Config{Certificates: []stdtls.Certificate{identity},
		Time:       func() time.Time { return metadataHandshakeTime },
		MinVersion: stdtls.VersionTLS12, MaxVersion: stdtls.VersionTLS12,
		CipherSuites: []uint16{stdtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}}
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	server.SetSessionTicketKeys([][32]byte{key})
	return client, server, cache, clock
}

func assertMetadataHandshake(t *testing.T, run metadataHandshakeRun, resumed bool) {
	t.Helper()
	if run.err != nil || run.serverErr != nil {
		t.Fatalf("verified handshake: client=%v server=%v", run.err, run.serverErr)
	}

	if !run.client.HandshakeComplete || !run.server.HandshakeComplete ||
		run.client.DidResume != resumed || run.server.DidResume != resumed ||
		run.client.Version != VersionTLS12 || run.client.CipherSuite != TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 ||
		len(run.client.VerifiedChains) != 1 ||
		len(run.client.VerifiedChains[0]) != 2 || run.client.PeerCertificates[0].DNSNames[0] != "ticket.example" {
		t.Fatalf("handshake lost trust or resumption: client=%+v server=%+v", run.client, run.server)
	}
}

func cachedMetadata(t *testing.T, cache *metadataHandshakeCache) (*ClientSessionState, TLS12TicketMetadata) {
	t.Helper()
	state, _ := cache.snapshot()
	if state == nil {
		t.Fatal("authenticated ticket was not cached")
	}

	info, ok := state.TLS12TicketMetadata()
	if !ok {
		t.Fatal("authenticated ticket lacks metadata")
	}
	return state, info
}

func metadataStandardBridge(t *testing.T, input *ClientSessionState) *ClientSessionState {
	t.Helper()
	ticket, state, err := input.ResumptionState()
	if err != nil {
		t.Fatal(err)
	}

	encoded, err := state.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	standard, err := stdtls.ParseSessionState(encoded)
	if err != nil {
		t.Fatal(err)
	}

	standardClient, err := stdtls.NewResumptionState(ticket, standard)
	if err != nil {
		t.Fatal(err)
	}

	label, standard, err := standardClient.ResumptionState()
	if err != nil {
		t.Fatal(err)
	}

	encoded, err = standard.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := ParseSessionState(encoded)
	if err != nil {
		t.Fatal(err)
	}

	result, err := NewResumptionState(label, decoded)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestTLS12TicketMetadataAuthenticatedWire(t *testing.T) {
	for _, mode := range []struct {
		name     string
		hello    ClientHelloID
		ordinary bool
	}{
		{name: "Conn", ordinary: true},
		{name: "UConnGolang", hello: HelloGolang},
		{name: "Chrome155", hello: HelloChrome_155},
		{name: "Firefox120", hello: HelloFirefox_120},
	} {
		for _, hint := range []uint32{0, 1, 7200, ^uint32(0)} {
			t.Run(fmt.Sprintf("%s/hint%d", mode.name, hint), func(t *testing.T) {
				client, server, cache, _ := metadataHandshakeConfigs(t)
				run := runMetadataHandshake(t, client, server, mode.hello,
					metadataTLS12Peer{transform: true, hint: hint, ordinaryClient: mode.ordinary})
				assertMetadataHandshake(t, run, false)
				_, info := cachedMetadata(t, cache)
				if !run.peer.seenTicket || !run.peer.checkedProof || info.LifetimeHint != hint ||
					!info.OriginalSessionKnown || info.Resumed || info.PreviousTicketReceivedAtKnown ||
					!info.SessionCreatedAt.Before(info.TicketReceivedAt) || !info.TicketReceivedAt.Before(info.SessionAuthenticatedAt) {
					t.Fatalf("wrong authenticated issuance facts: %+v", info)
				}

				// Changing NST after the full client's Finished must preserve EMS
				// and the original session's interoperability with a normal peer.
				run = runMetadataHandshake(t, client, server, mode.hello, metadataTLS12Peer{ordinaryClient: mode.ordinary})
				assertMetadataHandshake(t, run, true)
				_, renewed := cachedMetadata(t, cache)
				if !renewed.Resumed || !renewed.OriginalSessionKnown || renewed.LifetimeHint != 0 ||
					renewed.SessionCreatedAt != info.SessionCreatedAt || renewed.SessionAuthenticatedAt != info.SessionAuthenticatedAt ||
					renewed.PreviousTicketReceivedAt != info.TicketReceivedAt {
					t.Fatalf("modified-hint full session failed ordinary renewal: %+v", renewed)
				}
			})
		}
	}
}

func TestTLS12TicketMetadataLineageAndStandardBridge(t *testing.T) {
	client, server, cache, clock := metadataHandshakeConfigs(t)
	assertMetadataHandshake(t, runMetadataHandshake(t, client, server, HelloChrome_155, metadataTLS12Peer{}), false)
	original, first := cachedMetadata(t, cache)
	_, originalState, _ := original.ResumptionState()
	originalState.Extra = append(originalState.Extra, []byte("application/v1:do-not-inherit"), nil)
	sourceBytes, err := originalState.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	bridged := metadataStandardBridge(t, original)
	_, bridgedState, _ := bridged.ResumptionState()
	bridgedBytes, err := bridgedState.Bytes()
	if err != nil || !bytes.Equal(bridgedBytes, sourceBytes) || !bytes.Equal(bridged.SessionTicket(), original.SessionTicket()) {
		t.Fatalf("stdlib bridge changed secret-bearing state: %v", err)
	}
	cache.Put("ticket.example", bridged)
	clock.set(metadataHandshakeTime.Add(10 * time.Minute))
	assertMetadataHandshake(t, runMetadataHandshake(t, client, server, HelloChrome_155, metadataTLS12Peer{}), true)
	renewed, second := cachedMetadata(t, cache)
	if !second.Resumed || !second.OriginalSessionKnown || !second.PreviousTicketReceivedAtKnown ||
		second.SessionCreatedAt != first.SessionCreatedAt || second.SessionAuthenticatedAt != first.SessionAuthenticatedAt ||
		second.PreviousTicketReceivedAt != first.TicketReceivedAt || !second.TicketReceivedAt.After(first.TicketReceivedAt) ||
		bytes.Equal(renewed.SessionTicket(), original.SessionTicket()) {
		t.Fatalf("renewal refreshed original age or lost predecessor: first=%+v second=%+v", first, second)
	}

	_, renewedState, _ := renewed.ResumptionState()
	if len(renewedState.Extra) != 1 {
		t.Fatalf("renewal inherited foreign Extra: %q", renewedState.Extra)
	}
	unchanged, err := originalState.Bytes()
	if err != nil || !bytes.Equal(unchanged, sourceBytes) {
		t.Fatal("renewal mutated the original cache state")
	}

	// Rejected resumption has an offered predecessor but creates new lineage.
	var replacement [32]byte
	if _, err := rand.Read(replacement[:]); err != nil {
		t.Fatal(err)
	}
	server.SetSessionTicketKeys([][32]byte{replacement})
	clock.set(metadataHandshakeTime.Add(20 * time.Minute))
	assertMetadataHandshake(t, runMetadataHandshake(t, client, server, HelloChrome_155, metadataTLS12Peer{}), false)
	_, third := cachedMetadata(t, cache)
	if third.Resumed || !third.OriginalSessionKnown || third.PreviousTicketReceivedAtKnown ||
		!third.SessionCreatedAt.After(second.TicketReceivedAt) || !third.SessionAuthenticatedAt.After(third.TicketReceivedAt) {
		t.Fatalf("server rejection inherited old session age: %+v", third)
	}
}

func TestTLS12TicketMetadataLegacyRenewal(t *testing.T) {
	client, server, cache, clock := metadataHandshakeConfigs(t)
	assertMetadataHandshake(t, runMetadataHandshake(t, client, server, HelloGolang, metadataTLS12Peer{}), false)
	state, _ := cache.snapshot()
	_, session, _ := state.ResumptionState()
	session.Extra = [][]byte{[]byte("legacy/application-state")}
	cache.Put("ticket.example", metadataStandardBridge(t, state))
	for i := 0; i < 2; i++ {
		clock.set(metadataHandshakeTime.Add(time.Duration(i+1) * time.Minute))
		assertMetadataHandshake(t, runMetadataHandshake(t, client, server, HelloGolang, metadataTLS12Peer{}), true)
		_, info := cachedMetadata(t, cache)
		if !info.Resumed || info.OriginalSessionKnown || !info.SessionCreatedAt.IsZero() || !info.SessionAuthenticatedAt.IsZero() ||
			info.PreviousTicketReceivedAtKnown != (i == 1) {
			t.Fatalf("legacy renewal invented original age: %+v", info)
		}
	}
}

func TestTLS12TicketMetadataRejectsUnauthenticatedIssuance(t *testing.T) {
	for _, failure := range []string{"certificate", "finished", "finished-resumed", "truncated", "verify-full", "verify-resumed"} {
		t.Run(failure, func(t *testing.T) {
			client, server, cache, _ := metadataHandshakeConfigs(t)
			if strings.HasSuffix(failure, "-resumed") {
				assertMetadataHandshake(t, runMetadataHandshake(t, client, server, HelloChrome_155, metadataTLS12Peer{}), false)
			}
			_, before := cache.snapshot()
			proofErr := errors.New("metadata test rejects authenticated peer")
			options := metadataTLS12Peer{}
			switch failure {
			case "certificate":
				client.RootCAs = x509.NewCertPool()
			case "finished", "finished-resumed":
				options.transform, options.badFinished = true, true
				if state, _ := cache.snapshot(); state != nil {
					options.secret = slices.Clone(state.MasterSecret())
				}
			case "truncated":
				options.transform, options.stopAfterTicket = true, true
			case "verify-full", "verify-resumed":
				client.VerifyConnection = func(ConnectionState) error { return proofErr }
			}

			run := runMetadataHandshake(t, client, server, HelloChrome_155, options)
			if run.err == nil {
				t.Fatal("unauthenticated or explicitly rejected ticket completed handshake")
			}
			if failure == "certificate" && !strings.Contains(run.err.Error(), "unknown authority") {
				t.Fatalf("test did not reach certificate trust validation: %v", run.err)
			}
			if strings.HasPrefix(failure, "finished") && (!run.peer.checkedProof || !strings.Contains(run.err.Error(), "Finished message was incorrect")) {
				t.Fatalf("test did not reach Finished proof validation: %v", run.err)
			}
			if failure == "truncated" && !run.peer.seenTicket {
				t.Fatal("test did not stage a ticket before truncating the handshake")
			}
			if failure == "truncated" && !errors.Is(run.err, io.EOF) && !errors.Is(run.err, io.ErrUnexpectedEOF) {
				t.Fatalf("test did not fail on truncated peer flight: %v", run.err)
			}
			if strings.HasPrefix(failure, "verify-") && !errors.Is(run.err, proofErr) {
				t.Fatalf("VerifyConnection failure was lost: %v", run.err)
			}
			if _, after := cache.snapshot(); after != before {
				t.Fatalf("failed handshake committed a staged ticket: before=%d after=%d", before, after)
			}
			if state, _ := cache.snapshot(); strings.HasSuffix(failure, "-resumed") && state != nil {
				t.Fatal("failed resumed handshake retained the rejected cached session")
			}
		})
	}
}

func TestTLS12TicketMetadataEmptyTicketPreservesEngineDefaults(t *testing.T) {
	client, server, cache, _ := metadataHandshakeConfigs(t)
	server.WrapSession = func(stdtls.ConnectionState, *stdtls.SessionState) ([]byte, error) {
		return []byte{}, nil
	}
	run := runMetadataHandshake(t, client, server, HelloGolang, metadataTLS12Peer{transform: true})
	assertMetadataHandshake(t, run, false)
	state, info := cachedMetadata(t, cache)
	if !run.peer.seenTicket || !run.peer.checkedProof || len(state.SessionTicket()) != 0 || !info.OriginalSessionKnown {
		t.Fatal("empty authenticated NST changed engine behavior or lost recorded facts")
	}
	assertMetadataHandshake(t, runMetadataHandshake(t, client, server, HelloGolang, metadataTLS12Peer{}), false)
}

func TestTLS12TicketMetadataCanceledAfterReceipt(t *testing.T) {
	client, server, cache, clock := metadataHandshakeConfigs(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	received := make(chan struct{}, 1)
	client.Time = func() time.Time {
		now := clock.time()
		select {
		case <-ready:
			select {
			case received <- struct{}{}:
			default:
			}
		default:
		}
		return now
	}
	go func() {
		select {
		case <-received:
			cancel()
		case <-ctx.Done():
		}
	}()
	run := runMetadataHandshake(t, client, server, HelloGolang, metadataTLS12Peer{
		transform: true, ticketReady: ready, finishedGate: make(chan struct{}), handshakeContext: ctx,
	})
	if !errors.Is(run.err, context.Canceled) || !run.peer.seenTicket {
		t.Fatalf("did not cancel between authenticated message receipt and Finished: %v", run.err)
	}
	if state, count := cache.snapshot(); state != nil || count != 0 {
		t.Fatal("cancellation committed an unauthenticated ticket")
	}
}

func TestTLS12TicketMetadataFinalResumedWriteFailureDoesNotCommit(t *testing.T) {
	client, server, cache, _ := metadataHandshakeConfigs(t)
	assertMetadataHandshake(t, runMetadataHandshake(t, client, server, HelloChrome_155, metadataTLS12Peer{}), false)
	source, before := cache.snapshot()
	sentinel := errors.New("final resumed TLS flight write failed")
	broken := &metadataFinalWriteFailure{err: sentinel}
	client.VerifyConnection = func(state ConnectionState) error {
		if !state.DidResume || len(state.VerifiedChains) != 1 {
			return errors.New("final-write fixture did not authenticate a resumed peer")
		}
		// VerifyConnection is called after validating the resumed peer's
		// Finished and before sending the final local CCS/Finished flight.
		broken.armed.Store(true)
		return nil
	}
	run := runMetadataHandshake(t, client, server, HelloChrome_155, metadataTLS12Peer{
		transform: true, secret: slices.Clone(source.MasterSecret()), clientWriteFailure: broken,
	})
	if !errors.Is(run.err, sentinel) || !broken.failed.Load() || !run.peer.seenTicket || !run.peer.checkedProof {
		t.Fatalf("did not fail the final flight after authenticating NST/Finished: client=%v server=%v", run.err, run.serverErr)
	}
	if state, commits := cache.snapshot(); state != nil || commits != before {
		t.Fatalf("failed final flight committed a ticket or retained rejected source: state=%v before=%d after=%d", state != nil, before, commits)
	}
}

func TestTLS12TicketMetadataConcurrentRenewalsPreserveSource(t *testing.T) {
	client, server, cache, _ := metadataHandshakeConfigs(t)
	assertMetadataHandshake(t, runMetadataHandshake(t, client, server, HelloChrome_155, metadataTLS12Peer{}), false)
	source, first := cachedMetadata(t, cache)
	_, original, _ := source.ResumptionState()
	original.Extra = append(original.Extra, []byte("application/shared-state"))
	before, err := original.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	var workers sync.WaitGroup
	for i := range 8 {
		workers.Go(func() {
			localCache := &metadataHandshakeCache{state: source}
			clock := &metadataHandshakeClock{now: metadataHandshakeTime.Add(time.Duration(i+1) * time.Minute)}
			config := client.Clone()
			config.ClientSessionCache, config.Time = localCache, clock.time
			run := runMetadataHandshake(t, config, server, HelloChrome_155, metadataTLS12Peer{})
			if run.err != nil || run.serverErr != nil || !run.client.DidResume || !run.server.DidResume {
				t.Errorf("concurrent renewal failed: client=%v server=%v", run.err, run.serverErr)
				return
			}

			state, _ := localCache.snapshot()
			info, ok := state.TLS12TicketMetadata()
			_, current, _ := state.ResumptionState()
			if !ok || info.SessionCreatedAt != first.SessionCreatedAt ||
				info.SessionAuthenticatedAt != first.SessionAuthenticatedAt || info.PreviousTicketReceivedAt != first.TicketReceivedAt ||
				len(current.Extra) != 1 {
				t.Errorf("concurrent renewal changed lineage or inherited application state: %+v", info)
			}
		})
	}
	workers.Wait()
	after, err := original.Bytes()
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("concurrent renewals mutated shared source state")
	}
}

func TestTLS12TicketMetadataDisabledCachingAndIssuance(t *testing.T) {
	for _, disabled := range []string{"client", "server", "cache"} {
		t.Run(disabled, func(t *testing.T) {
			client, server, cache, _ := metadataHandshakeConfigs(t)
			switch disabled {
			case "client":
				client.SessionTicketsDisabled = true
			case "server":
				server.SessionTicketsDisabled = true
			case "cache":
				client.ClientSessionCache = nil
			}

			run := runMetadataHandshake(t, client, server, HelloGolang, metadataTLS12Peer{transform: true})
			assertMetadataHandshake(t, run, false)
			if run.peer.seenTicket {
				t.Fatal("disabled tickets were issued on wire")
			}
			if state, count := cache.snapshot(); state != nil || count != 0 {
				t.Fatal("disabled caching produced a session commit")
			}
		})
	}
}

func TestTLS12TicketMetadataOutOfRangeClockDoesNotChangeHandshake(t *testing.T) {
	client, server, cache, clock := metadataHandshakeConfigs(t)
	client.VerifyConnection = func(ConnectionState) error {
		clock.set(time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC))
		return nil
	}
	run := runMetadataHandshake(t, client, server, HelloGolang, metadataTLS12Peer{})
	assertMetadataHandshake(t, run, false)
	state, count := cache.snapshot()
	if state == nil || count != 1 || len(state.SessionTicket()) == 0 {
		t.Fatal("metadata range checks changed default ticket caching")
	}
	if _, ok := state.TLS12TicketMetadata(); ok {
		t.Fatal("unrepresentable clock was serialized as valid metadata")
	}
}
