package tls

import (
	"bytes"
	"errors"
	"testing"
)

type earlySecretFailingKeyLog struct {
	err    error
	failed bool
}

func (w *earlySecretFailingKeyLog) Write(p []byte) (int, error) {
	if bytes.HasPrefix(p, []byte(keyLogLabelClientEarly+" ")) {
		w.failed = true
		return 0, w.err
	}

	return len(p), nil
}

func TestUQUICEarlySecretKeyLogFailureAbortsResumption(t *testing.T) {
	clientConfig := testConfigClient.Clone()
	clientConfig.NextProtos = []string{"h3"}
	clientConfig.ClientSessionCache = NewLRUClientSessionCache(1)
	serverConfig := testConfigServer.Clone()
	serverConfig.NextProtos = []string{"h3"}
	serverConfig.SetSessionTicketKeys([][32]byte{{1, 2, 3}})

	warmClient := newTestQUICClient(t, &QUICConfig{TLSConfig: clientConfig})
	warmServer := newTestQUICServer(t, &QUICConfig{TLSConfig: serverConfig})
	warmClient.conn.SetTransportParameters(nil)
	warmServer.conn.SetTransportParameters(nil)
	warmServer.ticketOpts.EarlyData = true
	if err := runTestQUICConnection(t.Context(), warmClient, warmServer, nil); err != nil {
		t.Fatal(err)
	}

	sentinel := errors.New("early traffic key log failed")
	keyLog := &earlySecretFailingKeyLog{err: sentinel}
	clientConfig = clientConfig.Clone()
	clientConfig.KeyLogWriter = keyLog
	client := UQUICClient(&QUICConfig{TLSConfig: clientConfig}, HelloCustom)
	defer client.Close()
	preset := go127ClientHelloSpec([]SignatureScheme{ECDSAWithP256AndSHA256})
	preset.CipherSuites = []uint16{warmClient.conn.ConnectionState().CipherSuite}
	preset.Extensions = append(preset.Extensions,
		&ALPNExtension{AlpnProtocols: []string{"h3"}},
		&QUICTransportParametersExtension{},
		&PSKKeyExchangeModesExtension{Modes: []uint8{PskModeDHE}},
		&EarlyDataExtension{},
		&UtlsPreSharedKeyExtension{},
	)
	if err := client.ApplyPreset(preset); err != nil {
		t.Fatal(err)
	}

	client.SetTransportParameters(nil)
	server := QUICServer(&QUICConfig{TLSConfig: serverConfig})
	defer server.Close()
	server.SetTransportParameters(nil)
	_, err := runUQUICHandshake(t.Context(), client, server)
	if !keyLog.failed || !errors.Is(err, sentinel) || client.ConnectionState().HandshakeComplete {
		t.Fatalf("failed early-secret logging did not abort the resumed handshake: failed=%t err=%v", keyLog.failed, err)
	}
}
