package naive

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"io"
	"testing"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/stretchr/testify/assert"
)

func TestPaddedWriteReadRoundTrip(t *testing.T) {
	// Test that padded writes can be correctly read back by padded reads.
	originalData := []byte("Hello, World! This is a test payload for naiveproxy padding.")

	var buf bytes.Buffer
	pw := newPaddedWriter(&buf, true)

	n, err := pw.Write(originalData)
	assert.NoError(t, err)
	assert.Equal(t, len(originalData), n)

	// Read back with padded reader
	pr := newPaddedReader(&buf, true)
	readBuf := make([]byte, len(originalData)+256) // extra space
	n, err = pr.Read(readBuf)
	assert.NoError(t, err)
	assert.Equal(t, len(originalData), n)
	assert.Equal(t, originalData, readBuf[:n])
}

func TestPaddedWriteReadMultipleChunks(t *testing.T) {
	// Test multiple write/read operations with padding.
	chunks := [][]byte{
		[]byte("chunk1"),
		[]byte("chunk2_with_more_data"),
		[]byte("c3"),
		[]byte("chunk_number_four"),
		[]byte("5"),
		[]byte("sixth"),
		[]byte("seven"),
		[]byte("eighth_and_final"),
	}

	var buf bytes.Buffer
	pw := newPaddedWriter(&buf, true)

	for _, chunk := range chunks {
		n, err := pw.Write(chunk)
		assert.NoError(t, err)
		assert.Equal(t, len(chunk), n)
	}

	// After kFirstPaddings (8), further writes should be unpadded.
	extraData := []byte("this_should_be_unpadded")
	n, err := pw.Write(extraData)
	assert.NoError(t, err)
	assert.Equal(t, len(extraData), n)

	// Read all back
	pr := newPaddedReader(&buf, true)
	var allRead []byte
	readBuf := make([]byte, 4096)
	for {
		n, err = pr.Read(readBuf)
		if err == io.EOF {
			break
		}
		assert.NoError(t, err)
		allRead = append(allRead, readBuf[:n]...)
	}

	expected := bytes.Join(chunks, nil)
	expected = append(expected, extraData...)
	assert.Equal(t, expected, allRead)
}

func TestPaddedReaderSmallBufferDoesNotLoseData(t *testing.T) {
	originalData := []byte("small buffer should still receive the entire padded frame")

	var buf bytes.Buffer
	pw := newPaddedWriter(&buf, true)
	n, err := pw.Write(originalData)
	assert.NoError(t, err)
	assert.Equal(t, len(originalData), n)

	pr := newPaddedReader(&buf, true)
	readBuf := make([]byte, 7)
	var allRead []byte
	for {
		n, err = pr.Read(readBuf)
		if err == io.EOF {
			break
		}
		assert.NoError(t, err)
		allRead = append(allRead, readBuf[:n]...)
	}

	assert.Equal(t, originalData, allRead)
}

func TestPaddedWriteDisabled(t *testing.T) {
	// When padding is disabled, data should pass through unchanged.
	originalData := []byte("unpadded data")

	var buf bytes.Buffer
	pw := newPaddedWriter(&buf, false)

	n, err := pw.Write(originalData)
	assert.NoError(t, err)
	assert.Equal(t, len(originalData), n)
	assert.Equal(t, originalData, buf.Bytes())
}

func TestPaddedReadDisabled(t *testing.T) {
	// When padding is disabled, data should pass through unchanged.
	originalData := []byte("unpadded data")

	pr := newPaddedReader(bytes.NewReader(originalData), false)
	readBuf := make([]byte, len(originalData))

	n, err := pr.Read(readBuf)
	assert.NoError(t, err)
	assert.Equal(t, len(originalData), n)
	assert.Equal(t, originalData, readBuf)
}

func TestLargePayloadSplit(t *testing.T) {
	// Test that payloads larger than 65535 are split correctly.
	largeData := make([]byte, 70000)
	_, _ = rand.Read(largeData)

	var buf bytes.Buffer
	pw := newPaddedWriter(&buf, true)

	n, err := pw.Write(largeData)
	assert.NoError(t, err)
	assert.Equal(t, len(largeData), n)

	// Read back
	pr := newPaddedReader(&buf, true)
	readBuf := make([]byte, len(largeData))
	totalRead := 0
	for totalRead < len(largeData) {
		n, err = pr.Read(readBuf[totalRead:])
		if err != nil && err != io.EOF {
			assert.NoError(t, err)
		}
		totalRead += n
		if err == io.EOF {
			break
		}
	}
	assert.Equal(t, largeData, readBuf[:totalRead])
}

func TestGeneratePaddingHeader(t *testing.T) {
	header := GeneratePaddingHeaderRequest()
	assert.GreaterOrEqual(t, len(header), kMinPaddingHeaderLen)
	assert.LessOrEqual(t, len(header), kMaxPaddingHeaderLen)

	headerResp := GeneratePaddingHeaderResponse()
	assert.GreaterOrEqual(t, len(headerResp), kMinPaddingHeaderLenResp)
	assert.LessOrEqual(t, len(headerResp), kMaxPaddingHeaderLenResp)
}

func TestParseNaiveURL(t *testing.T) {
	tests := []struct {
		name      string
		link      string
		wantErr   bool
		wantProto string
		wantUser  string
		wantPass  string
		wantHost  string
		wantPort  int
		wantSni   string
		wantInsec bool
	}{
		{
			name:      "basic https",
			link:      "naive+https://user:pass@example.com:443#MyProxy",
			wantErr:   false,
			wantProto: "naive+https",
			wantUser:  "user",
			wantPass:  "pass",
			wantHost:  "example.com",
			wantPort:  443,
			wantSni:   "example.com",
		},
		{
			name:      "default port",
			link:      "naive+https://user:pass@example.com",
			wantErr:   false,
			wantProto: "naive+https",
			wantUser:  "user",
			wantPass:  "pass",
			wantHost:  "example.com",
			wantPort:  443,
			wantSni:   "example.com",
		},
		{
			name:      "custom sni",
			link:      "naive+https://user:pass@example.com:8443?sni=cdn.example.com#tag",
			wantErr:   false,
			wantProto: "naive+https",
			wantUser:  "user",
			wantPass:  "pass",
			wantHost:  "example.com",
			wantPort:  8443,
			wantSni:   "cdn.example.com",
		},
		{
			name:      "quic scheme",
			link:      "naive+quic://user:pass@example.com:443",
			wantErr:   false,
			wantProto: "naive+quic",
			wantUser:  "user",
			wantPass:  "pass",
			wantHost:  "example.com",
			wantPort:  443,
			wantSni:   "example.com",
		},
		{
			name:      "allow insecure alias",
			link:      "naive+https://user:pass@example.com:443?allowinsecure=1",
			wantErr:   false,
			wantProto: "naive+https",
			wantUser:  "user",
			wantPass:  "pass",
			wantHost:  "example.com",
			wantPort:  443,
			wantSni:   "example.com",
			wantInsec: true,
		},
		{
			name:    "unsupported scheme",
			link:    "http://user:pass@example.com",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := parseNaiveURL(tt.link)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.wantProto, s.Protocol)
			assert.Equal(t, tt.wantUser, s.Username)
			assert.Equal(t, tt.wantPass, s.Password)
			assert.Equal(t, tt.wantHost, s.Server)
			assert.Equal(t, tt.wantPort, s.Port)
			assert.Equal(t, tt.wantSni, s.Sni)
			assert.Equal(t, tt.wantInsec, s.AllowInsecure)
		})
	}
}

func TestExportToURL(t *testing.T) {
	s := &Naive{
		Name:          "TestProxy",
		Server:        "example.com",
		Port:          443,
		Username:      "user",
		Password:      "pass",
		Sni:           "cdn.example.com",
		AllowInsecure: true,
		Protocol:      "naive+https",
	}

	link := s.exportToURL()
	assert.Contains(t, link, "naive+https://")
	assert.Contains(t, link, "user:pass@example.com:443")
	assert.Contains(t, link, "sni=cdn.example.com")
	assert.Contains(t, link, "allowInsecure=1")
	assert.Contains(t, link, "#TestProxy")

	// Parse it back
	s2, err := parseNaiveURL(link)
	assert.NoError(t, err)
	assert.Equal(t, s.Name, s2.Name)
	assert.Equal(t, s.Server, s2.Server)
	assert.Equal(t, s.Port, s2.Port)
	assert.Equal(t, s.Username, s2.Username)
	assert.Equal(t, s.Password, s2.Password)
	assert.Equal(t, s.Sni, s2.Sni)
	assert.Equal(t, s.AllowInsecure, s2.AllowInsecure)
	assert.Equal(t, s.Protocol, s2.Protocol)
}

func TestNewNaiveRejectsQuic(t *testing.T) {
	_, _, err := NewNaive(&dialer.ExtraOption{}, nil, "naive+quic://user:pass@example.com:443")
	assert.EqualError(t, err, "naive+quic is not supported yet")
}

func TestNewConnectRequestUsesProxyAuthorization(t *testing.T) {
	d := &naiveDialer{
		username: "user",
		password: "pass",
	}

	req, pw, err := d.newConnectRequest("example.com:443")
	assert.NoError(t, err)
	assert.NotNil(t, pw)
	assert.Equal(t, "Basic "+base64.StdEncoding.EncodeToString([]byte("user:pass")), req.Header.Get("Proxy-Authorization"))
	assert.Empty(t, req.Header.Get("Authorization"))
	assert.NotEmpty(t, req.Header.Get(paddingHeaderKey))
}
