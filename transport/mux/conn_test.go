package mux

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// oneByteConn 每次 Read 最多返回 1 字节，模拟极端 TCP 分片。
type oneByteConn struct {
	data []byte
	pos  int
}

func (c *oneByteConn) Read(p []byte) (int, error) {
	if c.pos >= len(c.data) {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = c.data[c.pos]
	c.pos++
	return 1, nil
}

func (c *oneByteConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *oneByteConn) Close() error                { return nil }
func (c *oneByteConn) LocalAddr() net.Addr         { return nil }
func (c *oneByteConn) RemoteAddr() net.Addr        { return nil }
func (c *oneByteConn) SetDeadline(time.Time) error { return nil }
func (c *oneByteConn) SetReadDeadline(time.Time) error {
	return nil
}
func (c *oneByteConn) SetWriteDeadline(time.Time) error {
	return nil
}

// TestConnReadFragmentedStatus 回归测试：status 字段被 TCP 分片时
// 必须用 ReadFull 读满 2 字节，否则帧流永久错位（desync）。
func TestConnReadFragmentedStatus(t *testing.T) {
	payload := []byte("hello")
	var frame []byte
	// 帧头: 2B length(=4) + 2B id + 2B status + 2B dataLen + payload
	frame = binary.BigEndian.AppendUint16(frame, 4)
	frame = binary.BigEndian.AppendUint16(frame, 0)                  // id
	frame = binary.BigEndian.AppendUint16(frame, uint16(OptionData)) // status: keep=0, opts=OptionData
	frame = binary.BigEndian.AppendUint16(frame, uint16(len(payload)))
	frame = append(frame, payload...)

	c := &Conn{Conn: &oneByteConn{data: frame}}
	buf := make([]byte, len(payload))
	// Read 允许返回部分数据（m.remain 机制），用 io.ReadFull 读完整载荷。
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("got %q, want %q (frame stream desynced?)", buf, payload)
	}
}

// 保证 Conn 满足最小接口要求（编译期检查 oneByteConn 不会静默错用）。
var _ interface {
	Read([]byte) (int, error)
	io.Writer
	io.Closer
} = (*oneByteConn)(nil)

var _ = errors.New
