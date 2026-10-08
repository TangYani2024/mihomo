package outbound

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	tlsC "github.com/metacubex/mihomo/component/tls"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/tls"
	utls "github.com/metacubex/utls"
	"github.com/metacubex/yamux"
)

var mirageMagicHeader = []byte{'M', 'R', 'G', '1'}

const (
	mirageAddrTypeIPv4   = 0x01
	mirageAddrTypeDomain = 0x03
	mirageAddrTypeIPv6   = 0x04
)

type Mirage struct {
	*Base
	option *MirageOption
	pool   *mirageMuxPool
}

type MirageOption struct {
	BasicOption
	Name              string `proxy:"name"`
	Server            string `proxy:"server"`
	Port              int    `proxy:"port"`
	Secret            string `proxy:"secret"`
	SNI               string `proxy:"sni,omitempty"`
	SkipCertVerify    bool   `proxy:"skip-cert-verify,omitempty"`
	ClientFingerprint string `proxy:"client-fingerprint,omitempty"`
	PoolSize          int    `proxy:"pool-size,omitempty"`
}

type mirageMuxPool struct {
	dialer      C.Dialer
	serverAddr  string
	serverName  string
	secret      []byte
	insecure    bool
	fingerprint utls.ClientHelloID
	poolSize    int

	mu       sync.RWMutex
	sessions []*yamux.Session
	index    uint64
	closed   bool
	closeCh  chan struct{}
}

func generateMirageAuthToken(secret []byte) []byte {
	token := make([]byte, 44)
	copy(token[0:4], mirageMagicHeader)

	now := time.Now().Unix()
	binary.BigEndian.PutUint64(token[4:12], uint64(now))

	mac := hmac.New(sha256.New, secret)
	mac.Write(token[4:12])
	expected := mac.Sum(nil)
	copy(token[12:44], expected)

	return token
}

func writeTargetAddr(w io.Writer, metadata *C.Metadata) error {
	port := metadata.DstPort
	if metadata.Host != "" {
		host := metadata.Host
		if len(host) > 255 {
			return errors.New("host name too long")
		}
		buf := make([]byte, 1+1+len(host)+2)
		buf[0] = mirageAddrTypeDomain
		buf[1] = byte(len(host))
		copy(buf[2:2+len(host)], host)
		binary.BigEndian.PutUint16(buf[2+len(host):], port)
		_, err := w.Write(buf)
		return err
	}

	if metadata.DstIP.IsValid() {
		if metadata.DstIP.Is4() {
			buf := make([]byte, 1+4+2)
			buf[0] = mirageAddrTypeIPv4
			ip4 := metadata.DstIP.As4()
			copy(buf[1:5], ip4[:])
			binary.BigEndian.PutUint16(buf[5:7], port)
			_, err := w.Write(buf)
			return err
		} else if metadata.DstIP.Is6() {
			buf := make([]byte, 1+16+2)
			buf[0] = mirageAddrTypeIPv6
			ip6 := metadata.DstIP.As16()
			copy(buf[1:17], ip6[:])
			binary.BigEndian.PutUint16(buf[17:19], port)
			_, err := w.Write(buf)
			return err
		}
	}

	target := metadata.RemoteAddress()
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	p, err := strconv.Atoi(portStr)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		buf := make([]byte, 1+4+2)
		buf[0] = mirageAddrTypeIPv4
		copy(buf[1:5], ip4)
		binary.BigEndian.PutUint16(buf[5:7], uint16(p))
		_, err := w.Write(buf)
		return err
	} else if ip != nil {
		buf := make([]byte, 1+16+2)
		buf[0] = mirageAddrTypeIPv6
		copy(buf[1:17], ip)
		binary.BigEndian.PutUint16(buf[17:19], uint16(p))
		_, err := w.Write(buf)
		return err
	} else {
		if len(host) > 255 {
			return errors.New("host name too long")
		}
		buf := make([]byte, 1+1+len(host)+2)
		buf[0] = mirageAddrTypeDomain
		buf[1] = byte(len(host))
		copy(buf[2:2+len(host)], host)
		binary.BigEndian.PutUint16(buf[2+len(host):], uint16(p))
		_, err := w.Write(buf)
		return err
	}
}

func (p *mirageMuxPool) createSession(ctx context.Context) (*yamux.Session, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	rawConn, err := p.dialer.DialContext(dialCtx, "tcp", p.serverAddr)
	if err != nil {
		return nil, fmt.Errorf("dial %s failed: %w", p.serverAddr, err)
	}

	uConfig := &utls.Config{
		ServerName:         p.serverName,
		InsecureSkipVerify: p.insecure,
		RootCAs:            ca.GetCertPool(),
		MinVersion:         tls.VersionTLS13,
	}

	uConn := utls.UClient(rawConn, uConfig, p.fingerprint)
	if err := uConn.HandshakeContext(dialCtx); err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("uTLS handshake failed: %w", err)
	}

	token := generateMirageAuthToken(p.secret)
	if _, err := uConn.Write(token); err != nil {
		_ = uConn.Close()
		return nil, fmt.Errorf("send auth token failed: %w", err)
	}

	yConf := yamux.DefaultConfig()
	yConf.EnableKeepAlive = true
	yConf.KeepAliveInterval = time.Duration(25+rand.Intn(11)) * time.Second
	yConf.MaxStreamWindowSize = 1024 * 1024
	yConf.LogOutput = io.Discard

	session, err := yamux.Client(uConn, yConf, nil)
	if err != nil {
		_ = uConn.Close()
		return nil, fmt.Errorf("yamux init failed: %w", err)
	}

	return session, nil
}

func (p *mirageMuxPool) GetStream(ctx context.Context) (*yamux.Stream, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	p.mu.RLock()
	if p.closed {
		p.mu.RUnlock()
		return nil, errors.New("mirage pool is closed")
	}

	var active []*yamux.Session
	for _, s := range p.sessions {
		if !s.IsClosed() {
			active = append(active, s)
		}
	}
	p.mu.RUnlock()

	if len(active) > 0 {
		idx := atomic.AddUint64(&p.index, 1) % uint64(len(active))
		s := active[idx]
		stream, err := s.OpenStream(ctx)
		if err == nil {
			return stream, nil
		}
	}

	s, err := p.createSession(ctx)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		_ = s.Close()
		return nil, errors.New("mirage pool is closed")
	}
	p.sessions = append(p.sessions, s)
	p.mu.Unlock()

	return s.OpenStream(ctx)
}

func (p *mirageMuxPool) maintainPool() {
	go func() {
		for {
			select {
			case <-p.closeCh:
				return
			case <-time.After(time.Duration(3000+rand.Intn(2000)) * time.Millisecond):
			}

			p.mu.Lock()
			if p.closed {
				p.mu.Unlock()
				return
			}
			active := make([]*yamux.Session, 0, p.poolSize)
			for _, s := range p.sessions {
				if !s.IsClosed() {
					active = append(active, s)
				}
			}
			p.sessions = active
			needed := p.poolSize - len(p.sessions)
			p.mu.Unlock()

			for i := 0; i < needed; i++ {
				select {
				case <-p.closeCh:
					return
				case <-time.After(time.Duration(150+rand.Intn(500)) * time.Millisecond):
				}

				s, err := p.createSession(context.Background())
				if err != nil {
					log.Debugln("[Mirage] maintain pool create session failed: %v", err)
					break
				}
				p.mu.Lock()
				if p.closed {
					p.mu.Unlock()
					_ = s.Close()
					return
				}
				p.sessions = append(p.sessions, s)
				p.mu.Unlock()
			}
		}
	}()
}

func (p *mirageMuxPool) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	close(p.closeCh)
	sessions := p.sessions
	p.sessions = nil
	p.mu.Unlock()

	for _, s := range sessions {
		_ = s.Close()
	}
	return nil
}

func (m *Mirage) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	stream, err := m.pool.GetStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s get stream error: %w", m.addr, err)
	}

	defer func() {
		if err != nil {
			_ = stream.Close()
		}
	}()

	if err = writeTargetAddr(stream, metadata); err != nil {
		return nil, fmt.Errorf("%s write target error: %w", m.addr, err)
	}

	var status [1]byte
	if _, err = io.ReadFull(stream, status[:]); err != nil {
		return nil, fmt.Errorf("%s read status error: %w", m.addr, err)
	}

	if status[0] != 0x00 {
		return nil, fmt.Errorf("%s target connect rejected by remote", m.addr)
	}

	return NewConn(stream, m), nil
}

func (m *Mirage) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	return nil, C.ErrNotSupport
}

func (m *Mirage) SupportUDP() bool {
	return false
}

func (m *Mirage) SupportUOT() bool {
	return false
}

func (m *Mirage) ProxyInfo() C.ProxyInfo {
	info := m.Base.ProxyInfo()
	info.DialerProxy = m.option.DialerProxy
	info.SMUX = true
	return info
}

func (m *Mirage) Close() error {
	if m.pool != nil {
		_ = m.pool.Close()
	}
	return m.Base.Close()
}

func NewMirage(option MirageOption) (*Mirage, error) {
	if option.Server == "" || option.Port <= 0 || option.Port > 0xffff {
		return nil, fmt.Errorf("mirage %s requires a valid server and port", option.Name)
	}
	if option.Secret == "" {
		return nil, fmt.Errorf("mirage %s requires secret", option.Name)
	}
	if option.SNI == "" {
		option.SNI = option.Server
	}
	if option.PoolSize <= 0 {
		option.PoolSize = 3
	}

	fingerprint := utls.HelloChrome_Auto
	if option.ClientFingerprint != "" {
		if fp, ok := tlsC.GetFingerprint(option.ClientFingerprint); ok {
			fingerprint = fp
		}
	}

	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	m := &Mirage{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.Mirage,
			ProviderName: option.ProviderName,
			UDP:          false,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option: &option,
	}

	dialer := option.NewDialer(m.DialOptions())
	pool := &mirageMuxPool{
		dialer:      dialer,
		serverAddr:  addr,
		serverName:  option.SNI,
		secret:      []byte(option.Secret),
		insecure:    option.SkipCertVerify,
		fingerprint: fingerprint,
		poolSize:    option.PoolSize,
		sessions:    make([]*yamux.Session, 0, option.PoolSize),
		closeCh:     make(chan struct{}),
	}
	pool.maintainPool()
	m.pool = pool

	return m, nil
}
