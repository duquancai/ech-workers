package ech

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	TypeHTTPS     = 65
	MaxRetries    = 5
	RetryInterval = 2 * time.Second
)

type ECHManager struct {
	echList   []byte
	echListMu sync.RWMutex
	echDomain string
	dnsServer string
}

func NewECHManager(echDomain, dnsServer string) *ECHManager {
	return &ECHManager{
		echDomain: echDomain,
		dnsServer: dnsServer,
	}
}

func (m *ECHManager) Prepare() error {
	for attempt := 1; attempt <= MaxRetries; attempt++ {
		echBase64, err := m.queryHTTPSRecord(m.echDomain, m.dnsServer)
		if err != nil {
			log.Printf("[客户端] DNS 查询失败 (%d/%d): %v，%v后重试...", attempt, MaxRetries, err, RetryInterval)
			time.Sleep(RetryInterval)
			continue
		}
		if echBase64 == "" {
			log.Printf("[客户端] 未找到 ECH 参数 (%d/%d)，%v后重试...", attempt, MaxRetries, RetryInterval)
			time.Sleep(RetryInterval)
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(echBase64)
		if err != nil {
			log.Printf("[客户端] ECH Base64 解码失败 (%d/%d): %v，%v后重试...", attempt, MaxRetries, err, RetryInterval)
			time.Sleep(RetryInterval)
			continue
		}
		m.echListMu.Lock()
		m.echList = raw
		m.echListMu.Unlock()
		return nil
	}
	return errors.New("ECH配置获取失败，已达最大重试次数")
}

func (m *ECHManager) GetECHList() ([]byte, error) {
	m.echListMu.RLock()
	defer m.echListMu.RUnlock()
	if len(m.echList) == 0 {
		return nil, errors.New("ECH配置未加载")
	}
	return m.echList, nil
}

func (m *ECHManager) Refresh() error {
	return m.Prepare()
}

func (m *ECHManager) BuildTLSConfig(serverName string) (*tls.Config, error) {
	echBytes, err := m.GetECHList()
	if err != nil {
		return nil, err
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("加载系统根证书失败: %w", err)
	}
	return &tls.Config{
		MinVersion:                     tls.VersionTLS13,
		ServerName:                     serverName,
		EncryptedClientHelloConfigList: echBytes,
		EncryptedClientHelloRejectionVerify: func(cs tls.ConnectionState) error {
			return errors.New("服务器拒绝ECH")
		},
		RootCAs: roots,
	}, nil
}

func (m *ECHManager) queryHTTPSRecord(domain, dnsServer string) (string, error) {
	dohURL := dnsServer
	if !strings.HasPrefix(dohURL, "https://") && !strings.HasPrefix(dohURL, "http://") {
		dohURL = "https://" + dohURL
	}
	return m.queryDoH(domain, dohURL)
}

func (m *ECHManager) queryDoH(domain, dohURL string) (string, error) {
	u, err := url.Parse(dohURL)
	if err != nil {
		return "", fmt.Errorf("无效的DoH URL: %v", err)
	}

	dnsQuery := m.buildDNSQuery(domain, TypeHTTPS)
	dnsBase64 := base64.RawURLEncoding.EncodeToString(dnsQuery)

	q := u.Query()
	q.Set("dns", dnsBase64)
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("创建请求失败: %v", err)
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("DoH请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("DoH服务器返回错误: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("读取DoH响应失败: %v", err)
	}

	return m.parseDNSResponse(body)
}

func (m *ECHManager) buildDNSQuery(domain string, qtype uint16) []byte {
	query := make([]byte, 0, 512)
	query = append(query, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	for _, label := range strings.Split(domain, ".") {
		query = append(query, byte(len(label)))
		query = append(query, []byte(label)...)
	}
	query = append(query, 0x00, byte(qtype>>8), byte(qtype), 0x00, 0x01)
	return query
}

func (m *ECHManager) parseDNSResponse(response []byte) (string, error) {
	if len(response) < 12 {
		return "", errors.New("响应过短")
	}

	ancount := binary.BigEndian.Uint16(response[6:8])
	if ancount == 0 {
		return "", errors.New("无应答记录")
	}
	offset := 12
	for offset < len(response) && response[offset] != 0 {
		offset += int(response[offset]) + 1
	}
	offset += 5

	for i := 0; i < int(ancount); i++ {
		if offset >= len(response) {
			break
		}
		if response[offset]&0xC0 == 0xC0 {
			offset += 2
		} else {
			for offset < len(response) && response[offset] != 0 {
				offset += int(response[offset]) + 1
			}
			offset++
		}

		if offset+10 > len(response) {
			break
		}

		rrType := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 8
		dataLen := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 2

		if offset+int(dataLen) > len(response) {
			break
		}

		data := response[offset : offset+int(dataLen)]
		offset += int(dataLen)

		if rrType == TypeHTTPS {
			if ech := m.parseHTTPSRecord(data); ech != "" {
				return ech, nil
			}
		}
	}
	return "", nil
}

func (m *ECHManager) parseHTTPSRecord(data []byte) string {
	if len(data) < 2 {
		return ""
	}

	offset := 2
	if offset >= len(data) {
		return ""
	}

	if data[offset] == 0 {
		offset++
	} else {
		for offset < len(data) && data[offset] != 0 {
			step := int(data[offset]) + 1
			if step <= 0 || offset+step > len(data) {
				return ""
			}
			offset += step
		}
		offset++
	}

	for offset+4 <= len(data) {
		if offset+4 > len(data) {
			return ""
		}

		key := binary.BigEndian.Uint16(data[offset : offset+2])
		length := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		offset += 4

		if length == 0 || offset+int(length) > len(data) {
			break
		}

		value := data[offset : offset+int(length)]
		offset += int(length)

		if key == 5 {
			return base64.StdEncoding.EncodeToString(value)
		}
	}
	return ""
}
