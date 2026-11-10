package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const dynv6APIBase = "https://dynv6.com/api/v2"

type dynv6Zone struct {
	ID   json.Number `json:"id"`
	Name string      `json:"name"`
}

type dynv6Record struct {
	ID   json.Number `json:"id"`
	Name string      `json:"name"`
	Type string      `json:"type"`
	Data string      `json:"data"`
}

type createdTXT struct {
	zoneID   string
	recordID string
}

// dynv6DNS 用 dynv6 HTTP API 完成 DNS-01 的 TXT 记录创建与清理。
type dynv6DNS struct {
	token  string
	base   string
	sleep  time.Duration
	client *http.Client

	mu      sync.Mutex
	zones   []dynv6Zone
	created map[string][]createdTXT
	cancel  <-chan struct{} // 任务取消信号，可中断 DNS 生效等待
	store   *txtStore       // 持久化待清理的 TXT 记录，异常退出后可对账
}

func newDynv6DNS(token string, sleep time.Duration) *dynv6DNS {
	return &dynv6DNS{
		token:   strings.TrimSpace(token),
		base:    dynv6APIBase,
		sleep:   sleep,
		client:  &http.Client{Timeout: 30 * time.Second},
		created: map[string][]createdTXT{},
	}
}

func (d *dynv6DNS) do(method, path string, body any) ([]byte, error) {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, d.base+path, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+d.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "dynv6-manager/"+Version)
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		text := strings.TrimSpace(string(data))
		if len(text) > 200 {
			text = text[:200]
		}
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return nil, fmt.Errorf("dynv6 API 返回 %d：HTTP Token 无效或无权访问该域名 %s", resp.StatusCode, text)
		}
		return nil, fmt.Errorf("dynv6 API 返回 %d：%s", resp.StatusCode, text)
	}
	return data, nil
}

func (d *dynv6DNS) loadZones() ([]dynv6Zone, error) {
	d.mu.Lock()
	if len(d.zones) > 0 {
		zones := d.zones
		d.mu.Unlock()
		return zones, nil
	}
	d.mu.Unlock()
	data, err := d.do(http.MethodGet, "/zones", nil)
	if err != nil {
		return nil, err
	}
	var zones []dynv6Zone
	if err := json.Unmarshal(data, &zones); err != nil {
		return nil, fmt.Errorf("解析 dynv6 zone 列表失败: %w", err)
	}
	if len(zones) == 0 {
		return nil, fmt.Errorf("当前 HTTP Token 下没有可用域名（zone）")
	}
	d.mu.Lock()
	d.zones = zones
	d.mu.Unlock()
	return zones, nil
}

func (d *dynv6DNS) zoneFor(fqdn string) (dynv6Zone, error) {
	fqdn = strings.TrimSuffix(fqdn, ".")
	zones, err := d.loadZones()
	if err != nil {
		return dynv6Zone{}, err
	}
	best := dynv6Zone{}
	for _, zone := range zones {
		if fqdn == zone.Name || strings.HasSuffix(fqdn, "."+zone.Name) {
			if len(zone.Name) > len(best.Name) {
				best = zone
			}
		}
	}
	if best.ID.String() == "" || best.ID.String() == "0" {
		return dynv6Zone{}, fmt.Errorf("找不到 %s 对应的 dynv6 zone：请确认 Token 有该域名权限", fqdn)
	}
	return best, nil
}

// challengeRecord 按 ACME 规范本地计算 TXT 记录，不做 CNAME/DNS 查询，
// 避免在 DNS 解析受限的环境里卡住（lego 的 GetRecord 会解析 CNAME）。
func challengeRecord(domain, keyAuth string) (fqdn, value string) {
	sum := sha256.Sum256([]byte(keyAuth))
	return "_acme-challenge." + strings.TrimSuffix(domain, ".") + ".", base64.RawURLEncoding.EncodeToString(sum[:])
}

// Present 创建 _acme-challenge TXT 记录；按配置等待 DNS 生效。
func (d *dynv6DNS) Present(domain, token, keyAuth string) error {
	fqdn, value := challengeRecord(domain, keyAuth)
	fqdn = strings.TrimSuffix(fqdn, ".")
	zone, err := d.zoneFor(fqdn)
	if err != nil {
		return err
	}
	name := strings.TrimSuffix(fqdn, "."+zone.Name)
	if fqdn == zone.Name {
		name = ""
	}
	data, err := d.do(http.MethodPost, "/zones/"+zone.ID.String()+"/records", map[string]string{
		"name": name,
		"type": "TXT",
		"data": value,
	})
	if err != nil {
		return fmt.Errorf("创建 TXT 记录 %s 失败: %w", fqdn, err)
	}
	var rec dynv6Record
	if err := json.Unmarshal(data, &rec); err != nil || rec.ID.String() == "" {
		return fmt.Errorf("创建 TXT 记录 %s 后无法解析返回结果", fqdn)
	}
	d.mu.Lock()
	d.created[fqdn] = append(d.created[fqdn], createdTXT{zoneID: zone.ID.String(), recordID: rec.ID.String()})
	d.mu.Unlock()
	if d.store != nil {
		d.store.add(fqdn, zone.ID.String(), rec.ID.String())
	}
	if d.sleep > 0 {
		if d.cancel == nil {
			time.Sleep(d.sleep)
		} else {
			select {
			case <-time.After(d.sleep):
			case <-d.cancel:
				return fmt.Errorf("任务已取消，跳过 DNS 生效等待")
			}
		}
	}
	return nil
}

// CleanUp 删除本次创建的 TXT 记录。
func (d *dynv6DNS) CleanUp(domain, token, keyAuth string) error {
	fqdn, _ := challengeRecord(domain, keyAuth)
	fqdn = strings.TrimSuffix(fqdn, ".")
	d.mu.Lock()
	records := d.created[fqdn]
	delete(d.created, fqdn)
	d.mu.Unlock()
	var firstErr error
	all := append([]createdTXT{}, records...)
	if d.store != nil {
		for _, p := range d.store.list(fqdn) {
			all = append(all, createdTXT{zoneID: p.ZoneID, recordID: p.RecordID})
		}
	}
	seen := map[string]bool{}
	for _, rec := range all {
		key := rec.zoneID + "|" + rec.recordID
		if seen[key] {
			continue
		}
		seen[key] = true
		if _, err := d.do(http.MethodDelete, "/zones/"+rec.zoneID+"/records/"+rec.recordID, nil); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue // 删除失败时保留持久化记录，下次启动或 CleanUp 再试
		}
		if d.store != nil {
			d.store.removeByID(fqdn, rec.zoneID, rec.recordID)
		}
	}
	return firstErr
}
