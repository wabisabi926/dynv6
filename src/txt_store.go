package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// pendingTXT 把 DNS-01 创建的 TXT 记录持久化到数据目录。
// 进程被 kill -9 / 容器重启后仍可在下次启动时清理，避免 _acme-challenge 记录残留。
type pendingTXT struct {
	FQDN      string `json:"fqdn"`
	ZoneID    string `json:"zone_id"`
	RecordID  string `json:"record_id"`
	CreatedAt string `json:"created_at"` // RFC3339
}

type txtStore struct {
	mu    sync.Mutex
	path  string
	items []pendingTXT
}

func newTXTStore(dir string) *txtStore {
	s := &txtStore{path: filepath.Join(dir, "pending-txt.json")}
	s.load()
	return s
}

func (s *txtStore) load() {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	var items []pendingTXT
	if err := json.Unmarshal(data, &items); err != nil {
		return
	}
	s.items = items
}

func (s *txtStore) save() {
	if len(s.items) == 0 {
		_ = os.Remove(s.path)
		return
	}
	data, err := json.MarshalIndent(s.items, "", "  ")
	if err != nil {
		return
	}
	_ = atomicWrite(s.path, data, 0600)
}

func (s *txtStore) add(fqdn, zoneID, recordID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = append(s.items, pendingTXT{
		FQDN: fqdn, ZoneID: zoneID, RecordID: recordID,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	})
	s.save()
}

// list 返回某个 fqdn 的全部待清理记录（不修改文件，删除成功后再移除）
func (s *txtStore) list(fqdn string) []pendingTXT {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []pendingTXT
	for _, it := range s.items {
		if it.FQDN == fqdn {
			out = append(out, it)
		}
	}
	return out
}

// stale 返回创建时间超过 maxAge 的记录（不删除，等 API 删除成功后再移除）
func (s *txtStore) stale(maxAge time.Duration) []pendingTXT {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []pendingTXT
	for _, it := range s.items {
		t, err := time.Parse(time.RFC3339, it.CreatedAt)
		if err != nil || time.Since(t) >= maxAge {
			out = append(out, it)
		}
	}
	return out
}

func (s *txtStore) removeByID(fqdn, zoneID, recordID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	keep := make([]pendingTXT, 0, len(s.items))
	for _, it := range s.items {
		if it.FQDN == fqdn && it.ZoneID == zoneID && it.RecordID == recordID {
			continue
		}
		keep = append(keep, it)
	}
	s.items = keep
	s.save()
}

// cleanStaleTXT 启动时清理超过 1 小时仍未删除的 TXT 记录；失败保留到下次启动重试。
func (a *App) cleanStaleTXT() {
	if a.paths.Var == "" {
		return
	}
	store := newTXTStore(a.paths.Var)
	items := store.stale(time.Hour)
	if len(items) == 0 {
		return
	}
	c := a.getConfig()
	if c.Token == "" {
		a.log("存在 %d 条残留 TXT 记录待清理，但尚未配置 dynv6 Token，稍后重试", len(items))
		return
	}
	d := newDynv6DNS(c.Token, 0)
	for _, it := range items {
		path := fmt.Sprintf("/zones/%s/records/%s", it.ZoneID, it.RecordID)
		if _, err := d.do(http.MethodDelete, path, nil); err != nil {
			a.log("清理残留 TXT 记录 %s 失败（下次启动重试）: %v", it.FQDN, err)
			continue
		}
		store.removeByID(it.FQDN, it.ZoneID, it.RecordID)
		a.log("已清理残留的 _acme-challenge TXT 记录 %s", it.FQDN)
	}
}
