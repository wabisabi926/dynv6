package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestResolveToolOverrideAndCandidates(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "dynv6-sh")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if got := resolveTool("dynv6-no-such-tool", fake, nil); got != fake {
		t.Fatalf("环境变量指定的路径应优先，得到 %q", got)
	}
	if got := resolveTool("dynv6-no-such-tool", "", []string{filepath.Join(dir, "missing"), fake}); got != fake {
		t.Fatalf("PATH 找不到时应回退到绝对路径候选，得到 %q", got)
	}
	if got := resolveTool("dynv6-no-such-tool", "", []string{filepath.Join(dir, "missing")}); got != "" {
		t.Fatalf("全部不存在时应返回空，得到 %q", got)
	}
}

func TestShellCandidatesIncludeBinSh(t *testing.T) {
	if runtime.GOOS == "windows" {
		return
	}
	found := false
	for _, p := range shellCandidates() {
		if p == "/bin/sh" {
			found = true
		}
	}
	if !found {
		t.Fatal("候选列表应包含 /bin/sh")
	}
}
