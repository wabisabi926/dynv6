package main

import "embed"

// Windows 独立 exe 没有 app/vendor 目录，这里内嵌一份 acme.sh 与 dns_dynv6 插件。
// 飞牛安装目录存在 vendor 时优先使用磁盘版本，方便以后替换而不必重编译。
//
//go:embed embedded/acme.sh embedded/dnsapi/dns_dynv6.sh
var embeddedVendor embed.FS
