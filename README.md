```
命令行执行如下：
ech-win -l 127.0.0.1:30000 -f cf绑定域名[pages.dev]:443 -pyip proxyip反代域名或IP -token xxx -ip 优选ip
ech-win -f cf绑定域名:443 -pyip proxyip反代域名或IP -token xxx -ip 优选ip
ech-win -f cf绑定域名:443 -pyip tw.william.us.ci -token xxx -ip 104.17.0.0

Usage of ech-win:
  -dns string
        ECH 查询 DNS 服务器 (default "119.29.29.29:53")
  -ech string
        ECH 查询域名 (default "cloudflare-ech.com")
  -f string
        服务端地址 (格式: x.x.workers.dev:443)
  -ip string
        指定服务端 IP（绕过 DNS 解析）
  -l string
        代理监听地址 (支持 SOCKS5 和 HTTP) (default "127.0.0.1:30000")
  -pyip string
        代理服务器 IP（用于 Worker 连接回退）
  -token string
        身份验证令牌
```
##### 注：workers、pages、snippets三种部署都支持, TOKEN=xxx 部署时请更换

### 🛠 开源代码引用
- [https://github.com/hhsw2015/ech-workers](https://github.com/hhsw2015/ech-workers)
