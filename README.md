# AG-Secret

AG-Secret 为 Agent 工作流保存凭据，用 ID 引用当前凭据值，在命令执行时替换，并过滤子进程的敏感输出。SQLite 数据库使用纯 Go 加密 VFS，无 CGO、无常驻服务。

Licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).

## 初始化

```sh
make build
export PATH="$PWD/bin:$PATH"
agsecret init
agsecret put api-token --secret-stdin
```

`init` 自动生成 32 字节随机口令，以 64 位 hex 保存到 `~/.local/share/agsecret/session.pass`（Unix 权限 0600），再创建 `secrets.db` 和 `secrets.db.unlock`。已有文件不会被覆盖。设置 `XDG_DATA_HOME` 会改变默认数据目录；`AGSECRET_DB` / `--db`、`AGSECRET_PASS_FILE` / `--pass-file` 可以指定外部路径。显式指定的 pass file 必须已存在；无 pass file 时可在终端输入口令。Unix 下 secret/pass file 必须是无 group/world 权限的普通文件；Windows 下应使用私有用户目录并通过 ACL 限制访问，Unix mode 位检查不适用。

`put` 支持参数、`--secret-stdin`、`--secret-file` 三种输入，后两种适合避免命令行历史和进程 argv 中出现明文。stdin/file 的原始输入（含行尾）最多 1 MiB，先检查长度，再去掉最后一个 LF/CRLF 或 CR；超限会拒绝，不截断保存。不要把真实凭据写进 Agent 的对话或工具调用参数。

## Agent 使用方式

```sh
agsecret list --json
agsecret view api-token --json
# 从 put/list/view 的输出取得当前 ID，例如 ags_9f8e7d6c5b4a3210
agsecret exec -- curl -H 'Authorization: Bearer ags_9f8e7d6c5b4a3210' https://example.test

# Linux 下通过间接管道使用明文
curl -H "Authorization: Bearer $(agsecret get api-token)" https://example.test
agsecret get api-token | trusted-consumer

# 发送给已经停在密码提示符处的 tmux pane
agsecret send tmux:%1 api-token
```

所有接受凭据引用的命令支持名称或 ID；`put` 新建时需要名称，更新时也支持已有 ID。唯一 token 格式是 `ags_` 后接 16 位随机小写 hex，新建时生成；secret 或 type 改变时会生成新 ID，策略更新保持原 ID。`ags_` 前缀保留给 ID。ID 标识当前凭据值，不是认证能力；Agent 应保存并优先使用 ID。轮换后旧 ID 立即失效，不保存历史别名，缓存该 ID 的命令或环境变量需要更新。迟到的 `report 旧ID` 会报找不到记录，**不要自动改用名称重试**，以免把旧值的泄露归到新值。旧 `tokenize`、`redact` 命令及旧 token 语法已移除。

`exec` 直接启动命令，展开参数和继承环境变量中的 ID；也可以显式执行 shell，但把 ID 放进 shell 源代码会将替换后的值交给 shell 解析，推荐通过位置参数或环境变量传递。可执行文件名不能是凭据 token。每个凭据在一次执行中解析一次，TOTP 在启动前计算。

stdout/stderr 过滤器加载全部未过期的 pass（至少 4 字节）和 TOTP 种子；本次实际注入的值也参与过滤。命中后输出 `[REDACTED:<id>]`，并在执行结束后向 stderr 追加一次说明；未命中时保持安静。执行中的权限/TTL 采用启动时快照，后续策略变化不会杀死已运行命令。

## 查看、获取与发送

`view NAME|ID` 默认显示元数据、状态与脱敏 `value`。TOTP 的 `value` 始终为 `[set]`，不应用会透露种子的 mask。`--dangerously-show-secret` 对 pass 显示明文，对 TOTP 仅显示当前 `current_otp`，不会显示种子。这个诊断入口不受 `allow_get/allow_exec` 限制。

`get` 检查 TTL 和 `allow_get`。TOTP 直接返回当前验证码。密码可输出到真实交互终端；在 Linux 的非交互 shell 中，只有 stdout 是与最近 `sh -c` 祖先 stdout/stderr 不同的管道时才视为间接使用。普通文件重定向无法可靠区分于 shell 子进程重定向，因此默认拒绝，使用 `exec` 或 `--dangerously-skip-check`。其他情况退出码为 2。`--dangerously-skip-check` 显式跳过输出路径检查，仍受 TTL/权限限制。

这项检查识别输出路径，**不能证明间接使用不会泄露**：例如 `echo "$(agsecret get NAME)"` 仍会输出明文。PTY 也可能被宿主捕获；工具无法证明终端另一端是人。Agent 应优先使用 `exec` 或 `send`。非交互 JSON 可使用全局 `--quiet` 抑制周期性 stderr 提示，避免 stdout/stderr 合并时污染 JSON。

`send tmux:<target> NAME|ID` 检查 TTL 和 `allow_exec`，读取 pane 的 TTY termios。开启 ECHO 时拒绝；`--force-echo` 显式覆盖。默认发送字面值后按 Enter；`--enter=false` 不按 Enter。密码中的换行或控制字符会在调用 tmux 前被拒绝，以免提前提交、触发中断或编辑终端输入；这类值请通过 `exec` 传递，`--force-echo` 不覆盖此检查。凭据仅发送到明确指定的 pane。目标程序仍可能自行记录输入；ECHO 检查和发送之间存在不可消除的状态变化窗口。

## TOTP、策略与轮换

```sh
agsecret put login-otp --type totp --secret-stdin
agsecret get login-otp
agsecret put api-token --secret-file ./private-token --ttl 7d --allow-get=false
```

类型限定为 `pass`、`totp`。TOTP 使用标准库实现 RFC 6238，默认 SHA1、6 位、30 秒；接受忽略空格/横杠/大小写的 Base32 种子，也接受 `otpauth://totp/...`。URI 可指定 SHA1/SHA256/SHA512、6/8 位、period；非法参数在入库时拒绝，错误不回显种子。

新记录默认允许 get/exec，TTL 永久，mask 为 `fixed:[set]`。更新凭据时，未显式传入的 `--type`、`--ttl`、`--mask`、`--allow-get`、`--allow-exec` 保持原值。secret 或 type 改变时生成新 ID，并清空旧值的泄露历史；提交相同值、相同类型时保留 ID 和泄露历史，包括只改策略的情况。不会因为重复 `put` 就把泄露标记清除。相同明文被其他 pass 凭据使用时，`put` 会向 stderr 警告对应 ID，不打印明文；检查也包括已过期或停用的记录。

TTL 支持 Go duration（如 `1h30m`），或单个数值加 `d`/`w`（如 `1.5d`）；不支持 `1h2d` 这种混写，请换算为 `49h`。`0`、`permanent`、`never` 表示永久。pass 的 mask 可用 `fixed[:TEXT]`、`prefix:N`、`suffix:N`、`both:N,M`、`length`、`hash`。默认不透露长度或任何字符；其他模式是主动披露，hash 对低熵口令可能被枚举。前后缀覆盖全部字符时回退到 `[set]`。TOTP 不通过 mask 暴露种子片段、长度或哈希；get/send/exec 使用动态验证码。

## 泄露汇报

```sh
agsecret report ags_9f8e7d6c5b4a3210 --reason 'unexpected log output' \
  --context 'request failed during authentication' \
  --attachment ./error.log --attachment ./screenshot.png --json
# 或从 stdin 精确匹配库中的明文
agsecret report --secret-stdin --reason 'credential found in output'
```

报告在数据库事务中追加，保留 `reported_at`、`reason`、`context`、`attachments`，并发报告不会互相覆盖。优先使用 ID，NAME 仍可用。无论使用 ID、名称还是 `--secret-stdin`，一次报告都为**所有使用相同明文的 pass 记录**追加事件，包括已过期或停用的记录。先按 ID/名称解析当前值，再匹配全部同值记录；解析和追加在同一个事务中完成。`--secret-stdin` 只匹配保存的 pass 明文，TOTP 种子和验证码均不参与汇报，按 TOTP ID/名称汇报会被拒绝。

报告不会修改访问策略，不提供 `--revoke`。是否停用权限由人决定，Agent 不应擅自修改 `allow_get/allow_exec`。attachment 仅保存路径引用，不读取文件内容。`list/view` 显示 `leaked (N times)`（过期时追加 `,expired`）；doctor 给出计数、列表与轮换提示。泄露历史不会自动截断；更换凭据值或类型时清空。报告可能包含敏感上下文，存储受数据库加密保护；`report --json` 始终输出数组，每个元素包含一个受影响凭据及其完整泄露历史，即使只匹配一条记录也是数组。

非交互 `list/view/doctor` 每个库最多每 12 小时向 stderr 提示一次 `agsecret help`。成功的 get/send/exec 不产生这条提示。

## 存储和安全边界

SQLite 使用 `ncruces/go-sqlite3` 的 Adiantum VFS，数据库和 WAL 数据页加密。随机数据库密钥使用 Argon2id（1 次、16 MiB、2 线程）派生的 XChaCha20-Poly1305 密钥包装。数据库与 `.unlock` 必须一起备份；活跃 WAL 数据库要通过 SQLite 在线备份或在所有进程关闭后复制，不能只复制主文件。

v1 数据库会在事务中升级为新 schema，旧 pass 保留、旧静态 otp 转为 pass，不把验证码误当成 TOTP 种子。旧 `.unlock` 仍以原 Argon2 参数解锁；新建库使用新参数。失败的迁移回滚，未知新版拒绝打开。

Adiantum 提供磁盘加密，不提供恶意篡改/回滚防护；同一 UID 能读取 pass file 的程序仍能解密数据库。权限标志和“由人决定停用”是工作流约束，不能在同一 UID 下强制区分人和 Agent。TOTP 的 CLI 不提供种子查看入口，但这不等于同一用户下的程序无法读取数据库或进程内存。输出过滤只处理精确字节串，不能防止主动编码、拆分到两个流、写文件/网络、终端旁路等泄露；argv/env/进程内存仍含执行所需明文，Go 内存清理不等于完整擦除保证。

并发与无 CGO 选型说明见 [docs/architecture.md](docs/architecture.md)。

## 开发验证

Go 1.26+：

```sh
make test
make check
make build
make integration  # Linux，Python 3；有 tmux 时测试独立的临时会话
```

端到端自检使用临时加密库、模拟凭据、本机回环 HTTP 服务及独立 tmux socket，覆盖认证、响应脱敏、交互提示、输入边界、重复汇报和轮换；结束时清理临时资源，不使用现有 tmux pane。

Linux 有 systemd 用户服务时，test/check 在独立 cgroup 内执行：总内存硬上限 2 GiB、禁止 swap、180 秒超时，并限制编译/测试并行度。无 user systemd 的 Linux 使用每进程 2 GiB 虚拟内存上限。`GOMEMLIMIT=512MiB` 是 Go GC 软目标，不替代硬性限制。其他平台保留 Go 超时和 GC 目标。
