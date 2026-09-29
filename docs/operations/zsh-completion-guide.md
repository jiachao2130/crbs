# Zsh 补全安装与使用

crbs 提供完整的 Zsh 自动补全，覆盖子命令、产品名与用户角色。

## 1 安装

### Oh My Zsh

```bash
crbs completions zsh > ~/.oh-my-zsh/completions/_crbs
exec zsh
```

输入 `crbs <Tab>` 应列出全部子命令。

### 原生 Zsh

```bash
# 写入 fpath 中的目录，例如
crbs completions zsh > /usr/share/zsh/site-functions/_crbs
```

若目录不在 `fpath` 中，在 `.zshrc` 开头补充：

```zsh
fpath=(/usr/share/zsh/site-functions $fpath)
```

补全脚本由当前二进制生成，升级 crbs 后重新生成一次以保持一致。

## 2 补全覆盖范围

### `crbs` 主命令

| 命令 | 补全内容 |
|------|---------|
| `crbs build` | 产品名（`--product`）、SRPM 文件路径、全部 flags |
| `crbs init` / `shell` / `clean` | 产品名 |
| `crbs logs` / `cancel` / `debug` / `download` / `sign` | 任务 ID（完整数字，不做前缀解析） |
| `crbs status` | 产品名、阶段过滤 |
| `crbs diff` / `verify` | 任务 ID（`verify` 第二个参数可选） |
| `crbs --remote` | 已配置的 profile 名 |

### `products` 子命令

```bash
crbs products <Tab>
# show create update fork delete clean history export publish unpublish transfer acl

crbs products acl <Tab>
# list grant revoke
```

## 3 常见问题

### admin 命令不在补全列表中

补全脚本过期。重新生成并重载 Shell：

```bash
crbs completions zsh > ~/.oh-my-zsh/completions/_crbs
exec zsh
```

### 补全不生效

检查 `fpath` 是否包含补全目录：

```bash
echo $fpath | grep oh-my-zsh/completions
```

若不在，按 §1 在 `.zshrc` 中补充 `fpath`。

### `--remote` 补全为空

补全读取 crbs 配置文件中的 profile（`~/.config/crbs/crbs.toml` 或 `/etc/crbs/crbs.toml`）：

```toml
[remote]
default = "prod"

[[remote.profiles]]
name = "prod"
url = "https://crbs.example.com"
token_file = "~/.crbs/token-prod"
ca_cert = "~/.crbs/prod-ca.crt"   # 自签/内网 CA
```

## 4 其他 Shell

```bash
crbs completions bash > /etc/bash_completion.d/crbs
crbs completions fish > ~/.config/fish/completions/crbs.fish
crbs completions powershell   # 输出到 stdout
```
