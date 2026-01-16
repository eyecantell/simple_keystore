# DevContainer Setup

This project uses a Docker volume-based devcontainer for improved performance on Windows and macOS.

## Why Docker Volumes?

Instead of bind-mounting the workspace from the host filesystem, the code lives in a Docker volume (`simple_keystore-workspace`). This provides:

- **Much faster I/O** - Linux-native filesystem instead of Windows/macOS mount overhead
- **Better file watching** - More reliable change detection for tests and hot reload
- **Consistent permissions** - No host/Linux permission translation issues

## Prerequisites

- Docker Desktop (Windows/macOS) or Docker Engine (Linux)
- VS Code with the "Dev Containers" extension (`ms-vscode-remote.remote-containers`)
- On your host: `~/dev` and `~/stuff_for_containers_home` directories

## How to Use

### First Time Setup

1. Open VS Code
2. Open Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`)
3. Run: `Dev Containers: Clone Repository in Container Volume...`
4. Enter your repository URL (e.g., `git@github.com:eyecantell/simple_keystore.git`)

VS Code will clone the repo directly into the Docker volume and open it.

### Reopening Later

Use any of these methods:

1. **File → Open Recent** - The workspace appears with a container icon
2. **Command Palette** → `Dev Containers: Open Named Volume...` → select `simple_keystore-workspace`
3. **Remote Explorer sidebar** → Dev Containers → click the folder icon

## What's Included

### Container Tools

| Tool | Purpose |
|------|---------|
| Python 3.10 | Runtime |
| PDM | Package manager |
| Ruff | Linting and formatting |
| Pyright | Type checking (LSP) |
| Redis | Key-value store backend |
| Claude Code | AI assistant |

### VS Code Extensions (Auto-installed)

- **ms-python.python** - Python language support
- **charliermarsh.ruff** - Ruff linter integration
- **be5invis.toml** - TOML syntax highlighting
- **ms-azuretools.vscode-docker** - Docker support
- **github.vscode-github-actions** - GitHub Actions support

## Directory Structure

| Path | Type | Purpose |
|------|------|---------|
| `/workspaces/simple_keystore` | Docker volume | Main workspace (fast) |
| `/mounted/dev` | Bind mount | Access to `~/dev` on host |
| `/mounted/stuff_for_containers_home` | Bind mount | Shared config files from host |
| `~/.claude` | Symlink | Points to `/mounted/dev/.claude-simple_keystore` |

The container runs as the `developer` user (non-root, with sudo access).

## Cross-Platform Support

The configuration works on both Windows and macOS by using:
```json
"source": "${localEnv:HOME}${localEnv:USERPROFILE}/dev"
```

- **macOS/Linux**: `HOME` is set, `USERPROFILE` is empty → uses `~/dev`
- **Windows**: `HOME` is empty, `USERPROFILE` is set → uses `%USERPROFILE%\dev`

## Claude Code Data

Each project uses a **separate** Claude data directory to avoid conflicts when running multiple Claude Code instances:

```
/mounted/dev/.claude-simple_keystore  →  ~/.claude (symlink)
```

This is set up automatically by `postCreateCommand`. The data persists on the host filesystem and survives container rebuilds.

## Configuration Files

| File | Purpose |
|------|---------|
| `devcontainer.json` | Container config, mounts, extensions, settings |
| `Dockerfile` | Base image (Python 3.10-slim) and installed tools |

## Troubleshooting

### "Volume not found" when reopening

The volume may have been deleted. Use "Clone Repository in Container Volume" again to recreate it.

### Changes not syncing to host

By design - the workspace lives in a Docker volume, not on your host. Use git to push/pull changes. The `/mounted/dev` bind mount is available if you need to access host files directly.

### Claude settings lost after rebuild

Check that the symlink exists:
```bash
ls -la ~/.claude
# Should show: .claude -> /mounted/dev/.claude-simple_keystore
```

If missing, recreate it:
```bash
mkdir -p /mounted/dev/.claude-simple_keystore
ln -sf /mounted/dev/.claude-simple_keystore ~/.claude
```

### postCreateCommand fails

If `/mounted/dev` doesn't exist on your host, the symlink creation will fail. Ensure you have a `~/dev` directory on your host machine before building the container.

### Redis not running

Redis is started automatically by `postCreateCommand`. To check status or restart:
```bash
sudo service redis-server status
sudo service redis-server start
redis-cli ping  # Should return PONG
```
