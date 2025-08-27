# Neovim Configuration

A modern Neovim configuration featuring LSP support, tree-sitter highlighting, fuzzy finding, AI coding assistance, and more.

## Prerequisites

- **Neovim 0.9.0+** (required)
- **Git** (required for plugin management)
- A terminal with true color support
- A [Nerd Font](https://www.nerdfonts.com/font-downloads) (recommended: JetBrains Mono Nerd Font)

## Installation

### 1. Install Neovim (from GitHub Releases)

Get the latest stable or nightly builds directly from Neovim's GitHub releases:
- Stable: https://github.com/neovim/neovim/releases/latest
- Nightly: https://github.com/neovim/neovim/releases/tag/nightly

#### Linux (AppImage - recommended)
```bash
# Stable
curl -LO https://github.com/neovim/neovim/releases/latest/download/nvim.appimage
chmod u+x nvim.appimage
sudo mv nvim.appimage /usr/local/bin/nvim

# Verify
nvim --version | head -n 3
```

### 2. Clone this Configuration

```bash
# Backup existing config (if any)
mv ~/.config/nvim ~/.config/nvim.backup 2>/dev/null || true

# Clone this configuration
git clone https://github.com/guusec/nvim-config.git ~/.config/nvim
```

### 3. Install Dependencies

#### Required System Packages

**Ubuntu/Debian/Pop!_OS:**
```bash
sudo apt update
sudo apt install -y \
    build-essential \
    curl \
    git \
    unzip \
    wget \
    ripgrep \
    fd-find \
    nodejs \
    npm \
    python3 \
    python3-pip \
    python3-venv \
    golang-go \
    clang \
    clangd
```

**macOS:**
```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

brew install \
    ripgrep \
    fd \
    node \
    python \
    go \
    llvm
```

#### Language Servers (Auto-installed via Mason)

The configuration uses Mason to automatically install language servers. The following LSPs are configured:

- **lua-language-server** - Lua LSP
- **python-lsp-server** - Python LSP
- **typescript-language-server** - TypeScript/JavaScript LSP  
- **clangd** - C/C++ LSP
- **gopls** - Go LSP
- **asm-lsp** - Assembly LSP (optional)

#### Optional Dependencies

**Ollama (for AI coding assistance):**
```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Pull the configured model
ollama pull gpt-oss:latest
```

**Tree-sitter CLI (for advanced syntax highlighting):**
```bash
npm install -g tree-sitter-cli
```

**Python development tools:**
```bash
# Install Python LSP server and formatters
pip3 install --user python-lsp-server[all] black isort flake8
```

### 4. First Launch

1. Start Neovim:
   ```bash
   nvim
   ```

2. The configuration will automatically:
   - Install lazy.nvim plugin manager
   - Download and install all plugins
   - Install language servers via Mason

3. Wait for all installations to complete (check `:Lazy` and `:Mason`)

## Key Mappings

### General
- `<Space>` - Leader key
- `<Leader>ff` - Find files
- `<Leader>fg` - Live grep
- `<Leader><Space>` - Search buffers
- `<Leader>?` - Recent files

### LSP
- `K` - Hover documentation
- `gd` - Go to definition
- `gr` - Go to references
- `<F2>` - Rename symbol
- `<F3>` - Format code
- `<F4>` - Code actions

### File Explorer
- `<Leader>e` - Toggle Neo-tree

### Terminal
- `c-g` - Toggle terminal

## Configuration Structure

```
~/.config/nvim/
├── init.lua                 # Entry point
├── lazy-lock.json          # Plugin lockfile
├── lua/
│   ├── user/
│   │   ├── settings.lua    # Neovim settings
│   │   ├── keymaps.lua     # Key mappings
│   │   ├── commands.lua    # Custom commands
│   │   └── plugins.lua     # Plugin manager setup
│   ├── plugins/            # Plugin configurations
│   │   ├── init.lua
│   │   ├── lspconfig.lua
│   │   ├── mason.lua
│   │   ├── treesitter.lua
│   │   ├── telescope.lua
│   │   └── lsp/           # Individual LSP configs
│   │       ├── lua_ls.lua
│   │       ├── pylsp.lua
│   │       ├── ts_ls.lua
│   │       ├── clangd.lua
│   │       └── gopls.lua
│   └── codeql-keymaps.lua # CodeQL specific mappings
└── README.md              # This file
```

## Customization

### Adding New Plugins
1. Create a new file in `lua/plugins/`
2. Follow the lazy.nvim plugin specification
3. Restart Neovim or run `:Lazy sync`

### Modifying Settings
Edit `lua/user/settings.lua` for Neovim options and `lua/user/keymaps.lua` for key bindings.

### Adding Language Servers
1. Install via Mason: `:Mason`
2. Add configuration in `lua/plugins/lsp/`
3. Update `lua/plugins/lspconfig.lua` if needed

## Updates

To update the configuration and plugins:

```bash
# Update configuration
cd ~/.config/nvim
git pull

# Update plugins
nvim +Lazy sync +qa
```

## Support

For issues specific to this configuration, check:
1. `:checkhealth` output
2. `:Lazy` for plugin issues  
3. `:Mason` for LSP server issues
4. `:messages` for error messages

## License

This configuration is provided as-is. Feel free to modify and adapt to your needs.
