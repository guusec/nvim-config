# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository. Do not create placeholder code. Only create code that does what the user says.

## Architecture Overview

This is a Neovim configuration built using Lua and the lazy.nvim plugin manager. The configuration follows a modular structure:

- **Entry Point**: `init.lua` - loads user modules and sets up colorscheme
- **Plugin Management**: Uses lazy.nvim for plugin management with auto-installation
- **Module Structure**:
  - `lua/user/` - Core user configuration (settings, keymaps, commands)
  - `lua/plugins/` - Individual plugin configurations 
  - `lua/plugins/lsp/` - Language server specific configurations

## Key Components

### Core Configuration
- `lua/user/settings.lua` - Basic Neovim settings (line numbers, indentation, etc.)
- `lua/user/keymaps.lua` - Custom key bindings
- `lua/user/commands.lua` - Custom commands
- `lua/user/plugins.lua` - Lazy.nvim setup and plugin loading

### Plugin Architecture
- Each plugin has its own configuration file in `lua/plugins/`
- Simple plugins without configuration are in `lua/plugins/init.lua`
- LSP configurations are modular in `lua/plugins/lsp/`

### Special Features
- **CodeQL Integration**: `lua/codeql-keymaps.lua` provides extensive CodeQL analysis functionality
- **AI Integration**: CodeCompanion plugin configured with both Ollama (gptoss) and Anthropic adapters
- **LSP Setup**: Comprehensive LSP configuration with Mason for language server management

## Plugin Management

The configuration uses lazy.nvim for plugin management:
- Plugins auto-install on first run
- Configurations are lazy-loaded for performance
- Plugin specs are modular and organized by functionality

## Development Commands

Since this is a Neovim configuration, there are no traditional build/test commands. Instead:

- **Reload Configuration**: Restart Neovim or use `:source $MYVIMRC`
- **Update Plugins**: `:Lazy update`
- **Check Plugin Status**: `:Lazy`
- **Check LSP Status**: `:LspInfo`
- **Mason Package Management**: `:Mason`

## CodeQL Integration

This configuration includes extensive CodeQL functionality via `codeql-keymaps.lua`:
- Database creation and management
- Query execution with multiple output formats
- Result visualization and navigation
- Automated SARIF to Markdown conversion

## LSP Configuration

The LSP setup uses Mason for automatic language server installation and management:
- Language servers are configured in `lua/plugins/lsp/` subdirectory
- Common LSP keybindings are defined in `lua/plugins/lspconfig.lua`
- Supports automatic formatting, diagnostics, and code actions

## File Organization Patterns

When adding new functionality:
- Simple plugins without config go in `lua/plugins/init.lua`
- Complex plugins get dedicated files in `lua/plugins/`
- Language-specific LSP configs go in `lua/plugins/lsp/`
- User settings and keymaps go in `lua/user/`
