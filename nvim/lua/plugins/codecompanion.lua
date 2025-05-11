local Plugin = { "olimorris/codecompanion.nvim" }

Plugin.dependencies = {
	"nvim-lua/plenary.nvim",
	"nvim-treesitter/nvim-treesitter",
	{
        "saghen/blink.cmp",
        lazy = false,
        version = "*",
        opts = {
          keymap = {
            preset = "enter",
            ["<S-Tab>"] = { "select_prev", "fallback" },
            ["<Tab>"] = { "select_next", "fallback" },
          },
          cmdline = { sources = { "cmdline" } },
          sources = {
            default = { "lsp", "path", "buffer", "codecompanion" },
          },
        },
    },
}

Plugin.opts = {
      --Refer to: https://github.com/olimorris/codecompanion.nvim/blob/main/lua/codecompanion/config.lua
      strategies = {
        --NOTE: Change the adapter as required
        chat = { adapter = "ollama" },
        inline = { adapter = "ollama" },
    },
}

Plugin.adapters = {
  llama3 = function()
      return require("codecompanion.adapters").extend("ollama", {
        name = "deepseek", -- Give this adapter a different name to differentiate it from the default ollama adapter
        schema = {
          model = {
            default = "deepseek-r1:14b",
          },
          num_ctx = {
            default = 16384,
          },
          num_predict = {
            default = -1,
          },
        },
      })
  end
}

-- require("lazy.minit").repro({ spec = plugins })

-- Setup Tree-sitter
local ts_status, treesitter = pcall(require, "nvim-treesitter.configs")
if ts_status then
  treesitter.setup({
    ensure_installed = { "lua", "markdown", "markdown_inline", "yaml" },
    highlight = { enable = true },
  })
end

return Plugin
