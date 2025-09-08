local Plugin = { "olimorris/codecompanion.nvim" }

Plugin.dependencies = {
	"nvim-lua/plenary.nvim",
	"nvim-treesitter/nvim-treesitter",
	{
  "MeanderingProgrammer/render-markdown.nvim",
  ft = { "markdown", "codecompanion" }
},
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
        chat = { adapter = "gptoss" },
        inline = { adapter = "gptoss" },
        -- chat = { adapter = "anthropic" },
        -- inline = { adapter = "anthropic" },
    },
    adapters = {
        http = {
            -- Your gptoss adapter (Ollama-based)
            gptoss = function()
                return require("codecompanion.adapters").extend("ollama", {
                    name = "gpt", -- Give this adapter a different name to differentiate it from the default ollama adapter
                    schema = {
                        model = {
                            default = "gpt-oss:20b",
                        },
                        num_ctx = {
                            default = 16384,
                        },
                        num_predict = {
                            default = -1,
                        },
                    },
                })
            end,
            -- Anthropic adapter configuration (commented out)
            --[[ anthropic = function()
                return require("codecompanion.adapters").extend("anthropic", {
                    env = {
                        api_key = "ANTHROPIC_API_KEY", -- Will read from environment variable
                    },
                    schema = {
                        model = {
                            default = "claude-sonnet-4-20250514", -- Claude Sonnet 4
                        },
                        temperature = {
                            default = 0.1, -- Low temperature for more focused responses
                        },
                        max_tokens = {
                            default = 4096,
                        },
                    },
                })
            end, --]]
        },
    },
}

-- Moved adapters configuration into Plugin.opts.adapters above
-- Plugin.adapters = {
--   gptoss = function()
--       return require("codecompanion.adapters").extend("ollama", {
--         name = "gpt", -- Give this adapter a different name to differentiate it from the default ollama adapter
--         schema = {
--           model = {
--             default = "gpt-oss:20b",
--           },
--           num_ctx = {
--             default = 16384,
--           },
--           num_predict = {
--             default = -1,
--           },
--         },
--       })
--   end
-- }

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
