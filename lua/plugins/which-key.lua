local Plugin = {
  "folke/which-key.nvim",
  event = "VeryLazy",
  opts = {
    -- your configuration comes here
    -- or leave it empty to use the default settings
    -- refer to the configuration section below
		-- debug = true,
		keys ={
			scroll_down = "<c-j>",
			scroll_up = "<c-k>",
		},
  },
  keys = {
    {
      "<leader>w",
      function()
        require("which-key").show({ global = true })
      end,
      desc = "Buffer Local Keymaps (which-key)",
    },
  },
}

return Plugin
