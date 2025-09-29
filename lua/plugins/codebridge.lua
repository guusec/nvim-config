local Plugin = 

{
  "samir-roy/code-bridge.nvim",
  config = function()
    require('code-bridge').setup({
      tmux = {
        target_mode = 'window_name',     -- 'window_name', 'current_window', 'find_process'
        window_name = 'claude',          -- used when target_mode = 'window_name'
        process_name = 'claude',         -- used when target_mode = 'current_window' or 'find_process'
        switch_to_target = true,         -- whether to switch to target after sending
        find_node_process = true,        -- whether to look for a node.js process
      },
      interactive = {
        use_telescope = true,            -- use telescope for interactive prompts (default: true)
      }
    })
  end
}

return Plugin
