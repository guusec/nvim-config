local Plugin = {
    'powerman/vim-plugin-AnsiEsc',
    cmd = 'AnsiEsc',
    keys = {
      { '<leader>ta',
  ':AnsiEsc<CR>', desc = 'Toggle ANSI colors' }
    }
  }
return Plugin
