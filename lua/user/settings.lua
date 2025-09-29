-- You can read the description of each option in the help page
-- use :help 'option_name' command
-- For example, :help 'hlsearch'

vim.opt.number = true
vim.opt.mouse = 'a'
vim.opt.ignorecase = true
vim.opt.smartcase = true
vim.opt.hlsearch = false
vim.opt.wrap = true
vim.opt.tabstop = 2
vim.opt.shiftwidth = 2
vim.opt.expandtab = false
vim.opt.signcolumn = 'yes'
vim.opt.termguicolors = true

-- Reduce input lag by setting shorter timeout for key sequences
vim.opt.timeoutlen = 200  -- Time to wait for key sequence completion (ms)
vim.opt.ttimeoutlen = 10  -- Time to wait for terminal key codes (ms)

