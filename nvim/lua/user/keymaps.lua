-- Space as leader key
vim.g.mapleader = ' '

-- Shortcuts
vim.keymap.set({'n', 'x', 'o'}, '<leader>h', '^', {desc = 'Go to first non-blank character of the line'})
vim.keymap.set({'n', 'x', 'o'}, '<leader>l', 'g_', {desc = 'Go to last non-blank character of the line'})
vim.keymap.set('n', '<leader>a', ':keepjumps normal! ggVG<cr>', {desc = 'Select all text in buffer'})

-- Basic clipboard interaction
vim.keymap.set({'n', 'x'}, 'gy', '"+y', {desc = 'Copy to clipboard'})
vim.keymap.set({'n', 'x'}, 'gp', '"+p', {desc = 'Paste clipboard content'})

-- Delete text without changing vim's internal registers
vim.keymap.set({'n', 'x'}, 'x', '"_x', {desc = 'Cut the character under the cursor'})
vim.keymap.set({'n', 'x'}, 'X', '"_d', {desc = 'Cut text'})

-- Commands
-- vim.keymap.set('n', '<leader>w', '<cmd>write<cr>', {desc = 'Save buffer'})
vim.keymap.set('n', '<leader>bq', '<cmd>bdelete<cr>', {desc = 'Close buffer'})
-- vim.keymap.set('n', '<leader>bl', '<cmd>buffer #<cr>', {desc = 'Go to last active buffer'})
vim.keymap.set('n', '<leader>c', '<cmd>CodeCompanion toggle<cr>', {desc = 'Code Companion prompt'})

vim.keymap.set('n', '<leader>bb', '<cmd>buffer #<cr>', {desc = 'Go to last active buffer'})
vim.keymap.set('n', '<leader>ww', '<cmd>set wrap!<cr>', {desc = 'Toggle word wrapping'})
vim.keymap.set('n', '<leader>tt', function()
  vim.diagnostic.enable(not vim.diagnostic.is_enabled())
end, { silent = true, noremap = true })

-- Dedupe and preserve order
vim.keymap.set('n','<leader>dd', function()
  local lines = vim.api.nvim_buf_get_lines(0, 0, -1, false)
  local seen = {}
  local result = {}
  
  for _, line in ipairs(lines) do
    if not seen[line] then
      seen[line] = true
      table.insert(result, line)
    end
  end
  
  vim.api.nvim_buf_set_lines(0, 0, -1, false, result)
end, {desc = 'Dedupe file and preserve order'})


-- Toggle JSON prettify
vim.keymap.set('n', '<leader>jq', function()
  local lines = vim.api.nvim_buf_get_lines(0, 0, -1, false)
  local content = table.concat(lines, '\n')
  
  -- Check if JSON is already formatted (has newlines and indentation)
  local is_formatted = content:match('\n%s+') ~= nil
  
  if is_formatted then
    -- Compact the JSON
    vim.cmd(':%!jq -c .')
  else
    -- Format the JSON
    vim.cmd(':%!jq .')
  end
end, {desc = 'Toggle JSON formatting with jq'})