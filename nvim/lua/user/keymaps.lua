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


-- JSON to markdown
vim.keymap.set('n', '<leader>jm', function()
  local lines = vim.api.nvim_buf_get_lines(0, 0, -1, false)
  local content = table.concat(lines, '\n')
  
  local ok, json_data = pcall(vim.fn.json_decode, content)
  if not ok then
    print("Error: Invalid JSON")
    return
  end
  
  local markdown_lines = {}
  
  -- Check if this is SARIF format
  if json_data.runs and type(json_data.runs) == "table" then
    -- SARIF format
    table.insert(markdown_lines, "# CodeQL SARIF Results")
    table.insert(markdown_lines, "")
    
    if #json_data.runs > 0 then
      local run = json_data.runs[1]
      
      -- Tool info
      if run.tool and run.tool.driver then
        local driver = run.tool.driver
        table.insert(markdown_lines, "## Tool Information")
        table.insert(markdown_lines, "")
        table.insert(markdown_lines, "- **Name**: " .. (driver.name or "N/A"))
        table.insert(markdown_lines, "- **Organization**: " .. (driver.organization or "N/A"))
        table.insert(markdown_lines, "- **Version**: " .. (driver.semanticVersion or "N/A"))
        table.insert(markdown_lines, "")
      end
      
      -- Results
      if run.results and #run.results > 0 then
        table.insert(markdown_lines, "## Security Findings (" .. #run.results .. " total)")
        table.insert(markdown_lines, "")
        
        for i, result in ipairs(run.results) do
          table.insert(markdown_lines, "### Finding " .. i .. ": " .. (result.ruleId or "Unknown Rule"))
          table.insert(markdown_lines, "")
          
          -- Message
          if result.message and result.message.text then
            local message_lines = vim.split(result.message.text, "\n")
            table.insert(markdown_lines, "**Issue**: " .. message_lines[1])
            for j = 2, #message_lines do
              table.insert(markdown_lines, message_lines[j])
            end
            table.insert(markdown_lines, "")
          end
          
          -- Location
          if result.locations and #result.locations > 0 then
            local location = result.locations[1]
            if location.physicalLocation then
              local phys = location.physicalLocation
              table.insert(markdown_lines, "**Location**:")
              if phys.artifactLocation and phys.artifactLocation.uri then
                table.insert(markdown_lines, "- File: `" .. phys.artifactLocation.uri .. "`")
              end
              if phys.region then
                local region = phys.region
                local line_info = "Line " .. (region.startLine or "?")
                if region.startColumn then
                  line_info = line_info .. ", Column " .. region.startColumn
                end
                if region.endColumn and region.endColumn ~= region.startColumn then
                  line_info = line_info .. "-" .. region.endColumn
                end
                table.insert(markdown_lines, "- " .. line_info)
              end
              table.insert(markdown_lines, "")
            end
          end
          
          -- Rule details
          if run.tool and run.tool.driver and run.tool.driver.rules then
            for _, rule in ipairs(run.tool.driver.rules) do
              if rule.id == result.ruleId then
                if rule.fullDescription and rule.fullDescription.text then
                  local desc_lines = vim.split(rule.fullDescription.text, "\n")
                  table.insert(markdown_lines, "**Description**: " .. desc_lines[1])
                  for k = 2, #desc_lines do
                    if desc_lines[k]:match("^%s*$") then
                      table.insert(markdown_lines, "")
                    else
                      table.insert(markdown_lines, desc_lines[k])
                    end
                  end
                  table.insert(markdown_lines, "")
                end
                if rule.properties then
                  local props = rule.properties
                  if props["security-severity"] then
                    table.insert(markdown_lines, "**Security Severity**: " .. props["security-severity"])
                  end
                  if props["problem.severity"] then
                    table.insert(markdown_lines, "**Problem Severity**: " .. props["problem.severity"])
                  end
                  if props.tags then
                    table.insert(markdown_lines, "**Tags**: " .. table.concat(props.tags, ", "))
                  end
                  table.insert(markdown_lines, "")
                end
                break
              end
            end
          end
          
          table.insert(markdown_lines, "---")
          table.insert(markdown_lines, "")
        end
      end
    end
    
    print("Converted SARIF with " .. (json_data.runs[1].results and #json_data.runs[1].results or 0) .. " findings to Markdown")
  else
    -- Generic JSON format
    table.insert(markdown_lines, "# JSON Data")
    table.insert(markdown_lines, "")
    
    local function json_to_markdown(obj, level)
      level = level or 1
      if type(obj) == "table" then
        if vim.tbl_islist(obj) then
          -- Handle arrays
          for i, item in ipairs(obj) do
            if type(item) == "table" then
              table.insert(markdown_lines, string.rep("#", level + 1) .. " Item " .. i)
              table.insert(markdown_lines, "")
              json_to_markdown(item, level + 1)
            else
              table.insert(markdown_lines, "- " .. tostring(item))
            end
          end
        else
          -- Handle objects
          for key, value in pairs(obj) do
            table.insert(markdown_lines, string.rep("#", level) .. " " .. tostring(key))
            table.insert(markdown_lines, "")
            if type(value) == "table" then
              json_to_markdown(value, level + 1)
            else
              table.insert(markdown_lines, tostring(value))
              table.insert(markdown_lines, "")
            end
          end
        end
      else
        table.insert(markdown_lines, tostring(obj))
      end
    end
    
    json_to_markdown(json_data)
    
    print("Converted generic JSON to Markdown")
  end
  
  -- Replace buffer content
  vim.api.nvim_buf_set_lines(0, 0, -1, false, markdown_lines)
  
  -- Set filetype to markdown
  vim.bo.filetype = 'markdown'
end, {desc = 'Convert SARIF to Markdown report'})
