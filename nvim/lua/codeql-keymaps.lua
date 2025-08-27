local M = {}

-- Configuration
local config = {
  codeql_path = "/path/to/codeql",
  codeql_packs = "/path/to/codeql/packs",
  results_file = vim.fn.stdpath("cache") .. "/codeql_results.sarif",
  database_suffix = "-codeql-db",
  database_cache = vim.fn.stdpath("cache") .. "/codeql_database.json",
}

-- Helper function to run shell commands and capture output
local function run_command(cmd, callback)
  local output = {}
  local error_lines = {}
  local error_count = 0
  local max_errors = 5 -- Limit error messages to prevent flooding
  
  local job_id = vim.fn.jobstart(cmd, {
    stdout_buffered = true,
    stderr_buffered = true,
    on_stdout = function(_, data)
      for _, line in ipairs(data) do
        if line ~= "" then
          table.insert(output, line)
        end
      end
    end,
    on_stderr = function(_, data)
      for _, line in ipairs(data) do
        if line ~= "" then
          error_count = error_count + 1
          table.insert(error_lines, line)
          
          -- Only show first few errors to prevent flooding
          if error_count <= max_errors then
            vim.schedule(function()
              vim.notify("CodeQL: " .. line, vim.log.levels.ERROR)
            end)
          elseif error_count == max_errors + 1 then
            vim.schedule(function()
              vim.notify("CodeQL: Too many errors, suppressing further messages...", vim.log.levels.WARN)
            end)
          end
        end
      end
    end,
    on_exit = function(_, exit_code)
      vim.schedule(function()
        if exit_code == 0 then
          vim.notify("✅ CodeQL command completed successfully", vim.log.levels.INFO)
          if callback then callback(output) end
        else
          -- Show a summary of errors instead of flooding
          if #error_lines > 0 then
            local error_summary = "CodeQL failed with " .. #error_lines .. " error(s)"
            if #error_lines > max_errors then
              error_summary = error_summary .. " (showing first " .. max_errors .. ")"
            end
            
            -- Show detailed errors in a floating window for better UX
            M.show_error_details(error_lines, cmd)
          else
            vim.notify("CodeQL command failed with exit code: " .. exit_code, vim.log.levels.ERROR)
          end
        end
      end)
    end
  })
  
  if job_id == 0 then
    vim.notify("Failed to start CodeQL command", vim.log.levels.ERROR)
  elseif job_id == -1 then
    vim.notify("Invalid CodeQL command", vim.log.levels.ERROR)
  end
  
  return job_id
end

-- Function to detect language from directory
local function detect_language(directory)
  local js_patterns = {"*.js", "*.jsx", "*.ts", "*.tsx", "*.vue"}
  local py_patterns = {"*.py"}
  local java_patterns = {"*.java", "*.kt"}
  local go_patterns = {"*.go"}
  local cpp_patterns = {"*.cpp", "*.cc", "*.cxx", "*.c", "*.h", "*.hpp"}
  
  for _, pattern in ipairs(js_patterns) do
    if vim.fn.glob(directory .. "/**/" .. pattern) ~= "" then
      return "javascript"
    end
  end
  
  for _, pattern in ipairs(py_patterns) do
    if vim.fn.glob(directory .. "/**/" .. pattern) ~= "" then
      return "python"
    end
  end
  
  for _, pattern in ipairs(java_patterns) do
    if vim.fn.glob(directory .. "/**/" .. pattern) ~= "" then
      return "java"
    end
  end
  
  for _, pattern in ipairs(go_patterns) do
    if vim.fn.glob(directory .. "/**/" .. pattern) ~= "" then
      return "go"
    end
  end
  
  for _, pattern in ipairs(cpp_patterns) do
    if vim.fn.glob(directory .. "/**/" .. pattern) ~= "" then
      return "cpp"
    end
  end
  
  return "javascript" -- default fallback
end

-- Helper functions for database persistence
local function json_encode(obj)
  -- Simple JSON encoding for basic objects
  if type(obj) == "table" then
    local items = {}
    for k, v in pairs(obj) do
      local key = '"' .. tostring(k) .. '"'
      local value
      if type(v) == "string" then
        value = '"' .. v .. '"'
      elseif type(v) == "number" then
        value = tostring(v)
      else
        value = '"' .. tostring(v) .. '"'
      end
      table.insert(items, key .. ':' .. value)
    end
    return '{' .. table.concat(items, ',') .. '}'
  else
    return '"' .. tostring(obj) .. '"'
  end
end

local function parse_sarif_with_python(sarif_file)
  -- Create a simple Python script to parse SARIF and extract key info
  local python_script = [[
import json
import sys

try:
    with open(sys.argv[1], 'r') as f:
        sarif = json.load(f)
    
    results = sarif.get('runs', [{}])[0].get('results', [])
    rules = {rule['id']: rule for rule in sarif.get('runs', [{}])[0].get('tool', {}).get('driver', {}).get('rules', [])}
    
    print(f"TOTAL_RESULTS:{len(results)}")
    
    for i, result in enumerate(results):
        rule_id = result.get('ruleId', 'unknown')
        message = result.get('message', {}).get('text', 'No message')
        
        rule = rules.get(rule_id, {})
        rule_name = rule.get('name', rule_id)
        severity = rule.get('defaultConfiguration', {}).get('level', 'warning')
        security_severity = rule.get('properties', {}).get('security-severity', 'N/A')
        
        print(f"RESULT:{i}|{rule_id}|{rule_name}|{severity}|{security_severity}|{message}")
        
        # Extract locations
        locations = result.get('locations', [])
        for j, loc in enumerate(locations):
            phys_loc = loc.get('physicalLocation', {})
            if phys_loc:
                uri = phys_loc.get('artifactLocation', {}).get('uri', '')
                line = phys_loc.get('region', {}).get('startLine', 1)
                print(f"LOCATION:{i}|{j}|{uri}|{line}")

except Exception as e:
    print(f"ERROR:Failed to parse SARIF: {e}")
    sys.exit(1)
]]
  
  local temp_script = vim.fn.tempname() .. ".py"
  local script_file = io.open(temp_script, "w")
  if script_file then
    script_file:write(python_script)
    script_file:close()
    
    local handle = io.popen("python3 '" .. temp_script .. "' '" .. sarif_file .. "' 2>/dev/null")
    if handle then
      local output = handle:read("*a")
      handle:close()
      vim.fn.delete(temp_script)
      
      if output and output ~= "" then
        return parse_python_output(output)
      end
    else
      vim.fn.delete(temp_script)
    end
  end
  
  return nil
end

local function parse_python_output(output)
  local sarif = {runs = {{results = {}, tool = {driver = {rules = {}}}}}}
  local results = {}
  local current_result = nil
  
  for line in output:gmatch("[^\n]+") do
    if line:match("^TOTAL_RESULTS:") then
      -- We know how many results to expect
    elseif line:match("^RESULT:") then
      local parts = {}
      for part in line:gmatch("([^|]+)") do
        table.insert(parts, part)
      end
      
      if #parts >= 6 then
        local idx = parts[1]:match("RESULT:(%d+)")
        local rule_id = parts[2]
        local rule_name = parts[3]
        local severity = parts[4]
        local security_severity = parts[5]
        local message = parts[6]
        
        current_result = {
          ruleId = rule_id,
          message = {text = message},
          locations = {}
        }
        table.insert(results, current_result)
        
        -- Add rule info
        sarif.runs[1].tool.driver.rules[rule_id] = {
          id = rule_id,
          name = rule_name,
          defaultConfiguration = {level = severity},
          properties = {["security-severity"] = security_severity}
        }
      end
    elseif line:match("^LOCATION:") and current_result then
      local parts = {}
      for part in line:gmatch("([^|]+)") do
        table.insert(parts, part)
      end
      
      if #parts >= 4 then
        local uri = parts[3]
        local line_num = tonumber(parts[4]) or 1
        
        table.insert(current_result.locations, {
          physicalLocation = {
            artifactLocation = {uri = uri},
            region = {startLine = line_num}
          }
        })
      end
    elseif line:match("^ERROR:") then
      vim.notify("SARIF parsing error: " .. line:gsub("^ERROR:", ""), vim.log.levels.ERROR)
      return nil
    end
  end
  
  sarif.runs[1].results = results
  return sarif
end

local function json_decode(str)
  -- For simple JSON (like our database cache), use basic parsing
  -- For SARIF files, we need robust parsing
  if vim.fn.exists('*json_decode') == 1 then
    return vim.fn.json_decode(str)
  elseif vim.json and vim.json.decode then
    return vim.json.decode(str)
  else
    -- Fallback: simple JSON parsing for basic objects
    local result = {}
    str = str:gsub('^{', ''):gsub('}$', '')
    for kv_pair in str:gmatch('"([^"]+)":[^,}]+') do
      local key, value = kv_pair:match('"([^"]+)":"?([^,}"]+)"?')
      if key and value then
        if value:match('^%d+$') then
          result[key] = tonumber(value)
        else
          result[key] = value:gsub('"', '')
        end
      end
    end
    return result
  end
end

local function save_database_info(db_path, language, source_dir)
  local db_info = {
    path = db_path,
    language = language,
    source_dir = source_dir,
    created = os.time()
  }
  
  local file = io.open(config.database_cache, "w")
  if file then
    file:write(json_encode(db_info))
    file:close()
  end
end

local function load_database_info()
  if vim.fn.filereadable(config.database_cache) == 1 then
    local file = io.open(config.database_cache, "r")
    if file then
      local content = file:read("*a")
      file:close()
      
      local ok, db_info = pcall(json_decode, content)
      if ok and db_info and db_info.path and vim.fn.isdirectory(db_info.path) == 1 then
        vim.g.codeql_current_db = db_info.path
        vim.g.codeql_current_language = db_info.language
        return db_info
      end
    end
  end
  return nil
end

-- Auto-discover database in current directory
local function find_database_in_dir(directory)
  local db_pattern = directory .. "/*" .. config.database_suffix
  local matches = vim.fn.glob(db_pattern, false, true)
  
  for _, match in ipairs(matches) do
    if vim.fn.isdirectory(match) == 1 then
      local language = detect_language(directory)
      vim.g.codeql_current_db = match
      vim.g.codeql_current_language = language
      save_database_info(match, language, directory)
      return match
    end
  end
  
  return nil
end

-- Get current database (try multiple sources)
local function get_current_database()
  -- 1. Check session variables
  if vim.g.codeql_current_db and vim.fn.isdirectory(vim.g.codeql_current_db) == 1 then
    return vim.g.codeql_current_db
  end
  
  -- 2. Try to load from cache
  local db_info = load_database_info()
  if db_info then
    return db_info.path
  end
  
  -- 3. Auto-discover in current directory
  local found_db = find_database_in_dir(vim.fn.getcwd())
  if found_db then
    return found_db
  end
  
  return nil
end

-- 1. Create CodeQL Database
function M.create_database()
  vim.ui.input({
    prompt = "Enter directory to scan (or press Enter for current): ",
    default = vim.fn.getcwd(),
  }, function(input)
    if not input then return end
    
    local source_dir = vim.fn.expand(input)
    local db_name = vim.fn.fnamemodify(source_dir, ":t") .. config.database_suffix
    local db_path = source_dir .. "/" .. db_name
    local language = detect_language(source_dir)
    
    -- Remove existing database if it exists
    if vim.fn.isdirectory(db_path) == 1 then
      vim.fn.delete(db_path, "rf")
    end
    
    vim.notify("Creating CodeQL database for " .. language .. " in " .. source_dir, vim.log.levels.INFO)
    
    local cmd = {
      config.codeql_path,
      "database",
      "create",
      db_path,
      "--language=" .. language,
      "--source-root=" .. source_dir,
      "--overwrite"
    }
    
    run_command(cmd, function()
      vim.notify("✅ CodeQL database created: " .. db_path, vim.log.levels.INFO)
      -- Store the database path for later use
      vim.g.codeql_current_db = db_path
      vim.g.codeql_current_language = language
      save_database_info(db_path, language, source_dir)
    end)
  end)
end

-- 2. Scan Database
function M.scan_database()
  local db_path = get_current_database()
  local language = vim.g.codeql_current_language or "javascript"
  
  if not db_path then
    vim.notify("No CodeQL database found. Create one first with <leader>cd or try <leader>cq", vim.log.levels.WARN)
    return
  end
  
  vim.notify("🔍 Scanning database with " .. language .. " security queries...", vim.log.levels.INFO)
  vim.notify("Database: " .. db_path, vim.log.levels.INFO)
  
  local cmd = {
    config.codeql_path,
    "database",
    "analyze",
    db_path,
    "--format=sarif-latest",
    "--output=" .. config.results_file,
    "--search-path=" .. config.codeql_packs,
    "codeql/" .. language .. "-queries:codeql-suites/" .. language .. "-security-and-quality.qls"
  }
  
  run_command(cmd, function()
    vim.notify("✅ CodeQL scan completed. Results saved to " .. config.results_file, vim.log.levels.INFO)
  end)
end

-- 3. Parse and Display Results
function M.show_results()
  if vim.fn.filereadable(config.results_file) == 0 then
    vim.notify("No results file found. Run a scan first with <leader>cs", vim.log.levels.WARN)
    return
  end
  
  -- Read and parse SARIF file
  local file = io.open(config.results_file, "r")
  if not file then
    vim.notify("Failed to read results file", vim.log.levels.ERROR)
    return
  end
  
  local content = file:read("*a")
  file:close()
  
  local ok, sarif = pcall(vim.fn.json_decode, content)
  if not ok then
    vim.notify("Failed to parse SARIF results", vim.log.levels.ERROR)
    return
  end
  
  -- Create results buffer
  local buf = vim.api.nvim_create_buf(false, true)
  local win = vim.api.nvim_open_win(buf, true, {
    relative = 'editor',
    width = math.floor(vim.o.columns * 0.8),
    height = math.floor(vim.o.lines * 0.8),
    row = math.floor(vim.o.lines * 0.1),
    col = math.floor(vim.o.columns * 0.1),
    style = 'minimal',
    border = 'rounded',
    title = ' CodeQL Security Results ',
    title_pos = 'center'
  })
  
  vim.api.nvim_buf_set_option(buf, 'modifiable', true)
  vim.api.nvim_buf_set_option(buf, 'filetype', 'markdown')
  
  local lines = {}
  local locations = {} -- Store file locations for jumping
  
  table.insert(lines, "# 🛡️  CodeQL Security Analysis Results")
  table.insert(lines, "")
  
  local results = sarif.runs[1].results or {}
  local rules = {}
  
  -- Build rules lookup
  for _, rule in ipairs(sarif.runs[1].tool.driver.rules or {}) do
    rules[rule.id] = rule
  end
  
  if #results == 0 then
    table.insert(lines, "✅ **No security vulnerabilities found!**")
    table.insert(lines, "")
    table.insert(lines, "Your code appears to be secure. Great job! 🎉")
  else
    table.insert(lines, string.format("**Total Findings:** %d", #results))
    table.insert(lines, "")
    
    -- Group by severity
    local by_severity = {error = {}, warning = {}}
    for _, result in ipairs(results) do
      local rule = rules[result.ruleId] or {}
      local severity = rule.defaultConfiguration and rule.defaultConfiguration.level or "warning"
      table.insert(by_severity[severity] or by_severity.warning, result)
    end
    
    -- Display critical issues first
    if #by_severity.error > 0 then
      table.insert(lines, "## 🚨 Critical Issues (" .. #by_severity.error .. ")")
      table.insert(lines, "")
      
      for i, result in ipairs(by_severity.error) do
        local rule = rules[result.ruleId] or {}
        local security_severity = rule.properties and rule.properties["security-severity"] or "Unknown"
        
        table.insert(lines, string.format("### %d. %s", i, rule.name or result.ruleId))
        table.insert(lines, string.format("**Rule:** `%s`", result.ruleId))
        table.insert(lines, string.format("**Security Severity:** %s/10", security_severity))
        table.insert(lines, string.format("**Message:** %s", result.message.text))
        table.insert(lines, "")
        
        -- Show locations
        if result.locations then
          table.insert(lines, "**Locations:**")
          for j, location in ipairs(result.locations) do
            if location.physicalLocation then
              local uri = location.physicalLocation.artifactLocation.uri
              local start_line = location.physicalLocation.region and location.physicalLocation.region.startLine or 1
              local line_text = string.format("📍 `%s:%d`", uri, start_line)
              table.insert(lines, line_text)
              
              -- Store location for jumping (line number in our buffer -> file info)
              locations[#lines] = {file = uri, line = start_line}
            end
          end
          table.insert(lines, "")
        end
        
        -- Show data flow if available
        if result.codeFlows and #result.codeFlows > 0 then
          local flow = result.codeFlows[1]
          if flow.threadFlows and #flow.threadFlows > 0 then
            local threadFlow = flow.threadFlows[1]
            if threadFlow.locations and #threadFlow.locations > 1 then
              table.insert(lines, "**Data Flow Path:**")
              for k, flowLocation in ipairs(threadFlow.locations) do
                if flowLocation.location and flowLocation.location.physicalLocation then
                  local flowUri = flowLocation.location.physicalLocation.artifactLocation.uri
                  local flowLine = flowLocation.location.physicalLocation.region.startLine
                  local step_text = string.format("  %d. `%s:%d`", k, flowUri, flowLine)
                  if flowLocation.location.message then
                    step_text = step_text .. " - " .. flowLocation.location.message.text
                  end
                  table.insert(lines, step_text)
                  locations[#lines] = {file = flowUri, line = flowLine}
                end
              end
              table.insert(lines, "")
            end
          end
        end
        
        -- Show fix suggestions if available
        if rule.help and rule.help.text then
          table.insert(lines, "**Recommendation:**")
          table.insert(lines, rule.help.text)
          table.insert(lines, "")
        end
        
        table.insert(lines, "---")
        table.insert(lines, "")
      end
    end
    
    -- Display warnings
    if #by_severity.warning > 0 then
      table.insert(lines, "## ⚠️  Warnings (" .. #by_severity.warning .. ")")
      table.insert(lines, "")
      
      -- Show first 10 warnings to avoid overwhelming
      local warning_limit = math.min(10, #by_severity.warning)
      for i = 1, warning_limit do
        local result = by_severity.warning[i]
        local rule = rules[result.ruleId] or {}
        
        table.insert(lines, string.format("### %d. %s", i, rule.name or result.ruleId))
        table.insert(lines, string.format("**Message:** %s", result.message.text))
        
        if result.locations and result.locations[1] and result.locations[1].physicalLocation then
          local uri = result.locations[1].physicalLocation.artifactLocation.uri
          local start_line = result.locations[1].physicalLocation.region.startLine
          table.insert(lines, string.format("**Location:** `%s:%d`", uri, start_line))
          locations[#lines] = {file = uri, line = start_line}
        end
        table.insert(lines, "")
      end
      
      if #by_severity.warning > warning_limit then
        table.insert(lines, string.format("... and %d more warnings", #by_severity.warning - warning_limit))
        table.insert(lines, "")
      end
    end
  end
  
  table.insert(lines, "")
  table.insert(lines, "---")
  table.insert(lines, "**Navigation:**")
  table.insert(lines, "- Press `<Enter>` on file locations to jump to code")
  table.insert(lines, "- Press `q` to close this window")
  table.insert(lines, "- Press `<leader>cr` to refresh results")
  
  -- Set buffer content
  vim.api.nvim_buf_set_lines(buf, 0, -1, false, lines)
  vim.api.nvim_buf_set_option(buf, 'modifiable', false)
  
  -- Set up key mappings for the results buffer
  local function jump_to_location()
    local line_num = vim.api.nvim_win_get_cursor(win)[1]
    local location = locations[line_num]
    if location then
      -- Close results window
      vim.api.nvim_win_close(win, true)
      
      -- Open the file
      local file_path = location.file
      -- Handle relative paths
      if not vim.startswith(file_path, "/") then
        local db_path = vim.g.codeql_current_db
        if db_path then
          local source_root = vim.fn.fnamemodify(db_path, ":h")
          file_path = source_root .. "/" .. file_path
        end
      end
      
      if vim.fn.filereadable(file_path) == 1 then
        vim.cmd("edit " .. vim.fn.fnameescape(file_path))
        vim.api.nvim_win_set_cursor(0, {location.line, 0})
        vim.notify("Jumped to " .. file_path .. ":" .. location.line, vim.log.levels.INFO)
      else
        vim.notify("File not found: " .. file_path, vim.log.levels.WARN)
      end
    end
  end
  
  vim.keymap.set('n', '<CR>', jump_to_location, {buffer = buf, desc = "Jump to location"})
  vim.keymap.set('n', 'q', function() vim.api.nvim_win_close(win, true) end, {buffer = buf, desc = "Close results"})
end

-- Show detailed errors in a floating window
function M.show_error_details(error_lines, cmd)
  local buf = vim.api.nvim_create_buf(false, true)
  local max_width = math.floor(vim.o.columns * 0.8)
  local max_height = math.floor(vim.o.lines * 0.6)
  
  local win = vim.api.nvim_open_win(buf, true, {
    relative = 'editor',
    width = max_width,
    height = max_height,
    row = math.floor(vim.o.lines * 0.2),
    col = math.floor(vim.o.columns * 0.1),
    style = 'minimal',
    border = 'rounded',
    title = ' CodeQL Error Details ',
    title_pos = 'center'
  })
  
  vim.api.nvim_buf_set_option(buf, 'modifiable', true)
  vim.api.nvim_buf_set_option(buf, 'filetype', 'text')
  
  local lines = {}
  table.insert(lines, "# ❌ CodeQL Command Failed")
  table.insert(lines, "")
  table.insert(lines, "**Command:** `" .. table.concat(cmd, " ") .. "`")
  table.insert(lines, "")
  table.insert(lines, "**Errors (" .. #error_lines .. " total):**")
  table.insert(lines, "")
  
  -- Show errors with line numbers
  for i, error_line in ipairs(error_lines) do
    if i <= 20 then -- Limit to 20 lines to prevent overwhelming
      table.insert(lines, string.format("%2d: %s", i, error_line))
    elseif i == 21 then
      table.insert(lines, "...")
      table.insert(lines, string.format("(%d more errors truncated)", #error_lines - 20))
      break
    end
  end
  
  table.insert(lines, "")
  table.insert(lines, "---")
  table.insert(lines, "**Navigation:**")
  table.insert(lines, "- Press `q` to close this window")
  table.insert(lines, "- Press `y` to copy all errors to clipboard")
  
  -- Set buffer content
  vim.api.nvim_buf_set_lines(buf, 0, -1, false, lines)
  vim.api.nvim_buf_set_option(buf, 'modifiable', false)
  
  -- Set up key mappings
  vim.keymap.set('n', 'q', function() vim.api.nvim_win_close(win, true) end, {buffer = buf, desc = "Close error window"})
  vim.keymap.set('n', 'y', function()
    local all_errors = table.concat(error_lines, "\n")
    vim.fn.setreg('+', all_errors)
    vim.notify("📋 Copied " .. #error_lines .. " errors to clipboard", vim.log.levels.INFO)
  end, {buffer = buf, desc = "Copy errors to clipboard"})
  
  -- Show helpful message
  vim.notify("❌ CodeQL failed with " .. #error_lines .. " errors. See floating window for details.", vim.log.levels.ERROR)
end

-- 4. Run Custom Query File
function M.run_query_file()
  local current_file = vim.api.nvim_buf_get_name(0)
  
  -- Check if current file is a .ql file
  if not vim.endswith(current_file, ".ql") then
    vim.notify("Current file is not a .ql file. Open a CodeQL query file first.", vim.log.levels.WARN)
    return
  end
  
  local db_path = get_current_database()
  if not db_path then
    vim.notify("No CodeQL database found. Create one first with <leader>cd or try <leader>cq", vim.log.levels.WARN)
    return
  end
  
  vim.notify("🔍 Running custom query: " .. vim.fn.fnamemodify(current_file, ":t"), vim.log.levels.INFO)
  vim.notify("Database: " .. db_path, vim.log.levels.INFO)
  
  local cmd = {
    config.codeql_path,
    "query", 
    "run",
    current_file,
    "--database=" .. db_path,
    "--output=" .. config.results_file,
    "--format=sarif-latest"
  }
  
  run_command(cmd, function()
    vim.notify("✅ Custom query completed. Results saved to " .. config.results_file, vim.log.levels.INFO)
    vim.schedule(function()
      M.show_results()
    end)
  end)
end

-- 5. Run Prettier on JavaScript files
function M.run_prettier()
  local cwd = vim.fn.getcwd()
  vim.notify("🎨 Running Prettier on JavaScript files in " .. cwd, vim.log.levels.INFO)
  
  local cmd = {"prettier", "--write", "*.js"}
  
  run_command(cmd, function(output)
    if #output > 0 then
      vim.notify("✅ Prettier completed. Formatted files:", vim.log.levels.INFO)
      for _, line in ipairs(output) do
        if line ~= "" then
          vim.notify("  📝 " .. line, vim.log.levels.INFO)
        end
      end
    else
      vim.notify("✅ Prettier completed successfully", vim.log.levels.INFO)
    end
  end)
end

-- 6. Quick Security Scan (combines all steps)
function M.quick_scan()
  vim.ui.input({
    prompt = "Enter directory to scan (or press Enter for current): ",
    default = vim.fn.getcwd(),
  }, function(input)
    if not input then return end
    
    local source_dir = vim.fn.expand(input)
    local db_name = vim.fn.fnamemodify(source_dir, ":t") .. config.database_suffix
    local db_path = source_dir .. "/" .. db_name
    local language = detect_language(source_dir)
    
    vim.notify("🚀 Starting quick security scan of " .. source_dir, vim.log.levels.INFO)
    
    -- Step 1: Create database
    if vim.fn.isdirectory(db_path) == 1 then
      vim.fn.delete(db_path, "rf")
    end
    
    local create_cmd = {
      config.codeql_path,
      "database",
      "create",
      db_path,
      "--language=" .. language,
      "--source-root=" .. source_dir,
      "--overwrite"
    }
    
    run_command(create_cmd, function()
      vim.g.codeql_current_db = db_path
      vim.g.codeql_current_language = language
      
      -- Step 2: Analyze database
      local analyze_cmd = {
        config.codeql_path,
        "database",
        "analyze",
        db_path,
        "--format=sarif-latest",
        "--output=" .. config.results_file,
        "--search-path=" .. config.codeql_packs,
        "codeql/" .. language .. "-queries:codeql-suites/" .. language .. "-security-and-quality.qls"
      }
      
      run_command(analyze_cmd, function()
        -- Step 3: Show results
        vim.schedule(function()
          M.show_results()
        end)
      end)
    end)
  end)
end

-- Set up keymaps
function M.setup()
  vim.keymap.set('n', '<leader>cd', M.create_database, {desc = "CodeQL: Create Database"})
  vim.keymap.set('n', '<leader>cs', M.scan_database, {desc = "CodeQL: Scan Database"})
  vim.keymap.set('n', '<leader>cr', M.show_results, {desc = "CodeQL: Show Results"})
  vim.keymap.set('n', '<leader>cq', M.quick_scan, {desc = "CodeQL: Quick Security Scan"})
  vim.keymap.set('n', '<leader>cf', M.run_query_file, {desc = "CodeQL: Run Query File"})
  vim.keymap.set('n', '<leader>pp', M.run_prettier, {desc = "Prettier: Format JavaScript files"})
  
  vim.notify("CodeQL keymaps loaded:", vim.log.levels.INFO)
  vim.notify("  <leader>cd - Create Database", vim.log.levels.INFO)
  vim.notify("  <leader>cs - Scan Database", vim.log.levels.INFO)
  vim.notify("  <leader>cr - Show Results", vim.log.levels.INFO)
  vim.notify("  <leader>cq - Quick Scan (all-in-one)", vim.log.levels.INFO)
  vim.notify("  <leader>cf - Run Query File", vim.log.levels.INFO)
  vim.notify("  <leader>pp - Run Prettier on *.js files", vim.log.levels.INFO)
end

return M
