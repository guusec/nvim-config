-- Custom CodeQL Neovim Keymaps
-- Place this in your Neovim config (e.g., ~/.config/nvim/lua/codeql-keymaps.lua)

local M = {}

-- Configuration
local config = {
  codeql_path = "/home/giuseppe/.local/bin/codeql",
  codeql_packs = "/home/giuseppe/.codeql",
  results_file = function() return vim.fn.getcwd() .. "/codeql_results.sarif" end,
  markdown_file = function() return vim.fn.getcwd() .. "/codeql_results.md" end,
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

-- Language configuration for CodeQL
local language_config = {
  cpp = {
    extensions = {".cpp", ".cc", ".cxx", ".c", ".h", ".hpp", ".hxx", ".C", ".H"},
    indicators = {"CMakeLists.txt", "Makefile", "*.vcxproj"},
    query_pack = "codeql/cpp-queries:codeql-suites/cpp-security-and-quality.qls"
  },
  go = {
    extensions = {".go"},
    indicators = {"go.mod", "go.sum", "Gopkg.toml"},
    query_pack = "codeql/go-queries:codeql-suites/go-security-and-quality.qls"
  },
  java = {
    extensions = {".java", ".kt", ".kts"},
    indicators = {"pom.xml", "build.gradle", "build.gradle.kts", "build.xml"},
    query_pack = "codeql/java-queries:codeql-suites/java-security-and-quality.qls"
  },
  javascript = {
    extensions = {".js", ".jsx", ".ts", ".tsx", ".vue", ".mjs", ".cjs"},
    indicators = {"package.json", "tsconfig.json", "jsconfig.json", "webpack.config.js"},
    query_pack = "codeql/javascript-queries:codeql-suites/javascript-security-and-quality.qls"
  },
  python = {
    extensions = {".py", ".pyw", ".pyi"},
    indicators = {"requirements.txt", "setup.py", "pyproject.toml", "Pipfile", "poetry.lock",
                  "environment.yml", "conda.yml", "tox.ini", "pytest.ini"},
    query_pack = "codeql/python-queries:codeql-suites/python-security-and-quality.qls"
  },
  rust = {
    extensions = {".rs"},
    indicators = {"Cargo.toml", "Cargo.lock"},
    query_pack = "codeql/rust-queries:codeql-suites/rust-security-and-quality.qls"
  }
}

-- Recursive file scanner to collect all file extensions in a directory
local function scan_directory_recursive(directory, max_files)
  max_files = max_files or 10000  -- Limit to prevent excessive scanning
  local extensions = {}
  local file_count = 0

  -- Use find command for efficient recursive scanning
  local handle = io.popen("find '" .. directory .. "' -type f 2>/dev/null | head -n " .. max_files)
  if not handle then
    return extensions
  end

  for filepath in handle:lines() do
    file_count = file_count + 1

    -- Extract extension
    local ext = filepath:match("(%.[^/.]+)$")
    if ext then
      extensions[ext:lower()] = (extensions[ext:lower()] or 0) + 1
    end

    -- Stop if we've hit the limit
    if file_count >= max_files then
      break
    end
  end
  handle:close()

  return extensions
end

-- Detect all languages present in a directory
local function detect_languages(directory)
  local detected_languages = {}
  local language_scores = {}

  -- Initialize scores
  for lang, _ in pairs(language_config) do
    language_scores[lang] = 0
  end

  -- Check for project indicators (high confidence)
  for lang, config in pairs(language_config) do
    for _, indicator in ipairs(config.indicators) do
      if indicator:find("%*") then
        -- Pattern-based indicator
        if vim.fn.glob(directory .. "/" .. indicator) ~= "" then
          language_scores[lang] = language_scores[lang] + 10
        end
      else
        -- Exact file indicator
        if vim.fn.filereadable(directory .. "/" .. indicator) == 1 then
          language_scores[lang] = language_scores[lang] + 10
        end
      end
    end
  end

  -- Scan directory for file extensions
  vim.notify("🔍 Scanning directory for source files...", vim.log.levels.INFO)
  local extensions = scan_directory_recursive(directory)

  -- Count files by language based on extensions
  for lang, config in pairs(language_config) do
    for _, ext in ipairs(config.extensions) do
      local count = extensions[ext:lower()] or 0
      if count > 0 then
        language_scores[lang] = language_scores[lang] + count
      end
    end
  end

  -- Add languages with significant presence
  local min_threshold = 1
  for lang, score in pairs(language_scores) do
    if score >= min_threshold then
      table.insert(detected_languages, {
        name = lang,
        score = score
      })
    end
  end

  -- Sort by score (most prevalent first)
  table.sort(detected_languages, function(a, b)
    return a.score > b.score
  end)

  return detected_languages
end

-- Get primary language from detected languages (for backward compatibility)
local function get_primary_language(languages)
  if #languages == 0 then
    return "javascript"  -- default fallback
  end
  return languages[1].name
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

local function save_database_info(db_path, languages, source_dir)
  local db_info = {
    path = db_path,
    languages = languages,  -- Now stores array of languages
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
        vim.g.codeql_current_languages = db_info.languages or {db_info.language}  -- Support old format
        return db_info
      end
    end
  end
  return nil
end

-- Auto-discover database in current directory
local function find_database_in_dir(directory)
  -- Look for language-specific databases (e.g., myproject-codeql-db-python)
  local db_pattern = directory .. "/*" .. config.database_suffix .. "-*"
  local matches = vim.fn.glob(db_pattern, false, true)

  if #matches == 0 then
    -- Fallback: look for old-style single database
    db_pattern = directory .. "/*" .. config.database_suffix
    matches = vim.fn.glob(db_pattern, false, true)
  end

  if #matches > 0 then
    -- Extract base database path (remove language suffix if present)
    local first_match = matches[1]
    local base_db_path = first_match:match("^(.+%-codeql%-db)")

    if not base_db_path then
      base_db_path = first_match
    end

    local languages = detect_languages(directory)
    vim.g.codeql_current_db = base_db_path
    vim.g.codeql_current_languages = languages
    save_database_info(base_db_path, languages, directory)
    return base_db_path
  end

  return nil
end

-- Get current database (try multiple sources)
local function get_current_database()
  local cwd = vim.fn.getcwd()

  -- 1. First, always check current directory for databases
  local found_db = find_database_in_dir(cwd)
  if found_db then
    return found_db
  end

  -- 2. Check session variables (in case we switched directories)
  if vim.g.codeql_current_db then
    -- Verify the database still exists
    local base_path = vim.g.codeql_current_db
    -- Check if at least one language-specific database exists
    local languages = vim.g.codeql_current_languages or {}
    for _, lang in ipairs(languages) do
      local lang_db_path = base_path .. "-" .. lang.name
      if vim.fn.isdirectory(lang_db_path) == 1 then
        return base_path
      end
    end
  end

  -- 3. Try to load from cache as last resort
  local db_info = load_database_info()
  if db_info then
    return db_info.path
  end

  return nil
end

-- 1. Create CodeQL Database (Multi-language support)
function M.create_database()
  vim.ui.input({
    prompt = "Enter directory to scan (or press Enter for current): ",
    default = vim.fn.getcwd(),
  }, function(input)
    if not input then return end

    local source_dir = vim.fn.expand(input)
    local db_name = vim.fn.fnamemodify(source_dir, ":t") .. config.database_suffix
    local db_path = source_dir .. "/" .. db_name

    -- Detect all languages in the directory
    local languages = detect_languages(source_dir)

    if #languages == 0 then
      vim.notify("❌ No supported languages detected in " .. source_dir, vim.log.levels.WARN)
      vim.notify("Supported: cpp, go, java, javascript, python, rust", vim.log.levels.INFO)
      return
    end

    -- Display detected languages
    local lang_names = {}
    for _, lang in ipairs(languages) do
      table.insert(lang_names, lang.name .. " (" .. lang.score .. " files)")
    end
    vim.notify("📊 Detected languages: " .. table.concat(lang_names, ", "), vim.log.levels.INFO)

    -- Remove existing database if it exists
    if vim.fn.isdirectory(db_path) == 1 then
      vim.fn.delete(db_path, "rf")
    end

    -- Create databases for each detected language
    local function create_next_db(idx)
      if idx > #languages then
        vim.notify("✅ All CodeQL databases created successfully!", vim.log.levels.INFO)
        vim.notify("📂 Base path: " .. db_path, vim.log.levels.INFO)
        vim.g.codeql_current_db = db_path
        vim.g.codeql_current_languages = languages
        save_database_info(db_path, languages, source_dir)
        return
      end

      local lang = languages[idx].name
      local lang_db_path = db_path .. "-" .. lang

      vim.notify("🔨 [" .. idx .. "/" .. #languages .. "] Creating " .. lang .. " database...", vim.log.levels.INFO)
      vim.notify("   📂 " .. lang_db_path, vim.log.levels.INFO)

      local cmd = {
        config.codeql_path,
        "database",
        "create",
        lang_db_path,
        "--language=" .. lang,
        "--source-root=" .. source_dir,
        "--overwrite"
      }

      run_command(cmd, function()
        vim.notify("✅ " .. lang .. " database created", vim.log.levels.INFO)
        create_next_db(idx + 1)
      end)
    end

    create_next_db(1)
  end)
end

-- 2. Scan Database (Multi-language support)
function M.scan_database()
  local db_path = get_current_database()
  local languages = vim.g.codeql_current_languages

  if not db_path then
    vim.notify("❌ No CodeQL database found in " .. vim.fn.getcwd(), vim.log.levels.WARN)
    vim.notify("💡 Create one first with <leader>cd or try <leader>cq", vim.log.levels.INFO)
    return
  end

  vim.notify("📂 Found database: " .. db_path, vim.log.levels.INFO)

  if not languages or #languages == 0 then
    vim.notify("❌ No language information found. Please recreate the database.", vim.log.levels.ERROR)
    return
  end

  -- Display scanning info
  local lang_names = {}
  for _, lang in ipairs(languages) do
    table.insert(lang_names, lang.name)
  end
  vim.notify("🔍 Scanning databases for: " .. table.concat(lang_names, ", "), vim.log.levels.INFO)

  local results_file = config.results_file()
  local all_results = {runs = {}}

  -- Scan each language database
  local function scan_next_language(idx)
    if idx > #languages then
      -- Merge all results into a single SARIF file
      if #all_results.runs > 0 then
        local merged_sarif = {
          version = "2.1.0",
          ["$schema"] = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
          runs = all_results.runs
        }

        local file = io.open(results_file, "w")
        if file then
          file:write(vim.fn.json_encode(merged_sarif))
          file:close()
          vim.notify("✅ All language scans completed. Results merged to " .. results_file, vim.log.levels.INFO)
          vim.schedule(function()
            M.show_results()
          end)
        else
          vim.notify("❌ Failed to write merged results", vim.log.levels.ERROR)
        end
      else
        vim.notify("⚠️  All scans completed but no results generated", vim.log.levels.WARN)
      end
      return
    end

    local lang = languages[idx].name
    local lang_db_path = db_path .. "-" .. lang

    if vim.fn.isdirectory(lang_db_path) == 0 then
      vim.notify("⚠️  Database not found for " .. lang .. ", skipping...", vim.log.levels.WARN)
      scan_next_language(idx + 1)
      return
    end

    vim.notify("🔍 Scanning " .. idx .. "/" .. #languages .. ": " .. lang .. " security queries...", vim.log.levels.INFO)

    local lang_results_file = results_file:gsub("%.sarif$", "_" .. lang .. ".sarif")
    local query_pack = language_config[lang].query_pack

    local cmd = {
      config.codeql_path,
      "database",
      "analyze",
      lang_db_path,
      "--format=sarif-latest",
      "--output=" .. lang_results_file,
      "--search-path=" .. config.codeql_packs,
      query_pack
    }

    run_command(cmd, function()
      vim.notify("✅ " .. lang .. " scan completed", vim.log.levels.INFO)

      -- Read and merge results
      if vim.fn.filereadable(lang_results_file) == 1 then
        local file = io.open(lang_results_file, "r")
        if file then
          local content = file:read("*a")
          file:close()

          local ok, sarif = pcall(vim.fn.json_decode, content)
          if ok and sarif and sarif.runs then
            for _, run in ipairs(sarif.runs) do
              table.insert(all_results.runs, run)
            end
          end

          -- Clean up individual result file
          vim.fn.delete(lang_results_file)
        end
      end

      scan_next_language(idx + 1)
    end)
  end

  scan_next_language(1)
end

-- Generate Markdown Report
function M.generate_markdown_report()
  local results_file = config.results_file()
  if vim.fn.filereadable(results_file) == 0 then
    vim.notify("No SARIF results file found. Run a scan first with <leader>cs", vim.log.levels.WARN)
    return
  end
  
  -- Read and parse SARIF file
  local file = io.open(results_file, "r")
  if not file then
    vim.notify("Failed to read SARIF results file", vim.log.levels.ERROR)
    return
  end
  
  local content = file:read("*a")
  file:close()
  
  local ok, sarif = pcall(vim.fn.json_decode, content)
  if not ok then
    vim.notify("Failed to parse SARIF results", vim.log.levels.ERROR)
    return
  end
  
  local markdown_file = config.markdown_file()
  local md_file = io.open(markdown_file, "w")
  if not md_file then
    vim.notify("Failed to create markdown file", vim.log.levels.ERROR)
    return
  end
  
  -- Write markdown header
  md_file:write("# CodeQL Security Analysis Results\n\n")
  md_file:write("Generated: " .. os.date("%Y-%m-%d %H:%M:%S") .. "\n\n")
  
  local results = sarif.runs[1].results or {}
  local rules = {}
  
  -- Build rules lookup
  for _, rule in ipairs(sarif.runs[1].tool.driver.rules or {}) do
    rules[rule.id] = rule
  end
  
  if #results == 0 then
    md_file:write("✅ **No security vulnerabilities found!**\n\n")
    md_file:write("Your code appears to be secure. Great job! 🎉\n")
  else
    md_file:write(string.format("**Total Findings:** %d\n\n", #results))
    
    -- Group by severity
    local by_severity = {error = {}, warning = {}}
    for _, result in ipairs(results) do
      local rule = rules[result.ruleId] or {}
      local severity = rule.defaultConfiguration and rule.defaultConfiguration.level or "warning"
      table.insert(by_severity[severity] or by_severity.warning, result)
    end
    
    -- Display critical issues first
    if #by_severity.error > 0 then
      md_file:write("## 🚨 Critical Issues (" .. #by_severity.error .. ")\n\n")
      
      for i, result in ipairs(by_severity.error) do
        local rule = rules[result.ruleId] or {}
        local security_severity = rule.properties and rule.properties["security-severity"] or "Unknown"
        
        md_file:write(string.format("### %d. %s\n\n", i, rule.name or result.ruleId))
        md_file:write(string.format("**Rule:** `%s`\n", result.ruleId))
        md_file:write(string.format("**Security Severity:** %s/10\n", security_severity))
        md_file:write(string.format("**Message:** %s\n\n", result.message.text or ""))
        
        -- Show locations with enhanced clickable links
        if result.locations then
          md_file:write("**Vulnerable Code Locations:**\n\n")
          for j, location in ipairs(result.locations) do
            if location.physicalLocation then
              local uri = location.physicalLocation.artifactLocation.uri
              local start_line = location.physicalLocation.region and location.physicalLocation.region.startLine or 1
              local end_line = location.physicalLocation.region and location.physicalLocation.region.endLine or start_line
              
              -- Create multiple link formats for better usability
              md_file:write(string.format("%d. **File:** `%s` **Line:** `%d`\n", j, uri, start_line))
              md_file:write(string.format("   - 📍 [Jump to code](%s#L%d)\n", uri, start_line))
              md_file:write(string.format("   - 🔗 Plain: %s:%d\n", uri, start_line))
              
              -- Add context if available
              if location.physicalLocation.region and location.physicalLocation.region.snippet then
                local snippet = location.physicalLocation.region.snippet.text
                if snippet and snippet ~= "" then
                  md_file:write(string.format("   - 📝 Code: `%s`\n", snippet:gsub("\n", " ")))
                end
              end
              md_file:write("\n")
            end
          end
        end
        
        -- Show data flow (sources and sinks) if available
        if result.codeFlows and #result.codeFlows > 0 then
          local flow = result.codeFlows[1]
          if flow.threadFlows and #flow.threadFlows > 0 then
            local threadFlow = flow.threadFlows[1]
            if threadFlow.locations and #threadFlow.locations > 1 then
              md_file:write("**Data Flow Path (Sources ➜ Sinks):**\n\n")
              for k, flowLocation in ipairs(threadFlow.locations) do
                if flowLocation.location and flowLocation.location.physicalLocation then
                  local flowUri = flowLocation.location.physicalLocation.artifactLocation.uri
                  local flowLine = flowLocation.location.physicalLocation.region.startLine
                  local step_type = k == 1 and "🔴 Source" or (k == #threadFlow.locations and "🎯 Sink" or "📍 Step " .. k)
                  local flow_msg = flowLocation.location.message and flowLocation.location.message.text or ""
                  
                  md_file:write(string.format("%d. **%s** in `%s`\n", k, step_type, flowUri))
                  md_file:write(string.format("   - 📍 [Line %d](%s#L%d)\n", flowLine, flowUri, flowLine))
                  md_file:write(string.format("   - 🔗 Plain: %s:%d\n", flowUri, flowLine))
                  if flow_msg ~= "" then
                    md_file:write(string.format("   - 💬 %s\n", flow_msg))
                  end
                  md_file:write("\n")
                end
              end
              md_file:write("\n")
            end
          end
        end
        
        -- Show fix suggestions if available
        if rule.help and rule.help.text then
          md_file:write("**Recommendation:**\n\n")
          md_file:write(rule.help.text .. "\n\n")
        end
        
        md_file:write("---\n\n")
      end
    end
    
    -- Display warnings
    if #by_severity.warning > 0 then
      md_file:write("## ⚠️ Warnings (" .. #by_severity.warning .. ")\n\n")
      
      for i, result in ipairs(by_severity.warning) do
        local rule = rules[result.ruleId] or {}
        
        md_file:write(string.format("### %d. %s\n\n", i, rule.name or result.ruleId))
        md_file:write(string.format("**Message:** %s\n\n", result.message.text or ""))
        
        if result.locations and result.locations[1] and result.locations[1].physicalLocation then
          local uri = result.locations[1].physicalLocation.artifactLocation.uri
          local start_line = result.locations[1].physicalLocation.region.startLine
          md_file:write(string.format("**Location:** `%s:%d`\n", uri, start_line))
          md_file:write(string.format("- 📍 [Jump to code](%s#L%d)\n", uri, start_line))
          md_file:write(string.format("- 🔗 Plain: %s:%d\n\n", uri, start_line))
        end
        
        -- Show data flow for warnings too
        if result.codeFlows and #result.codeFlows > 0 then
          local flow = result.codeFlows[1]
          if flow.threadFlows and #flow.threadFlows > 0 then
            local threadFlow = flow.threadFlows[1]
            if threadFlow.locations and #threadFlow.locations > 1 then
              md_file:write("**Data Flow Path:**\n\n")
              for k, flowLocation in ipairs(threadFlow.locations) do
                if flowLocation.location and flowLocation.location.physicalLocation then
                  local flowUri = flowLocation.location.physicalLocation.artifactLocation.uri
                  local flowLine = flowLocation.location.physicalLocation.region.startLine
                  local step_type = k == 1 and "🔴 Source" or (k == #threadFlow.locations and "🎯 Sink" or "📍 Step " .. k)
                  
                  md_file:write(string.format("%d. **%s** in `%s`\n", k, step_type, flowUri))
                  md_file:write(string.format("   - 📍 [Line %d](%s#L%d)\n", flowLine, flowUri, flowLine))
                  md_file:write(string.format("   - 🔗 Plain: %s:%d\n\n", flowUri, flowLine))
                end
              end
              md_file:write("\n")
            end
          end
        end
      end
    end
  end
  
  md_file:write("\n---\n\n")
  md_file:write("**Navigation Notes:**\n\n")
  md_file:write("- File links are clickable in compatible editors/viewers\n")
  md_file:write("- Use `<leader>cv` to view this markdown report in Neovim\n")
  md_file:write("- Use `<leader>cr` to view interactive results browser\n")
  
  md_file:close()
  
  vim.notify("✅ Markdown report generated: " .. markdown_file, vim.log.levels.INFO)
end

-- View Markdown Report
function M.view_markdown_report()
  local markdown_file = config.markdown_file()
  if vim.fn.filereadable(markdown_file) == 0 then
    vim.notify("No markdown report found. Generate one first with <leader>cm", vim.log.levels.WARN)
    return
  end
  
  -- Open markdown file in a new buffer
  vim.cmd("edit " .. vim.fn.fnameescape(markdown_file))
  vim.api.nvim_buf_set_option(0, 'filetype', 'markdown')
  
  -- Set up key mappings for the markdown buffer
  local buf = vim.api.nvim_get_current_buf()
  
  -- Function to jump to file location from markdown links
  local function jump_to_file_from_link()
    local line = vim.api.nvim_get_current_line()
    
    -- Try multiple patterns to match different markdown link formats
    local patterns = {
      -- Pattern 1: [text](file.ext#L123)
      "\\[([^%]]+)\\]\\(([^)]+)#L(%d+)\\)",
      -- Pattern 2: [file.ext:123](file.ext#L123) 
      "\\[([^:]+):(%d+)\\]\\(([^)]+)#L%d+\\)",
      -- Pattern 3: file.ext:123 (plain text)
      "([%w%./%-_]+%.%w+):(%d+)",
      -- Pattern 4: Simple file pattern with line number
      "([%w%./%-_]+%.%w+).*:.*(%d+)"
    }
    
    local file_path, line_num
    
    for _, pattern in ipairs(patterns) do
      local match1, match2, match3 = line:match(pattern)
      if match1 and match2 then
        if pattern:find("#L") then
          -- Pattern with #L format
          file_path = match2
          line_num = match3
        else
          -- Pattern with :line format
          file_path = match1
          line_num = match2
        end
        break
      end
    end
    
    if file_path and line_num then
      -- Clean up file path (remove any anchors or extra characters)
      file_path = file_path:gsub("#L%d+$", "")
      
      -- Handle relative paths
      if not vim.startswith(file_path, "/") then
        file_path = vim.fn.getcwd() .. "/" .. file_path
      end
      
      if vim.fn.filereadable(file_path) == 1 then
        vim.cmd("edit " .. vim.fn.fnameescape(file_path))
        vim.api.nvim_win_set_cursor(0, {tonumber(line_num), 0})
        vim.notify("🎯 Jumped to " .. file_path .. ":" .. line_num, vim.log.levels.INFO)
      else
        vim.notify("❌ File not found: " .. file_path, vim.log.levels.WARN)
      end
    else
      -- Fallback: try to extract any file-like pattern
      local fallback_file = line:match("([%w%./%-_]+%.%w+)")
      if fallback_file then
        if not vim.startswith(fallback_file, "/") then
          fallback_file = vim.fn.getcwd() .. "/" .. fallback_file
        end
        if vim.fn.filereadable(fallback_file) == 1 then
          vim.cmd("edit " .. vim.fn.fnameescape(fallback_file))
          vim.notify("📂 Opened file: " .. fallback_file, vim.log.levels.INFO)
        else
          vim.notify("❌ No valid file link found on this line", vim.log.levels.WARN)
        end
      else
        vim.notify("❌ No file link found on this line", vim.log.levels.WARN)
      end
    end
  end
  
  vim.keymap.set('n', '<CR>', jump_to_file_from_link, {buffer = buf, desc = "Jump to file from link"})
  vim.keymap.set('n', 'gf', jump_to_file_from_link, {buffer = buf, desc = "Jump to file from link"})
  
  vim.notify("📄 Viewing markdown report. Press <Enter> or gf on file links to jump to code.", vim.log.levels.INFO)
end

-- 3. Parse and Display Results
function M.show_results()
  local results_file = config.results_file()
  if vim.fn.filereadable(results_file) == 0 then
    vim.notify("No results file found. Run a scan first with <leader>cs", vim.log.levels.WARN)
    return
  end
  
  -- Read and parse SARIF file
  local file = io.open(results_file, "r")
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
        -- Split multiline messages into separate lines
        local message_lines = vim.split(result.message.text or "", "\n", {plain = true})
        if #message_lines == 1 then
          table.insert(lines, string.format("**Message:** %s", message_lines[1]))
        else
          table.insert(lines, "**Message:**")
          for _, msg_line in ipairs(message_lines) do
            table.insert(lines, "  " .. msg_line)
          end
        end
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
                    local flow_msg = flowLocation.location.message.text or ""
                    -- Replace newlines with spaces for inline display
                    flow_msg = flow_msg:gsub("\n", " ")
                    step_text = step_text .. " - " .. flow_msg
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
          -- Split multiline help text into separate lines
          local help_lines = vim.split(rule.help.text, "\n", {plain = true})
          for _, help_line in ipairs(help_lines) do
            table.insert(lines, help_line)
          end
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
        -- Split multiline messages into separate lines
        local message_lines = vim.split(result.message.text or "", "\n", {plain = true})
        if #message_lines == 1 then
          table.insert(lines, string.format("**Message:** %s", message_lines[1]))
        else
          table.insert(lines, "**Message:**")
          for _, msg_line in ipairs(message_lines) do
            table.insert(lines, "  " .. msg_line)
          end
        end
        
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
  
  local results_file = config.results_file()
  local cmd = {
    config.codeql_path,
    "query", 
    "run",
    current_file,
    "--database=" .. db_path,
    "--output=" .. results_file,
    "--format=sarif-latest"
  }
  
  run_command(cmd, function()
    vim.notify("✅ Custom query completed. Results saved to " .. results_file, vim.log.levels.INFO)
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

-- 6. Python-specific Security Scan (uses multi-language detection but filters for Python)
function M.python_security_scan()
  vim.ui.input({
    prompt = "Enter Python project directory (or press Enter for current): ",
    default = vim.fn.getcwd(),
  }, function(input)
    if not input then return end

    local source_dir = vim.fn.expand(input)
    local db_name = vim.fn.fnamemodify(source_dir, ":t") .. config.database_suffix
    local db_path = source_dir .. "/" .. db_name

    -- Detect languages
    local languages = detect_languages(source_dir)

    -- Filter for Python
    local python_lang = nil
    for _, lang in ipairs(languages) do
      if lang.name == "python" then
        python_lang = lang
        break
      end
    end

    if not python_lang then
      vim.ui.input({
        prompt = "No Python files detected. Continue anyway? (y/N): ",
      }, function(confirm)
        if not confirm or confirm:lower() ~= "y" then
          vim.notify("Python scan cancelled", vim.log.levels.INFO)
          return
        end
        -- Force Python language
        python_lang = {name = "python", score = 1}
        start_python_scan(source_dir, db_path, python_lang)
      end)
    else
      start_python_scan(source_dir, db_path, python_lang)
    end
  end)
end

-- Helper function to start Python scan
local function start_python_scan(source_dir, db_path, python_lang)
  vim.notify("🐍 Starting Python security scan of " .. source_dir, vim.log.levels.INFO)

  -- Check for virtual environment and provide guidance
  local venv_paths = {source_dir .. "/venv", source_dir .. "/.venv", source_dir .. "/env"}
  local venv_found = false
  for _, venv_path in ipairs(venv_paths) do
    if vim.fn.isdirectory(venv_path) == 1 then
      venv_found = true
      vim.notify("📦 Virtual environment detected: " .. vim.fn.fnamemodify(venv_path, ":t"), vim.log.levels.INFO)
      break
    end
  end

  if not venv_found then
    vim.notify("💡 Tip: CodeQL works better with Python virtual environments", vim.log.levels.INFO)
  end

  local lang_db_path = db_path .. "-python"

  -- Remove existing database if it exists
  if vim.fn.isdirectory(lang_db_path) == 1 then
    vim.fn.delete(lang_db_path, "rf")
  end

  local create_cmd = {
    config.codeql_path,
    "database",
    "create",
    lang_db_path,
    "--language=python",
    "--source-root=" .. source_dir,
    "--overwrite"
  }

  run_command(create_cmd, function()
    vim.g.codeql_current_db = db_path
    vim.g.codeql_current_languages = {python_lang}
    save_database_info(db_path, {python_lang}, source_dir)

    -- Step 2: Analyze with Python security queries
    local results_file = config.results_file()
    local query_pack = language_config["python"].query_pack

    local analyze_cmd = {
      config.codeql_path,
      "database",
      "analyze",
      lang_db_path,
      "--format=sarif-latest",
      "--output=" .. results_file,
      "--search-path=" .. config.codeql_packs,
      query_pack
    }

    vim.notify("🔍 Running Python security analysis...", vim.log.levels.INFO)
    run_command(analyze_cmd, function()
      -- Step 3: Show results
      vim.schedule(function()
        vim.notify("📊 Python security scan complete! Showing results...", vim.log.levels.INFO)
        M.show_results()
      end)
    end)
  end)
end

-- 7. Quick Security Scan (combines all steps with multi-language support)
function M.quick_scan()
  vim.ui.input({
    prompt = "Enter directory to scan (or press Enter for current): ",
    default = vim.fn.getcwd(),
  }, function(input)
    if not input then return end

    local source_dir = vim.fn.expand(input)
    local db_name = vim.fn.fnamemodify(source_dir, ":t") .. config.database_suffix
    local db_path = source_dir .. "/" .. db_name

    -- Detect all languages
    local languages = detect_languages(source_dir)

    if #languages == 0 then
      vim.notify("❌ No supported languages detected", vim.log.levels.WARN)
      return
    end

    -- Display detected languages
    local lang_names = {}
    for _, lang in ipairs(languages) do
      table.insert(lang_names, lang.name)
    end
    vim.notify("🚀 Quick scan starting for: " .. table.concat(lang_names, ", "), vim.log.levels.INFO)

    -- Remove existing databases
    for _, lang in ipairs(languages) do
      local lang_db_path = db_path .. "-" .. lang.name
      if vim.fn.isdirectory(lang_db_path) == 1 then
        vim.fn.delete(lang_db_path, "rf")
      end
    end

    local results_file = config.results_file()
    local all_results = {runs = {}}

    -- Create database and scan for each language
    local function process_next_language(idx)
      if idx > #languages then
        -- Merge all results
        if #all_results.runs > 0 then
          local merged_sarif = {
            version = "2.1.0",
            ["$schema"] = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            runs = all_results.runs
          }

          local file = io.open(results_file, "w")
          if file then
            file:write(vim.fn.json_encode(merged_sarif))
            file:close()

            vim.g.codeql_current_db = db_path
            vim.g.codeql_current_languages = languages
            save_database_info(db_path, languages, source_dir)

            vim.notify("✅ Quick scan complete! Showing results...", vim.log.levels.INFO)
            vim.schedule(function()
              M.show_results()
            end)
          end
        else
          vim.notify("⚠️  Scan completed but no results found", vim.log.levels.WARN)
        end
        return
      end

      local lang = languages[idx].name
      local lang_db_path = db_path .. "-" .. lang

      vim.notify("🔨 [" .. idx .. "/" .. #languages .. "] Creating " .. lang .. " database...", vim.log.levels.INFO)

      -- Create database
      local create_cmd = {
        config.codeql_path,
        "database",
        "create",
        lang_db_path,
        "--language=" .. lang,
        "--source-root=" .. source_dir,
        "--overwrite"
      }

      run_command(create_cmd, function()
        vim.notify("🔍 [" .. idx .. "/" .. #languages .. "] Scanning " .. lang .. "...", vim.log.levels.INFO)

        -- Analyze database
        local lang_results_file = results_file:gsub("%.sarif$", "_" .. lang .. ".sarif")
        local query_pack = language_config[lang].query_pack

        local analyze_cmd = {
          config.codeql_path,
          "database",
          "analyze",
          lang_db_path,
          "--format=sarif-latest",
          "--output=" .. lang_results_file,
          "--search-path=" .. config.codeql_packs,
          query_pack
        }

        run_command(analyze_cmd, function()
          -- Read and merge results
          if vim.fn.filereadable(lang_results_file) == 1 then
            local file = io.open(lang_results_file, "r")
            if file then
              local content = file:read("*a")
              file:close()

              local ok, sarif = pcall(vim.fn.json_decode, content)
              if ok and sarif and sarif.runs then
                for _, run in ipairs(sarif.runs) do
                  table.insert(all_results.runs, run)
                end
              end

              vim.fn.delete(lang_results_file)
            end
          end

          process_next_language(idx + 1)
        end)
      end)
    end

    process_next_language(1)
  end)
end

-- Set up keymaps
function M.setup()
  vim.keymap.set('n', '<leader>cd', M.create_database, {desc = "CodeQL: Create Database"})
  vim.keymap.set('n', '<leader>cs', M.scan_database, {desc = "CodeQL: Scan Database"})
  vim.keymap.set('n', '<leader>cr', M.show_results, {desc = "CodeQL: Show Results"})
  vim.keymap.set('n', '<leader>cq', M.quick_scan, {desc = "CodeQL: Quick Security Scan"})
  vim.keymap.set('n', '<leader>cp', M.python_security_scan, {desc = "CodeQL: Python Security Scan"})
  vim.keymap.set('n', '<leader>cf', M.run_query_file, {desc = "CodeQL: Run Query File"})
  vim.keymap.set('n', '<leader>cm', M.generate_markdown_report, {desc = "CodeQL: Generate Markdown Report"})
  vim.keymap.set('n', '<leader>cv', M.view_markdown_report, {desc = "CodeQL: View Markdown Report"})
  vim.keymap.set('n', '<leader>pp', M.run_prettier, {desc = "Prettier: Format JavaScript files"})
  
  --[[ vim.notify("CodeQL keymaps loaded:", vim.log.levels.INFO)
  vim.notify("  <leader>cd - Create Database", vim.log.levels.INFO)
  vim.notify("  <leader>cs - Scan Database", vim.log.levels.INFO)
  vim.notify("  <leader>cr - Show Results", vim.log.levels.INFO)
  vim.notify("  <leader>cq - Quick Scan (all-in-one)", vim.log.levels.INFO)
  vim.notify("  <leader>cp - Python Security Scan", vim.log.levels.INFO)
  vim.notify("  <leader>cf - Run Query File", vim.log.levels.INFO)
  vim.notify("  <leader>cm - Generate Markdown Report", vim.log.levels.INFO)
  vim.notify("  <leader>cv - View Markdown Report", vim.log.levels.INFO)
  vim.notify("  <leader>pp - Run Prettier on *.js files", vim.log.levels.INFO) ]]--
end

return M
