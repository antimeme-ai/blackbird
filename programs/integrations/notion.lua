-- Builtin Blackbird SaaS Integration Pack: Notion API (Notion-Version: 2025-09-03).
-- Secrets and host pinning (api.notion.com) are enforced exclusively in C++.

---@class NotionHttpResponse
---@field status integer
---@field headers table<string, string>
---@field body string
---@field json any

---@class NotionHttpApi
---@field request fun(op: table): NotionHttpResponse
---@field url_encode fun(text: string): string

---@return NotionHttpApi
local function bb_http()
  local bb = rawget(_G, "blackbird")
  assert(type(bb) == "table", "blackbird unavailable")
  local http = rawget(bb, "http")
  assert(type(http) == "table", "blackbird.http unavailable")
  return http
end

local NOTION_HEADERS = { ["Notion-Version"] = "2025-09-03" }

---@param rich_text table?
---@return string
local function flatten_rich_text(rich_text)
  if type(rich_text) ~= "table" then
    return ""
  end
  local parts = {}
  for _, seg in ipairs(rich_text) do
    if type(seg) == "table" then
      local txt = seg.plain_text
      if type(txt) ~= "string" and type(seg.text) == "table" then
        txt = seg.text.content
      end
      if type(txt) == "string" then
        parts[#parts + 1] = txt
      end
    end
  end
  return table.concat(parts, "")
end

---@param page table
---@return string
local function extract_page_title(page)
  if type(page.properties) == "table" then
    for _, prop in pairs(page.properties) do
      if type(prop) == "table" and prop.type == "title" then
        local t = flatten_rich_text(prop.title)
        if #t > 0 then
          return t
        end
      end
    end
  end
  if type(page.title) == "table" then
    local t = flatten_rich_text(page.title)
    if #t > 0 then
      return t
    end
  end
  return tostring(page.id or "(untitled)")
end

---@param block table
---@return string?
local function block_to_markdown(block)
  local kind = tostring(block.type or "")
  local inner = type(block[kind]) == "table" and block[kind] or {}
  local text = flatten_rich_text(inner.rich_text)
  if kind == "heading_1" then
    return "# " .. text
  elseif kind == "heading_2" then
    return "## " .. text
  elseif kind == "heading_3" then
    return "### " .. text
  elseif kind == "paragraph" then
    return text
  elseif kind == "bulleted_list_item" then
    return "- " .. text
  elseif kind == "numbered_list_item" then
    return "1. " .. text
  elseif kind == "to_do" then
    local box = inner.checked == true and "[x] " or "[ ] "
    return "- " .. box .. text
  elseif kind == "quote" or kind == "callout" then
    return "> " .. text
  elseif kind == "code" then
    local lang = tostring(inner.language or "")
    return "```" .. lang .. "\n" .. text .. "\n```"
  elseif kind == "divider" then
    return "---"
  end
  if #text > 0 then
    return text
  end
  return nil
end

local operations = {}

---@param args table?
---@return string
function operations.search(args)
  local opts = type(args) == "table" and args or {}
  local body = {
    page_size = type(opts.page_size) == "number" and opts.page_size or 10,
  }
  if type(opts.query) == "string" and #opts.query > 0 then
    body.query = opts.query
  end
  if type(opts.filter_object) == "string" and #opts.filter_object > 0 then
    body.filter = { property = "object", value = opts.filter_object }
  end
  if type(opts.start_cursor) == "string" and #opts.start_cursor > 0 then
    body.start_cursor = opts.start_cursor
  end
  local resp = bb_http().request({
    service = "notion",
    method = "POST",
    path = "/v1/search",
    headers = NOTION_HEADERS,
    effect = "read",
    json = body,
  })
  assert(
    resp.status >= 200 and resp.status < 300,
    "Notion search HTTP " .. tostring(resp.status)
  )
  local data = type(resp.json) == "table" and resp.json or {}
  local results = type(data.results) == "table" and data.results or {}
  local lines = { "# Notion Search (" .. tostring(#results) .. " results)" }
  for _, item in ipairs(results) do
    local title = extract_page_title(item)
    lines[#lines + 1] = "- ["
      .. tostring(item.object or "page")
      .. "] **"
      .. title
      .. "** (id="
      .. tostring(item.id or "")
      .. ")"
  end
  return table.concat(lines, "\n")
end

---@param args table
---@return string
function operations.read_page(args)
  assert(type(args) == "table", "notion.read_page requires arguments table")
  assert(
    type(args.page_id) == "string" and #args.page_id > 0,
    "notion.read_page requires page_id"
  )
  local safe_id = bb_http().url_encode(args.page_id)
  local page_resp = bb_http().request({
    service = "notion",
    method = "GET",
    path = "/v1/pages/" .. safe_id,
    headers = NOTION_HEADERS,
    effect = "read",
  })
  assert(
    page_resp.status >= 200 and page_resp.status < 300,
    "Notion get page HTTP " .. tostring(page_resp.status)
  )
  local page = type(page_resp.json) == "table" and page_resp.json or {}

  local blocks_resp = bb_http().request({
    service = "notion",
    method = "GET",
    path = "/v1/blocks/" .. safe_id .. "/children",
    headers = NOTION_HEADERS,
    query = {
      page_size = tostring(type(args.page_size) == "number" and args.page_size or 50),
    },
    effect = "read",
  })
  assert(
    blocks_resp.status >= 200 and blocks_resp.status < 300,
    "Notion get blocks HTTP " .. tostring(blocks_resp.status)
  )
  local bdata = type(blocks_resp.json) == "table" and blocks_resp.json or {}
  local blocks = type(bdata.results) == "table" and bdata.results or {}

  local lines = { "# " .. extract_page_title(page) }
  for _, blk in ipairs(blocks) do
    local md = block_to_markdown(blk)
    if md ~= nil then
      lines[#lines + 1] = md
    end
  end
  return table.concat(lines, "\n")
end

---@param args table
---@return string
function operations.append_block(args)
  assert(type(args) == "table", "notion.append_block requires arguments table")
  assert(
    type(args.block_id) == "string" and #args.block_id > 0,
    "notion.append_block requires block_id"
  )
  assert(
    type(args.text) == "string" and #args.text > 0,
    "notion.append_block requires text"
  )
  local btype = type(args.block_type) == "string"
      and #args.block_type > 0
      and args.block_type
    or "paragraph"
  local child = {
    object = "block",
    type = btype,
    [btype] = {
      rich_text = {
        { type = "text", text = { content = args.text } },
      },
    },
  }
  local resp = bb_http().request({
    service = "notion",
    method = "PATCH",
    path = "/v1/blocks/" .. bb_http().url_encode(args.block_id) .. "/children",
    headers = NOTION_HEADERS,
    effect = "write",
    json = { children = { child } },
  })
  assert(
    resp.status >= 200 and resp.status < 300,
    "Notion append_block HTTP " .. tostring(resp.status)
  )
  local data = type(resp.json) == "table" and resp.json or {}
  local added = type(data.results) == "table" and #data.results or 1
  return "Appended "
    .. tostring(added)
    .. " "
    .. btype
    .. " block(s) to "
    .. args.block_id
end

return {
  service = "notion",
  version = 1,
  allowed_hosts = { "api.notion.com" },
  operations = operations,
}
