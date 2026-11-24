-- Builtin Blackbird SaaS Integration Pack: GitHub REST API (issues, PRs, diff & comments).
-- Secrets and host pinning (api.github.com) are enforced exclusively in C++.

---@class GithubHttpResponse
---@field status integer
---@field headers table<string, string>
---@field body string
---@field json any

---@class GithubHttpApi
---@field request fun(op: table): GithubHttpResponse
---@field url_encode fun(text: string): string

---@return GithubHttpApi
local function bb_http()
  local bb = rawget(_G, "blackbird")
  assert(type(bb) == "table", "blackbird unavailable")
  local http = rawget(bb, "http")
  assert(type(http) == "table", "blackbird.http unavailable")
  return http
end

local GH_HEADERS = {
  ["Accept"] = "application/vnd.github+json",
  ["X-GitHub-Api-Version"] = "2022-11-28",
}

---@param args table
---@return string
local function repo_prefix(args)
  assert(type(args) == "table", "github operation requires arguments table")
  assert(
    type(args.owner) == "string" and #args.owner > 0,
    "github operation requires owner"
  )
  assert(
    type(args.repo) == "string" and #args.repo > 0,
    "github operation requires repo"
  )
  return "/repos/"
    .. bb_http().url_encode(args.owner)
    .. "/"
    .. bb_http().url_encode(args.repo)
end

local operations = {}

---@param args table
---@return string
function operations.list_items(args)
  local prefix = repo_prefix(args)
  local kind = args.kind == "pulls" and "pulls" or "issues"
  local resp = bb_http().request({
    service = "github",
    method = "GET",
    path = prefix .. "/" .. kind,
    headers = GH_HEADERS,
    query = {
      state = type(args.state) == "string" and args.state or "open",
      per_page = tostring(type(args.per_page) == "number" and args.per_page or 15),
    },
    effect = "read",
  })
  assert(
    resp.status >= 200 and resp.status < 300,
    "GitHub list_items HTTP " .. tostring(resp.status)
  )
  local items = type(resp.json) == "table" and resp.json or {}
  local lines = {
    "# GitHub " .. args.owner .. "/" .. args.repo .. " " .. kind .. " (" .. tostring(
      #items
    ) .. ")",
  }
  for _, item in ipairs(items) do
    local author = (type(item.user) == "table" and item.user.login) or "unknown"
    local tag = item.pull_request ~= nil and "PR" or "Issue"
    if kind == "pulls" then
      tag = "PR"
    end
    lines[#lines + 1] = "- #"
      .. tostring(item.number)
      .. " ["
      .. tag
      .. "/"
      .. tostring(item.state or "open")
      .. "] "
      .. tostring(item.title or "")
      .. " (@"
      .. author
      .. ")"
  end
  return table.concat(lines, "\n")
end

---@param args table
---@return string
function operations.view_item(args)
  local prefix = repo_prefix(args)
  assert(
    type(args.number) == "number" or type(args.number) == "string",
    "github.view_item requires number"
  )
  local num = tostring(args.number)
  local is_pr = args.is_pr == true
  local item_path = prefix
    .. (is_pr and "/pulls/" or "/issues/")
    .. bb_http().url_encode(num)
  local resp = bb_http().request({
    service = "github",
    method = "GET",
    path = item_path,
    headers = GH_HEADERS,
    effect = "read",
  })
  assert(
    resp.status >= 200 and resp.status < 300,
    "GitHub view_item HTTP " .. tostring(resp.status)
  )
  local item = type(resp.json) == "table" and resp.json or {}
  local author = (type(item.user) == "table" and item.user.login) or "unknown"
  local lines = {
    "# #" .. num .. ": " .. tostring(item.title or ""),
    "State: " .. tostring(item.state or "open") .. " | Author: @" .. author,
  }
  if type(item.body) == "string" and #item.body > 0 then
    lines[#lines + 1] = ""
    lines[#lines + 1] = item.body
  end

  if is_pr and args.include_diff ~= false then
    local files_resp = bb_http().request({
      service = "github",
      method = "GET",
      path = prefix .. "/pulls/" .. bb_http().url_encode(num) .. "/files",
      headers = GH_HEADERS,
      query = { per_page = "20" },
      effect = "read",
    })
    if
      files_resp.status >= 200
      and files_resp.status < 300
      and type(files_resp.json) == "table"
    then
      lines[#lines + 1] = ""
      lines[#lines + 1] = "## Changed Files (" .. tostring(#files_resp.json) .. ")"
      for _, f in ipairs(files_resp.json) do
        lines[#lines + 1] = "- "
          .. tostring(f.filename or "?")
          .. " (+"
          .. tostring(f.additions or 0)
          .. "/-"
          .. tostring(f.deletions or 0)
          .. ")"
        if type(f.patch) == "string" and #f.patch > 0 then
          lines[#lines + 1] = "```diff\n" .. f.patch:sub(1, 600) .. "\n```"
        end
      end
    end
  end

  local comments_resp = bb_http().request({
    service = "github",
    method = "GET",
    path = prefix .. "/issues/" .. bb_http().url_encode(num) .. "/comments",
    headers = GH_HEADERS,
    query = { per_page = "15" },
    effect = "read",
  })
  if
    comments_resp.status >= 200
    and comments_resp.status < 300
    and type(comments_resp.json) == "table"
    and #comments_resp.json > 0
  then
    lines[#lines + 1] = ""
    lines[#lines + 1] = "## Comments (" .. tostring(#comments_resp.json) .. ")"
    for _, c in ipairs(comments_resp.json) do
      local cauthor = (type(c.user) == "table" and c.user.login) or "unknown"
      local cbody = type(c.body) == "string"
          and c.body:gsub("\r\n", "\n"):gsub("\n", " ")
        or ""
      lines[#lines + 1] = "- **@" .. cauthor .. "**: " .. cbody:sub(1, 280)
    end
  end
  return table.concat(lines, "\n")
end

---@param args table
---@return string
function operations.create_issue(args)
  local prefix = repo_prefix(args)
  assert(
    type(args.title) == "string" and #args.title > 0,
    "github.create_issue requires title"
  )
  local body = { title = args.title }
  if type(args.body) == "string" then
    body.body = args.body
  end
  if type(args.labels) == "table" then
    body.labels = args.labels
  end
  local resp = bb_http().request({
    service = "github",
    method = "POST",
    path = prefix .. "/issues",
    headers = GH_HEADERS,
    effect = "write",
    json = body,
  })
  assert(
    resp.status >= 200 and resp.status < 300,
    "GitHub create_issue HTTP " .. tostring(resp.status)
  )
  local created = type(resp.json) == "table" and resp.json or {}
  return "Created issue #"
    .. tostring(created.number or "?")
    .. ": "
    .. tostring(created.title or args.title)
end

---@param args table
---@return string
function operations.comment_item(args)
  local prefix = repo_prefix(args)
  assert(
    type(args.number) == "number" or type(args.number) == "string",
    "github.comment_item requires number"
  )
  assert(
    type(args.body) == "string" and #args.body > 0,
    "github.comment_item requires body"
  )
  local num = tostring(args.number)
  local resp = bb_http().request({
    service = "github",
    method = "POST",
    path = prefix .. "/issues/" .. bb_http().url_encode(num) .. "/comments",
    headers = GH_HEADERS,
    effect = "send",
    json = { body = args.body },
  })
  assert(
    resp.status >= 200 and resp.status < 300,
    "GitHub comment_item HTTP " .. tostring(resp.status)
  )
  local created = type(resp.json) == "table" and resp.json or {}
  return "Posted comment id=" .. tostring(created.id or "?") .. " on #" .. num
end

return {
  service = "github",
  version = 1,
  allowed_hosts = { "api.github.com" },
  operations = operations,
}
