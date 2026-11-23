-- Builtin Blackbird SaaS Integration Pack: Slack Web API (compact user/channel formatting).
-- Secrets and host pinning (slack.com) are enforced exclusively in C++.

---@class SlackHttpResponse
---@field status integer
---@field headers table<string, string>
---@field body string
---@field json any

---@class SlackHttpApi
---@field request fun(op: table): SlackHttpResponse

---@return SlackHttpApi
local function bb_http()
  local bb = rawget(_G, "blackbird")
  assert(type(bb) == "table", "blackbird unavailable")
  local http = rawget(bb, "http")
  assert(type(http) == "table", "blackbird.http unavailable")
  return http
end

---@param resp SlackHttpResponse
---@param label string
---@return table
local function expect_slack_ok(resp, label)
  if resp.status == 429 then
    local retry = resp.headers["retry-after"] or "unknown"
    error(
      "Slack rate limited (429) on " .. label .. ", retry-after=" .. tostring(retry)
    )
  end
  assert(
    resp.status >= 200 and resp.status < 300,
    "Slack HTTP " .. tostring(resp.status) .. " on " .. label
  )
  local data = resp.json
  assert(type(data) == "table", "Slack returned non-JSON on " .. label)
  if data.ok ~= true then
    error("Slack API error on " .. label .. ": " .. tostring(data.error or "unknown"))
  end
  return data
end

---@param user_id any
---@param users table?
---@return string
local function format_user(user_id, users)
  local uid = tostring(user_id or "bot")
  if type(users) == "table" and type(users[uid]) == "string" then
    return "@" .. users[uid]
  end
  return "@" .. uid
end

---@param text any
---@param users table?
---@return string
local function format_message_text(text, users)
  if type(text) ~= "string" then
    return ""
  end
  local out = text:gsub("<@([A-Z0-9]+)>", function(uid)
    return format_user(uid, users)
  end)
  out = out:gsub("<#([A-Z0-9]+)|([^>]+)>", "#%2")
  out = out:gsub("\r\n", "\n"):gsub("\n", " ")
  return out
end

local operations = {}

---@param args table?
---@return string
function operations.list_channels(args)
  local opts = type(args) == "table" and args or {}
  local query = {
    types = type(opts.types) == "string" and opts.types
      or "public_channel,private_channel",
    limit = tostring(type(opts.limit) == "number" and opts.limit or 50),
    exclude_archived = "true",
  }
  if type(opts.cursor) == "string" and #opts.cursor > 0 then
    query.cursor = opts.cursor
  end
  local resp = bb_http().request({
    service = "slack",
    method = "GET",
    path = "/api/conversations.list",
    query = query,
    effect = "read",
  })
  local data = expect_slack_ok(resp, "conversations.list")
  local channels = type(data.channels) == "table" and data.channels or {}
  local lines = { "# Slack Channels (" .. tostring(#channels) .. ")" }
  for _, ch in ipairs(channels) do
    local prefix = ch.is_private == true and "lock:#" or "#"
    local members = tostring(ch.num_members or 0)
    local topic = (type(ch.topic) == "table" and type(ch.topic.value) == "string")
        and ch.topic.value
      or ""
    local suffix = #topic > 0 and (" — " .. topic:sub(1, 80)) or ""
    lines[#lines + 1] = "- "
      .. prefix
      .. tostring(ch.name or ch.id)
      .. " ("
      .. tostring(ch.id)
      .. ", "
      .. members
      .. " members)"
      .. suffix
  end
  local meta = type(data.response_metadata) == "table" and data.response_metadata or {}
  if type(meta.next_cursor) == "string" and #meta.next_cursor > 0 then
    lines[#lines + 1] = "next_cursor: " .. meta.next_cursor
  end
  return table.concat(lines, "\n")
end

---@param args table
---@return string
function operations.channel_history(args)
  assert(type(args) == "table", "slack.channel_history requires arguments table")
  assert(
    type(args.channel) == "string" and #args.channel > 0,
    "slack.channel_history requires channel"
  )
  local query = {
    channel = args.channel,
    limit = tostring(type(args.limit) == "number" and args.limit or 20),
  }
  if type(args.cursor) == "string" and #args.cursor > 0 then
    query.cursor = args.cursor
  end
  local resp = bb_http().request({
    service = "slack",
    method = "GET",
    path = "/api/conversations.history",
    query = query,
    effect = "read",
  })
  local data = expect_slack_ok(resp, "conversations.history")
  local msgs = type(data.messages) == "table" and data.messages or {}
  local users = type(args.users) == "table" and args.users or nil
  local lines =
    { "# Slack Channel " .. args.channel .. " (" .. tostring(#msgs) .. " msgs)" }
  for _, m in ipairs(msgs) do
    local replies = (type(m.reply_count) == "number" and m.reply_count > 0)
        and (" [" .. tostring(m.reply_count) .. " replies]")
      or ""
    lines[#lines + 1] = "- ["
      .. tostring(m.ts or "")
      .. "] "
      .. format_user(m.user, users)
      .. ": "
      .. format_message_text(m.text, users)
      .. replies
  end
  return table.concat(lines, "\n")
end

---@param args table
---@return string
function operations.read_thread(args)
  assert(type(args) == "table", "slack.read_thread requires arguments table")
  assert(
    type(args.channel) == "string" and #args.channel > 0,
    "slack.read_thread requires channel"
  )
  assert(
    type(args.thread_ts) == "string" and #args.thread_ts > 0,
    "slack.read_thread requires thread_ts"
  )
  local query = {
    channel = args.channel,
    ts = args.thread_ts,
    limit = tostring(type(args.limit) == "number" and args.limit or 50),
  }
  local resp = bb_http().request({
    service = "slack",
    method = "GET",
    path = "/api/conversations.replies",
    query = query,
    effect = "read",
  })
  local data = expect_slack_ok(resp, "conversations.replies")
  local msgs = type(data.messages) == "table" and data.messages or {}
  local users = type(args.users) == "table" and args.users or nil
  local lines = {
    "# Slack Thread " .. args.channel .. "@" .. args.thread_ts .. " (" .. tostring(
      #msgs
    ) .. " msgs)",
  }
  for _, m in ipairs(msgs) do
    lines[#lines + 1] = "- ["
      .. tostring(m.ts or "")
      .. "] "
      .. format_user(m.user, users)
      .. ": "
      .. format_message_text(m.text, users)
  end
  return table.concat(lines, "\n")
end

---@param args table
---@return string
function operations.post_message(args)
  assert(type(args) == "table", "slack.post_message requires arguments table")
  assert(
    type(args.channel) == "string" and #args.channel > 0,
    "slack.post_message requires channel"
  )
  assert(
    type(args.text) == "string" and #args.text > 0,
    "slack.post_message requires text"
  )
  local body = {
    channel = args.channel,
    text = args.text,
  }
  if type(args.thread_ts) == "string" and #args.thread_ts > 0 then
    body.thread_ts = args.thread_ts
  end
  local resp = bb_http().request({
    service = "slack",
    method = "POST",
    path = "/api/chat.postMessage",
    effect = "send",
    json = body,
  })
  local data = expect_slack_ok(resp, "chat.postMessage")
  return "Posted to "
    .. tostring(data.channel or args.channel)
    .. " (ts="
    .. tostring(data.ts or "")
    .. ")"
end

return {
  service = "slack",
  version = 1,
  allowed_hosts = { "slack.com" },
  operations = operations,
}
