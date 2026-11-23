-- Builtin Blackbird SaaS Integration Pack: Discord REST API v10 (rate-limit aware).
-- Secrets (Bot token) and host pinning (discord.com) are enforced exclusively in C++.

---@class DiscordHttpResponse
---@field status integer
---@field headers table<string, string>
---@field body string
---@field json any

---@class DiscordHttpApi
---@field request fun(op: table): DiscordHttpResponse
---@field url_encode fun(text: string): string

---@return DiscordHttpApi
local function bb_http()
  local bb = rawget(_G, "blackbird")
  assert(type(bb) == "table", "blackbird unavailable")
  local http = rawget(bb, "http")
  assert(type(http) == "table", "blackbird.http unavailable")
  return http
end

---@param headers table
---@return string
local function format_rate_limit(headers)
  local rem = headers["x-ratelimit-remaining"]
  local reset = headers["x-ratelimit-reset-after"]
  local bucket = headers["x-ratelimit-bucket"]
  if rem == nil and reset == nil and bucket == nil then
    return ""
  end
  local parts = {}
  if rem ~= nil then
    parts[#parts + 1] = "remaining=" .. tostring(rem)
  end
  if reset ~= nil then
    parts[#parts + 1] = "reset_after=" .. tostring(reset) .. "s"
  end
  if bucket ~= nil then
    parts[#parts + 1] = "bucket=" .. tostring(bucket)
  end
  return " [rate_limit: " .. table.concat(parts, ", ") .. "]"
end

---@param resp DiscordHttpResponse
---@param label string
local function check_discord_status(resp, label)
  if resp.status == 429 then
    local retry = resp.headers["retry-after"]
      or (type(resp.json) == "table" and resp.json.retry_after)
      or "unknown"
    error(
      "Discord rate limited (429) on "
        .. label
        .. ": retry_after="
        .. tostring(retry)
        .. format_rate_limit(resp.headers)
    )
  end
  assert(
    resp.status >= 200 and resp.status < 300,
    "Discord API v10 HTTP " .. tostring(resp.status) .. " on " .. label
  )
end

local CHANNEL_TYPES = {
  [0] = "text",
  [2] = "voice",
  [4] = "category",
  [5] = "announcement",
  [11] = "public_thread",
  [12] = "private_thread",
  [15] = "forum",
}

local operations = {}

---@param args table
---@return string
function operations.list_channels(args)
  assert(type(args) == "table", "discord.list_channels requires arguments table")
  assert(
    type(args.guild_id) == "string" and #args.guild_id > 0,
    "discord.list_channels requires guild_id"
  )
  local resp = bb_http().request({
    service = "discord",
    method = "GET",
    path = "/api/v10/guilds/" .. bb_http().url_encode(args.guild_id) .. "/channels",
    effect = "read",
  })
  check_discord_status(resp, "list_channels")
  local channels = type(resp.json) == "table" and resp.json or {}
  local lines = {
    "# Discord Guild "
      .. args.guild_id
      .. " Channels ("
      .. tostring(#channels)
      .. ")"
      .. format_rate_limit(resp.headers),
  }
  for _, ch in ipairs(channels) do
    local ctype = CHANNEL_TYPES[ch.type or 0] or tostring(ch.type or 0)
    lines[#lines + 1] = "- #"
      .. tostring(ch.name or ch.id)
      .. " (id="
      .. tostring(ch.id)
      .. ", "
      .. ctype
      .. ")"
  end
  return table.concat(lines, "\n")
end

---@param args table
---@return string
function operations.get_messages(args)
  assert(type(args) == "table", "discord.get_messages requires arguments table")
  assert(
    type(args.channel_id) == "string" and #args.channel_id > 0,
    "discord.get_messages requires channel_id"
  )
  local query = {
    limit = tostring(type(args.limit) == "number" and args.limit or 20),
  }
  if type(args.before) == "string" and #args.before > 0 then
    query.before = args.before
  end
  local resp = bb_http().request({
    service = "discord",
    method = "GET",
    path = "/api/v10/channels/" .. bb_http().url_encode(args.channel_id) .. "/messages",
    query = query,
    effect = "read",
  })
  check_discord_status(resp, "get_messages")
  local msgs = type(resp.json) == "table" and resp.json or {}
  local lines = {
    "# Discord Channel "
      .. args.channel_id
      .. " ("
      .. tostring(#msgs)
      .. " msgs)"
      .. format_rate_limit(resp.headers),
  }
  for _, m in ipairs(msgs) do
    local author = (type(m.author) == "table" and m.author.username) or "unknown"
    local content = type(m.content) == "string"
        and m.content:gsub("\r\n", "\n"):gsub("\n", " ")
      or ""
    lines[#lines + 1] = "- ["
      .. tostring(m.id or "")
      .. "] @"
      .. author
      .. ": "
      .. content
  end
  return table.concat(lines, "\n")
end

---@param args table
---@return string
function operations.send_message(args)
  assert(type(args) == "table", "discord.send_message requires arguments table")
  assert(
    type(args.channel_id) == "string" and #args.channel_id > 0,
    "discord.send_message requires channel_id"
  )
  assert(
    type(args.content) == "string" and #args.content > 0,
    "discord.send_message requires content"
  )
  local body = { content = args.content }
  if type(args.reply_to) == "string" and #args.reply_to > 0 then
    body.message_reference = { message_id = args.reply_to }
  end
  local resp = bb_http().request({
    service = "discord",
    method = "POST",
    path = "/api/v10/channels/" .. bb_http().url_encode(args.channel_id) .. "/messages",
    effect = "send",
    json = body,
  })
  check_discord_status(resp, "send_message")
  local msg = type(resp.json) == "table" and resp.json or {}
  return "Sent Discord message id="
    .. tostring(msg.id or "?")
    .. " to channel "
    .. args.channel_id
    .. format_rate_limit(resp.headers)
end

return {
  service = "discord",
  version = 1,
  allowed_hosts = { "discord.com" },
  operations = operations,
}
