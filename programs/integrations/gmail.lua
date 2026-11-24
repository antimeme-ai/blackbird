-- Builtin Blackbird SaaS Integration Pack: Gmail REST v1 (HTML-stripped compact threads).
-- Secrets and host pinning (gmail.googleapis.com) are enforced exclusively in C++.

---@class GmailHttpResponse
---@field status integer
---@field headers table<string, string>
---@field body string
---@field json any

---@class GmailHttpApi
---@field request fun(op: table): GmailHttpResponse
---@field url_encode fun(text: string): string
---@field base64url_encode fun(text: string): string
---@field base64url_decode fun(text: string): string

---@return GmailHttpApi
local function bb_http()
  local bb = rawget(_G, "blackbird")
  assert(type(bb) == "table", "blackbird unavailable")
  local http = rawget(bb, "http")
  assert(type(http) == "table", "blackbird.http unavailable")
  return http
end

---@param html string
---@return string
local function strip_html(html)
  local text = html
  text = text:gsub("<[Ss][Tt][Yy][Ll][Ee][^>]*>.-</[Ss][Tt][Yy][Ll][Ee]>", " ")
  text = text:gsub("<[Ss][Cc][Rr][Ii][Pp][Tt][^>]*>.-</[Ss][Cc][Rr][Ii][Pp][Tt]>", " ")
  text = text:gsub("<[Bb][Rr]%s*/?>", "\n")
  text = text:gsub("</[Pp]>", "\n")
  text = text:gsub("</[Dd][Ii][Vv]>", "\n")
  text = text:gsub("<[^>]+>", "")
  text = text:gsub("&nbsp;", " ")
  text = text:gsub("&amp;", "&")
  text = text:gsub("&lt;", "<")
  text = text:gsub("&gt;", ">")
  text = text:gsub("&quot;", '"')
  text = text:gsub("&#39;", "'")
  text = text:gsub("[ \t]+", " ")
  text = text:gsub("\n%s*\n+", "\n\n")
  return (text:gsub("^%s+", ""):gsub("%s+$", ""))
end

---@param headers table?
---@param name string
---@return string
local function find_mime_header(headers, name)
  if type(headers) ~= "table" then
    return ""
  end
  local target = name:lower()
  for _, h in ipairs(headers) do
    if type(h) == "table" and type(h.name) == "string" and h.name:lower() == target then
      return tostring(h.value or "")
    end
  end
  return ""
end

---@param payload table?
---@return string
local function extract_body(payload)
  if type(payload) ~= "table" then
    return ""
  end
  local mime = type(payload.mimeType) == "string" and payload.mimeType:lower() or ""
  if type(payload.body) == "table" and type(payload.body.data) == "string" then
    local decoded = bb_http().base64url_decode(payload.body.data)
    if mime == "text/plain" then
      return (decoded:gsub("\r\n", "\n"):gsub("^%s+", ""):gsub("%s+$", ""))
    elseif mime == "text/html" then
      return strip_html(decoded)
    end
  end
  local html_fallback = ""
  if type(payload.parts) == "table" then
    for _, part in ipairs(payload.parts) do
      local part_mime = type(part.mimeType) == "string" and part.mimeType:lower() or ""
      local extracted = extract_body(part)
      if #extracted > 0 then
        if part_mime == "text/plain" then
          return extracted
        elseif html_fallback == "" then
          html_fallback = extracted
        end
      end
    end
  end
  return html_fallback
end

---@param to string
---@param subject string
---@param body string
---@return string
local function build_rfc2822_raw(to, subject, body)
  local clean_to = to:gsub("[\r\n%z]", "")
  local clean_subj = subject:gsub("[\r\n%z]", "")
  local msg = "To: "
    .. clean_to
    .. "\r\nSubject: "
    .. clean_subj
    .. "\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n"
    .. body
  return bb_http().base64url_encode(msg)
end

local operations = {}

---@param args table?
---@return string
function operations.search_threads(args)
  local opts = type(args) == "table" and args or {}
  local query = {
    maxResults = tostring(
      type(opts.max_results) == "number" and opts.max_results or 10
    ),
  }
  if type(opts.query) == "string" and #opts.query > 0 then
    query.q = opts.query
  end
  if type(opts.page_token) == "string" and #opts.page_token > 0 then
    query.pageToken = opts.page_token
  end
  local resp = bb_http().request({
    service = "gmail",
    method = "GET",
    path = "/gmail/v1/users/me/threads",
    query = query,
    effect = "read",
  })
  assert(
    resp.status >= 200 and resp.status < 300,
    "Gmail search_threads HTTP " .. tostring(resp.status)
  )
  local data = type(resp.json) == "table" and resp.json or {}
  local threads = type(data.threads) == "table" and data.threads or {}
  local lines = { "# Gmail Threads (" .. tostring(#threads) .. ")" }
  for _, t in ipairs(threads) do
    local snippet = type(t.snippet) == "string" and t.snippet:gsub("\n", " ") or ""
    lines[#lines + 1] = "- **" .. tostring(t.id) .. "**: " .. snippet
  end
  if type(data.nextPageToken) == "string" and #data.nextPageToken > 0 then
    lines[#lines + 1] = "next_page_token: " .. data.nextPageToken
  end
  return table.concat(lines, "\n")
end

---@param args table
---@return string
function operations.read_thread(args)
  assert(type(args) == "table", "gmail.read_thread requires arguments table")
  assert(
    type(args.thread_id) == "string" and #args.thread_id > 0,
    "gmail.read_thread requires thread_id"
  )
  local safe_id = bb_http().url_encode(args.thread_id)
  local resp = bb_http().request({
    service = "gmail",
    method = "GET",
    path = "/gmail/v1/users/me/threads/" .. safe_id,
    query = { format = "full" },
    effect = "read",
  })
  assert(
    resp.status >= 200 and resp.status < 300,
    "Gmail read_thread HTTP " .. tostring(resp.status)
  )
  local data = type(resp.json) == "table" and resp.json or {}
  local messages = type(data.messages) == "table" and data.messages or {}
  local lines = {
    "# Gmail Thread " .. args.thread_id .. " (" .. tostring(#messages) .. " messages)",
  }
  for i, m in ipairs(messages) do
    local hdrs = type(m.payload) == "table" and m.payload.headers or nil
    local from = find_mime_header(hdrs, "From")
    local subject = find_mime_header(hdrs, "Subject")
    local date = find_mime_header(hdrs, "Date")
    local body = extract_body(m.payload)
    if body == "" and type(m.snippet) == "string" then
      body = m.snippet
    end
    lines[#lines + 1] = ""
    lines[#lines + 1] = "## Message " .. tostring(i) .. " — " .. subject
    lines[#lines + 1] = "From: " .. from .. " | Date: " .. date
    lines[#lines + 1] = body
  end
  return table.concat(lines, "\n")
end

---@param args table
---@return string
function operations.create_draft(args)
  assert(type(args) == "table", "gmail.create_draft requires arguments table")
  assert(type(args.to) == "string" and #args.to > 0, "gmail.create_draft requires to")
  assert(
    type(args.subject) == "string" and #args.subject > 0,
    "gmail.create_draft requires subject"
  )
  assert(type(args.body) == "string", "gmail.create_draft requires body")
  local message = { raw = build_rfc2822_raw(args.to, args.subject, args.body) }
  if type(args.thread_id) == "string" and #args.thread_id > 0 then
    message.threadId = args.thread_id
  end
  local resp = bb_http().request({
    service = "gmail",
    method = "POST",
    path = "/gmail/v1/users/me/drafts",
    effect = "write",
    json = { message = message },
  })
  assert(
    resp.status >= 200 and resp.status < 300,
    "Gmail create_draft HTTP " .. tostring(resp.status)
  )
  local data = type(resp.json) == "table" and resp.json or {}
  return "Created Gmail draft id="
    .. tostring(data.id or "unknown")
    .. " to "
    .. args.to
end

---@param args table
---@return string
function operations.send_message(args)
  assert(type(args) == "table", "gmail.send_message requires arguments table")
  assert(type(args.to) == "string" and #args.to > 0, "gmail.send_message requires to")
  assert(
    type(args.subject) == "string" and #args.subject > 0,
    "gmail.send_message requires subject"
  )
  assert(type(args.body) == "string", "gmail.send_message requires body")
  local payload = { raw = build_rfc2822_raw(args.to, args.subject, args.body) }
  if type(args.thread_id) == "string" and #args.thread_id > 0 then
    payload.threadId = args.thread_id
  end
  local resp = bb_http().request({
    service = "gmail",
    method = "POST",
    path = "/gmail/v1/users/me/messages/send",
    effect = "send",
    json = payload,
  })
  assert(
    resp.status >= 200 and resp.status < 300,
    "Gmail send_message HTTP " .. tostring(resp.status)
  )
  local data = type(resp.json) == "table" and resp.json or {}
  return "Sent Gmail message id=" .. tostring(data.id or "unknown") .. " to " .. args.to
end

return {
  service = "gmail",
  version = 1,
  allowed_hosts = { "gmail.googleapis.com" },
  operations = operations,
}
