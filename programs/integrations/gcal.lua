-- Builtin Blackbird SaaS Integration Pack: Google Calendar v3 (compact agenda & free/busy).
-- Secrets and host pinning (www.googleapis.com) are enforced exclusively in C++.

---@class GcalHttpResponse
---@field status integer
---@field headers table<string, string>
---@field body string
---@field json any

---@class GcalHttpApi
---@field request fun(op: table): GcalHttpResponse
---@field url_encode fun(text: string): string

---@return GcalHttpApi
local function bb_http()
  local bb = rawget(_G, "blackbird")
  assert(type(bb) == "table", "blackbird unavailable")
  local http = rawget(bb, "http")
  assert(type(http) == "table", "blackbird.http unavailable")
  return http
end

---@param dt table?
---@return string
local function format_when(dt)
  if type(dt) ~= "table" then
    return "?"
  end
  return tostring(dt.dateTime or dt.date or "?")
end

local operations = {}

---@param args table?
---@return string
function operations.list_events(args)
  local opts = type(args) == "table" and args or {}
  local cal = type(opts.calendar_id) == "string"
      and #opts.calendar_id > 0
      and opts.calendar_id
    or "primary"
  local query = {
    singleEvents = "true",
    orderBy = "startTime",
    maxResults = tostring(
      type(opts.max_results) == "number" and opts.max_results or 15
    ),
  }
  if type(opts.time_min) == "string" and #opts.time_min > 0 then
    query.timeMin = opts.time_min
  end
  if type(opts.time_max) == "string" and #opts.time_max > 0 then
    query.timeMax = opts.time_max
  end
  local resp = bb_http().request({
    service = "gcal",
    method = "GET",
    path = "/calendar/v3/calendars/" .. bb_http().url_encode(cal) .. "/events",
    query = query,
    effect = "read",
  })
  assert(
    resp.status >= 200 and resp.status < 300,
    "GCal list_events HTTP " .. tostring(resp.status)
  )
  local data = type(resp.json) == "table" and resp.json or {}
  local items = type(data.items) == "table" and data.items or {}
  local lines =
    { "# Calendar Agenda (" .. cal .. ", " .. tostring(#items) .. " events)" }
  for _, ev in ipairs(items) do
    local loc = (type(ev.location) == "string" and #ev.location > 0)
        and (" @ " .. ev.location)
      or ""
    local attendees = type(ev.attendees) == "table" and #ev.attendees or 0
    local att_str = attendees > 0 and (" (" .. tostring(attendees) .. " attendees)")
      or ""
    lines[#lines + 1] = "- "
      .. format_when(ev.start)
      .. " .. "
      .. format_when(ev["end"])
      .. " | **"
      .. tostring(ev.summary or "(untitled)")
      .. "**"
      .. loc
      .. att_str
  end
  return table.concat(lines, "\n")
end

---@param args table
---@return string
function operations.create_event(args)
  assert(type(args) == "table", "gcal.create_event requires arguments table")
  assert(
    type(args.summary) == "string" and #args.summary > 0,
    "gcal.create_event requires summary"
  )
  assert(
    type(args.start_time) == "string" and #args.start_time > 0,
    "gcal.create_event requires start_time"
  )
  assert(
    type(args.end_time) == "string" and #args.end_time > 0,
    "gcal.create_event requires end_time"
  )
  local cal = type(args.calendar_id) == "string"
      and #args.calendar_id > 0
      and args.calendar_id
    or "primary"
  local body = {
    summary = args.summary,
    start = { dateTime = args.start_time },
    ["end"] = { dateTime = args.end_time },
  }
  if type(args.description) == "string" then
    body.description = args.description
  end
  if type(args.location) == "string" then
    body.location = args.location
  end
  if type(args.attendees) == "table" then
    local list = {}
    for _, email in ipairs(args.attendees) do
      if type(email) == "string" then
        list[#list + 1] = { email = email }
      end
    end
    body.attendees = list
  end
  local resp = bb_http().request({
    service = "gcal",
    method = "POST",
    path = "/calendar/v3/calendars/" .. bb_http().url_encode(cal) .. "/events",
    effect = "write",
    json = body,
  })
  assert(
    resp.status >= 200 and resp.status < 300,
    "GCal create_event HTTP " .. tostring(resp.status)
  )
  local data = type(resp.json) == "table" and resp.json or {}
  return "Created event **"
    .. tostring(data.summary or args.summary)
    .. "** (id="
    .. tostring(data.id or "unknown")
    .. ")"
end

---@param args table
---@return string
function operations.free_busy(args)
  assert(type(args) == "table", "gcal.free_busy requires arguments table")
  assert(
    type(args.time_min) == "string" and #args.time_min > 0,
    "gcal.free_busy requires time_min"
  )
  assert(
    type(args.time_max) == "string" and #args.time_max > 0,
    "gcal.free_busy requires time_max"
  )
  local items = {}
  if type(args.calendar_ids) == "table" and #args.calendar_ids > 0 then
    for _, cid in ipairs(args.calendar_ids) do
      items[#items + 1] = { id = tostring(cid) }
    end
  else
    items[1] = { id = "primary" }
  end
  local resp = bb_http().request({
    service = "gcal",
    method = "POST",
    path = "/calendar/v3/freeBusy",
    effect = "read",
    json = {
      timeMin = args.time_min,
      timeMax = args.time_max,
      items = items,
    },
  })
  assert(
    resp.status >= 200 and resp.status < 300,
    "GCal free_busy HTTP " .. tostring(resp.status)
  )
  local data = type(resp.json) == "table" and resp.json or {}
  local cals = type(data.calendars) == "table" and data.calendars or {}
  local keys = {}
  for k in pairs(cals) do
    keys[#keys + 1] = k
  end
  table.sort(keys)
  local lines = { "# Free/Busy " .. args.time_min .. " .. " .. args.time_max }
  for _, cid in ipairs(keys) do
    local entry = cals[cid]
    local busy = (type(entry) == "table" and type(entry.busy) == "table") and entry.busy
      or {}
    if #busy == 0 then
      lines[#lines + 1] = "- " .. cid .. ": completely free"
    else
      local windows = {}
      for _, w in ipairs(busy) do
        windows[#windows + 1] = tostring(w.start or "?")
          .. ".."
          .. tostring(w["end"] or "?")
      end
      lines[#lines + 1] = "- " .. cid .. ": busy " .. table.concat(windows, ", ")
    end
  end
  return table.concat(lines, "\n")
end

return {
  service = "gcal",
  version = 1,
  allowed_hosts = { "www.googleapis.com" },
  operations = operations,
}
