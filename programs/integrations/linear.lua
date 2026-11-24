-- Builtin Blackbird SaaS Integration Pack: Linear (GraphQL, compact Markdown).
-- Secrets and host pinning (api.linear.app) are enforced exclusively in C++.

---@class LinearHttpResponse
---@field status integer
---@field headers table<string, string>
---@field body string
---@field json any

---@class LinearHttpApi
---@field request fun(op: table): LinearHttpResponse

---@return LinearHttpApi
local function bb_http()
  local bb = rawget(_G, "blackbird")
  assert(type(bb) == "table", "blackbird unavailable")
  local http = rawget(bb, "http")
  assert(type(http) == "table", "blackbird.http unavailable")
  return http
end

---@param text any
---@param max_len integer
---@return string
local function compact_text(text, max_len)
  if type(text) ~= "string" then
    return ""
  end
  local cleaned = text:gsub("\r\n", "\n"):gsub("\r", "\n"):gsub("\n+", " ")
  cleaned = cleaned:gsub("%s+", " "):gsub("^%s+", ""):gsub("%s+$", "")
  if #cleaned > max_len then
    return cleaned:sub(1, max_len - 3) .. "..."
  end
  return cleaned
end

---@param query string
---@param variables table
---@param effect string
---@return table
local function graphql(query, variables, effect)
  local resp = bb_http().request({
    service = "linear",
    method = "POST",
    path = "/graphql",
    effect = effect,
    json = {
      query = query,
      variables = variables,
    },
  })
  if resp.status == 429 then
    local retry = resp.headers["retry-after"] or "unknown"
    error("Linear rate limited (429), retry-after=" .. tostring(retry))
  end
  assert(
    resp.status >= 200 and resp.status < 300,
    "Linear GraphQL HTTP " .. tostring(resp.status)
  )
  local payload = resp.json
  assert(type(payload) == "table", "Linear GraphQL returned non-JSON payload")
  if type(payload.errors) == "table" and #payload.errors > 0 then
    local first = payload.errors[1]
    local msg = type(first) == "table" and tostring(first.message or "error")
      or "GraphQL error"
    error("Linear GraphQL error: " .. msg)
  end
  return type(payload.data) == "table" and payload.data or {}
end

local PRIORITY_LABELS = {
  [0] = "None",
  [1] = "Urgent",
  [2] = "High",
  [3] = "Medium",
  [4] = "Low",
}

local operations = {}

---@param args table
---@return string
function operations.search_issues(args)
  local q = type(args) == "table" and args.query or ""
  assert(type(q) == "string" and #q > 0, "linear.search_issues requires query")
  local limit = (type(args.limit) == "number" and args.limit > 0) and args.limit or 10
  if limit > 50 then
    limit = 50
  end
  local gql = [[
query SearchIssues($term: String!, $first: Int!) {
  searchIssues(term: $term, first: $first) {
    nodes {
      id identifier title priority url
      state { name }
      assignee { name }
      labels { nodes { name } }
    }
  }
}]]
  local data = graphql(gql, { term = q, first = limit }, "read")
  local nodes = (type(data.searchIssues) == "table" and data.searchIssues.nodes) or {}
  local lines = { "# Linear Search: " .. compact_text(q, 80) }
  if #nodes == 0 then
    lines[#lines + 1] = "(no matching issues)"
    return table.concat(lines, "\n")
  end
  for _, issue in ipairs(nodes) do
    local state_name = (type(issue.state) == "table" and issue.state.name) or "Unknown"
    local assignee = (type(issue.assignee) == "table" and issue.assignee.name)
      or "Unassigned"
    local prio = PRIORITY_LABELS[issue.priority or 0] or tostring(issue.priority or 0)
    local label_list = {}
    if type(issue.labels) == "table" and type(issue.labels.nodes) == "table" then
      for _, lbl in ipairs(issue.labels.nodes) do
        if type(lbl.name) == "string" then
          label_list[#label_list + 1] = lbl.name
        end
      end
    end
    local tag_str = #label_list > 0 and (" [" .. table.concat(label_list, ", ") .. "]")
      or ""
    lines[#lines + 1] = "- **"
      .. tostring(issue.identifier or issue.id)
      .. "** "
      .. compact_text(issue.title, 120)
      .. " | "
      .. state_name
      .. " | "
      .. prio
      .. " | @"
      .. assignee
      .. tag_str
  end
  return table.concat(lines, "\n")
end

---@param args table
---@return string
function operations.get_issue(args)
  local id = type(args) == "table" and args.id or ""
  assert(type(id) == "string" and #id > 0, "linear.get_issue requires id")
  local gql = [[
query GetIssue($id: String!) {
  issue(id: $id) {
    id identifier title description priority url
    state { name }
    assignee { name }
    labels { nodes { name } }
    comments(first: 10) {
      nodes { body createdAt user { name } }
    }
  }
}]]
  local data = graphql(gql, { id = id }, "read")
  local issue = data.issue
  assert(type(issue) == "table", "Linear issue not found: " .. id)
  local state_name = (type(issue.state) == "table" and issue.state.name) or "Unknown"
  local assignee = (type(issue.assignee) == "table" and issue.assignee.name)
    or "Unassigned"
  local prio = PRIORITY_LABELS[issue.priority or 0] or tostring(issue.priority or 0)
  local lines = {
    "# " .. tostring(issue.identifier or issue.id) .. ": " .. compact_text(
      issue.title,
      160
    ),
    "State: " .. state_name .. " | Priority: " .. prio .. " | Assignee: " .. assignee,
  }
  if type(issue.url) == "string" and #issue.url > 0 then
    lines[#lines + 1] = "URL: " .. issue.url
  end
  if type(issue.description) == "string" and #issue.description > 0 then
    lines[#lines + 1] = ""
    lines[#lines + 1] = issue.description
  end
  local comments = (type(issue.comments) == "table" and issue.comments.nodes) or {}
  if #comments > 0 then
    lines[#lines + 1] = ""
    lines[#lines + 1] = "## Comments (" .. tostring(#comments) .. ")"
    for _, c in ipairs(comments) do
      local author = (type(c.user) == "table" and c.user.name) or "Unknown"
      lines[#lines + 1] = "- **"
        .. author
        .. "** ("
        .. tostring(c.createdAt or "")
        .. "): "
        .. compact_text(c.body, 280)
    end
  end
  return table.concat(lines, "\n")
end

---@param args table
---@return string
function operations.create_issue(args)
  assert(type(args) == "table", "linear.create_issue requires arguments table")
  assert(
    type(args.team_id) == "string" and #args.team_id > 0,
    "linear.create_issue requires team_id"
  )
  assert(
    type(args.title) == "string" and #args.title > 0,
    "linear.create_issue requires title"
  )
  local input = {
    teamId = args.team_id,
    title = args.title,
  }
  if type(args.description) == "string" then
    input.description = args.description
  end
  if type(args.priority) == "number" then
    input.priority = args.priority
  end
  local gql = [[
mutation CreateIssue($input: IssueCreateInput!) {
  issueCreate(input: $input) {
    success
    issue { id identifier title url }
  }
}]]
  local data = graphql(gql, { input = input }, "write")
  local res = data.issueCreate
  assert(
    type(res) == "table" and res.success == true and type(res.issue) == "table",
    "Linear issueCreate failed"
  )
  return "Created **"
    .. tostring(res.issue.identifier or res.issue.id)
    .. "**: "
    .. compact_text(res.issue.title, 160)
    .. " ("
    .. tostring(res.issue.url or "")
    .. ")"
end

---@param args table
---@return string
function operations.comment_issue(args)
  assert(type(args) == "table", "linear.comment_issue requires arguments table")
  assert(
    type(args.issue_id) == "string" and #args.issue_id > 0,
    "linear.comment_issue requires issue_id"
  )
  assert(
    type(args.body) == "string" and #args.body > 0,
    "linear.comment_issue requires body"
  )
  local gql = [[
mutation CommentIssue($input: CommentCreateInput!) {
  commentCreate(input: $input) {
    success
    comment { id body }
  }
}]]
  local data =
    graphql(gql, { input = { issueId = args.issue_id, body = args.body } }, "send")
  local res = data.commentCreate
  assert(
    type(res) == "table" and res.success == true and type(res.comment) == "table",
    "Linear commentCreate failed"
  )
  return "Commented on "
    .. args.issue_id
    .. " (comment_id="
    .. tostring(res.comment.id)
    .. ")"
end

---@param args table
---@return string
function operations.update_issue(args)
  assert(type(args) == "table", "linear.update_issue requires arguments table")
  assert(type(args.id) == "string" and #args.id > 0, "linear.update_issue requires id")
  local input = {}
  if type(args.title) == "string" then
    input.title = args.title
  end
  if type(args.state_id) == "string" then
    input.stateId = args.state_id
  end
  if type(args.priority) == "number" then
    input.priority = args.priority
  end
  if type(args.description) == "string" then
    input.description = args.description
  end
  local gql = [[
mutation UpdateIssue($id: String!, $input: IssueUpdateInput!) {
  issueUpdate(id: $id, input: $input) {
    success
    issue { id identifier title state { name } }
  }
}]]
  local data = graphql(gql, { id = args.id, input = input }, "write")
  local res = data.issueUpdate
  assert(
    type(res) == "table" and res.success == true and type(res.issue) == "table",
    "Linear issueUpdate failed"
  )
  local state_name = (type(res.issue.state) == "table" and res.issue.state.name)
    or "Unknown"
  return "Updated **"
    .. tostring(res.issue.identifier or res.issue.id)
    .. "** ["
    .. state_name
    .. "]: "
    .. compact_text(res.issue.title, 140)
end

return {
  service = "linear",
  version = 1,
  allowed_hosts = { "api.linear.app" },
  operations = operations,
}
