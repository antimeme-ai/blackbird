-- Effective source is retained each turn. Edit this program; next turn reloads it.
for step = 1, 64 do
  blackbird.emit(3880, step)
  local response = blackbird.request()
  local calls = 0
  for _, item in ipairs(response.output) do
    if item.type == "function_call" then
      if item.namespace ~= nil and item.namespace ~= "" then
        error("Default workflow cannot dispatch a namespaced function call")
      end
      calls = calls + 1
      local args = item.arguments
      if args.output_max_bytes == nil then
        if item.name == "exec" then
          args.output_max_bytes = 8192
          if args.output_head_bytes == nil then
            args.output_head_bytes = 2048
          end
        elseif
          item.name == "read_file"
          and args.range == nil
          and args.byte_start == nil
          and args.byte_end == nil
          and args.line_start == nil
          and args.line_end == nil
        then
          args.output_max_bytes = 16384
        end
      end
      local result = blackbird.call(item.name, args)
      local output = {
        type = "function_call_output",
        call_id = item.call_id,
        output = result,
      }
      if item.name == "read_image" and result.image_original ~= nil then
        output.blackbird_output_parts = true
        output.output = {
          {
            type = "input_text",
            text = "Retained image original: "
              .. result.mime_type
              .. "; "
              .. tostring(result.file_bytes)
              .. " bytes.",
          },
          {
            type = "input_image",
            image_original = result.image_original,
            detail = result.detail,
          },
        }
      end
      blackbird.append({output})
    elseif item.type == "custom_tool_call" then
      error("Default workflow cannot dispatch a custom tool call")
    elseif item.type == "message" then
      blackbird.present(item)
    end
  end
  blackbird.emit(3881, calls)
  local restarting = blackbird.restarting()
  blackbird.emit(3882, restarting)
  if restarting or calls == 0 then
    return
  end
end
error("Workflow reached its configured 64-step budget; context is retained.")
