# DeepSeek Responses reasoning replay

A live DeepSeek V4.1 Flash Oxcart turn used native state, tab and screenshot
tools, then stopped when the portable Responses exporter rejected an opaque
reasoning field. The provider had returned the field despite the request's empty
`include`. Its documented input accepts plaintext reasoning and excludes
`summary` and `encrypted_content`.
[DeepSeek Responses compatibility](https://api-docs.deepseek.com/guides/responses_api/)

At the DeepSeek wire boundary, replay reasoning items with their plaintext
content and omit the unsupported fields. Skip opaque-only reasoning on that
route. Preserve the original retained response and existing handling for other
portable providers. The Responses contract tests cover both cases and verify
that the linked function call and result survive the translation.

With the rebuilt provider, the same real pilot task completed. Blackbird
sent the exact 117,434-byte Oxcart viewport PNG to DeepSeek after `read_image`.
The model described the live IANA page, opened RFC 2606 in a genuine child tab,
and queried the native state to verify the primary remained selected.
