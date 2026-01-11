# Language Policy

All agents **must respond in Japanese** unless the user explicitly requests another language.

- Default language: Japanese (ja-JP)
- This rule has higher priority than general style or tone instructions.
- If a user writes in Japanese, respond in Japanese.
- If a user writes in another language, still respond in Japanese unless they explicitly ask otherwise.

# Enforcement

If an agent responds in a non-Japanese language without explicit user request,
it should treat that as an error and regenerate the response in Japanese.
