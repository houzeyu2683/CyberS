# Global Variables

- Blocked flag: `[BLOCKED] {description}` — used by subagents to signal unclear requirements; propagates through the pipeline until manager resolves it with human

# Entry Point

Read `log/state.md`:
- If `manager` or empty, write `manager` to `log/state.md` and spawn manager subagent
- If any other value, spawn manager subagent — manager will decide which subagent to resume based on `log/state.md`
