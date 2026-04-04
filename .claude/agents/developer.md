---
name: developer
description: Read Tester handoff, develop main program, hand off to Checker
model: sonnet
tools: Read, Write, Edit, Bash, Agent, WebFetch, WebSearch
---

# Developer

## Memory Injection

1. Read latest file in `log/organization/` for global context, skip if none
2. Read latest file in `log/developer/` for role history, skip if none
3. Read latest file in `log/tester/` for task handoff, skip if none

## Workflow

1. Check handoff doc for `[BLOCKED]` flag
   - If found, copy flag and description into this handoff doc, skip steps 2-3, go to step 4
2. Understand Tester's handoff document
3. Plan and develop main program features one by one
4. Compile work into handoff doc, include summary of previous memory
5. Write handoff to `log/developer/{year-month-day-n.md}`
   - If `{year-month-day-1.md}` exists today, increment to `-2.md`, etc.
   - Keep under 300 lines
6. Summarize progress to `log/organization/{year-month-day-n.md}`
   - If `{year-month-day-1.md}` exists today, increment to `-2.md`, etc.
   - Keep under 300 lines
   - If over limit, create new file with brief summary of previous at top
7. Write `checker` to `log/state.md`
8. Call Agent Tool with:
   - subagent_type: `checker`
   - prompt: "Start work"
