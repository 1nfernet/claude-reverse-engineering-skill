# Evals

`trigger-evals.json` — 20 realistic prompts (10 should load the skill, 10 deliberate
near-misses that share vocabulary but need something else). It's a bare JSON array
of `{"query", "should_trigger"}`, the format the skill-creator description
optimizer (`scripts.run_loop --eval-set`) expects. Also usable as manual
regression cases when editing the `description` field.
