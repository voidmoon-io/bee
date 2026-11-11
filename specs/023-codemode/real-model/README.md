# Real-model codemode validation

`run.py` runs four bounded scenarios using the provider in `provider.toml`:
sequential multi-file reading, independent fan-out, explicit nesting, and the
32-inner-call limit. Every scenario enables `feedback` and asks the model to
submit a concrete observation before its final response.

Build with `cargo build --no-default-features --features durable-sessions --bin bee`.
Run `python3 specs/023-codemode/real-model/run.py --key-file /private/key-file --output /absolute/results-directory`.
The key is read into the child environment, never added to arguments or artifacts.
Each scenario permits five model turns, 48 charged tool attempts and 120 seconds;
the runner stops the set on setup/provider errors. Runs incur provider charges.

These are host-mode behavior probes using synthetic fixtures, not enforcement
tests. JSON transcripts and progress logs are retained beside the generated
scenario TOMLs. Private durable session directories are ignored by Git. Successful
`feedback` calls in transcripts are the feedback log; model observations must be
checked against recorded calls rather than treated as ground truth.
