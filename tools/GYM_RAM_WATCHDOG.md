# Gym RAM watchdog

For a known CPU-only gym, run its usual command under the watchdog:

```text
python tools/gym_ram_watchdog.py --cpu-only --report-only -- python path/to/runner.py
python tools/gym_ram_watchdog.py --cpu-only -- python path/to/runner.py
```

Use the environment's existing `psutil` dependency (configure it in the gym's
virtual environment if needed). If it is missing, the wrapper refuses to launch the
command. Use report-only first on an unfamiliar workload. Add the usual runner
arguments after `--`; the wrapper does not edit data, checkpoints, or the command.

The default requires all three conditions for two continuous minutes: available
host RAM below 2 GiB, a descendant leaf worker with at least 512 MiB resident
memory, and that worker using less than 1% of one CPU core. Sampling is every
five seconds. CPU activity or disappearance resets the grace window. The wrapper
never signals the main command, a worker with children, or another run's workers.
It rechecks process identity and ancestry before signalling. It terminates first
(on Windows this is forceful) and may escalate after 15 seconds if the same
worker remains eligible. Events are JSON lines on stderr. A reaped worker makes
an otherwise successful run exit 86; existing nonzero command exits are preserved.
A reaped run is partial and must not be counted as a successful scientific result.

Keep existing hard RAM / Windows Job Object / container limits. This is a soft
host-memory policy, not a cgroup or Windows job memory limit, and it does not reap
detached workers, inspect GPU health, or establish job liveness. CPU-idle workers
can legitimately be blocked on I/O; use report-only or a longer quiet window
(`--idle-seconds`) for such gyms. Do not wrap accelerator or mixed-backend jobs.
It takes effect only for commands launched through it.

Focused test: `python tools/test_gym_ram_watchdog.py`.
