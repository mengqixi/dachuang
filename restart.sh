#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "$0")" && pwd)"
pid_file="$project_dir/data/app.pid"
log_file="$project_dir/logs/server.log"

mkdir -p "$project_dir/data" "$project_dir/logs"

if [[ -f "$pid_file" ]]; then
    app_pid="$(tr -d '[:space:]' < "$pid_file")"
    if [[ "$app_pid" =~ ^[0-9]+$ ]] && kill -0 "$app_pid" 2>/dev/null; then
        process_cwd="$(readlink -f "/proc/$app_pid/cwd" 2>/dev/null || true)"
        process_args="$(tr '\0' ' ' < "/proc/$app_pid/cmdline" 2>/dev/null || true)"
        if [[ "$process_cwd" != "$project_dir" || "$process_args" != *"app.py"* ]]; then
            echo "Refusing to stop PID $app_pid: it is not the recorded process for this project." >&2
            exit 2
        fi
        kill "$app_pid"
        for _ in {1..20}; do
            kill -0 "$app_pid" 2>/dev/null || break
            sleep 0.25
        done
        if kill -0 "$app_pid" 2>/dev/null; then
            echo "Recorded process did not stop cleanly; refusing a forced or broad kill." >&2
            exit 2
        fi
    fi
fi

cd "$project_dir"
nohup python3 app.py >> "$log_file" 2>&1 &
new_pid=$!
printf '%s\n' "$new_pid" > "$pid_file"
echo "Started this project's app.py as PID $new_pid. Log: $log_file"
