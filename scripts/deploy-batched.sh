#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME=$(basename "$0")
BATCH_SIZE=5
DELAY=30
SOLO=("sudoFundAndCreateCard")
DRYRUN=0
FUNCTIONS_FILE=""

usage() {
  cat <<EOF
Usage: $SCRIPT_NAME [options] [function1 function2 ...]
Options:
  --batch-size N        Number of functions per batch (default 5)
  --delay N             Delay in seconds between batches (default 30)
  --solo f1,f2          Comma-separated solo functions (default: sudoFundAndCreateCard)
  --file FILE           Read functions from FILE (one per line)
  --dry-run             Print firebase commands without executing
  -h, --help            Show this help
If no functions are provided, script will read 'functions.txt' if present.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --batch-size) BATCH_SIZE="$2"; shift 2;;
    --delay) DELAY="$2"; shift 2;;
    --solo) IFS=',' read -r -a SOLO <<< "$2"; shift 2;;
    --file) FUNCTIONS_FILE="$2"; shift 2;;
    --dry-run) DRYRUN=1; shift;;
    -h|--help) usage; exit 0;;
    --) shift; break;;
    -*) echo "Unknown option: $1"; usage; exit 1;;
    *) break;;
  esac
done

if [ "$#" -gt 0 ]; then
  functions=("$@")
else
  if [ -n "$FUNCTIONS_FILE" ] && [ -f "$FUNCTIONS_FILE" ]; then
    mapfile -t functions < <(grep -v '^\s*#' "$FUNCTIONS_FILE" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
  elif [ -f functions.txt ]; then
    mapfile -t functions < <(grep -v '^\s*#' functions.txt | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
  else
    # attempt to auto-detect exported names from functions/index.js
    script_dir="$(cd "$(dirname "$0")" && pwd)"
    index_file="$script_dir/../functions/index.js"

    if [ -f "$index_file" ]; then
      if command -v node >/dev/null 2>&1; then
        mapfile -t functions < <(node - "$index_file" <<'NODE'
const fs=require('fs');
const p=process.argv[1];
let t=fs.readFileSync(p,'utf8');
t = t.replace(/\/\*[\s\S]*?\*\//g,'').replace(/\/\/.*$/gm,'');
const s=new Set();
let m;
while((m=/exports\.(\w+)/g.exec(t))){s.add(m[1])}
while((m=/exports\[['"]([^'\"]+)['"]\]/g.exec(t))){s.add(m[1])}
const mm=/module\.exports\s*=\s*{([\s\S]*?)}/.exec(t);
if(mm){const body=mm[1]; let k; while((k=/['"]?([A-Za-z0-9_$]+)['"]?\s*:/g.exec(body)){s.add(k[1])}}
console.log([...s].join('\n'));
NODE
)
      else
        mapfile -t functions < <(grep -oE 'exports\.[A-Za-z0-9_]+' "$index_file" | sed 's/^exports\.//')
      fi
    else
      echo "No functions provided and functions.txt not found."
      usage
      exit 1
    fi
  fi
fi

if [ "$DRYRUN" -eq 0 ]; then
  if ! command -v firebase >/dev/null 2>&1; then
    echo "firebase CLI not found. Install with: npm i -g firebase-tools"
    exit 2
  fi
fi

# Deploy solo functions first
for s in "${SOLO[@]}"; do
  for idx in "${!functions[@]}"; do
    if [ "${functions[idx]}" = "$s" ]; then
      echo "Deploying solo function: $s"
      if [ "$DRYRUN" -eq 1 ]; then
        echo "DRYRUN: firebase deploy --only functions:$s"
      else
        firebase deploy --only "functions:$s"
        rc="$?"
        if [ "$rc" -ne 0 ]; then echo "Warning: deploy failed for $s (exit $rc)"; fi
      fi
      sleep "$DELAY"
      unset 'functions[idx]'
    fi
  done
done

# Rebuild remaining array
remaining=()
for f in "${functions[@]}"; do
  if [ -n "$f" ]; then remaining+=("$f"); fi
done

if [ "${#remaining[@]}" -eq 0 ]; then
  echo "No remaining functions to deploy"
  exit 0
fi

for ((i=0; i<${#remaining[@]}; i+=BATCH_SIZE)); do
  batch=("${remaining[@]:i:BATCH_SIZE}")
  joined=$(IFS=, ; echo "${batch[*]}")
  echo "Deploying batch: $joined"
  if [ "$DRYRUN" -eq 1 ]; then
    echo "DRYRUN: firebase deploy --only functions:$joined"
  else
    firebase deploy --only "functions:$joined"
    rc="$?"
    if [ "$rc" -ne 0 ]; then echo "Warning: batch deploy failed for $joined (exit $rc)"; fi
  fi
  if [ $((i + BATCH_SIZE)) -lt ${#remaining[@]} ]; then
    sleep "$DELAY"
  fi
done

echo "All deployments completed."