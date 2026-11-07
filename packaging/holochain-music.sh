#!/bin/sh
# Holochain Music launcher. Relocatable: resolves its bundle relative to
# itself, uses only bundled code (python -I ignores user site-packages and
# PYTHONPATH from the environment) and the bundled native helpers.
set -eu
here=$(dirname "$(readlink -f "$0")")
lib=$(readlink -f "$here/../lib/holochain-music")
export HOLOCHAIN_MUSIC_LIBEXEC="$lib/bin"
export HOLOCHAIN_MUSIC_HAPP="$lib/holochain_music.happ"
exec /usr/bin/python3 -I -c 'import sys; sys.path.insert(0, sys.argv.pop(1)); from holochain_music.cli import main; sys.exit(main(sys.argv[1:]))' "$lib/python" "$@"
