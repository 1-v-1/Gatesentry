#!/bin/sh
# Basedir shim for GateSentry.
#
# The binary derives its data directory from
#     filepath.Dir(os.Args[0]) + "/gatesentry"
# so when procd execs it as a full path, the data dir would land under
# /usr/lib/gatesentry/gatesentry/ (read-only). By exec'ing it by basename
# after chdir, we ensure os.Args[0] is "gatesentry-bin" and basedir resolves
# to /var/lib/gatesentry/gatesentry/.

cd /var/lib/gatesentry
exec ./gatesentry-bin