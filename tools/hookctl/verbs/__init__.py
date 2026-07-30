"""One module per verb family.

Every handler has the same shape — it takes the frozen `Context` and returns an
exit code — so the registry can hold them in a table and dispatch is a lookup.
A handler never reads `sys.argv`, never touches `os.environ`, and never imports
the registry: everything it is allowed to know arrives in the context.

    operator.py     setup, upgrade, uninstall — the verbs that write
    passthrough.py  the verbs that are a front for a gate subcommand
    dev.py          build, test, parity, fmt, selfcheck, verify
    audit.py        audit, and the counting that makes it worth reading
    reap.py         reap, the auto-reap before a build, and doctor's ninth check
"""
