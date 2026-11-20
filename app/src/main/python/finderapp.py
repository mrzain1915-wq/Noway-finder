"""Android bootstrap for NOWAY Finder: starts the local web workspace.

The Finder code itself is unchanged. This module only adapts it to Android:
writable scratch areas inside the app's private storage, and a DNS fallback,
because Android has no /etc/resolv.conf for dnspython's default resolver.
"""

import os


def start(db_path, cache_dir, port=8765):
    os.environ["TMPDIR"] = cache_dir
    os.environ.setdefault("HOME", os.path.dirname(db_path))
    try:
        import dns.asyncresolver

        _orig_init = dns.asyncresolver.Resolver.__init__

        def _patched_init(self, *args, **kwargs):
            try:
                _orig_init(self, *args, **kwargs)
            except Exception:
                _orig_init(self, *args, configure=False, **kwargs)
                self.nameservers = ["1.1.1.1", "8.8.8.8"]

        dns.asyncresolver.Resolver.__init__ = _patched_init
    except Exception:
        pass
    from noway_finder.cli import main

    main(["--database", db_path, "serve", "--port", str(port)])
