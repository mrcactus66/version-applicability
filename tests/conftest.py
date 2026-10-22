"""Windows compatibility for gltest 0.29.2's stdin injection.

Windows cannot unlink the message file while duplicated fd 0 is open.
Keep its normal injection logic and defer only that cleanup until VM teardown.
"""
import os

import pytest


@pytest.fixture(autouse=True)
def windows_message_cleanup(monkeypatch):
    if os.name != "nt":
        yield
        return
    from gltest.direct import loader
    original = loader._inject_message_to_fd0
    unlink = os.unlink
    deferred = []

    def inject(vm):
        def unlink_or_defer(path):
            try:
                unlink(path)
            except PermissionError:
                deferred.append(path)
        with monkeypatch.context() as scoped:
            scoped.setattr(os, "unlink", unlink_or_defer)
            original(vm)

    monkeypatch.setattr(loader, "_inject_message_to_fd0", inject)
    yield
    for path in deferred:
        try:
            unlink(path)
        except (PermissionError, FileNotFoundError):
            pass
