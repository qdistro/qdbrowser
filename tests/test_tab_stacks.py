"""Tab stacks plugin."""


def test_clear_when_unset(window):
    plug = window.plugins._instances["tab_stacks"]
    plug._clear_current()
    assert window._active_webview.group is None


def test_clear_after_assigned(window):
    plug = window.plugins._instances["tab_stacks"]
    window._active_webview.group = "ops"
    plug._clear_current()
    assert window._active_webview.group is None


def test_commands_present(window):
    plug = window.plugins._instances["tab_stacks"]
    labels = [l for l, _ in plug.get_commands(window)]
    assert any("Tab stack" in l for l in labels)


def test_list_works_with_no_groups(window):
    plug = window.plugins._instances["tab_stacks"]
    plug._list()  # must not raise
