# KAgent suite-tab audit

The reported environment is Burp Suite Community 2026.9.2. A count of one
suite tab establishes a registration, not visibility in the main window.
Actual visibility in that application has not been reproduced locally:
this environment has Java 17, but no Burp or Jython installation.

## Component and registration

`BurpExtender` implements `ITab`, passes itself to `addSuiteTab`, and returns
the nonempty caption `KAgent`. The component construction uses valid Swing
constructors and returns a populated `JPanel(BorderLayout())`: a vertical
container with three control rows in `NORTH`, and a label plus scrollable,
read-only activity text area in `CENTER`. No code hides or removes the tab.
Neither a frame nor `setVisible(True)` is required for an embedded suite tab.
`customizeUiComponent` is a Burp styling hook, not a tab-registration prerequisite.

The original getter constructed a new panel on every call and replaced the
extension's URL field, token field, checkboxes, and log references. A minimal
test using the existing Java/Burp stand-ins registered the first panel, edited
its URL to `http://127.0.0.1:9999`, retrieved the component again, and invoked
Save. The roots and fields differed; Save retained the default `:8888` URL,
and the original activity log did not receive the message. This confirms a
component/state identity defect. It does **not** demonstrate that Burp 2026.9.2
calls the getter twice or that this defect caused the missing main-window tab.

The fix builds one component before registration and returns that same
component on every getter call. Construction and registration run on Swing's
event dispatch thread (EDT); an already-EDT load does not call `invokeAndWait`.
The initialization is synchronous, so successful load completion follows tab
registration and there is no deferred tab-add task left after load returns.
The getter subsequently performs no Swing construction.

A separate Java 17 headless smoke experiment constructed the same Swing layout
and inserted it into a `JTabbedPane`. It produced a nonzero preferred size and
one tab with caption `KAgent`. Its `isShowing()` was false because there was no
displayed window. This checks the Swing layout, not Jython interoperability,
Burp's tab manager, or real application visibility.

## Load and unload

There is one `addSuiteTab` call per extension instance and no explicit
`removeSuiteTab`, `extensionUnloaded`, or extension state listener. The UI owns
no custom threads, timers, windows, or other long-lived resources. No unload
hook was added merely to try to reveal a hidden tab. Removal of registrations
when Burp unloads an extension remains a host lifecycle behavior to verify in
the actual application. Regression tests check that a new extension instance
has separate widgets; they do not simulate or certify Burp's unload cleanup.

## Burp layout can hide a registered tab

PortSwigger documents that top-level tabs, including extension tabs, can be
hidden or detached and that Burp remembers layout preferences. `View` lists
hidden tabs and can redisplay them in their last window. `View > Restore
default tab layout` reveals hidden tabs and returns detached tabs to the main
window. This is a documented explanation compatible with the reported
registration counts; it is not a confirmed diagnosis of this user's layout.
The 2026.9.2 release notes describe a browser upgrade, not a suite-tab API
change or a fix for this symptom.

## Verification in Burp Community 2026.9.2

1. Record the currently loaded extension path and inspect its Errors panel.
   Inspect `View` for `KAgent`, including its hidden-tab indicator, and check
   detached windows. Select `View > KAgent` if listed.
2. If needed, use `View > Restore default tab layout`. This resets the user's
   tab arrangement. Record whether KAgent appears; its appearance after this
   step supports a layout explanation.
3. Reload the updated `kagent_burp.py`. Confirm that exactly one KAgent entry
   appears in `View`, that opening it displays all controls and the activity
   log, and that the Errors panel has no initialization exception. Edit a
   local URL, press Save, hide/show and detach/reattach the tab, and verify the
   same URL, checkbox state, and activity log survive. No bridge or network
   request is required for these UI checks.
4. Unload the extension. Verify its tab and `View` entry disappear, including
   when detached. Reload once and verify only one tab returns. Repeat a rapid
   unload/reload to check for stale tabs or errors.
5. If the tab still cannot be found, load the minimal Python/Jython probe below
   as a separate extension. Its distinct caption avoids assuming that the
   saved KAgent layout is also used for the probe. Inspect `View` and Errors
   for the probe, and repeat the default-layout check. A registered but absent
   probe isolates the symptom from KAgent's control layout and bridge code.
   A visible probe with an absent KAgent tab calls for inspecting KAgent's
   actual getter/registration execution and application errors.

```python
from burp import IBurpExtender, ITab
from java.lang import Runnable
from javax.swing import JPanel, JLabel, SwingUtilities

class BurpExtender(IBurpExtender, ITab, Runnable):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        callbacks.setExtensionName("KAgent UI probe")
        if SwingUtilities.isEventDispatchThread():
            self.run()
        else:
            SwingUtilities.invokeAndWait(self)

    def run(self):
        self.panel = JPanel()
        self.panel.add(JLabel("KAgent UI probe component"))
        self.callbacks.addSuiteTab(self)

    def getTabCaption(self):
        return "KAgent UI probe"

    def getUiComponent(self):
        return self.panel
```

## Focused verification

The tests use Java/Burp stand-ins and exercise getters during registration,
stable component identity, visible control callbacks, preserved log contents,
EDT dispatch, already-EDT loading, failed construction, and separate reload
instances. Existing extension tests also exercise the retained capture actions.
The integration test file is excluded by the repository's default `addopts`,
so run it explicitly with that option overridden:

```bash
venv-linux/bin/python -m pytest -o addopts='' \
  tests/integration/test_kagent_burp_ui.py \
  tests/integration/test_kagent_burp.py -q
venv-linux/bin/python -m pytest \
  tests/integration/test_burp_offline_audit.py \
  tests/integration/test_kagent_burp_ui.py -q
```

Capture ingestion, Workflow, MCP, permissions, and runtime implementation were
not changed. Full-suite, real Burp, and real Jython checks were not run.

## References

- [ITab contract](https://portswigger.net/burp/extender/api/burp/itab.html)
- [Tab registration and styling API](https://portswigger.net/burp/extender/api/burp/iburpextendercallbacks.html)
- [Top-level tab visibility and layout](https://portswigger.net/burp/documentation/desktop/burps-layout/customize-top-level-tabs)
- [Extension state listener contract](https://portswigger.net/burp/extender/api/burp/iextensionstatelistener.html)
- [Swing GUI initialization and EDT requirements](https://docs.oracle.com/javase/tutorial/uiswing/concurrency/initial.html)
- [2026.9.2 release notes](https://portswigger.net/burp/releases/professional-community-2026-9-2)
