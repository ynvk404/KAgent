"""Explicit local access to bridge credentials; never writes a transcript."""
from rich.text import Text
from src.ui.render.sanitize import sanitize_text


class BridgeCredentialsModal:
    def __init__(self, state, copy, close):
        self.state, self.copy, self.close = state, copy, close
        self.revealed = False

    def handle_key(self, key):
        if key in {"escape", "esc", "enter"}:
            self.close()
        elif key == "v":
            self.revealed = not self.revealed
        elif key == "c":
            # Explicit credential copy is confined to this operator-invoked view.
            self.copy(self.state.token)

    def render(self):
        token = self.state.token if self.revealed else "[hidden]"
        return Text(f"Burp bridge credentials\n{sanitize_text(self.state.url)}\nToken: {token}\nv reveal/hide · c copy token · Esc close")
