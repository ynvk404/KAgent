from __future__ import annotations

from rich.text import Text
from textual.widget import Widget

from src.ui.widgets.input_box import InputBox

# TODO: bảng màu cho các style-name ("prompt"/"gray"/"text"/"cursor"/
# "cursor_char") mà InputBox.render() trả về KHÔNG được định nghĩa ở
# đâu trong code bạn đã gửi (InputBox chỉ trả string tên style, không
# phải rich style thật). Đây là widget Python thuần, không có JSX
# tương ứng để đối chiếu 1:1, nên bảng dưới đây là lựa chọn hợp lý dựa
# theo palette đã dùng trong StatusBar (vd "grey62"). Xác nhận / chỉnh
# lại nếu bạn có style-guide khác cho input box.
_STYLE_MAP: dict[str | None, str] = {
    None: "",
    "gray": "grey62",
    "prompt": "bold cyan",
    "text": "",
    "cursor": "reverse",
    "cursor_char": "reverse",
}


class InputBoxWidget(Widget):
    """
    Bọc InputBox (pure renderer, không phải textual.widget.Widget) thành
    1 Widget thật để mount trong compose(). InputBox tự nó chỉ trả về
    list[InputLine] — không có quyền truy cập app/refresh — nên widget
    này giữ 1 instance InputBox và tự gọi self.refresh() khi state đổi.
    """

    DEFAULT_CSS = """
    InputBoxWidget {
        width: 100%;
        height: auto;
    }
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._box = InputBox(value="", cursor=0)

    def update_box(
        self,
        value: str,
        cursor: int,
        disabled: bool,
        placeholder: str | None = None,
        prompt: str = "❯ ",
    ) -> None:
        self._box = InputBox(
            value=value,
            cursor=cursor,
            prompt=prompt,
            placeholder=placeholder,
            disabled=disabled,
        )
        self.refresh()

    def render(self) -> Text:
        out = Text()
        lines = self._box.render()
        for i, line in enumerate(lines):
            if i > 0:
                out.append("\n")
            for seg in line.segments:
                out.append(seg.text, style=_STYLE_MAP.get(seg.style, ""))
        return out