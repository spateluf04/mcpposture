"""JSON-with-comments parser that records the source line of every value.

Accepts ``//`` and ``/* */`` comments and trailing commas (the dialect VS Code
uses for mcp.json); everything else follows RFC 8259. The standard library
``json`` module cannot report positions, which SARIF output needs, and
stripping comments with a regex breaks on ``//`` inside strings such as URLs.

Duplicate keys resolve last-wins, matching JavaScript's ``JSON.parse`` that the
audited clients use, so the tool sees the same value the client would load.
"""

from __future__ import annotations

import bisect
import json
import re
from dataclasses import dataclass, field

MAX_DEPTH = 64

_SKIP = re.compile(r"(?:[ \t\n\r]+|//[^\n]*|/\*.*?\*/)*", re.DOTALL)
# Unrolled-loop form keeps matching linear on unterminated input (no ReDoS).
_STRING = re.compile(
    r'"[^"\\\x00-\x1f]*(?:\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4})[^"\\\x00-\x1f]*)*"'
)
_NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?")
_LITERALS = (("true", True), ("false", False), ("null", None))


class JsoncError(ValueError):
    def __init__(self, message: str, line: int) -> None:
        super().__init__(f"{message} at line {line}")
        self.line = line


@dataclass(frozen=True)
class Document:
    value: object
    lines: dict[str, int] = field(default_factory=dict)


def escape_pointer_token(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def loads(text: str) -> Document:
    return _Parser(text).parse()


class _Parser:
    def __init__(self, text: str) -> None:
        if text.startswith("﻿"):
            text = text[1:]
        self._s = text
        self._i = 0
        self._newlines = [m.start() for m in re.finditer("\n", text)]
        self._lines: dict[str, int] = {}

    def parse(self) -> Document:
        self._skip()
        value = self._value("", 0)
        self._skip()
        if self._i != len(self._s):
            self._fail("unexpected content after the top-level value")
        return Document(value, self._lines)

    def _line_at(self, pos: int) -> int:
        return bisect.bisect_left(self._newlines, pos) + 1

    def _fail(self, message: str) -> None:
        raise JsoncError(message, self._line_at(self._i))

    def _skip(self) -> None:
        self._i = _SKIP.match(self._s, self._i).end()  # type: ignore[union-attr]

    def _peek(self) -> str:
        return self._s[self._i : self._i + 1]

    def _value(self, pointer: str, depth: int) -> object:
        if depth > MAX_DEPTH:
            self._fail(f"nesting deeper than {MAX_DEPTH} levels")
        self._lines[pointer] = self._line_at(self._i)
        c = self._peek()
        if c == "{":
            return self._object(pointer, depth)
        if c == "[":
            return self._array(pointer, depth)
        if c == '"':
            return self._string()
        if c and c in "-0123456789":
            return self._number()
        for word, val in _LITERALS:
            if self._s.startswith(word, self._i):
                self._i += len(word)
                return val
        self._fail("unexpected end of input" if not c else f"unexpected character {c!r}")
        return None  # unreachable; _fail raises

    def _string(self) -> str:
        m = _STRING.match(self._s, self._i)
        if m is None:
            self._fail("invalid or unterminated string")
        assert m is not None
        self._i = m.end()
        return json.loads(m.group())

    def _number(self) -> int | float:
        m = _NUMBER.match(self._s, self._i)
        if m is None:
            self._fail("invalid number")
        assert m is not None
        self._i = m.end()
        text = m.group()
        try:
            return float(text) if (m.group(1) or m.group(2)) else int(text)
        except ValueError:
            self._fail("number too large")
            raise  # unreachable

    def _end_of_member(self, close: str) -> bool:
        self._skip()
        c = self._peek()
        if c == ",":
            self._i += 1
            self._skip()
            if self._peek() == close:
                self._i += 1
                return True
            return False
        if c == close:
            self._i += 1
            return True
        self._fail(f"expected ',' or '{close}'")
        return False  # unreachable

    def _object(self, pointer: str, depth: int) -> dict[str, object]:
        self._i += 1
        out: dict[str, object] = {}
        self._skip()
        if self._peek() == "}":
            self._i += 1
            return out
        while True:
            if self._peek() != '"':
                self._fail("expected a property name in double quotes")
            key = self._string()
            self._skip()
            if self._peek() != ":":
                self._fail("expected ':'")
            self._i += 1
            self._skip()
            out[key] = self._value(f"{pointer}/{escape_pointer_token(key)}", depth + 1)
            if self._end_of_member("}"):
                return out

    def _array(self, pointer: str, depth: int) -> list[object]:
        self._i += 1
        out: list[object] = []
        self._skip()
        if self._peek() == "]":
            self._i += 1
            return out
        while True:
            out.append(self._value(f"{pointer}/{len(out)}", depth + 1))
            if self._end_of_member("]"):
                return out
