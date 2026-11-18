import json
import time

import pytest

from mcpposture.jsonc import MAX_DEPTH, JsoncError, loads


@pytest.mark.parametrize(
    "text",
    ["{}", "[]", '"s"', "0", "-1.5e3", '{"a": [1, 2.5, -3e2, true, false, null, "x\\u00e9\\n\\"q"]}'],
)
def test_plain_json_matches_stdlib(text):
    assert loads(text).value == json.loads(text)


def test_comments_and_trailing_commas():
    doc = loads(
        """// header comment
        {
          /* block
             comment */
          "url": "https://example.com//not-a-comment", // trailing comment
          "args": ["a", "/* not a comment */",],
        }"""
    )
    assert doc.value == {"url": "https://example.com//not-a-comment", "args": ["a", "/* not a comment */"]}


def test_records_line_of_every_value():
    doc = loads('{\n  "a": {\n    "b": [\n      1,\n      2\n    ]\n  }\n}')
    assert doc.lines[""] == 1
    assert doc.lines["/a"] == 2
    assert doc.lines["/a/b"] == 3
    assert doc.lines["/a/b/1"] == 5


def test_json_pointer_escaping():
    assert "/a~1b/c~0d" in loads('{"a/b": {"c~d": 1}}').lines


def test_utf8_bom_is_ignored():
    assert loads('﻿{"a": 1}').value == {"a": 1}


def test_duplicate_keys_last_wins_like_json_parse():
    assert loads('{"a": 1, "a": 2}').value == {"a": 2}


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "{",
        '{"a" 1}',
        '{"a": 1,,}',
        "[1 2]",
        '{"a": 1} x',
        "/* never closed",
        '"unterminated',
        '{"a": 01}',
        "NaN",
        "{a: 1}",
        "{'a': 1}",
        '"\x01"',
        '"\\x41"',
        "[,]",
        "{,}",
        "/ {}",
    ],
)
def test_rejects_malformed_input(bad):
    with pytest.raises(JsoncError):
        loads(bad)


def test_error_reports_line():
    with pytest.raises(JsoncError) as e:
        loads('{\n  "a": 1,\n  "b": }')
    assert e.value.line == 3


def test_nesting_limit_prevents_recursion_exhaustion():
    with pytest.raises(JsoncError):
        loads("[" * (MAX_DEPTH + 2) + "]" * (MAX_DEPTH + 2))
    with pytest.raises(JsoncError):
        loads("[" * 200_000)


def test_huge_integer_is_rejected_not_crashing():
    with pytest.raises(JsoncError):
        loads("1" * 10_000)


def test_unterminated_string_fails_in_linear_time():
    hostile = '"' + 'a\\"' * 300_000
    start = time.perf_counter()
    with pytest.raises(JsoncError):
        loads(hostile)
    assert time.perf_counter() - start < 2.0
