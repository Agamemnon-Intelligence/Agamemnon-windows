#!/usr/bin/env python3
"""Generate platform design-token files from design/tokens.json.

    python3 design/generate_tokens.py           # write the generated files
    python3 design/generate_tokens.py --check   # exit 1 if any file is stale (used by CI)

Outputs:
    windows/src/Agamemnon.App/Themes/Tokens.g.xaml   WPF resource dictionary
    windows/src/Agamemnon.App/Themes/DesignTokens.g.cs   C# constants (tray icon, code-drawn UI)
    mac/Shared/DesignTokens.swift                    SwiftUI tokens for the macOS app
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOKENS = ROOT / "design" / "tokens.json"

HEADER = "Generated from design/tokens.json by design/generate_tokens.py. Do not edit by hand."
HEX = re.compile(r"^#[0-9A-Fa-f]{6}$")


def pascal(name: str) -> str:
    return name[0].upper() + name[1:]


def load() -> dict:
    data = json.loads(TOKENS.read_text(encoding="utf-8"))
    if data.get("theme") != "dark":
        raise SystemExit("tokens.json: Agamemnon ships a dark theme only")
    for key, value in data["color"].items():
        if not HEX.match(value):
            raise SystemExit(f"tokens.json: color.{key} must be #RRGGBB, got {value!r}")
    return data


def xaml(data: dict) -> str:
    lines = [
        '<ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"',
        '                    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"',
        '                    xmlns:sys="clr-namespace:System;assembly=mscorlib">',
        f"    <!-- {HEADER} -->",
    ]
    for key, value in data["color"].items():
        lines.append(f'    <Color x:Key="{pascal(key)}Color">{value.upper()}</Color>')
    for key in data["color"]:
        name = pascal(key)
        lines.append(
            f'    <SolidColorBrush x:Key="{name}Brush" Color="{{StaticResource {name}Color}}" />'
        )
    for key, value in data["radius"].items():
        lines.append(f'    <CornerRadius x:Key="Radius{pascal(key)}">{value}</CornerRadius>')
    for key, value in data["spacing"].items():
        lines.append(f'    <sys:Double x:Key="Space{pascal(key)}">{value}</sys:Double>')
        lines.append(f'    <Thickness x:Key="Pad{pascal(key)}">{value}</Thickness>')
    for key, value in data["fontSize"].items():
        lines.append(f'    <sys:Double x:Key="FontSize{pascal(key)}">{value}</sys:Double>')
    for key, value in data["layout"].items():
        lines.append(f'    <GridLength x:Key="{pascal(key)}">{value}</GridLength>')
    lines.append("</ResourceDictionary>")
    return "\n".join(lines) + "\n"


def csharp(data: dict) -> str:
    lines = [
        f"// {HEADER}",
        "namespace Agamemnon.App.Themes;",
        "",
        "public static class DesignTokens",
        "{",
    ]
    for key, value in data["color"].items():
        lines.append(f'    public const string {pascal(key)} = "{value.upper()}";')
    for key, value in data["radius"].items():
        lines.append(f"    public const double Radius{pascal(key)} = {value};")
    lines.append("}")
    return "\n".join(lines) + "\n"


def swift(data: dict) -> str:
    def rgb(value: str) -> str:
        r, g, b = (int(value[i : i + 2], 16) for i in (1, 3, 5))
        return f"Color(red: {r} / 255, green: {g} / 255, blue: {b} / 255)"

    lines = [
        f"// {HEADER}",
        "import SwiftUI",
        "",
        "public enum DesignTokens {",
        "    public enum Colors {",
    ]
    for key, value in data["color"].items():
        lines.append(f"        public static let {key} = {rgb(value)}  // {value.upper()}")
    lines.append("    }")
    lines.append("")
    lines.append("    public enum Radius {")
    for key, value in data["radius"].items():
        lines.append(f"        public static let {key}: CGFloat = {value}")
    lines.append("    }")
    lines.append("")
    lines.append("    public enum Spacing {")
    for key, value in data["spacing"].items():
        lines.append(f"        public static let {key}: CGFloat = {value}")
    lines.append("    }")
    lines.append("")
    lines.append("    public enum FontSize {")
    for key, value in data["fontSize"].items():
        lines.append(f"        public static let {key}: CGFloat = {value}")
    lines.append("    }")
    lines.append("")
    lines.append("    public enum Layout {")
    for key, value in data["layout"].items():
        lines.append(f"        public static let {key}: CGFloat = {value}")
    lines.append("    }")
    lines.append("}")
    return "\n".join(lines) + "\n"


def main() -> int:
    data = load()
    outputs = {
        ROOT / "windows/src/Agamemnon.App/Themes/Tokens.g.xaml": xaml(data),
        ROOT / "windows/src/Agamemnon.App/Themes/DesignTokens.g.cs": csharp(data),
        ROOT / "mac/Shared/DesignTokens.swift": swift(data),
    }
    check = "--check" in sys.argv[1:]
    stale = []
    for path, content in outputs.items():
        current = path.read_text(encoding="utf-8") if path.exists() else None
        if current == content:
            continue
        if check:
            stale.append(path.relative_to(ROOT))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8", newline="\n")
            print(f"wrote {path.relative_to(ROOT)}")
    if stale:
        print("Design tokens are out of date. Run: python3 design/generate_tokens.py")
        for path in stale:
            print(f"  stale: {path}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
