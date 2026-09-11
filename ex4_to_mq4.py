#!/usr/bin/env python3
"""Minimal EX4 -> MQL4 decompiler.

Strict command-line equivalent of the project's GUI tools, reduced to the one
thing actually needed: read a compiled MT4 `.ex4` file, pull out whatever
metadata/strings/patterns survive compilation, and emit an approximate
`.mq4` source file next to it.

No GUI, no multi-language output, no extra dependencies (stdlib only).
As with the rest of this project: EX4 is a compiled/encrypted format, so
this reconstructs a best-effort skeleton (detected functions, parameters,
indicators) rather than the exact original source.

Usage:
    python ex4_to_mq4.py file1.ex4 [file2.ex4 ...]
    python ex4_to_mq4.py --dir "EX4 file (indicator)"
"""

import argparse
import os
import re
import struct
import sys
from datetime import datetime

KNOWN_INDICATORS = [
    (b'iMA', 'Moving Average'),
    (b'iRSI', 'RSI'),
    (b'iMACD', 'MACD'),
    (b'iATR', 'ATR'),
    (b'iBands', 'Bollinger Bands'),
    (b'iStochastic', 'Stochastic'),
    (b'iCCI', 'CCI'),
    (b'iADX', 'ADX'),
]

TRADING_FUNCTIONS = [b'OrderSend', b'OrderClose', b'OrderModify', b'OrderDelete']

PARAM_KEYWORDS = {
    'period': ('int', 14),
    'shift': ('int', 0),
    'lots': ('double', 0.1),
    'lot': ('double', 0.1),
    'stoploss': ('int', 50),
    'takeprofit': ('int', 100),
    'maxlots': ('double', 1.0),
    'slippage': ('int', 3),
    'magic': ('int', 12345),
    'risk': ('double', 1.0),
    'percent': ('double', 2.0),
}


def extract_metadata(data: bytes, strings: list, filename: str = '') -> dict:
    metadata = {
        'type': 'Unknown',
        'version': 'Unknown',
        'creation_date': 'Unknown',
        'copyright': 'Unknown',
        'author': 'Unknown',
        'link': 'Unknown',
        'file_size': len(data),
    }

    if b'indicator' in data.lower():
        metadata['type'] = 'Indicator'
    elif b'expert' in data.lower() or b'EA' in data:
        metadata['type'] = 'Expert Advisor'
    elif b'script' in data.lower():
        metadata['type'] = 'Script'
    else:
        # Modern (encrypted) EX4 builds carry none of the above in plaintext;
        # the filename is the only remaining hint of what the file is.
        name_lower = filename.lower()
        if 'indicator' in name_lower:
            metadata['type'] = 'Indicator'
        elif 'expert' in name_lower or re.search(r'\bea\b', name_lower):
            metadata['type'] = 'Expert Advisor'
        elif 'script' in name_lower:
            metadata['type'] = 'Script'

    # Modern EX4 builds encrypt the bytecode/string table, so most text only
    # survives as plaintext ASCII or UTF-16LE runs already pulled out by
    # extract_strings(); fall back to scanning those too, not just raw bytes.
    text = "\x00".join(strings)

    version_match = re.search(r'ver(?:sion)?[\s=:]*(\d+\.\d+(?:\.\d+)?)', text, re.IGNORECASE) or \
        re.search(rb'ver(?:sion)?[\s=:]*(\d+\.\d+(?:\.\d+)?)', data, re.IGNORECASE)
    if version_match:
        value = version_match.group(1)
        metadata['version'] = value if isinstance(value, str) else value.decode('ascii', errors='ignore')

    if data.startswith(b'MZ') and len(data) > 0x40:
        try:
            pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
            if pe_offset < len(data) - 8 and data[pe_offset:pe_offset + 4] == b'PE\x00\x00':
                timestamp = struct.unpack('<I', data[pe_offset + 8:pe_offset + 12])[0]
                if timestamp > 0:
                    metadata['creation_date'] = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
        except (struct.error, OSError, OverflowError, ValueError):
            pass

    copyright_match = re.search(r'copyright[\s:(]*([^\x00]{3,50})', text, re.IGNORECASE)
    if copyright_match:
        metadata['copyright'] = copyright_match.group(1).strip()

    author_match = re.search(r'author[\s:(]*([^\x00]{3,50})', text, re.IGNORECASE)
    if author_match:
        metadata['author'] = author_match.group(1).strip()

    link_match = re.search(r'(https?://\S{3,100})', text, re.IGNORECASE)
    if link_match:
        metadata['link'] = link_match.group(1).strip()

    return metadata


def extract_strings(data: bytes) -> list:
    """ASCII and UTF-16LE printable strings (MT4 stores names/labels either way)."""
    strings = []
    current = ''
    for byte in data:
        if 32 <= byte <= 126:
            current += chr(byte)
        elif current:
            if len(current) > 3:
                strings.append(current)
            current = ''
    if len(current) > 3:
        strings.append(current)

    i = 0
    while i < len(data) - 1:
        if data[i] != 0 and data[i + 1] == 0:
            unicode_bytes = bytearray()
            j = i
            while j < len(data) - 1 and j < i + 200 and data[j] != 0 and data[j + 1] == 0 and 32 <= data[j] <= 126:
                unicode_bytes.append(data[j])
                j += 2
            if len(unicode_bytes) > 3:
                strings.append(unicode_bytes.decode('ascii', errors='ignore'))
            i = j if j > i else i + 1
        else:
            i += 1

    seen = set()
    unique = []
    for s in strings:
        if s not in seen:
            seen.add(s)
            unique.append(s)
    return unique


def extract_input_parameters(strings: list) -> list:
    parameters = []
    seen_names = set()
    for s in strings:
        s_lower = s.lower()
        for keyword, (param_type, default) in PARAM_KEYWORDS.items():
            if keyword in s_lower and s not in seen_names and s.isidentifier():
                parameters.append({'name': s, 'type': param_type, 'default': default})
                seen_names.add(s)
                break
    return parameters


def analyze(data: bytes, filename: str = '') -> dict:
    strings = extract_strings(data)
    return {
        'metadata': extract_metadata(data, strings, filename),
        'strings': strings,
        'input_parameters': extract_input_parameters(strings),
        'indicators_used': [name for sig, name in KNOWN_INDICATORS if sig in data],
        'has_trading_functions': any(sig in data for sig in TRADING_FUNCTIONS),
        'risk': {
            'stop_loss': b'StopLoss' in data or b'SL' in data,
            'take_profit': b'TakeProfit' in data or b'TP' in data,
            'trailing_stop': b'TrailingStop' in data,
        },
    }


def generate_mql4(analysis: dict, source_name: str) -> str:
    meta = analysis['metadata']
    is_indicator = meta['type'] == 'Indicator'
    is_expert = meta['type'] == 'Expert Advisor'
    lines = []

    lines.append("//+------------------------------------------------------------------+")
    lines.append(f"//| Decompiled from {source_name}")
    lines.append(f"//| Type: {meta['type']}")
    lines.append(f"//| Version: {meta['version']}")
    if meta['creation_date'] != 'Unknown':
        lines.append(f"//| Compiled: {meta['creation_date']}")
    if meta['copyright'] != 'Unknown':
        lines.append(f"//| Copyright: {meta['copyright']}")
    if meta['author'] != 'Unknown':
        lines.append(f"//| Author: {meta['author']}")
    if meta['link'] != 'Unknown':
        lines.append(f"//| Link: {meta['link']}")
    lines.append("//+------------------------------------------------------------------+")
    lines.append("//| NOTE: EX4 is a compiled/encrypted format. This is a best-effort")
    lines.append("//| reconstruction from surviving metadata/strings, not the original")
    lines.append("//| source. Review and adapt before use.")
    lines.append("//+------------------------------------------------------------------+")
    lines.append("")

    if is_indicator:
        lines.append("#property indicator_separate_window")
        lines.append("#property indicator_buffers 1")
        lines.append("")

    params = analysis['input_parameters']
    if params:
        lines.append("// Input parameters (inferred from strings surviving compilation)")
        for param in params:
            lines.append(f"extern {param['type']} {param['name']} = {param['default']};")
        lines.append("")

    if is_indicator:
        lines.append("double Buffer1[];")
        lines.append("")

    lines.append("//+------------------------------------------------------------------+")
    lines.append("//| Initialization function")
    lines.append("//+------------------------------------------------------------------+")
    lines.append("int init()")
    lines.append("{")
    if is_indicator:
        lines.append("    SetIndexStyle(0, DRAW_LINE);")
        lines.append("    SetIndexBuffer(0, Buffer1);")
        lines.append("    SetIndexLabel(0, \"Main Buffer\");")
    lines.append("    return(0);")
    lines.append("}")
    lines.append("")

    lines.append("//+------------------------------------------------------------------+")
    lines.append("//| Deinitialization function")
    lines.append("//+------------------------------------------------------------------+")
    lines.append("int deinit()")
    lines.append("{")
    lines.append("    return(0);")
    lines.append("}")
    lines.append("")

    lines.append("//+------------------------------------------------------------------+")
    lines.append("//| Main function")
    lines.append("//+------------------------------------------------------------------+")
    lines.append("int start()")
    lines.append("{")

    indicators_used = analysis['indicators_used']
    calc_snippets = {
        'Moving Average': '    double ma = iMA(Symbol(), Period(), 14, 0, MODE_SMA, PRICE_CLOSE, 0);',
        'RSI': '    double rsi = iRSI(Symbol(), Period(), 14, PRICE_CLOSE, 0);',
        'MACD': '    double macd = iMACD(Symbol(), Period(), 12, 26, 9, PRICE_CLOSE, MODE_MAIN, 0);',
        'ATR': '    double atr = iATR(Symbol(), Period(), 14, 0);',
        'Bollinger Bands': (
            '    double bbUpper = iBands(Symbol(), Period(), 20, 2, 0, PRICE_CLOSE, MODE_UPPER, 0);\n'
            '    double bbLower = iBands(Symbol(), Period(), 20, 2, 0, PRICE_CLOSE, MODE_LOWER, 0);'
        ),
        'Stochastic': '    double stoch = iStochastic(Symbol(), Period(), 5, 3, 3, MODE_SMA, 0, MODE_MAIN, 0);',
        'CCI': '    double cci = iCCI(Symbol(), Period(), 14, PRICE_TYPICAL, 0);',
        'ADX': '    double adx = iADX(Symbol(), Period(), 14, PRICE_CLOSE, MODE_MAIN, 0);',
    }
    for name in indicators_used:
        if name in calc_snippets:
            lines.append(f"    // {name} (detected)")
            lines.append(calc_snippets[name])

    if is_expert and analysis['has_trading_functions']:
        lines.append("")
        lines.append("    // Trading logic (pattern detected, review before use)")
        risk = analysis['risk']
        if risk['stop_loss']:
            lines.append("    double stopLoss = 50 * Point;")
        if risk['take_profit']:
            lines.append("    double takeProfit = 100 * Point;")
        lines.append("    if(OrdersTotal() < 1)")
        lines.append("    {")
        lines.append("        int ticket = OrderSend(Symbol(), OP_BUY, 0.1, Ask, 3, 0, 0, \"Auto Trade\", 0, 0, clrGreen);")
        lines.append("        if(ticket > 0) Print(\"Order opened: \", ticket);")
        lines.append("    }")

    lines.append("    return(0);")
    lines.append("}")

    return "\n".join(lines) + "\n"


def decompile_file(ex4_path: str) -> str:
    with open(ex4_path, 'rb') as f:
        data = f.read()
    analysis = analyze(data, os.path.basename(ex4_path))
    mq4_code = generate_mql4(analysis, os.path.basename(ex4_path))
    mq4_path = os.path.splitext(ex4_path)[0] + '.mq4'
    with open(mq4_path, 'w', encoding='utf-8') as f:
        f.write(mq4_code)
    return mq4_path


def main():
    parser = argparse.ArgumentParser(description="Decompile MT4 .ex4 files to approximate .mq4 source.")
    parser.add_argument('files', nargs='*', help="EX4 file(s) to decompile.")
    parser.add_argument('--dir', help="Decompile every .ex4 file found in this directory.")
    args = parser.parse_args()

    targets = list(args.files)
    if args.dir:
        targets.extend(
            os.path.join(args.dir, name)
            for name in sorted(os.listdir(args.dir))
            if name.lower().endswith('.ex4')
        )

    if not targets:
        parser.print_help()
        sys.exit(1)

    for ex4_path in targets:
        try:
            mq4_path = decompile_file(ex4_path)
            print(f"{ex4_path} -> {mq4_path}")
        except OSError as e:
            print(f"Error processing {ex4_path}: {e}", file=sys.stderr)


if __name__ == '__main__':
    main()
