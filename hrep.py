#!/usr/bin/env python
from __future__ import print_function
import io
import os
import re
import sys
import argparse
import binascii

BUFSIZE = 4*1024*1024
TAILSIZE = BUFSIZE
HEXDIGITS = "0123456789abcdef"

try:
    range = xrange
except NameError:
    pass

def hex_pattern(expr):
    m = re.match(br"^\s*((?:[0-9a-f?]{2}|\*|\s*)*)\s*$", expr, re.I)
    if m:
        # parse hex pattern
        groups = re.findall(br"([0-9a-f?]{2}|\*)", m.group(1), re.I)
        pat = []
        for b in groups:
            if b == "??":
                pat.append(b'.')
            elif b == "*":
                pat.append(b".*?")
            elif '?' in b:
                pat.append(b"[%s]" % "".join(br"\x%s" % b.replace('?', i).lower() for i in HEXDIGITS))
            else:
                pat.append(br"\x%s" % b.lower())
        return re.compile(b''.join(pat), re.S)
    else:
        raise ValueError("Invalid hex pattern: `%s'" % expr)

def verbatim_pattern(expr):
    return re.compile(b''.join(br"\x%02x" % b for b in bytearray(expr)))

def fblocks(fobj, start=0, length=None, chunksize=BUFSIZE, tailsize=None):
    if tailsize is None:
        tailsize = chunksize
    assert tailsize <= chunksize

    buf = bytearray(chunksize + tailsize)
    head = memoryview(buf)[tailsize:]
    tail = memoryview(buf)[:tailsize]
    total = 0

    while length is None or total < length:
        if total == 0:
            tailsize = fobj.readinto(tail)
        read = fobj.readinto(head)

        if read < chunksize:
            yield total + start, buf[:tailsize + read]
            break
        else:
            yield total + start, buf

        tail[:] = head[-tailsize:]
        total += read


def findall(haystack, needle):
    i = -1
    while True:
        i = haystack.find(needle, i + 1)
        if i == -1:
            break
        yield i

def multisearch(block, patterns):
    for i, p in enumerate(patterns):
        for m in p.finditer(block):
            yield m

def open_files(filenames):
    if len(filenames) == 0:
        yield io.open(sys.stdin.fileno(), "rb", buffering=0)
        return

    for fn in filenames:
        try:
            yield io.open(fn, "rb", buffering=0)
        except IOError as e:
            print("Error opening file: `%s`: %s" % (e.filename, e.strerror), file=sys.stderr)

class HexDumper(object):
    translate_tbl = bytearray([i if 32 <= i < 127 else ord('.') for i in range(256)])

    def __init__(self, width, align, before, after, mark, unmark):
        self.width = width
        self.align = align
        self.mark = mark
        self.unmark = unmark
        self.before = before
        self.after = after

    def hexdump(self, data, offset, start, end):
        lines = []
        marking = False
        width = self.width

        dstart = (start // self.align) * self.align - self.before * width
        dend = ((end + self.align - 1) // self.align) * self.align + self.after * width
        dstart = max(0, dstart)

        for i in range(dstart, dend, width):
            bs = ['{:02x}'.format(x) for x in bytearray(data[i:i + width])] + ['  '] * width
            bs = bs[:width]
            ss = list((data[i:i+width]).translate(self.translate_tbl).decode('ascii')) + [' '] * width
            ss = ss[:width]
            addr_mark = ''
            if i + width > start and i < end:
                mark_end = min(end - i, width)
                if mark_end < width:
                    bs[mark_end] = self.unmark + bs[mark_end]
                    ss[mark_end] = self.unmark + ss[mark_end]

                mark_start = max(start - i, 0)
                bs[mark_start] = self.mark + bs[mark_start]
                ss[mark_start] = self.mark + ss[mark_start]
                addr_mark = self.mark


            dump = ' '.join(''.join(bs[j:j+2]) for j in range(0, width, 2))
            ascii = ''.join(ss)
            addr = offset + i
            line_fmt = "{addr_mark}0x{addr:06x}{self.unmark}| {dump} {self.unmark}|{ascii}{self.unmark}|"
            lines.append(line_fmt.format(**locals()))
        return '\n'.join(lines)

def print_match(filename, block, offset, match, decimal):
    match_hex = binascii.hexlify(block[match.start():match.end()]).decode('ascii')
    start = offset + match.start()
    if decimal:
        print("{}:{}:{}".format(filename, start, match_hex))
    else:
        print("{}:0x{:x}:{}".format(filename, start, match_hex))

def main():
    ap = argparse.ArgumentParser("hrep", 
        description="Search for binary sequences in files",
        epilog="Each output line corresponds to a match in the format:\n\
        <filename>:<offset>:<match>")
    ap.add_argument("-x", "--hex", dest="hex", action="append", default=[],
        help="Search for a hexadecimal pattern"
             "('?' matches a single nibble, '*' matches any number of bytes)")
    ap.add_argument("-a", "--ascii", dest="ascii", action="append", default=[],
        help="Search for an ASCII string")
    ap.add_argument("-e", "--regex", dest="regex", action="append", default=[],
        help="Search for a regular expression")

    ap.add_argument("--chunk-size",  default=BUFSIZE,
        help="Override default buffer size")
    ap.add_argument("-d", "--decimal-offset", action="store_true",
        help="Output decimal file offsets (by default prints hex)")
    ap.add_argument("-X", "--no-hexdump", action="store_true",
        help="Disable hex dump")
    ap.add_argument("-C", "--no-colors", action="store_true",
        help="Don't use colors in dump output")
    ap.add_argument("-w", "--dump-width", type=int, default=16,
        help="Width of hex dump")
    ap.add_argument("-s", "--summary", action="store_true",
        help="Print summary at the end")
    ap.add_argument("-A", "--after", type=int, default=0,
        help="Number of additional dump lines to display after match")
    ap.add_argument("-B", "--before", type=int, default=0,
        help="Number of additional dump lines to display before match")

    ap.add_argument("--debug", action="store_true", help=argparse.SUPPRESS)

    ap.add_argument(dest="hex_a", metavar="HEX", 
        nargs="?", help="Hex encoded binary sequence to search for")
    ap.add_argument(dest="filename", nargs="*",
        help="List of files to search in")
    args = ap.parse_args()

    if args.hex or args.ascii or args.regex:
        if args.hex_a is not None:
            args.filename.insert(0, args.hex_a)
    else:
        if args.hex_a is not None:
            args.hex.append(args.hex_a)
        else:
            ap.error("No pattern specified")

    if args.no_colors or os.name == 'nt':
        mark = unmark = ""
    else:
        mark = "\033[31;1m"
        unmark = "\033[0m"
    try:
        patterns = [hex_pattern(x) for x in args.hex] + \
                   [verbatim_pattern(x.encode("ascii")) for x in args.ascii] + \
                   [re.compile(x.encode("ascii")) for x in args.regex]
    except ValueError as e:
        ap.error(str(e))
    if args.debug:
        for p in patterns:
            print(p.pattern)
    files = open_files(args.filename)
    matches = 0
    matched_files = set()

    dumper = HexDumper(args.dump_width, args.dump_width, args.before, args.after, mark, unmark)

    for f in files:
        fname = f.name
        if fname == 0:
            fname = '<stdin>'
        for offset, block in fblocks(f, chunksize=args.chunk_size, tailsize=args.chunk_size):
            for m in sorted(multisearch(block, patterns), key=lambda m: m.start()):
                if args.debug:
                    print('match {} at {}'.format(m, offset))

                if m.end() > args.chunk_size:
                    # Already matched this one (in the tail)
                    continue
                matches += 1
                matched_files.add(f)
                print_match(fname, block, offset, m, args.decimal_offset)

                if not args.no_hexdump:
                    print(dumper.hexdump(block, offset, m.start(), m.end()), file=sys.stderr)
                    print(file=sys.stderr)

    if args.summary:
        print("{} match(es) accross {} file(s)".format(matches, len(matched_files)),
            file=sys.stderr)
    return 0 if matches > 0 else 1




if __name__ == '__main__':
    sys.exit(main())
