from __future__ import print_function
import io
import os
import sys
import argparse
import binascii

CHUNK_SIZE = 4*1024*1024

try:
    range = xrange
except NameError:
    pass

def fblocks(fobj, start=0, length=None, chunksize=CHUNK_SIZE, tailsize=None):
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
        for o in findall(block, p):
            yield o, i

def open_files(filenames):
    if len(filenames) == 0:
        yield io.open(sys.stdin.fileno(), "rb", buffering=0)
        return

    for fn in filenames:
        try:
            yield io.open(fn, "rb", buffering=0)
        except IOError as e:
            print("Error opening file: `%s`: %s" % (e.filename, e.strerror), file=sys.stderr)

translate_tbl = bytearray([i if 32 <= i < 127 else ord('.') for i in range(256)])
def marked_hexdump(data, offset, start, end, width, mark, unmark):
    lines = []
    marking = False
    for i in range(0, len(data), width):
        bs = ['{:02x}'.format(x) for x in bytearray(data[i:i + width])] + ['  '] * width
        bs = bs[:width]
        ss = list((data[i:i+width]).translate(translate_tbl).decode('ascii')) + [' '] * width
        ss = ss[:width]
        if i + width > start and i < end:
            mark_end = min(end - i, width)
            if mark_end < width:
                bs[mark_end] = unmark + bs[mark_end]
                ss[mark_end] = unmark + ss[mark_end]

            mark_start = max(start - i, 0)
            bs[mark_start] = mark + bs[mark_start]
            ss[mark_start] = mark + ss[mark_start]


        dump = ' '.join(''.join(bs[j:j+2]) for j in range(0, width, 2))
        ascii = ''.join(ss)
        addr = offset + i
        line_fmt = "0x{addr:06x}| {dump} {unmark}|{ascii}{unmark}|"
        lines.append(line_fmt.format(**locals()))
    return '\n'.join(lines)

def print_match(filename, block, offset, match, pattern, args):
    pathex = binascii.hexlify(pattern).decode("ascii")
    start = offset + match
    if args.decimal_offset:
        print("{}:{}:{}".format(filename, start, pathex))
    else:
        print("{}:0x{:x}:{}".format(filename, start, pathex))

    if not args.no_hexdump:
        patlen = len(pattern)
        dump_start = (match // args.dump_width) * args.dump_width
        dump_end = ((match + patlen) \
            // args.dump_width + 1) * args.dump_width
        data = block[dump_start:dump_end]
        match_start = match - dump_start
        match_end = match_start + patlen
        print(marked_hexdump(data, offset + dump_start, match_start, match_end, 
            args.dump_width, args.mark, args.unmark), file=sys.stderr)
        print(file=sys.stderr)


def main():
    ap = argparse.ArgumentParser("hrep", 
        description="Search for binary sequences in files",
        epilog="Each output line corresponds to a match in the format:\n\
        <filename>:<offset>:<match>")
    ap.add_argument("-x", "--hex", dest="hex", action="append", default=[],
        help="Search for a binary string (hex-encoded)")
    ap.add_argument("-a", "--ascii", dest="ascii", action="append", default=[],
        help="Search for an ASCII string")
    ap.add_argument("--chunk-size",  default=CHUNK_SIZE,
        help="Override default chunk size")

    ap.add_argument("-d", "--decimal-offset", action="store_true",
        help="Output decimal file offsets (by default prints hex)")
    ap.add_argument("-X", "--no-hexdump", action="store_true",
        help="Disable hex dump")
    ap.add_argument("-n", "--no-colors", action="store_true",
        help="Don't use colors in dump output")
    ap.add_argument("-w", "--dump-width", type=int, default=16,
        help="Width of hex dump")
    ap.add_argument("-s", "--summary", action="store_true",
        help="Print summary at the end")

    ap.add_argument(dest="hex_a", metavar="HEX", 
        nargs="?", help="Hex encoded binary sequence to search for")
    ap.add_argument(dest="filename", nargs="*",
        help="List of files to search in")
    args = ap.parse_args()

    if args.hex_a is not None:
        if len(args.hex) + len(args.ascii) > 0:
            args.filename.insert(0, args.hex_a)
        else:
            args.hex.append(args.hex_a)
    if len(args.hex) + len(args.ascii) == 0:
        ap.error("No pattern specified")

    if args.no_colors or os.name == 'nt':
        args.mark = args.unmark = ""
    else:
        args.mark = "\033[31;1m"
        args.unmark = "\033[0m"

    patterns = [bytes(bytearray.fromhex(x)) for x in args.hex] + \
               [x.encode("ascii") for x in args.ascii]
    files = open_files(args.filename)
    matches = 0
    matched_files = set()

    tailsize = min(args.chunk_size, min(len(x) for x in patterns))

    for f in files:
        fname = f.name
        if fname == 0:
            fname = '<stdin>'
        for offset, block in fblocks(f, chunksize=args.chunk_size, tailsize=tailsize):
            for match, i in sorted(multisearch(block, patterns)):
                if match + len(patterns[i]) < tailsize:
                    # Already matched this one
                    continue
                matches += 1
                matched_files.add(f)
                print_match(fname, block, offset, match, patterns[i], args)

    if args.summary:
        print("{} match(es) accross {} file(s)".format(matches, len(matched_files)),
            file=sys.stderr)
    return 0 if matches > 0 else 1




if __name__ == '__main__':
    sys.exit(main())