# hrep

`grep` for binary files.

## Usage

```
usage: hrep [-h] [-x HEX] [-a ASCII] [-e REGEX] [--chunk-size CHUNK_SIZE] [-d]
            [-X] [-C] [-w DUMP_WIDTH] [-s] [-A AFTER] [-B BEFORE]
            [HEX] [filename [filename ...]]

Search for binary sequences in files

positional arguments:
  HEX                   Hex encoded binary sequence to search for
  filename              List of files to search in

optional arguments:
  -h, --help            show this help message and exit
  -x HEX, --hex HEX     Search for a hexadecimal pattern('?' matches a single
                        nibble, '*' matches any number of bytes)
  -a ASCII, --ascii ASCII
                        Search for an ASCII string
  -e REGEX, --regex REGEX
                        Search for a regular expression
  --chunk-size CHUNK_SIZE
                        Override default buffer size
  -d, --decimal-offset  Output decimal file offsets (by default prints hex)
  -X, --no-hexdump      Disable hex dump
  -C, --no-colors       Don't use colors in dump output
  -w DUMP_WIDTH, --dump-width DUMP_WIDTH
                        Width of hex dump
  -s, --summary         Print summary at the end
  -A AFTER, --after AFTER
                        Number of additional dump lines to display after match
  -B BEFORE, --before BEFORE
                        Number of additional dump lines to display before
                        match

Each output line corresponds to a match in the format:
<filename>:<offset>:<match>
```
