# hrep

`grep` for binary files.

## Usage

```
usage: hrep [-h] [-x HEX] [-a ASCII] [--chunk-size CHUNK_SIZE] [-d] [-X] [-n]
            [-w DUMP_WIDTH] [-s]
            [HEX] [filename [filename ...]]

Search for binary sequences in files

positional arguments:
  HEX                   Hex encoded binary sequence to search for
  filename              List of files to search in

optional arguments:
  -h, --help            show this help message and exit
  -x HEX, --hex HEX     Search for a binary string (hex-encoded)
  -a ASCII, --ascii ASCII
                        Search for an ASCII string
  --chunk-size CHUNK_SIZE
                        Override default chunk size
  -d, --decimal-offset  Output decimal file offsets (by default prints hex)
  -X, --no-hexdump      Disable hex dump
  -n, --no-colors       Don't use colors in dump output
  -w DUMP_WIDTH, --dump-width DUMP_WIDTH
                        Width of hex dump
  -s, --summary         Print summary at the end

Each output line corresponds to a match in the format:
<filename>:<offset>:<match>
```
