# log

A tiny custom logger, distinct from the standard library's `log` package (which several handlers also import directly, sometimes in the same file under an alias). `logging.go`'s `Log(format string, v ...any)` marshals the format string to JSON and appends it as a line to `logging.json` in this directory. Note it currently only serializes the format string itself, not the variadic args — so it's closer to a fixed-message line logger than a real `fmt.Sprintf`-style logger today.

## Byte Thoughts:

### Notes from Cloud Team
some notes 

### Notes from Backend Team
more notes

### Notes from Dev Ops
technical thinking thoughts be bussin
```
