# Linux host

`dosmnt` is a small FUSE filesystem that speaks the same serial protocol as
the DOS resident server. Once connected it presents the remote FAT tree as a
mount point on the Linux machine, allowing you to read from and write to the
DOS volume over a single serial cable. Common POSIX operations—`mkdir`, `rmdir`,
`unlink`, `truncate`, and plain file reads/writes—are forwarded over the link.

## Dependencies

* `cmake`
* `pkg-config`
* `libfuse3` development headers

## Build

```
cmake -S . -B build
cmake --build build
```

## Usage

```
sudo build/dosmnt \
  --device /dev/ttyUSB0 \
  --mount /mnt/dos \
  --baud 115200 \
  --drive C
```

* `--device` – serial TTY connected to the DOS box
* `--mount` – target directory on the Linux machine (must exist)
* `--baud` – serial baud rate (default `115200`)
* `--drive` – optional DOS drive letter to pin requests to

The filesystem stays in the foreground (FUSE `-f`). Unmount with
`fusermount3 -u /mnt/dos` when done.
