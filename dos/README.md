# DOS resident server

`DOSSRV.EXE` is a small real-mode helper that keeps the serial link busy with
filesystem replies for the Linux host.

## Building (Open Watcom)

```
wmake
```

The default makefile expects the Open Watcom `wcl` front-end to be in `PATH`.
The executable lands in `build/DOSSRV.EXE`.

## Running

1. Copy `DOSSRV.EXE` to the DOS machine.
2. Connect COM1 to the Linux host (115200 8N1, no flow control).
3. Run `DOSSRV` from `AUTOEXEC.BAT` or manually; leave it running while the
   filesystem is mounted on the host.
4. Press `Ctrl+Break` to stop the server if needed.

`DOSSRV.EXE` accepts two optional switches to match your hardware:

* `-C COMx` – pick `COM1`-`COM4` (defaults to `COM1` / 0x3F8).
* `-B baud` – override the serial speed (defaults to `115200`).

You can also stick the value right after the flag (`-B57600`, `-CCOM2`) if you
prefer DOS-style concatenated switches.

Once active the program waits for framed commands and serves directory listings,
stat information, file reads/writes, truncation, and directory/file maintenance
requests (mkdir, rmdir, delete) from the host.
