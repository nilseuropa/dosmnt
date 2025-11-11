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

Once active the program waits for framed commands and serves directory listings,
stat information, and file reads. It never modifies the DOS filesystem.
