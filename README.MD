# usbhostfs
- This is a port of the `usbhostfs` [PSP plugin](https://github.com/tyranid/psplinkusb) to the PS Vita.
- It adds a `host0:` device to the system, allowing you to access your PC's hard drive from VitaShell.

- NOTE: This doesn't work well at all, most file ops will fail with the same error code, browsing directories seems to work fine though.
- Sometimes it works out of the blue, but more often than not it just doesn't work at all.

## Building
### Building the plugin
```
cd usbhostfs && mkdir build && cd build
cmake ..
make
```

### Building the client (Linux)
- NOTE: You'll need `libusb-dev` installed.
```
cd usbhostfs_pc && mkdir build && cd build
cmake ..
make
```

### Building the client (Windows, using Cygwin)
```
cd usbhostfs_pc
make BUILD_WIN32=1
```

## Installation
- Copy `usbhostfs.skprx` to `ur0:tai/`.
- Add the following line to `ur0:tai/config.txt`:
```
*KERNEL
ur0:tai/usbhostfs.skprx
```
- Reboot.

## Usage
- Connect the Vita using the USB cable to your PC.
- Windows: Install the `libusb-win32` driver using [Zadig](https://zadig.akeo.ie/).
- Run `usbhostfs_pc` on your PC.
- Open VitaShell and see if it `host0:` is available.
- NOTE: You may want to run the PC app and then connect the Vita, however, the Vita must be plugged in to install the driver with Zadig.

## Thanks
consolex-bordeaux.fr, ScHlAuChi, noname120, motoharu, xyz, yifanlu, frangarcj, Rinnegatamante, davee and people i may forget for what they do for the ps vita.
