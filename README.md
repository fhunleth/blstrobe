# blstrobe
[![Build Status](https://travis-ci.org/fhunleth/blstrobe.svg)](https://travis-ci.org/fhunleth/blstrobe)

This utility is used to configure the backlight strobe setting on BENQ Z-Series
monitors with the V2 firmware. It's similar in purpose to the awesome [Blur Busters Strobe
Utility](http://www.blurbusters.com/benq/strobe-utility/), but it works on Linux
from the command line. If you don't know why you'd want such a program, take a
look at the [Blur Busters](http://www.blurbusters.com/) website for all of the
information that you could possibly want on this topic.

NOTE: I only have an XL2420Z monitor so monitor detection is limited. Use
the -f flag for now and let me know your monitor's manufacture/product ID. If
you are having trouble with inconsistent results, try the `-r` option and let me
know your setup and what value works for you.

# Building

Download, compile and install the source code by running the following:

    git clone https://github.com/fhunleth/blstrobe.git
    cd blstrobe

    # On Debian/Ubuntu, you may need to run "sudo apt-get install autoconf"

    ./autogen.sh
    ./configure
    make
    sudo make install

# Invoking

Before you run `blstrobe`, you'll need to make sure that the `i2c-dev` kernel
module has been loaded. This program uses that kernel module to communicate with the
monitor. To load,

    sudo modprobe i2c-dev

If you have an AMD graphics card, you may also need to load the radeonfb module.

    sudo modprobe radeonfb

Now that the kernel modules have been loaded, you can use the blstrobe utility. To turn
backlight strobing on with a flash duration of 2 ms on all connected monitors,
run the following (the time is specified in microseconds):

    sudo blstrobe -e -t 2000

You can also get the current settings by running:

    sudo blstrobe -g

The following is the list of options:

    -d disable backlight strobe overrides
    -e enable backlight strobe overrides
    -f force operation on unsupported display
    -g get the current settings
    -o <path> set path to i2c device (e.g., /dev/i2c-0)
    -p <phase> backlight strobe phase (0-47)
    -r <retry count> increase if you're getting flakey results (default 20)
    -t <duration in us> backlight strobe time in microseconds (167-5000)
    -v verbose

# Raspberry Pi

By default, the Raspberry Pi doesn't expose the HDMI port's DDC lines via the
Linux I2C drivers. The kernel can be patched to fix this. Instructions are at
[koalo's blog](http://blog.koalo.de/2013/11/i2c-over-hdmi.html).

# Contributing

Please feel free to fork the project and send me a pull request with any
updates. I only have one compatible monitor, but will gladly integrate changes
to make this more useful to the other Linux users out there.
