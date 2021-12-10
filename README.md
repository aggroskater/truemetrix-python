True Metrix Linux Drivers in Python
===================================

This package is strictly for exposing an API for interacting with the True
Metrix Blood Glucose Monitor (in combination with the USB docking station). It
is meant to in turn be used by other software --such as a GUI or TUI or CLI--
in order to work with the data from the monitor.

The underlying efforts that went into reverse engineering the USB protocol used
by the device can be found in reversing/. Future devices and future reversing
efforts can be kept there as well.

The `dev-requirements.txt` file includes various packages that were useful
during the reversing of the USB protocol for the device. They are not needed
for actually interacting with it though. Only the packages listed in the
"production" `requirements.txt` file are necessary for this package to do its
job of talking to the device.

LICENSE
=======

This project is licensed under the GPLv3 or later, SPDX designations:

GNU General Public License v3.0 or later
GPL-3.0-or-later

