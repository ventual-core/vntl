
Debian
====================
This directory contains files used to package ventuald/ventual-qt
for Debian-based Linux systems. If you compile ventuald/ventual-qt yourself, there are some useful files here.

## ventual: URI support ##


ventual-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install ventual-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your ventualqt binary to `/usr/bin`
and the `../../share/pixmaps/ventual128.png` to `/usr/share/pixmaps`

ventual-qt.protocol (KDE)

