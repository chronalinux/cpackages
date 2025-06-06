#!/bin/sh
# Ağ yöneticisi ikonunu arkaplanda başlat
nm-applet &

# Ses kontrol ikonunu arkaplanda başlat
qasmixer --tray &

# Tint2 paneli için bekletme (gerekirse 2 saniyeyi artırabilirsiniz)
sleep 2

# Tint2 panelini arkaplanda başlat
tint2 &

sh ~/.config/cdesktop/cdesktop-wallpaper &

# SpaceFM masaüstü ortamını son olarak ve ön planda başlat
exec spacefm --desktop
