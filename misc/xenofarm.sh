#! /bin/sh

# Driver the xenofarm test compilation. Used together with
# lsh-server.pike, source-transform.sh and result-parser.pike in
# the lsh xenofarm project.

# Loosely based on the xenofarm.sh script in lyskom-server.

# Copyright 2002, 2003 Niels Möller, Lysator Academic Computer Association 
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

cfgargs=
makeargs=
while [ $# -gt 0 ]
do
  case "$1" in
      --cfg)    shift; cfgargs="$1"; shift;;
      --make)   shift; makeargs="$1"; shift;;
      *)        echo $0: unsupported argument $1 >&2; exit 1;;
  esac
done

rm -rf r
mkdir r
exec > r/shlog.txt 2>&1

BASE=`echo lsh-*.tar.gz | sed 's/.tar.gz$//'`
VERS=`echo "$BASE" | sed 's/^lsh-//'`

