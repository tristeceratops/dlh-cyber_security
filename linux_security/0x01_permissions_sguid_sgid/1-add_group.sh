#!/bin/bash
sudo addgroup $1
sudo chgrp $1 $2
chmod g+rx $2
