#!/usr/bin/env sh

cargo build --release
sudo cp ../target/release/kromd /usr/local/bin/kromd
sudo cp krom.service /etc/systemd/system/krom.service
sudo mkdir /etc/krom
sudo cp config.json /etc/krom/config.json
sudo sqlite3 /etc/krom/proc_data.db < schema.sql
