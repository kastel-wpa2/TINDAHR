# TINDAHR
**T**ool for **I**nteractive **D**eauth-**A**ttacks and **H**andshake **R**ecording

# Disclaimer: The code provided in this repository is solely meant for academic research. Use it only in networks that are governed by you or you are elligible to operate in those. Usage against third party might be punishable by law and is in no way encouraged by the authors of this code!

# Requirements
Your systems needs to have the `aircrack-ng`-suite installed and there should be a wireless device available that is capable of switching to monitor mode. Developed and tested with decent version of `Kali Linux`.

Install the needed dependencies with pip: `pip install -r requirements.txt`. You might do this in a `virtual-env`.

# How to use `TINDAHR`
Just run `./tindahr.py` or `./tindahr.py -h` to get information on the flag and options available. No need to run `airmon-ng check kill && airmon-ng start wlan0` first, `TINDAHR` will try to do this for you. After this navigate your webbrowser (should support websockets, in Kali use Firefox ESR) to `localhost:1337`. The rest is pretty much self-explaining. Please respect other people and their digital infrastructure. Never use this against networks you are not permitted to attack!

# What else is in this repository?
There are some scripts for analyzing SSID broadcasting, detection probe requests and responses etcetera in the `analyzr_scripts` directory.

# Known problems
Currently the implementation used for channel hopping is pretty basic and causes to also switch channels while sending deauthenticaion frames - which might result in not properly submitted packets and/or a missed handshake (because we also capture on the wrong channel in this case). Current workaround: run with `-c` flag in order to specify the channel and disable channel hopping.