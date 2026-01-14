# floofbox
a dropbox like flask script for a linux based nas

# python
### if python --version prints anything
### skip this step and if any issues occur install the latest python
### this script was tested with python 3.10
### to install python
```bash
sudo apt update && sudo apt install python3 python3-pip python3-venv
```
replace apt with your package manager common ones are: pacman and dnf how ever the syntax changes slightly depending on what you use but apt is standard on debian based OSes eg raspberrypi os or ubuntu
# to run
### (assuming python and git are installed)
to test if both are installed you can run
```bash
git --version && python3 --version
```
if that prints two versions along the lines of
```
git version 2.34.1
Python 3.10.12
```
then continue below if not then install python (see above) or intall git (see below)
```bash
sudo apt install git
```
once all that is out of the way clone the repo
```bash
git clone https://github.com/shadowdragonns/floofbox.git
```
```bash
cd floofbox
```
### and then
```bash
python3 -m venv .venv
```

```bash
source .venv/bin/activate
```

```bash
pip install -r requirments.txt
```

```bash
python setup.py
```
### or

```bash
python3 setup.py
```
this script sets up the config and after will tell you to run either 
```bash
python app.py
```
or 
```
sudo /full/path/to/python install_service.py
```
the script will give a copy pasteable command with the full path in it if you choose to install it as a systemd service 
# setting it up with tailscale
```bash
curl -fsSL https://tailscale.com/install.sh | sh
```
if you dont want to pipe output into sh
you can probably do something along the lines of
```bash
curl -fsSL https://tailscale.com/install.sh > install.sh
```
allow execution
```bash
chmod +x install.sh
```
```bash
./install.sh
```
for more help see [here](https://tailscale.com/kb/1017/install) 


after tailscale is installed you can run 
```bash
sudo tailscale up
```
or follow the guide above (recomended as im not really to great with the tailscale cli

# once you have a working tailnet
on the nas run
```bash
sudo tailscale funnel 32000
```
replace 32000 with what ever port you choose in setup.py or if you are useing a proxy like nginx set it to that port instead 
if you would like it to run in the background run 
```bash
sudo tailscale funnel --bg 32000
```


