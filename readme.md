this program aims to not be 100x security, but rather a comfortable middle ground where passwords are not totally random

the main problem i have with totally random passwords for my entirely personal opinion is that i feel that they are no longer MY password. furthermore they are tied to whatever service i made them with. I wanted a password that was not completely random, which could be easily made and REMADE if you somehow lost that password. such as the site name + username + secret key
and that of course made me wanting to make this. every password generated is a hash of the site name, username, and a secret key, which acts as your master password, dont lose this! the master password could be literally anything, the master password is stored encrypted on disk, and is unlocked by a smaller password. this makes storing your passwords in a git repo totally fine. your pin is really all you need to remember, you can get clever hiding it, but its just one password for all your passwords! in an extremely literal sense. 

the great thing about this system is that the password never has to be stored on disk. but can be recomputed every time it is requested. which should be pretty quick. the resulting password can be stored in password managers as normal, but this program acts as a source of truth to generating unique passwords that are still made by you. of course making them deterministic and reproducible makes them less secure than totally random passwords, but unless youre being targeted by the government you'll be fine.

if you ARE being targeted by the government, i would advise using a different password management solution.

<!--# Disk State
data is stored at `~/.local/state/haprocrates/` and contains a `vault` file, and a `secrets/` directory.-->

<!--and all passwords will start with `$HPCT$-` when successfully -->
<!--passwords arent decrypted, they are computed. so this shouldnt be necessary-->

<!--# Usage-->

# Installation
## Nix
```nix
nix shell github:nimrodium/haprocrates
```
## Cargo
```bash
cargo install --git https://github.com/nimrodium/haprocrates
```

# Usage
Haprocrates is used to manage passwords, it has a command line interface.
the pin to decrypt the disk is cached for a default of 15 minutes. 
to aid in reproduciblity, all input from the user is normalized, this means that `https://` is removed, case is lowercased, and any spaces are replaced by dashes.

## Getting Started
getting started with Haprocrates is very simple, just generate your master key, you will be prompted to create a password to encrypt the key. 
```bash
haprocrates generate-master-key --key IDENTIFIER
```
using the `--key` flag will use a custom identifier, else, an old man name will be randomly chosen. he is your key now!
if you have multiple master keys, `--key` on other commands will specify which key file to use.

now you can use haprocrates! unlike a traditional password manager haprocrates doesn't need a vault to operate, only your mind and a huge secret, so instead of the main command be called get, it is called `derive`. This is because it is being computed, not read. 

```bash
haprocrates derive -s google.com -u nimrodium@example.com
```

However if you would like a vault, which can be used for caching results and storing inputs, you can optionally you can enable the vault, this makes haprocrates not so state-less, and more like a regular password manager. 
```bash
haprocrates allow-disk-state
```
to disable disk state use `disable-disk-state`, this will permenantly delete the vault. there is interactive confirmation and you are required to type the password. however the vault file can always be deleted on disk without these safety checks.

with the vault enabled, you have a few more commands, such as `delete` and `list`. you can always show the full decrypted file (TOML format) by using the `show` command.
# Features
Haprocrates allows for creating local state other than the master key, this makes the details of the passwords exposed in the vault when decrypted, but allows haprocrates to be used as a standard password manager, it also allows for declarative statements of your password such as adding constraints. 
# Command line syntax
```bash
haprocrates derive -s twitter -u nimrodium@example.com
haprocrates constraint-add -s twitter -u nimrodium@example.com max-length 50
haprocrates constraint-add -s twitter -u nimrodium@example.com iterate
haprocrates iterate -s twitter -u nimrodium@example.com
haprocrates export -s twitter -u nimrodium@example.com
haprocrates generate-master -p password123
haprocrates share qr -s twitter -u nimrodium@example.com
```
## Commands
- **derive**
derive the password from its inputs and the master key.
- **export**
exports a text file containing the username, site name, and password.
- **share**
distribute a password via either `qr` or `http` methods.
- **share qr**
generate a qr code and present it so that a camera can scan it and obtain the password
- **share http**
slightly less secure, spin up a basic static site which one can connect to locally and copy the password.
- **generate-master**
generates the master key which is used to make passwords unique.
- **show**
decrypts and opens vault for viewing 
- **allow-disk-state**, **create-vault**
creates the vault file, if this file does not exist or does exist but is not valid, it will not write to it, if 
## Flags
- **-s**, **--site**
site name
- **-u**, **--username**, **-e**, **--email**
username/email used
- **-i N**, **--iteration N**
number of iterations to apply to the password. this is meant for if the password was exposed in a databreach or needs to be changed, it applies a transformation to the inputs n times before computing the hash.
- **-p**, **--password**
set the password used to decrypt the master key.
- **-db**, **--database**
disk state database.
- **--no-vault**
disable attempting to open the vault
- **--no-agent**
prevent the authentication agent from being used or spawning.

## Environment variables
- HAPROCRATES_PASSWORD
password used to decrypt disk state
- HAPROCRATES_PASSWORD_FILE
path to file containing password used to decrypt disk state
- HAPROCRATES_DATABASE
path to disk state, will override default of `~/.local/state/haprocrates/`
- HAPROCRATES_AUTH_TIMEOUT
time in minutes before the authentication agent dies. default is 15 minutes. setting to 0 disables the authentication agent.

# Implementation Notes
Haprocrates uses the Argon2 hashing function to compute password hashes and generates keys used to encrypt / decrypt disk files.
