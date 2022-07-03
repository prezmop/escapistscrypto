# escapistscrypto
a simple program allowing for encryption and decryption of files form "The Escapists"

## Dependencies
* Python 3.4+
* python-blowfish <https://pypi.org/project/blowfish/>

## Usage examples


### Encrypt/decrypt
Files can be decrypted by running the program like shown below
```sh
$ escapistscrypto.py dec tiles_perks.gif
$ escapistscrypto.py dec tiles_perks.gif -o custom_name.gif
$ escapistscrypto.py dec tiles_perks.gif -n #use this to keep null bytes at the end of a decrypted file
```
Similarly, they can be encrypted
```
$ escapistscrypto.py enc tiles_perks.gif
$ escapistscrypto.py enc tiles_perks.gif -o custom_name.gif
```

### Validate
In order to validate custom data/items/speech files, first lay the files out like this:
```
somedir
├─custom_files
│ ├─data_eng.dat
│ ├─items_eng.dat
│ └─speech_eng.dat
└─original_val.dat
```
You can include any combination of data/items/speech files from any languages supported by the game.

After that run the program like this
```
$ escapistscrypto.py val custom_files original_val.dat
```
A modified val.dat file will be created in the custom_files directory. This will make the game work properly with the modified files.
