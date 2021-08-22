#! /usr/bin/env python3

# escapistscrypto
# Copyright © 2021 Przemysław Piasecki
# check the end of this file for license information

from pathlib import Path
from hashlib import md5
from configparser import ConfigParser
import argparse
import blowfish

def decrypt(ifile, ofile, strip_null = True, key = b"mothking"):
	ifile.seek(0,0)
	ciphertext = ifile.read()

	cipher = blowfish.Cipher(key, byte_order = "little")
	plaintext = b"".join(cipher.decrypt_ecb(ciphertext))

	if strip_null:
		plaintext = plaintext.rstrip(b"\0")

	ofile.write(plaintext)

def encrypt(ifile, ofile, key = b"mothking"):
	#pad with \0 to a size multiple of 8 bytes
	ifile.seek(0,2)
	size = ifile.tell()
	ifile.seek(0,0)

	plaintext = ifile.read() + bytes((8 - size) % 8)

	cipher = blowfish.Cipher(key, byte_order = "little")
	ciphertext = b"".join(cipher.encrypt_ecb(plaintext))

	ofile.write(ciphertext)

def hash(path):
	hashString = "l0l_" + str(path.stat().st_size)
	return md5(hashString.encode("UTF8")).hexdigest()

def create_config_parser(file):
	#data files contain unmarked comments before the first section
	#that need to be skipped before passing it to a ConfigParser object
	while True:
		pos = file.tell()
		line = file.readline()
		if not line:
			raise EOFError("The file doesn't appear to be valid")
		line = line.lstrip()
		if line and line[0] == "[":
			break
	file.seek(pos)

	parser = ConfigParser()
	parser.read_file(file)

	return parser

def make_valid(orig_val_file, validate_dir):
	if not validate_dir.is_dir():
		raise NotADirectoryError

	languages = ["eng","fre","ger","spa","rus","pol","ita"]
	files = ["data","items","speech"]
	hashlookup = {"data":0,"items":1,"speech":2}

	hashes = create_config_parser(orig_val_file)

	for lang in languages:
		langhashes = hashes["Val"][lang[0]].split("_")

		for file in files:
			filepath = validate_dir.joinpath(file + "_" + lang + ".dat")
			if filepath.is_file():
				langhashes[hashlookup[file]] = hash(filepath)

		hashes["Val"][lang[0]] = "_".join(langhashes)

	with validate_dir.joinpath("val.dat").open("w",encoding="UTF-16") as file:
		hashes.write(file,space_around_delimiters=False)

def cli():
	parser = argparse.ArgumentParser(description="Decrypt or encrypt escapists files")

	mode = parser.add_mutually_exclusive_group(required=True)
	mode.add_argument("-D", "--decrypt", help="decrypt file", action='store_true')
	mode.add_argument("-E", "--encrypt", help="encrypt file", action='store_true')

	parser.add_argument("-i", "--input", help="specify input file", required=True)
	parser.add_argument("-o", "--output", help="specify output file")
	parser.add_argument("-f", "--force", help="force, will overwrite any existing output file", action='store_true')
	parser.add_argument("-n", "--keep-null", help="keep tailing null bytes in a decrypted file", action='store_true')

	args = parser.parse_args()

	ipath = Path(args.input)

	if args.output:
		ofile = args.output
	else:
		if args.decrypt:
			app = "_decr"
		elif args.encrypt:
			app = "_encr"
		else:
			#how did we get here?
			raise RuntimeError()

		opath = ipath.with_stem(ipath.stem + app)

	try:
		ifile = ipath.open("rb")
	except FileNotFoundError:
		errmsg = ipath.name + " doesn't exist"
		parser.error(errmsg)

	if args.force:
		ofile = opath.open("wb")
	else:
		try:
			ofile = opath.open("xb")
		except FileExistsError:
			errmsg = opath.name + " already exists! use -f to overwrite it"
			parser.error(errmsg)

	if args.decrypt:
		decrypt(ifile,ofile, not args.keep_null)
	elif args.encrypt:
		encrypt(ifile,ofile)
	else:
		#how did we get here?
		raise RuntimeError()

if __name__ == "__main__":
	cli()
	
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
