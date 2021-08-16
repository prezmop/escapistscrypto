#! /usr/bin/env python3

from pathlib import Path
import argparse
import blowfish

def decrypt(ifile, ofile, key = b"mothking"):
	#read file
	ifile.seek(0,0)
	ciphertext = ifile.read()

	#decrypt
	cipher = blowfish.Cipher(key, byte_order = "little")
	plaintext = b"".join(cipher.decrypt_ecb(ciphertext))

	#save the decrypted version
	ofile.write(plaintext)

def encrypt(ifile, ofile, key = b"mothking"):
	#pad with \0 to a size multiple of 8 bytes
	ifile.seek(0,2)
	size = ifile.tell()
	ifile.seek(0,0)

	plaintext = ifile.read() + bytes((8 - size) % 8)

	#encrypt
	cipher = blowfish.Cipher(key, byte_order = "little")
	ciphertext = b"".join(cipher.encrypt_ecb(plaintext))

	#save the encrypted version
	ofile.write(ciphertext)

def cli():
	parser = argparse.ArgumentParser(description="Decrypt or encrypt escapists files")

	mode = parser.add_mutually_exclusive_group(required=True)
	mode.add_argument("-D", "--decrypt", help="decrypt file", action='store_true')
	mode.add_argument("-E", "--encrypt", help="encrypt file", action='store_true')

	parser.add_argument("-i", "--input", help="specify input file", required=True)
	parser.add_argument("-o", "--output", help="specify output file")
	parser.add_argument("-f", "--force", help="force, will overwrite any existing output file", action='store_true')

	args = parser.parse_args()

	ipath = Path(args.input)


	if args.output:
		ofile = args.output
	else:
		#add _decr to file name
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
		decrypt(ifile,ofile)
	elif args.encrypt:
		encrypt(ifile,ofile)
	else:
		#how did we get here?
		raise RuntimeError()

if __name__ == "__main__":
	cli()
	