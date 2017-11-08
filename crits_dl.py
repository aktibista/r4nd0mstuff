#!/usr/bin/env python


import requests
import argparse
import os
from io import BytesIO
import sys

# CRITs CONFIG
_HOST = 'http://<IP_ADDRESS>'
_USERNAME = 'web'
_API_KEY = '<API_KEY>'
_SAMPLES_API = 'api/v1/samples/'


def get_binary_from_url(urlpath, params):
	ret = None
	try:
		response = requests.get(urlpath, params, verify=True, proxies=None)
		ret = BytesIO(response.content)
	except Exception, e:
		print("ERROR: %s." % str(e))

	finally:
		return ret


def parse_cmd():
	usage = '\n%(prog)s --hash <MD5_OR_SHA2_HASH_HERE>'
	usage += '\n%(prog)s --hash --save-dir <DOWNLOAD_DIR>'
	parser = argparse.ArgumentParser(prog="crits_dl", usage=usage, description='Tool for downloading samples from CRITs.')
	parser.add_argument('--hash', dest='t_hash', required=True, help='MD5 or SHA256 Hash of the file that will be downloaded.')
	parser.add_argument('--save-dir', dest='save_dir', default=os.getcwd(), help='Directory where the file will be saved.')

	return parser.parse_args()


if __name__ == "__main__":
	args = parse_cmd()
	params = {'username': _USERNAME, 'api_key': _API_KEY, 'file': 1}
	# Check the Hash
	if len(args.t_hash) == 32:
		params['c-md5'] = args.t_hash.lower()
	elif len(args.t_hash) == 64:
		params['c-sha256'] = args.t_hash.lower()
	else:
		print("ERROR: %s is NOT valid." % args.t_hash)
		exit()

	# Check the Directory
	if args.save_dir is not None:
		# Check if Directory exist
		if not os.path.isdir(os.path.abspath(args.save_dir)):
			print("ERROR: %s in NOT a valid directory." % args.save_dir)
			exit()

	# Construct the RESTful API for samples
	samples_rest_api = _HOST + '/' + _SAMPLES_API

	# Connect to CRITs
	sys.stdout.write('[*] Downloading %s....' % args.t_hash)
	bin = get_binary_from_url(samples_rest_api, params)

	# Save Binary to file
	if bin is not None:
		file(os.path.join(args.save_dir, args.t_hash + '.zip'), 'wb').write(bin.read())
		sys.stdout.write('Done.\n')

	else:
		sys.stdout.write('ERROR.\n')

	sys.stdout.flush()

