
import argparse

a = "ILMxgTnvbzVtBiry3=X^KWQAG847oYdFZlR1NPe5j/mS0hODs.aU2qkCJ6H;wcu9fpE"
b = "^=/0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm;no.pqrstuvwxyz"

def decode_string(string_data):
	decoded_str=""
	for h in bytearray(string_data.decode("hex")):
		try:
			decoded_str+=str(b[a.index(chr(h^0xAA))])
		except:
			decoded_str+=chr(h^0xAA)

	return decoded_str


def decode_log_file(logfile):
	decoded = []
	decoded_all = ""
	data = file(logfile, "rb").read()
	ctr = 0
	for n in data.split():
		if ctr == 0:
			decoded_all += n + "\n"
			ctr+=1
			continue
		for g in n.split("."):
			if g not in ["tt1", "tt2", "notice"]:
				decoded.append(decode_string(g))
			else:
				decoded.append(g)
		
		decoded_all += ".".join(decoded) + "\n"

	return decoded_all



def cmdparse():
	usage = "\n%(prog)s <logfile>"
	parser = argparse.ArgumentParser(prog="framework_pos", usage=usage, description='Tool to decrypt Framework Point-of-Sale Log file.')
	parser.add_argument("targetfile", help="Log file of Framework Point-of-Sale malware.")

	return parser.parse_args()


if __name__ == "__main__":


	
	args = cmdparse()

	print(decode_log_file(args.targetfile))
