import sys
import binascii
import pefile
import struct
import hashlib
from Crypto.Cipher import AES
import xml.etree.ElementTree as ET

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[:-ord(s[len(s)-1:])]

def hash_rounds(data_buf):
    while len(data_buf) <= 0x1000:
        buf_hash = hashlib.sha256(data_buf).digest()
        data_buf += buf_hash
    return buf_hash

def aes_decrypt(data):
    key = hash_rounds(data[:0x20])[:0x20]
    iv = hash_rounds(data[0x10:0x30])[:0x10]
    aes = AES.new(key, AES.MODE_CBC, iv)
    data = pad(data[0x30:])
    return aes.decrypt(data)


def derive_key(n_rounds, input_bf):
	intermediate = input_bf
	for i in range(0, n_rounds):
		sha = hashlib.sha256()
		sha.update(intermediate)
		current = sha.digest()
		intermediate += current
	return current


# expects a str of binary data open().read()
def trick_decrypt(data):
	key = derive_key(128, data[:32])
	iv = derive_key(128, data[16:48])[:16]
	aes = AES.new(key, AES.MODE_CBC, iv)
	mod = len(data[48:]) % 16
	if mod != 0:
		data += '0' * (16 - mod)
	return aes.decrypt(data[48:])[:-(16 - mod)]


def get_rsrc(pe):
	ret = []
	for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
		if resource_type.name is not None:
			name = str(resource_type.name)
		else:
			name = str(pefile.RESOURCE_TYPE.get(resource_type.struct.Id))
		if name == None:
			name = str(resource_type.struct.name)
		if hasattr(resource_type, 'directory'):
			for resource_id in resource_type.directory.entries:
				if hasattr(resource_id, 'directory'):
					for resource_lang in resource_id.directory.entries:
						data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
						ret.append((name, data, resource_lang.data.struct.Size, resource_type))
	return ret


def decode_onboard_config(data):
	pe = pefile.PE(data=data)
	rsrcs = get_rsrc(pe)

	a = rsrcs[0][1]

	data = trick_decrypt(a[4:])
	length = struct.unpack_from('<I', data)[0]
	return data[8:length + 8]


# def config(data):
# 	xml = decode_onboard_config(f)
# 	root = ET.fromstring(xml)
# 	raw_config = {}
# 	for child in root:
#
# 		if hasattr(child, 'key'):
# 			tag = child.attrib["key"]
# 		else:
# 			tag = child.tag
#
# 		if tag == 'autorun':
# 			val = str(map(lambda x: x.items(), child.getchildren()))
# 		elif tag == 'servs':
# 			val = ','.join(map(lambda x: x.text, child.getchildren()))
# 		else:
# 			val = child.text
#
# 		raw_config[tag] = val
#
# 	return raw_config


if __name__ == "__main__":
	print("Hello")

	# with open('C:\\_vmshare\\hello\\necurs_spam\\realnatalaga.exe.1', 'rb') as f:
	# 	tbot = f.read()
	#
	# tbot_config = decode_onboard_config(tbot)
	# print(tbot_config)

	# with open('C:\\_vmshare\\hello\\necurs_spam\\config.conf', 'rb') as f:
	# 	config_conf = f.read()
	# conf = trick_decrypt(config_conf)
	# file('C:\\_vmshare\\hello\\necurs_spam\\config.dmp', 'wb').write(conf)

	# with open('C:\\_vmshare\\hello\\necurs_spam\\Modules\\injectDll32_configs\\dinj', 'rb') as f:
	# 	config_conf = f.read()
	# conf = trick_decrypt(config_conf)
	# file('C:\\_vmshare\\hello\\necurs_spam\\Modules\\injectDll32_configs\\dinj.dmp', 'wb').write(conf)
	#
	# with open('C:\\_vmshare\\hello\\necurs_spam\\Modules\\injectDll32_configs\\dpost', 'rb') as f:
	# 	config_conf = f.read()
	# conf = trick_decrypt(config_conf)
	# file('C:\\_vmshare\\hello\\necurs_spam\\Modules\\injectDll32_configs\\dpost.dmp', 'wb').write(conf)
	#
	# with open('C:\\_vmshare\\hello\\necurs_spam\\Modules\\injectDll32_configs\\sinj', 'rb') as f:
	# 	config_conf = f.read()
	# conf = trick_decrypt(config_conf)
	# file('C:\\_vmshare\\hello\\necurs_spam\\Modules\\injectDll32_configs\\sinj.dmp', 'wb').write(conf)
	#
	# with open('C:\\_vmshare\\hello\\necurs_spam\\Modules\\mailsearcher32_configs\\mailconf', 'rb') as f:
	# 	config_conf = f.read()
	# conf = trick_decrypt(config_conf)
	# file('C:\\_vmshare\\hello\\necurs_spam\\Modules\\mailsearcher32_configs\\mailconf.dmp', 'wb').write(conf)

	#
	# with open('C:\\_vmshare\\hello\\necurs_spam\\Modules\\injectDll32_configs\dpost', 'rb') as f:
	# 	config_conf = f.read()
	# conf = trick_decrypt(config_conf)
	# print(conf)

	# with open('C:\\_vmshare\\hello\\necurs_spam\\Modules\\injectDll32_configs\sinj', 'rb') as f:
	# 	config_conf = f.read()
	# conf = trick_decrypt(config_conf)
	# with open('C:\\_vmshare\\hello\\necurs_spam\\Modules\\mailsearcher32', 'rb') as f:
	# 	config_conf = f.read()
	# conf = trick_decrypt(config_conf)
	# file('C:\\_vmshare\\hello\\necurs_spam\\Modules\\mailsearcher32.dmp', 'wb').write(conf)
	#
	# with open('C:\\_vmshare\\hello\\necurs_spam\\Modules\\systeminfo32', 'rb') as f:
	# 	config_conf = f.read()
	# conf = trick_decrypt(config_conf)
	# file('C:\\_vmshare\\hello\\necurs_spam\\Modules\\systeminfo32.dmp', 'wb').write(conf)
	#
	# with open('C:\\_vmshare\\hello\\necurs_spam\\Modules\\injectDll32', 'rb') as f:
	# 	config_conf = f.read()
	# conf = trick_decrypt(config_conf)
	# file('C:\\_vmshare\\hello\\necurs_spam\\Modules\\injectDll32.dmp', 'wb').write(conf)
	#
	# with open('C:\\_vmshare\\hello\\necurs_spam\\Modules\\outlookDll32', 'rb') as f:
	# 	config_conf = f.read()
	# conf = trick_decrypt(config_conf)
	# file('C:\\_vmshare\\hello\\necurs_spam\\Modules\\outlookDll32.dmp', 'wb').write(conf)
	#
	# with open('C:\\_vmshare\\hello\\necurs_spam\\Modules\\importDll32', 'rb') as f:
	# 	config_conf = f.read()
	# conf = trick_decrypt(config_conf)
	# file('C:\\_vmshare\\hello\\necurs_spam\\Modules\\importDll32.dmp', 'wb').write(conf)

	# encdata = file(r'C:\_vmshare\autoexec.bat.enc', 'rb').read()
	# encdata = file(r'C:\_vmshare\testko.enc', 'rb').read()
	# hehe = encdata[0x60:]
	# g = aes_decrypt(hehe)
	# file(r'C:\_vmshare\testko.dec', 'wb').write(g)

	


