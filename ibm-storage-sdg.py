################################           References        ##############################

# http://www.java2s.com/Tutorial/Python/0360__Tkinker/LoadfilefromFileDialog.htm
# http://stackoverflow.com/questions/19964603/creating-a-menu-in-python
# http://stackoverflow.com/questions/20852664/python-pycrypto-encrypt-decrypt-text-files-with-aes
# http://stackoverflow.com/questions/11833266/how-do-i-read-the-first-line-of-a-string
# http://stackoverflow.com/questions/2104080/how-to-check-file-size-in-python
# https://developer.ibm.com/recipes/tutorials/use-python-to-access-your-bluemix-object-storage/
# https://docs.python.org/2/library/bz2.html

###########################################################################################

import os
import Tkinter 
import bz2
import tkFileDialog
#import gnupg
import swiftclient
from hashlib import md5
from Crypto.Cipher import AES
from Crypto import Random

####################################################################################
def derive_key_and_iv(password, salt, key_length, iv_length):
    d = d_i = ''
    while len(d) < key_length + iv_length:
        d_i = md5(d_i + password + salt).digest()
        d += d_i
    return d[:key_length], d[key_length:key_length+iv_length]

def encrypt(in_file, out_file, password, key_length=32):
    bs = AES.block_size
    salt = Random.new().read(bs - len('Salted__'))
    key, iv = derive_key_and_iv(password, salt, key_length, bs)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    out_file.write('Salted__' + salt)
    finished = False
    while not finished:
        chunk = in_file.read(1024 * bs)
        if len(chunk) == 0 or len(chunk) % bs != 0:
            padding_length = (bs - len(chunk) % bs) or bs
            chunk += padding_length * chr(padding_length)
            finished = True
        out_file.write(cipher.encrypt(chunk))

def decrypt(in_file, out_file, password, key_length=32):
    bs = AES.block_size
    salt = in_file.read(bs)[len('Salted__'):]
    key, iv = derive_key_and_iv(password, salt, key_length, bs)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    next_chunk = ''
    finished = False
    while not finished:
        chunk, next_chunk = next_chunk, cipher.decrypt(in_file.read(1024 * bs))
        if len(next_chunk) == 0:
            padding_length = ord(chunk[-1])
            chunk = chunk[:-padding_length]
            finished = True
        out_file.write(chunk)
########################################################################################################
#def closewindows():
#    statusbar.config(text = open.show())

# Credentials from runtime
auth_url= "https://identity.open.softlayer.com"
project_id= "a5dba2716aee48aebb66d262ac36ede8"
region= "dallas"
user_id= "32fd8435f263490b82eda30fbca9237c"
username= "admin_84fdd126c72259aa414bf9fc4315fdc4b21d294b",
password= "F-bseikk2Vb,4}z8"
container="Disk"

# to establish a connection (OAuth)
conn = swiftclient.Connection(
    key=password,
    authurl=auth_url+"/v3",
    auth_version='3',
    os_options={
        "project_id": project_id,
        "user_id": user_id,
        "region_name": region})

#########################    Function declaration   ###############################################
# to create a container in object storage
def putContainer():
	container=input ('Enter name of container: ')
	conn.put_container(container)

#Upload an encrypted file using connection established on the container created using above function. 
def upload():
	#fname=input ('Enter file name to upload: ')
	root = Tkinter.Tk()
	#myfiletypes = [('Python files', '*.py'), ('All files', '*')]
	open = tkFileDialog.askopenfile(parent=root,mode='rb',title='Choose a file')
	abs_path = os.path.abspath(open.name)
        fName =  os.path.basename(abs_path)
	fContent=open.read()
	print 'encrypted file'
	print fName
	#gpg=gnupg.GPG(gnu)
	conn.put_object(container,fName,bz2.compress(fContent),'text/plain')

# Download a file from a specific container and decrypt it.
def download():
	listFiles()
	container=raw_input ('Enter name of container: ')
	fname=raw_input ('Enter file name to download: ')
	try:			
		fContent=conn.get_object(container,fname)
		stri=bz2.decompress(fContent[1])
		
#		fContent=fname.read()
#		print 'here'
		print 'File Download successful. First Line of file is:'
		print stri.splitlines()[0]
	except:
		print 'File Does not Exist.'

# Limit filesize (< 1MB) and upload. 
def limitUpload():
	root = Tkinter.Tk()
	#myfiletypes = [('Python files', '*.py'), ('All files', '*')]
	open = tkFileDialog.askopenfile(parent=root,mode='rb',title='Choose a file')
	abs_path = os.path.abspath(open.name)
        fName =  os.path.basename(abs_path)
	statinfo = os.stat(fName)
	sz = statinfo.st_size
	fContent=open.read()
	print 'size of the file:', sz	
	if sz/1024 < 1024 :
		conn.put_object(container,fName,fContent,'text/plain')
		print 'File ' + fName + ' uploaded to container '+ container +' successfully.'
	else: 
		print 'File Size exceeded.'
	fContent=open.read()
############## Encrypt ########################################
	
	#print 'encrypted file'
	#print fName
	#gpg=gnupg.GPG(gnu)
	#conn.put_object(container,fName,bz2.compress(fContent),'text/plain')

# Delete a file from a Container
def delete():
	container=raw_input ('Enter name of container: ')
	fname=raw_input ('Enter file name to delete: ')
	try:	
		conn.delete_object(container,fname)
		print fname + ' deleted successfully.'
	except:
		print 'File Does not Exist.'	
	
# Enlist files from root of the object storage
def listFiles():
	
	for container in conn.get_account()[1]:
		# display total file size (quiz0) in each container		
		print 'Total File Size: ' , container['bytes'] , " bytes." , "in container: " , container['name']
		for data in conn.get_container(container['name'])[1]:
			print 'object: {0}\t size: {1}\t date: {2}'.format(data['name'],data['bytes'],data['last_modified'])


############################ Menu driven thingy ################################
menu = {}
menu['1']="Upload File" 
menu['2']="Download File"
menu['3']="List Files"
menu['4']="Delete File"
menu['5']="File size Limit Upload"
menu['6']="Exit"
while True: 
  options=menu.keys()
  options.sort()
  for entry in options: 
  	print entry, menu[entry]

  selection=raw_input("Please Select:") 
  if selection =='1': 
      upload() 
  elif selection == '2': 
      download()
  elif selection == '3':
      listFiles() 
  elif selection == '4': 
      delete()
  elif selection == '5': 
      limitUpload()
  elif selection == '6': 
      break
  else: 
      print "Unknown Option Selected!" 

# base code for all functions	
#conn.put_container(container)
#conn.put_object(container, "inputFile.txt","abc",'text/plain')

