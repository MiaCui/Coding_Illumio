import csv

class firewall(object):
	"""docstring for firewall"""
	def __init__(self):
		self.path=None
		self.validinputa={}
		self.validinputb={}
		self.validinputc={}
		self.validinputd={}
		self.validinpute={}
		self.validinputf={}
	def new(self,path):
		self.path=path
		i=0
		with open(self.path,'r') as f:
			reader=csv.reader(f)
			for line in reader:
				i+=1
				a,b,c,d=line
				if a in self.validinputa:
					self.validinputa[a].append(i)
				else:
					self.validinputa[a]=[i]

				if b in self.validinputb:
					self.validinputb[b].append(i)
				else:
					self.validinputb[b]=[i]

				if '-' in c:
					if c in self.validinpute:
						self.validinpute[c].append(i)
					else:
						self.validinpute[c]=[i]
				else:
					if int(c) in self.validinputc:
						self.validinputc[int(c)].append(i)
					else:
						self.validinputc[int(c)]=[i]

				if '-' in d:
					if d in self.validinputf:
						self.validinputf[d].append(i)
					else:
						self.validinputf[d]=[i]
				else:
					if d in self.validinputd:
						self.validinputd[d].append(i)
					else:
						self.validinputd[d]=[i]

	def accept_packet(self,direction,protocol,port,ip_address):
		if port not in self.validinputc:
			t=[]
			for key in self.validinpute:
				a,b=key.split('-')
				if int(a)<=port and int(b)>=port:
					for item in self.validinpute[key]:
						t.append(item)
		else:
			t=self.validinputc[port]

		if ip_address not in self.validinputd:
			p=[]
			for key in self.validinputf:
				a,b=key.split('-')
				if a<=ip_address and b>=ip_address:
					for item in self.validinputf[key]:
						p.append(item)
		else:
			p=self.validinputd[ip_address]

		if direction in self.validinputa and protocol in self.validinputb and t and p:
			if set(self.validinputa[direction])&set(self.validinputb[protocol])&set(t)&set(p):
				print('success')
				return True
			else:
				print('false')
				return False
		else:
			print("false")
			return False

test=firewall()
test.new('test.csv')
with open('testdata.csv','r') as f:
	reader=csv.reader(f)
	for line in reader:
		a,b,c,d=line
		test.accept_packet(a,b,int(c),d)






		