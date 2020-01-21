import csv

class firewall(object):
	"""docstring for firewall"""
	def __init__(self):
		self.path=None
		self.validinputdirection={}
		self.validinputprotocol={}
		self.validinputport={}
		self.validinputipa={}
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
				
				if a in self.validinputdirection:
					self.validinputdirection[a].append(i)
				else:
					self.validinputdirection[a]=[i]

				if b in self.validinputprotocol:
					self.validinputprotocol[b].append(i)
				else:
					self.validinputprotocol[b]=[i]

				if '-' in c:
					if c in self.validinpute:
						self.validinpute[c].append(i)
					else:
						self.validinpute[c]=[i]
				else:
					if int(c) in self.validinputport:
						self.validinputport[int(c)].append(i)
					else:
						self.validinputport[int(c)]=[i]

				if '-' in d:
					if d in self.validinputf:
						self.validinputf[d].append(i)
					else:
						self.validinputf[d]=[i]
				else:
					if d in self.validinputipa:
						self.validinputipa[d].append(i)
					else:
						self.validinputipa[d]=[i]

	def accept_packet(self,direction,protocol,port,ip_address):
		if port not in self.validinputport:
			t=[]
			for key in self.validinpute:
				a,b=key.split('-')
				if int(a)<=port and int(b)>=port:
					for item in self.validinpute[key]:
						t.append(item)
		else:
			t=self.validinputport[port]

		if ip_address not in self.validinputipa:
			p=[]
			for key in self.validinputf:
				a,b=key.split('-')
				if a<=ip_address and b>=ip_address:
					for item in self.validinputf[key]:
						p.append(item)
		else:
			p=self.validinputipa[ip_address]

		if direction in self.validinputdirection and protocol in self.validinputprotocol and t and p:
			if set(self.validinputdirection[direction])&set(self.validinputprotocol[protocol])&set(t)&set(p):
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






		
