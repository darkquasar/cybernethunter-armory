#!/usr/bin/env python3

'''
 VERSION: 0.1
 AUTHOR: Diego Perez (@darkquasar) - 2018
 DESCRIPTION: A class for multiple output options for Fireye RedLine Collections
 
 Updates: 
    v0.1: ---.
    
 ToDo:
    1. ----.
'''

# 

class Output(object):
	def __init__(self, outfilepointer, Xdict2, out_type, hostname):
		
		self.log = LogMessage()
		
		if out_type in "tsv, all":
			self.headers_list = [k for k in Xdict2.keys()]
			self.outfile = open(outfilepointer,'w', newline='')
			self.writer = csv.DictWriter(self.outfile, delimiter='\t', fieldnames=self.headers_list)
			self.writer.writeheader()
		
		if out_type in "sqlite3, all":
		
			''' Preparing the string of fields that will be used as column headers in the sqlite3 database;
				this will allow us to pass any list of values as the table headers, thus it's re-usable '''
			
			Xdict2.update({'host':hostname})
			Xdict2.move_to_end('host', last=False)
			
			fields_list = list(Xdict2.keys())
			fields_asOneString = ""
			fields_number = ""
			
			for i in range(len(fields_list)):
				fields_asOneString += fields_list[i] + ","
				fields_number += "?,"
			
			self.fields_asOneString = fields_asOneString.strip(",") # getting rid of trailing ","
			self.fields_number = fields_number.strip(",")
			
			self.conn = sqlite3.connect(outfilepointer)
			self.cur = self.conn.cursor()
			
			if self.conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='StateAgentTable';").fetchone():
				self.log.logtostdout("Table StateAgentTable already exists, information will be appended")
				
			else:
				self.cur.execute("CREATE TABLE StateAgentTable (" + self.fields_asOneString + ");")
		
		if out_type in "stdout":
			None
		
	def csvwrite(self, doctype, data):
		self.writer.writerow(data)	
	
	def closefile(self, closing_type):
		if closing_type == "tsv":
			self.outfile.close()
			
		if closing_type == "db":
			self.conn.commit()
			self.conn.close()
		
	def toSqlite(self, data, hostname):
		
		data.pop(0)
		data.insert(0, hostname)
		#print(data)
		#sys.exit()
		
		try:
			self.cur.executemany("INSERT INTO StateAgentTable (" + self.fields_asOneString + ") VALUES (" + self.fields_number + ");", [data])
			
		except Exception as e:
			print(e)
	
	def toStdout(self, data_dict):
		# store non-empty keys in a list so as to only display those keys with actual values for each event category to stdout
		nonemptykey = []
		#print(data_dict)
		for x in data_dict.keys():
			if data_dict[x] != '':
				nonemptykey.append(x)
		try:	
			print(dict({key : data_dict[key] for key in nonemptykey}))
		except:
			pass
