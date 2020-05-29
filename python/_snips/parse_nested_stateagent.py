'''
 VERSION: 0.1
 AUTHOR: Diego Perez (@darkquasar) - 2018
 DESCRIPTION: This snip parses agent XML assigning the proper values ('hostname' instead of {'name':'hostname'})
 
 Updates: 
    v0.1: ---.
 ToDo:
    1. ----.

'''

def recurse_nodes_test_worked(self, xmltree, new_elem=None):
        # https://stackoverflow.com/questions/19286118/python-convert-very-large-6-4gb-xml-files-to-json?newreg=1f34414a077a4ed5a951054f7859b7d8
            
        items = defaultdict(list)

        '''
        elem.attrib appends the attributes found within the same tag; not required here
        if new_elem:
            items.update(new_elem.attrib)
        '''
        
        text = ""
        
        for event, elem in xmltree:
        
            if event == "end" and elem.tag == self.filter[0]:
                self.root.clear()
        
            if event == 'start' and elem.tag == 'name':
                items[elem.text].append(self.recurse_nodes_test(xmltree, elem))
            
            if event == 'start' and elem.tag == 'value':
                print("fart")
                sys.exit()
                return

            if event == 'start' and elem.tag not in  ['name','value']:
                items[elem.tag].append(self.recurse_nodes_test(xmltree, elem))

            if event == 'end' and elem.tag == 'value':
                continue

            if event == 'end' and elem.tag == 'name':
                try:
                    text = xmltree.__next__()[1].text.strip().replace('"','') if elem.text else ""
                    break
                except:
                    break
                
            elif event == 'end':
                text = elem.text.strip().replace('"','') if elem.text else ""
                elem.clear()
                self.root.clear()
                break
            
        if len(items) == 0:
            return text

        return { k: v if len(v) == 1 else v for k, v in items.items() }
