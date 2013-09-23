#utils.py
import os, sys, traceback, pprint, errno
from xml.dom import minidom
import xml

print "Loading Utils..."

def ptree(a_dict,string_so_far='',depth_index=0,print_it=True):
    ""    
    #Usa una variable global salida=[]
    if not hasattr(a_dict,'iteritems'):
        return ''
    
    local_string = string_so_far
    spacer = '\n' + '\t'*depth_index
    
    for item in a_dict.iteritems():                     
        try:
            assert len(item) >= 2
        except (AssertionError,TypeError):
            print "Error produced by a dictionary-produced iteritem item. Returning string_so_far."
            return local_string
        
        k = item[0]
        v = item[1]
        
        if hasattr(v,'iteritems'):    
            local_string += spacer + str(k) + '->:'                                   
            local_string += ptree(v,string_so_far,depth_index = depth_index+1)            
        else:
            local_string += spacer + str(k) + ':-> ' + str(v)
            
    if depth_index == 0 and print_it:
        #print local_string
        for i in local_string.split():
            if ("->:" in i):
                aux=i.replace("->:","")
                salida.append(aux)
            elif (":->" in i):
                aux=i.replace(":->","")
                salida.append(aux)
                    
    return local_string

def mediag(numbers):
    
    product = 1
    for n in numbers:
        product *= n
    
    return product ** (1.0/len(numbers))

def debug(var):
    print var
    raw_input()
    
    return 0

def tree(a_dict,string_so_far='',depth_index=0,print_it=True):
    ""    
    if not hasattr(a_dict,'iteritems'):
        return ''
    
    local_string = string_so_far
    spacer = '\n' + '\t'*depth_index
    
    for item in a_dict.iteritems():                     
        try:
            assert len(item) >= 2
        except (AssertionError,TypeError):
            print "Error produced by a dictionary-produced iteritem item. Returning string_so_far."
            return local_string
        
        k = item[0]
        v = item[1]
        
        if hasattr(v,'iteritems'):    
            local_string += spacer + str(k) + '->:'                                   
            local_string += ptree(v,string_so_far,depth_index = depth_index+1)            
        else:
            local_string += spacer + str(k) + ':-> ' + str(v)
            
    if depth_index == 0 and print_it:
        print local_string
    
    return local_string

def fixed_writexml(self, writer, indent="", addindent="", newl=""):
    # indent = current indentation
    # addindent = indentation to add to higher levels
    # newl = newline string
    writer.write(indent+"<" + self.tagName)

    attrs = self._get_attributes()
    a_names = attrs.keys()
    a_names.sort()

    for a_name in a_names:
        writer.write(" %s=\"" % a_name)
        xml.dom.minidom._write_data(writer, attrs[a_name].value)
        writer.write("\"")
    if self.childNodes:
        if len(self.childNodes) == 1 \
          and self.childNodes[0].nodeType == xml.dom.minidom.Node.TEXT_NODE:
            writer.write(">")
            self.childNodes[0].writexml(writer, "", "", "")
            writer.write("</%s>%s" % (self.tagName, newl))
            return
        writer.write(">%s"%(newl))
        for node in self.childNodes:
            node.writexml(writer,indent+addindent,addindent,newl)
        writer.write("%s</%s>%s" % (indent,self.tagName,newl))
    else:
        writer.write("/>%s"%(newl))

def makepath(path):
    try:
        os.makedirs(path)
    except OSError as exception:
        if exception.errno != errno.EEXIST:
            raise

