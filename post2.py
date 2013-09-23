import sys, traceback, glob
import xml.etree.ElementTree as xml

print "Loading Post..."


#The Research View CWE-1000 in XML format
xmlFile='1000.xml'
tree = xml.parse(xmlFile)
rootElement = tree.getroot()
#The tree of weaknesses in XML format
weaks = rootElement.findall("Weakness")
print weaks
raw_input()

#Classification Attributes level in order of relevance
Level3 = ["Owner","User","UI_GUI","Sanitize","Trust","DB_DNS_IDS_FW"]
Level2 = ["Spoofing","Tampering","Encryption","Attachment","Thirdparty"]
Level1 = ["Transformation","Transfering","TimeOut","MaxMin","ErrorHandling","Client_Server","WebAppService","Logs"]
top25 = ["89","78","120","79","306","862","798","311","434","807","250","352","22","494","863","829","732","676","327","131","307","601","134","190","759"]

def mediag(numbers):
    
    product = 1
    for n in numbers:
        product *= n
    
    return product ** (1.0/len(numbers))

def makePost():
                
    #files=glob.glob("workspace/data/*.data")
    data=av2data()
    
    cwe={}
    maxprio={}

    for d in data.items():                
        name = d[0]
        fname=name.split(" ")[0]
        #if the cweid below to cwetop25
        n25 = name.split("-")[1].split(" ")[0]
        #Initializing the priority
        p=0
        #if the weakness belong to top25 the top25 priority p0=1
        p0=0
        if (n25 in top25):
            p0=1        
        #Here we create the headers for gnuplot file to see graphical interpretation
        post=open("workspace/post/data/"+fname+".post","w")
        data=open("workspace/data/"+fname+".data","a")                
        cwe[name]=name
        post.write("#"+cwe[name]+"\n")
        post.write("Attributes"+" "+"Value\n")
                        
        p1=0
        p2=0
        p3=0
                
        for i in d[1].items():                        
            plot=[str(x) for x in i[1]]
            plot=str(plot).replace("[","")
            plot=str(plot).replace("]","")
            plot=str(plot).replace(",","")
            plot=str(plot).replace("'","")
            data.write(i[0]+" "+plot+"\n")                                  
            aux=[]                                                
            #aux=mediag([float(x) for x in i[1]])
            aux=min([float(x) for x in i[1]])
            if (i[0] in Level3):
                p3+=aux                
            elif (i[0] in Level2):
                p2+=aux                
            elif (i[0] in Level1):
                p1+=aux
                                                    
            post.write(i[0])            
            aux="%.2f"%aux
            post.write(" "+aux+"\n")                      

        n=len(d[1].items())      
        p = (p0 + (p3*0.75)+(p2*0.5)+(p1*0.25))/n
        
        maxprio[name]=p
        #post.write("Priority, "+str(p)+"\n")
        data.close()             
        post.close()        
    return maxprio,cwe

def postOrder(maxprio,cwe):
    
    fprior=open("finalCWElist.txt","w")
    cont=0
    match={}
    for key,value in sorted(maxprio.iteritems(), key=lambda (k,v):(v,k), reverse=True):
        x=cwe[key]             
        x=x.rstrip('\n')        
        id=x.split()[0].split('-')[1]                

        for i in listaw:            
            listawID=i.attributes.get('ID').value                                              
            if (listawID==id):
                try:
                    listawREL=i.getElementsByTagName('Relationship')
                    aux=[]
                    for j in range(0,len(listawREL)):
                        if (listawREL[j].childNodes[1].childNodes[1].firstChild.data == '1000' and listawREL[j].childNodes[5].firstChild.data == 'ChildOf'):                                       
                            aux.append(listawREL[j].childNodes[7].firstChild.data)                            
                            if match.has_key(listawREL[j].childNodes[7].firstChild.data):
                                match[listawREL[j].childNodes[7].firstChild.data][id]=value
                            else:
                                match.update([(listawREL[j].childNodes[7].firstChild.data,{id:value})])
                                
                except:
                    print "Relationship error: ", id
                    aux=[]
                    print "Sorry:", sys.exc_info()                    
                    raw_input()               
        
        cont+=1
        #print "%s %s %.2f" % (cont,x,value)        
        #fprior.write(str(cont)+". "+x+":"+" "+str(value)+"\n")
    #fprior.close()    
    
    for k in match.keys():
        cont=0
        print match.viewvalues()
        raw_input()    
        fprior.write(str(cont)+". "+k+":"+" "+str(match[k])+"\n")
                         
    fprior.close()    
    return 0

def av2data():

    avxml='av.xml'
    xmlDoc = minidom.parse(avxml)
    rootNode = xmlDoc.firstChild
    avcomp=rootNode.getElementsByTagName('Component')

    match={}
    gnuplot="Attributes"
    for i in avcomp:        
        gnuplot+=" "+i.attributes.get('name').value.capitalize()        
        cwe=i.getElementsByTagName('CWE')
        for j in cwe:                       
            id=j.attributes.get('id').value            
            cwename=j.attributes.get('name').value
            cwename=cwename.lstrip()            
            cweatt=j.getElementsByTagName('Attribute')
            cwe=id+" "+cwename
            data=open("workspace/data/"+id+".data","wb")
            data.write("#"+cwe+"\n")                           
            data.write(gnuplot+"\n")
            data.close()
            if match.has_key(cwe):                
                for k in cweatt[0].attributes.keys():
                    try:
                        aux=cweatt[0].attributes.get(k).value                        
                    except:
                        aux=0
                    match[cwe][k]+=[aux]                    
            else:
                match[cwe]={}
                for k in cweatt[0].attributes.keys():
                    try:
                        aux=cweatt[0].attributes.get(k).value
                    except:
                        aux=0                 
                    match[cwe][k]=[aux]     
          
    return match    

#av2data()
items=makePost()
postOrder(items[0],items[1])

print "Post Loaded!!!"