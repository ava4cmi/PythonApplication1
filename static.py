'''
Created on 26/09/2011

@author: Jairo
'''
from xml.dom.minidom import Document, parse
import pickle, xml, sys
import utils 

print "Loading Static..."

#The Research View CWE-1000 in XML format
xmlFile='workspace/xml/1000.xml'
xmlDoc = parse(xmlFile)
rootNode = xmlDoc.firstChild
#The tree of weaknesses in XML format
weaks = rootNode.childNodes[2]
listaw = weaks.getElementsByTagName('Weakness')

def loadCWE():
    ""
    #create the minidom document
    doc = Document()
    #create the <root> base element
    root = doc.createElement("Attributes")
    doc.appendChild(root)

    cweOwner=[]
    f = open("cweOwner.l","rb")
    while 1:
        try:
            cweOwner.append(pickle.load(f))
        except EOFError:
            break
    f.close()

    writeAttXML(root,doc,"Owner",cweOwner)
          
    cweUser=[]
    f = open("cweUser.l","rb")
    while 1:
        try:
            cweUser.append(pickle.load(f))
        except EOFError:
            break
    f.close()

    writeAttXML(root,doc,"User",cweUser)    
               
    cweUIcom=[]
    f = open("cweUIcom.l","rb")
    while 1:
        try:
            cweUIcom.append(pickle.load(f))
        except EOFError:
            break
    f.close()
            
    writeAttXML(root,doc,"User_Interface",cweUIcom)
        
    cweSanit=[]
    f = open("cweSanit.l","rb")
    while 1:
        try:
            cweSanit.append(pickle.load(f))
        except EOFError:
            break
    f.close()

    writeAttXML(root,doc,"Sanitize",cweSanit)
    
    cweTransfor=[]
    f = open("cweTransfor.l","rb")
    while 1:
        try:
            cweTransfor.append(pickle.load(f))
        except EOFError:
            break
    f.close()

    writeAttXML(root,doc,"Transformation",cweTransfor)    

    cweTransfer=[]
    f = open("cweTransfer.l","rb")
    while 1:
        try:
            cweTransfer.append(pickle.load(f))
        except EOFError:
            break
    f.close()

    writeAttXML(root,doc,"Transfering",cweTransfer)        

    cweTrust=[]
    f = open("cweTrust.l","rb")
    while 1:
        try:
            cweTrust.append(pickle.load(f))
        except EOFError:
            break
    f.close()

    writeAttXML(root,doc,"Trust",cweTrust)            

    cweDBint=[]
    f = open("cweDBint.l","rb")
    while 1:
        try:
            cweDBint.append(pickle.load(f))
        except EOFError:
            break
    f.close()

    writeAttXML(root,doc,"Database",cweDBint)    
        
    cweTime=[]
    f = open("cweTime.l","rb")
    while 1:
        try:
            cweTime.append(pickle.load(f))
        except EOFError:
            break
    f.close()

    writeAttXML(root,doc,"Timeout",cweTime)    
    #component = doc.createElement("Timeout")
    
    cweMaxmin=[]
    f = open("cweMaxmin.l","rb")
    while 1:
        try:
            cweMaxmin.append(pickle.load(f))
        except EOFError:
            break
    f.close()

    writeAttXML(root,doc,"Max_Min",cweMaxmin)

    cweCall3p=[]
    f = open("cweCall3p.l","rb")
    while 1:
        try:
            cweCall3p.append(pickle.load(f))
        except EOFError:
            break
    f.close()

    writeAttXML(root,doc,"Thirdparty",cweCall3p)    

    cweSpoof=[]
    f = open("cweSpoof.l","rb")
    while 1:
        try:
            cweSpoof.append(pickle.load(f))
        except EOFError:
            break
    f.close()

    writeAttXML(root,doc,"Spoofing",cweSpoof)    

    cweTamper=[]
    f = open("cweTamper.l","rb")
    while 1:
        try:
            cweTamper.append(pickle.load(f))
        except EOFError:
            break
    f.close()

    writeAttXML(root,doc,"Tampering",cweTamper)
    
    cweEncryp=[]
    f = open("cweEncryp.l","rb")
    while 1:
        try:
            cweEncryp.append(pickle.load(f))
        except EOFError:
            break
    f.close()

    writeAttXML(root,doc,"Encryption",cweEncryp)
    
    cweUError=[]
    f = open("cweUError.l","rb")
    while 1:
        try:
            cweUError.append(pickle.load(f))
        except EOFError:
            break
    f.close()

    writeAttXML(root,doc,"Error_Handling",cweUError)
    
    cweCliSer=[]
    f = open("cweCliSer.l","rb")
    while 1:
        try:
            cweCliSer.append(pickle.load(f))
        except EOFError:
            break
    f.close()

    writeAttXML(root,doc,"Client_Server",cweCliSer)
    
    cweWeb=[]
    f = open("cweWeb.l","rb")
    while 1:
        try:
            cweWeb.append(pickle.load(f))
        except EOFError:
            break
    f.close()

    writeAttXML(root,doc,"Web",cweWeb)
    
    cweLogB=[]
    f = open("cweLogB.l","rb")
    while 1:
        try:
            cweLogB.append(pickle.load(f))
        except EOFError:
            break
    f.close()

    writeAttXML(root,doc,"Log_Backup",cweLogB)
    
    cweAttach=[]
    f = open("cweAttach.l","rb")
    while 1:
        try:
            cweAttach.append(pickle.load(f))
        except EOFError:
            break
    f.close()

    writeAttXML(root,doc,"Attachments",cweAttach)

    file = open("attributes.xml","wb")
    try:
        file.write(doc.toprettyxml(indent="   "))
    finally:
        file.close()
    
    lista=[cweOwner,cweUser,cweUIcom,cweSanit,cweTransfor,cweTransfer,cweTrust,cweDBint,cweTime,cweMaxmin,cweCall3p,cweSpoof,cweTamper,cweEncryp,cweAttach,cweUError,cweCliSer,cweWeb,cweLogB]
    #for i in range(0,len(cweAttach)):
     #   print i, cweAttach[i]
    return lista
               
def writeAttXML(root,doc, name,cweatt):
    ""
    atributo = doc.createElement("Attribute")
    atributo.setAttribute("name",name)
    for i in cweatt:
        id=i[0].split()[0] 
        #id2=i[0].split()[0]
        weakness=i[0][3:]
             
        cwe = doc.createElement("CWE")
        cwe.setAttribute("id",id)
        cwe.setAttribute("name",weakness.lstrip())
        
        lang = doc.createElement("Languages")
        textlang = doc.createTextNode(i[1].lstrip())
        lang.appendChild(textlang)
        cwe.appendChild(lang)   
        #
        osrel=searchCWE(id)
        #           
        oss = doc.createElement("Operating_Systems") 
        textoss = doc.createTextNode(osrel[0].lstrip())
        oss.appendChild(textoss)
        cwe.appendChild(oss)            

        top = doc.createElement("Top25") 
        texttop = doc.createTextNode(i[2])
        top.appendChild(texttop)
        cwe.appendChild(top)

        childof = doc.createElement("Child_of") 
        textchildof = doc.createTextNode(osrel[1].lstrip())
        childof.appendChild(textchildof) 
        cwe.appendChild(childof)

        atributo.appendChild(cwe)

    root.appendChild(atributo)
    ""
    return 0

def searchCWE(id):
    ""
    wOS=''
    wRel=''
    
    for i in range(0,682):
        #
        wId = listaw[i].attributes.get('ID').value        
        #print "id=%s, wId=%s"%(id,wId)
        if id==wId:
            #Operating System Begin
            try:
                t=listaw[i].getElementsByTagName('Operating_System_Class')
                if (len(t)>=1):
                    aux=''
                    for j in range(0,len(t)):
                        if (t[j].attributes.get('Operating_System_Class_Description')!=None):
                            aux+=' '+t[j].attributes.get('Operating_System_Class_Description').value
                    wOS=aux
            except:
                print "Operating System error: ", i, wId
                wOS+=''
                print "Sorry:", sys.exc_info()[1]
            #Operating System End
            #Relationship Begin
            try:
                t=listaw[i].getElementsByTagName('Relationship')
                aux=''
                for j in range(0,len(t)):                    
                    if (t[j].childNodes[1].childNodes[1].firstChild.data == '1000' and t[j].childNodes[5].firstChild.data == 'ChildOf'):                                       
                        aux+=' '+t[j].childNodes[7].firstChild.data                        
                wRel+=aux          
            except:
                print "Relationship error: ", i, wId
                wRel+=''
                print "Sorry:", sys.exc_info()[1]
        #Relationship End

    return wOS,wRel

# replace minidom's function with ours
xml.dom.minidom.Element.writexml = utils.fixed_writexml
#
def loadAttCWE():
    ""
    #The Research View CWE-1000 in XML format
    xmlFile='workspace/xml/attributes.xml'
    xmlDoc = parse(xmlFile)
    rootNode = xmlDoc.firstChild
    #The tree of weaknesses in XML format
    attcwe= rootNode.getElementsByTagName('Attribute')

    cweOwner=[]
    cweUser=[] 
    cweUIcom=[]
    cweSanit=[]     
    cweTransfor=[]
    cweTransfer=[]
    cweTrust=[]
    cweDBint=[]
    cweTime=[]
    cweMaxmin=[]
    cweCall3p=[]
    cweSpoof=[]
    cweTamper=[]
    cweEncryp=[]
    cweAttach=[]
    cweUError=[]
    cweCliSer=[]
    cweWeb=[]
    cweLogB=[]

    for i in attcwe:
        ""                                 
        if i.attributes.get('name').value=="Owner":
            cweOwner=buscaAtt(i)
        if i.attributes.get('name').value=="User":
            cweUser=buscaAtt(i)
        if i.attributes.get('name').value=="User_Interface":
            cweUIcom=buscaAtt(i)
        if i.attributes.get('name').value=="Sanitize":
            cweSanit=buscaAtt(i)
        if i.attributes.get('name').value=="Transformation":
            cweTransfor=buscaAtt(i)
        if i.attributes.get('name').value=="Transfering":
            cweTransfer=buscaAtt(i)
        if i.attributes.get('name').value=="Trust":
            cweTrust=buscaAtt(i)
        if i.attributes.get('name').value=="Database":
            cweDBint=buscaAtt(i)
        if i.attributes.get('name').value=="Timeout":
            cweTime=buscaAtt(i)
        if i.attributes.get('name').value=="Max_Min":
            cweMaxmin=buscaAtt(i)
        if i.attributes.get('name').value=="Attachments":
            cweAttach=buscaAtt(i)
        if i.attributes.get('name').value=="Thirdparty":
            cweCall3p=buscaAtt(i)
        if i.attributes.get('name').value=="Spoofing":
            cweSpoof=buscaAtt(i)
        if i.attributes.get('name').value=="Tampering":
            cweTamper=buscaAtt(i)
        if i.attributes.get('name').value=="Encryption":
            cweEncryp=buscaAtt(i)
        if i.attributes.get('name').value=="Error_Handling":
            cweUError=buscaAtt(i)
        if i.attributes.get('name').value=="Client_Server":
            cweCliSer=buscaAtt(i)
        if i.attributes.get('name').value=="Web":
            cweWeb=buscaAtt(i)
        if i.attributes.get('name').value=="Log_Backup":
            cweLogB=buscaAtt(i)
                   
    lista=[cweOwner,cweUser,cweUIcom,cweSanit,cweTransfor,cweTransfer,cweTrust,cweDBint,cweTime,cweMaxmin,cweCall3p,cweSpoof,cweTamper,cweEncryp,cweAttach,cweUError,cweCliSer,cweWeb,cweLogB]          
    #Returns weakness by attribute
    return lista

def buscaAtt(att):
    ""
    cweAtt=[] 
    
    cwe=att.getElementsByTagName('CWE')                       
    for j in cwe:
        lista=[]
        id=j.attributes.get('id').value
        lista.append(id)            
        cwename=j.attributes.get('name').value
        lista.append(cwename)
        try:
            cwelang=j.getElementsByTagName('Languages')                    
            lista.append(cwelang.item(0).childNodes[0].data)
        except:
            #print "Sorry:", sys.exc_info()[1]
            lista.append('')
        try:
            cwetop=j.getElementsByTagName('Top25')                    
            lista.append(cwetop.item(0).childNodes[0].data)
        except:
            #print "Sorry:", sys.exc_info()[1]
            lista.append('')
        try:
            cwechild=j.getElementsByTagName('Child_of')                    
            lista.append(cwechild.item(0).childNodes[0].data)
        except:
            #print "Sorry:", sys.exc_info()[1]
            lista.append('')
        try:
            cweos=j.getElementsByTagName('Operating_Systems')                    
            lista.append(cweos.item(0).childNodes[0].data)
        except:
            #print "Sorry:", sys.exc_info()[1]
            lista.append('')
        cweAtt.append(lista)

    return cweAtt

print "Static Loaded!!!"





