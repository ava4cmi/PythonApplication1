'''
Created on 26/09/2011

@author: Jairo
'''
from xml.dom.minidom import Document, parse

import traceback
import sys
import component

print "Loading GraphML..."

def loadGraphML(graphml):
    ""
    xmlDoc = parse(graphml)
    rootNode = xmlDoc.firstChild
    graph = rootNode.childNodes[65]
    av = graph.childNodes[1].firstChild.data
    av = av.split(";")
    nodes = graph.getElementsByTagName('node')
                                            
    return av, nodes
               
def getComps(nodes):
    ""
    comps=[]
    for i in nodes:
        comp=component.Component()
        keys = i.getElementsByTagName('data')
        cId='' 
        cName=''
        cOwner=''
        cUser=''
        cLang=''
        cUIcom=''
        cSanit=''
        cTransform=''
        cTransfer=''
        cTrust=''
        cDBint=''
        cTime=''
        cMaxmin=''
        cCalltpf=''
        cSpoof=''
        cTamper=''
        cEncryp=''
        cAttach=''
        cUError=''
        cCliSer=''
        cWeb=''
        cLogB=''
        cPCWS=''
        cAS=''
        cIS=''
        cNC=''
        cPC=''
        try:
            for j in keys:
                att=j.attributes["key"].value
                if att=="id":
                    cId=j.childNodes[0].data
                if att=="name":
                    cName=j.childNodes[0].data                             
                if att=="owner":
                    cOwner=j.childNodes[0].data
                if att=="user":
                    cUser=j.childNodes[0].data
                if att=="language":
                    cLang=j.childNodes[0].data
                if att=="userInterface":
                    cUIcom=j.childNodes[0].data
                if att=="sanitize":
                    cSanit=j.childNodes[0].data
                if att=="transformData":
                    cTransform=j.childNodes[0].data
                if att=="transferData":
                    cTransfer=j.childNodes[0].data
                if att=="trust":
                    cTrust=j.childNodes[0].data
                if att=="databaseInteraction":
                    cDBint=j.childNodes[0].data
                if att=="timeoutOperations":
                    cTime=j.childNodes[0].data
                if att=="maxMinOperations":
                    cMaxmin=j.childNodes[0].data
                if att=="remote3PartyCall":
                    cCalltpf=j.childNodes[0].data
                if att=="spoofing":
                    cSpoof=j.childNodes[0].data
                if att=="tampering":
                    cTamper=j.childNodes[0].data
                if att=="encryption":
                    cEncryp=j.childNodes[0].data                
                if att=="attachment":
                    cAttach=j.childNodes[0].data
                if att=="errorHandling":
                    cUError=j.childNodes[0].data
                if att=="clientServer":
                    cCliSer=j.childNodes[0].data
                if att=="webService":
                    cWeb=j.childNodes[0].data
                if att=="logBackupCapability":
                    cLogB=j.childNodes[0].data                
                if att=="attackSurface":
                    cAS=j.childNodes[0].data
                if att=="impactSurface":
                    cIS=j.childNodes[0].data
                if att=="antecesores":
                    cPC=j.childNodes[0].data
                if att=="predecesores":
                    cNC=j.childNodes[0].data
            comp.attrib(cId, cName, cOwner, cUser, cLang, cUIcom, cSanit, cTransform, cTransfer, cTrust, cDBint, cTime, cMaxmin, cCalltpf, cSpoof, cTamper, cEncryp, cAttach, cUError, cCliSer,cWeb,cLogB, 0, cAS, cIS, cNC, cPC)
            comps.append(comp)
        except:
            print "Sorry:", sys.exc_info()[1]
            print traceback.print_exc(file=sys.stdout)            

    return comps

def loadAttCWE():
    ""
    #The Research View CWE-1000 in XML format
    xmlFile='workspace/xml/attributes.xml'
    xmlDoc = parse(xmlFile)
    rootNode = xmlDoc.firstChild
    #The tree of weaknesses in XML format
    attcwe= rootNode.getElementsByTagName('Attribute')
    
    for i in attcwe:
        ""  
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

print "GraphML Loaded!!!"





