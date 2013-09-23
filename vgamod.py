'''
Created on 26/09/2011

@author: Jairo
'''
from xml.dom.minidom import Document
import cwenum, MySQLdb

class Component:
    """ Component Class Container """
    def __init__(self):
        pass
        
    def attrib(self, cId, cName, cOwner, cUser, cLang, cUIcom, cSanitize, cTrans, cTransf, cTrust, cDBint, cTime, cMaxmin, cCalltpf, cSpoof, cTamper, cEncryp, cAttach, cUError, cRemote, cDataf, cLocalh, cAS, cIS, cNC, cPC, cCWSS):
        self.cId=cId 
        self.cName=cName 
        self.cOwner=cOwner 
        self.cUser=cUser 
        self.cLang=cLang 
        self.cUIcom=cUIcom 
        self.cSanit=cSanitize 
        self.cTrans=cTrans 
        self.cTransf=cTransf 
        self.cTrust=cTrust 
        self.cDBint=cDBint 
        self.cTime=cTime 
        self.cMaxmin=cMaxmin 
        self.cCalltpf=cCalltpf 
        self.cSpoof=cSpoof 
        self.cTamper=cTamper 
        self.cEncryp=cEncryp 
        self.cAttach=cAttach 
        self.cUError=cUError 
        self.cRemote=cRemote 
        self.cDataf=cDataf 
        self.cLocalh=cLocalh 
        self.cAS=cAS
        self.cIS=cIS
        self.cNC=cNC
        self.cPC=cPC
        self.cCWSS=cCWSS
        
    def test(self):
        return 'Clase Componente Modo TEST'

if __name__ == '__main__':
    
    cwe=cwenum.fweaks()
    
    submit=Component()
    logbook=Component()
    mysql=Component()
    
    submit.attrib("1","submit","root","edguser","python","yes","yes","yes","yes","yes","yes","yes","yes","yes","yes","yes","yes","yes","yes","yes","yes","yes","yes","no",[2],[],0)
    logbook.attrib("2","logbok","root","edguser","python","yes","yes","yes","yes","yes","yes","yes","yes","yes","yes","yes","yes","yes","yes","yes","yes","yes","no","no",[3],[1],0)
    mysql.attrib("3","mysql","mysql","mysql","python","yes","yes","yes","yes","yes","yes","yes","yes","yes","yes","yes","yes","yes","yes","yes","yes","yes","no","yes",[],[2],0)
    
    print "..."
    raw_input()