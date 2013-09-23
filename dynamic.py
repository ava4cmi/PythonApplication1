'''
Created on 26/09/2011

@author: Jairo
'''
import analyze
# rules uses a Not Applicable value of zero
# rules2 uses a Not Applicable value of min value

#from xml.dom import minidom

class Component:
    """ Component Class Container """
    def __init__(self):
        pass
        
    def attrib(self, cId, cName, cOwner, cUser, cLang, cUIcom, cSanit, cTrans, cTransf, cTrust, cDBint, cTime, cMaxmin, cCalltpf, cSpoof, cTamper, cEncryp, cAttach, cUError, cCliSer,cWeb,cLogB, cPCWS, cAS, cIS, cNC, cPC):
        self.cId=cId 
        self.cName=cName 
        self.cOwner=cOwner 
        self.cUser=cUser 
        self.cLang=cLang 
        self.cUIcom=cUIcom 
        self.cSanit=cSanit 
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
        self.cCliSer=cCliSer
        self.cWeb=cWeb
        self.cLogB=cLogB
        self.cPCWS=cPCWS
        self.cAS=cAS
        self.cIS=cIS
        self.cNC=cNC
        self.cPC=cPC
        
    def __repr__(self):
        return "<Test cId:%s cName:%s cOwner:%s cUser:%s cLang:%s cUIcom:%s cSanit:%s cTrans:%s cTransf:%s cTrust:%s cDBint:%s cTime:%s cMaxmin:%s cCalltpf:%s cSpoof:%s cTamper:%s cEncryp:%s cAttach:%s cUError:%s cCliSer:%s cWeb:%s cLogB:%s cPCWS:%s cAS:%s cIS:%s cNC:%s cPC:%s>"\
            %(self.cId,self.cName,self.cOwner,self.cUser,self.cLang,self.cUIcom,self.cSanit,self.cTrans,self.cTransf,self.cTrust,self.cDBint,self.cTime,self.cMaxmin,self.cCalltpf,self.cSpoof,self.cTamper,self.cEncryp,self.cAttach,self.cUError,self.cCliSer,self.cWeb,self.cLogB,self.cPCWS,self.cAS,self.cIS,self.cNC,self.cPC)

    def test(self):
        return 'Clase Componente Modo TEST'

if __name__ == '__main__':
    
    #cweAtts = ["Owner","User","UI/GUI","Sanitize","Transformation","Transfering","Trust", \
    #    "DB/DNS/IDS/FW","TimeOut","Max-Min","Thirdparty","Spoofing","Tampering","Encryption",\
    #    "Attachment","ErrorHandling","Client/Server","WebAppService","Logs"]
    
    submit=Component()
    submit.attrib(1,"submit","Administrator","Regular User","C++","Yes","Yes","Yes","Yes","No","Yes","Yes","Yes","No","Yes","Yes","Yes","Yes","Yes","Client","No","Yes",0,"Yes","No",[2],[0])    
    uam=Component()
    uam.attrib(2,"UAM-NS","Administrator","Partially-Privileged User","C++","No","Yes","Yes","Yes","Yes","No","Yes","Yes","No","Yes","Yes","Yes","No","Yes","Server","No","No",0,"No","No",[3],[1])
    inputfl=Component()
    inputfl.attrib(3,"input.fl","Partially-Privileged User","Partially-Privileged User","Language-independent","No","No","No","Yes","Yes","No","No","No","No","No","No","No","No","No","Server","No","No",0,"No","No",[4],[2])
    sagent=Component()
    sagent.attrib(4,"SA-WM","Administrator","Administrator","C++","No","No","Yes","Yes","Yes","No","Yes","Yes","No","Yes","Yes","Yes","No","Yes","Server","No","Yes",0,"No","No",[5],[3])
    outputfl=Component()
    outputfl.attrib(5,"output.fl","Partially-Privileged User","Partially-Privileged User","Language-independent","No","No","No","Yes","Yes","No","No","No","No","No","No","No","No","No","Server","No","No",0,"No","No",[6],[4])
    alaunch=Component()
    alaunch.attrib(6,"AL-JC","Administrator","Administrator","C++","No","No","No","Yes","Yes","No","Yes","Yes","No","Yes","Yes","Yes","No","Yes","Server","No","Yes",0,"No","No",[7],[5])
    condorg=Component()
    condorg.attrib(7,"Condor-G","Administrator","Partially-Privileged User","C++","No","No","No","Yes","Yes","No","Yes","Yes","No","Yes","Yes","Yes","Yes","Yes","Server","No","Yes",0,"No","No",[8],[6])
    lrms=Component()
    lrms.attrib(8,"LRMS","Administrator","Partially-Privileged User","C++","No","No","No","Yes","Yes","No","Yes","Yes","No","No","No","No","Yes","Yes","Server","No","Yes",0,"No","No",[9],[7])
    condorstd=Component()
    condorstd.attrib(9,"Condor_startd","Partially-Privileged User","Partially-Privileged User","C++","No","No","No","No","Yes","No","Yes","Yes","No","No","No","No","No","Yes","Server","No","Yes",0,"No","Yes",[10],[8])
    job=Component()
    job.attrib(10,"Job","Regular User","Partially-Privileged User","Language-independent","No","No","No","Yes","Yes","No","Yes","Yes","No","No","No","No","Yes","No","Server","No","No",0,"No","Yes",[0],[9])
    logbook=Component()        
    logbook.attrib(2,"logbook","Administrator","Partially-Privileged User","C++","No","Yes","Yes","Yes","Yes","Yes","Yes","Yes","No","Yes","Yes","Yes","No","Yes","Server","No","Yes",0,"No","No",[3],[1])
    mysql=Component()
    mysql.attrib(3,"mysql","Partially-Privileged User","Partially-Privileged User","C++","No","No","No","No","Yes","Yes","Yes","Yes","No","No","No","No","No","No","Server","No","Yes",0,"No","Yes",[0],[2])
    
    av=[]
    #av.append(submit)       
    #av.append(uam)
    #av.append(inputfl)
    #av.append(sagent)
    #av.append(outputfl)
    #av.append(alaunch)
    #av.append(condorg)
    #av.append(lrms)
    #av.append(condorstd)
    #av.append(job)
    
    av.append(submit)       
    av.append(logbook)
    av.append(mysql)
    
    os="ULM"
    web=False 
    analyze.analyzeAV(av,os,web)    
