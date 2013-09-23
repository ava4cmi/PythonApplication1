class Component:
    """ Component Class Container """
    def __init__(self):
        pass
        
    def attrib(self, cId, cName, cOwner, cUser, cLang, cUIcom, cSanit, cTransform, cTransfer, cTrust, cDBint, cTime, cMaxmin, cCalltpf, cSpoof, cTamper, cEncryp, cAttach, cUError, cCliSer,cWeb,cLogB, cPCWS, cAS, cIS, cNC, cPC):
        self.cId=cId 
        self.cName=cName 
        self.cOwner=cOwner 
        self.cUser=cUser 
        self.cLang=cLang 
        self.cUIcom=cUIcom 
        self.cSanit=cSanit 
        self.cTransform=cTransform 
        self.cTransfer=cTransfer 
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
            %(self.cId,self.cName,self.cOwner,self.cUser,self.cLang,self.cUIcom,self.cSanit,self.cTransform,self.cTransfer,self.cTrust,self.cDBint,self.cTime,self.cMaxmin,self.cCalltpf,self.cSpoof,self.cTamper,self.cEncryp,self.cAttach,self.cUError,self.cCliSer,self.cWeb,self.cLogB,self.cPCWS,self.cAS,self.cIS,self.cNC,self.cPC)

    def test(self):
        return 'Clase Componente Modo TEST'
