'''
Created on 26/09/2011

@author: Jairo
'''
import rules2, static
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
        self.cAS=cAS
        self.cIS=cIS
        self.cNC=cNC
        self.cPC=cPC
        self.cPCWS=cPCWS
        
    def test(self):
        return 'Clase Componente Modo TEST'

if __name__ == '__main__':
    
    #xmlgraph = "crossbroker_vulnerability_graph.xml" or other "middleware_vuln_graph.xml"
    #graph = minidom.parse(xmlgraph)

    #xmlrules = "rules.xml"
    #frules = minidom.parse(xmlrules)
    
    #should call a function to build the attack vectors from the vulnerability graph xml file
    #def attack_vectors(xmlgraph)

    #Repeat: Select one AV: until no more AV
    #Get CWE weaknesses 
    cweAtts = ["Owner","User","User_Interface","Sanitize","Transform_Data","Transfering_Data","Trust", \
        "Database_Interaction","Timeout_Operations","Max_Min_Operations","Thirdparty_Operations","Spoofing","Tampering","Encryption",\
        "Attachment","Unexpected_Error_handling","Client_Server_Installation","Web_App_Service","Log_Operations"]

    #function analyze attack vector
    def analyzeAV():
        
        submit=Component()
        logbook=Component()
        mysql=Component()
        
        submit.attrib("1",\
                         "submit",\
                         "Administrator",\
                         "Regular User",\
                         "Python",\
                          "Yes",\
                          "Yes",\
                          "Yes",\
                          "Yes",\
                          "No",\
                          "Yes",\
                          "Yes",\
                          "Yes",\
                          "Yes",\
                          "Yes",\
                          "Yes",\
                          "Yes",\
                          "Yes",\
                          "Yes",\
                          "Client",\
                          "No",\
                          "Yes",\
                          0,\
                          "Yes",\
                          "No",\
                          [2],\
                          [0])     

        # variable key decides how to apply the CWSS formula when we don't know all the factors.
        #key = "Not Applicable"
        
        # variables "a,a2,a3" store CWSS values from rules
        
        
        subanalyzeAV(submit)
       
        return 0

    def subanalyzeAV(componente):

        print componente.cName, componente.cCliSer
        raw_input()
        
    analyzeAV()
    
