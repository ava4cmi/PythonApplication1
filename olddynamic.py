'''
Created on 26/09/2011

@author: Jairo
'''
import oldrules, static
#from xml.dom import minidom

class Component:
    """ Component Class Container """
    def __init__(self):
        pass
        
    def attrib(self, cId, cName, cOwner, cUser, cLang, cUIcom, cSanit, cTrans, cTransf, cTrust, cDBint, cTime, cMaxmin, cCalltpf, cSpoof, cTamper, cEncryp, cAttach, cUError, cRemote, cDataf, cCliSer, cPCWS, cAS, cIS, cNC, cPC):
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
        self.cRemote=cRemote 
        self.cDataf=cDataf 
        self.cCliSer=cCliSer
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
    cweAtts = ["Owner","User","Programming_Language","User_Interface","Sanitize","Transform_Data","Transfering_Data","Trust", \
        "Database_Interaction","Timeout_Operations","Max_Min_Operations","Thirdparty_Operations","Spoofing","Tampering","Encryption",\
        "Attachment","Data_File_Format","Unexpected_Error_handling","Remote_External_Operation","Client_Server_Installation"]

    #function analyze attack vector
    def analyzeAV():
        
        submit=Component()
        logbook=Component()
        mysql=Component()

        submit.attrib("1",  "submit",   "Administrator","Partially-Privileged User",  "Python", "Yes",  "Yes",  "Yes",  "Yes",  "No",   "Yes",  "No",   "Yes",  "Yes",   "Yes", "No",   "Yes",  "Yes",  "No",   "No",   "JDL", "Client",0,     "Yes","No",[2],[0])
        logbook.attrib("2", "logbook",  "Administrator","Partially-Privileged User",  "C/C++",  "No",   "Yes",  "Yes",  "Yes",  "No",   "Yes",  "No",   "Yes",  "Yes",   "No",  "No",   "No",   "No",   "No",   "No",   "JDL", "Server",0,     "No", "No",[3],[1])
        mysql.attrib("3","mysql","Partially-Privileged User","Partially-Privileged User","C/C++",  "No",   "No",   "No",   "No",   "Yes",  "No",   "No",   "Yes",  "No",    "No",  "No",   "No",   "No",   "No",   "No",   "SQL", "Server",0,     "No", "Yes",[0],[2])                       

        # variables "a,a2,a3" store CWSS values from rules

        a1 = oldrules.reglas(submit.cOwner,submit.cUser,submit.cLang,submit.cUIcom,submit.cSanit,submit.cTrans,submit.cTransf,submit.cTrust,submit.cDBint,submit.cTime,submit.cMaxmin,submit.cCalltpf,submit.cSpoof,submit.cTamper,submit.cEncryp,submit.cAttach,submit.cDataf,submit.cUError,submit.cRemote,submit.cCliSer,0)
        a2 = oldrules.reglas(logbook.cOwner,logbook.cUser,logbook.cLang,logbook.cUIcom,logbook.cSanit,logbook.cTrans,logbook.cTransf,logbook.cTrust,logbook.cDBint,logbook.cTime,logbook.cMaxmin,logbook.cCalltpf,logbook.cSpoof,logbook.cTamper,logbook.cEncryp,logbook.cAttach,logbook.cDataf,logbook.cUError,logbook.cRemote,logbook.cCliSer,0)
        a3 = oldrules.reglas(mysql.cOwner,mysql.cUser,mysql.cLang,mysql.cUIcom,mysql.cSanit,mysql.cTrans,mysql.cTransf,mysql.cTrust,mysql.cDBint,mysql.cTime,mysql.cMaxmin,mysql.cCalltpf,mysql.cSpoof,mysql.cTamper,mysql.cEncryp,mysql.cAttach,mysql.cDataf,mysql.cUError,mysql.cRemote,mysql.cCliSer,0)
              
        b1 = [a1[0],a1[0]*a1[1],a1[1]*a1[2],a1[1]*a1[2],a1[0]*a1[2],a1[0],a1[0],a1[0]*a1[1],a1[0]*a1[1]*a1[2],a1[2],a1[2],a1[1]*a1[2],a1[2],a1[2],a1[2],a1[1]*a1[2],a1[1],a1[2],a1[0]*a1[1]*a1[2],a1[0]*a1[2]]
        b11 = ["%.2f"%elem for elem in b1]

        b2 = [a2[0],a2[0]*a2[1],a2[1]*a2[2],a2[1]*a2[2],a2[0]*a2[2],a2[0],a2[0],a2[0]*a2[1],a2[0]*a2[1]*a2[2],a2[2],a2[2],a2[1]*a2[2],a2[2],a2[2],a2[2],a2[1]*a2[2],a2[1],a2[2],a2[0]*a2[1]*a2[2],a2[0]*a2[2]]
        b22 = ["%.2f"%elem for elem in b2]

        b3 = [a3[0],a3[0]*a3[1],a3[1]*a3[2],a3[1]*a3[2],a3[0]*a3[2],a3[0],a3[0],a3[0]*a3[1],a3[0]*a3[1]*a3[2],a3[2],a3[2],a3[1]*a3[2],a3[2],a3[2],a3[2],a3[1]*a3[2],a3[1],a3[2],a3[0]*a3[1]*a3[2],a3[0]*a3[2]]
        b33 = ["%.2f"%elem for elem in b3]

        l1=static.buscaCWE()
        l2=l1

        subanalyzeAV("submit",b11,l1,l2)

        l3=static.buscaCWE()
        l4=l3
        subanalyzeAV("logbook",b22,l3,l4)

        l5=static.buscaCWE()
        l6=l5
        subanalyzeAV("mysql",b33,l5,l6)
       
        return 0

    def subanalyzeAV(output, b, listaCWE, listaCWE2):

        salida = open(output+".ovga","w")

        match={}       
        
        for x in range(0,20):
            for y in range(0,20):
                for i in range(0,len(listaCWE[x])):
                    for j in range(0,len(listaCWE2[y])):                  
                        if(x!=y and y>x):     
                            if((listaCWE[x][i]==listaCWE2[y][j]) and (listaCWE2[y][j]!=-1)):                                                                 
                                if (match.has_key(listaCWE[x][i])):
                                    match[listaCWE[x][i]]+=[cweAtts[y],b[y]]                   
                                else:
                                    match.update([(listaCWE[x][i],[cweAtts[x],b[x],cweAtts[y],b[y]])])
                                listaCWE2[y][j]=-1
                                listaCWE[y][j]=-1
                                break                            
        
        for i in match.keys():
            #print "CWE-%s\n"%i, match[i]
            #print "CWE-%s\n"%i
            salida.write("CWE-%s: %s\n"%(i, match[i]))
        salida.close()
        print output, "Done."
        return 0
    
    analyzeAV()
    
    
