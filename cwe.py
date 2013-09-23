from xml.dom import minidom
import sys, traceback, os, pickle

print "Loading CWE..."

#The Research View CWE-1000 in XML format
xmlFile='1000.xml'
xmlDoc = minidom.parse(xmlFile)

rootNode = xmlDoc.firstChild

#The tree of weaknesses in XML format
weaks = rootNode.childNodes[2]

#colors for terminal tests
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = "\033[1m"

    def disable(self):
        self.HEADER = ''
        self.OKBLUE = ''
        self.OKGREEN = ''
        self.WARNING = ''
        self.FAIL = ''
        self.ENDC = ''
        self.BOLD = ''


#Function to extract the useful and comparable XML information about weaknesses
def fweaks():
    
    listaw = weaks.getElementsByTagName('Weakness')
    weaknessTag = []
    conta=0 
    #print "len listaw: ",len(listaw)
    for i in range(0,682):
        wId=''
        wName=''
        wDesSum=''
        wExtDes=''
        wLang = ''
        wConSco = ''
        wConTecImp = ''
        wConNot = ''
        wMapNodNam = ''
        wMitDes = ''
        wObsExaDes = ''
        wRel = ''
        wOS = ''
        sql=''

        #Basic Info Begin
        try:
            wId = listaw[i].attributes.get('ID').value
            wName = listaw[i].attributes.get('Name').value
            #Description
            wDesSum = listaw[i].childNodes[1].childNodes[1].firstChild.data
            wDesSum = wDesSum.replace('\n\t\t\t\t\t',' ')
            wDesSum = wDesSum.replace('\"','\'')
        except:
            print "Basic Info error: ", i, wId
            print "Sorry:", sys.exc_info()[1]        
        try:
            t=listaw[i].childNodes[1].getElementsByTagName('Extended_Description')
            if (len(t)>0):
                try:
                    if (len(t[0].childNodes)>1):
                        wExtDes = t[0].childNodes[1].firstChild.data
                        wExtDes = wExtDes.replace('\n\t\t\t\t\t\t',' ')
                        wExtDes = wExtDes.replace('\"','\'')
                    else:
                        wExtDes = ''
                except:
                    wExtDes=''
                    print "1. Extended_Description error: ", i, wId
                    print "Sorry:", sys.exc_info()[1]
                    print traceback.print_exc(file=sys.stdout)                                
        except:
            print "2. Extended_Description error: ", i, wId
            print "Sorry:", sys.exc_info()[1]
            print traceback.print_exc(file=sys.stdout)            
            wExtDes=''
            
        #Basic Info End
            
        #Programming Language Begin
        try:
            t1=listaw[i].getElementsByTagName('Language')
            if (len(t1)>=1):
                aux=''
                for j in range(0,len(t1)):
                    if (t1[j].attributes.get('Language_Name')!=None):
                        aux+=' '+t1[j].attributes.get('Language_Name').value
                wLang=aux
        except:
            print "Prog. Language error 1: ", i, wId
            wLang+=''
            print "Sorry:", sys.exc_info()[1]
            
        try:
            t2=listaw[i].getElementsByTagName('Languages')            
            if (len(t2)>=1):
                aux=''
                for j in range(0,len(t2)):
                    if (t2[j].attributes.get('Language_Class_Description')!=None):
                        aux+=' '+t2[j].attributes.get('Language_Class_Description').value
                wLang+=aux
        except:
            print "Prog. Language error 2: ", i, wId
            wLang+=''
            print "Sorry:", sys.exc_info()[1]
            
        try:
            t3=listaw[i].getElementsByTagName('Language_Class')            
            if (len(t3)>=1):
                aux=''
                for j in range(0,len(t3)):
                    if (t3[j].attributes.get('Language_Class_Description')!=None):
                        aux+=' '+t3[j].attributes.get('Language_Class_Description').value
                wLang+=aux
        except:
            print "Prog. Language error 3: ", i, wId
            wLang+=''
            print "Sorry:", sys.exc_info()[1]
        #Programming Language End
        
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
                #if (t[j].childNodes[5].firstChild.data == 'ChildOf'):
                if (t[j].childNodes[1].childNodes[1].firstChild.data == '1000' and t[j].childNodes[5].firstChild.data == 'ChildOf'):                                       
                    aux+=' '+t[j].childNodes[7].firstChild.data
                    #aux+=' '+t[j].childNodes[7].firstChild.data+' '+t[j].childNodes[9].data
            wRel+=aux          
        except:
            print "Relationship error: ", i, wId
            wRel+=''
            print "Sorry:", sys.exc_info()[1]
        #Relationship End
        
        #Common Consequences Begin
        try:
            t=listaw[i].getElementsByTagName('Consequence_Scope')
            aux=''
            for j in range(0,len(t)):
                aux+=' '+t[j].firstChild.data
            wConSco+=aux
        except:
            print "Cons. Scope error: ", i, wId
            wConSco+=''
            print "Sorry:", sys.exc_info()[1]

        try:
            t=listaw[i].getElementsByTagName('Consequence_Technical_Impact')
            aux=''
            for j in range(0,len(t)):
                aux+=' '+t[j].firstChild.data
            aux=aux.replace('\n\t\t\t\t\t\t',' ')
            aux=aux.replace('\"','\'')
            wConTecImp+=aux
        except:
            print "Cons. Tec. Impact error: ", i, wId
            wConTecImp+=''
            print "Sorry:", sys.exc_info()[1]

        try:
            t=listaw[i].getElementsByTagName('Consequence_Note')
            aux=''
            for j in range(0,len(t)):
                aux+=' '+t[j].childNodes[1].firstChild.data
            aux=aux.replace('\n\t\t\t\t\t\t\t',' ')
            aux=aux.replace('\"','\'')
            wConNot+=aux
        except:
            print "Cons. Note error: ", i, wId
            wConNot+=''
            print "Sorry:", sys.exc_info()[1]
        #Common Consequences End
        
        #Taxonomy Mappings Begin
        try:
            t=listaw[i].getElementsByTagName('Mapped_Node_Name')
            aux=''
            for j in range(0,len(t)):
                try:
                    aux+=' '+t[j].firstChild.data
                    aux=aux.replace('\n\t\t\t\t\t\t',' ')
                    aux=aux.replace('\"','\'')
                except:
                    wMapNodNam+=''
            wMapNodNam+=aux
        except:
            print "Mapped_Node_Name error: ", i, wId
            wMapNodNam+=''
            print "Sorry:", sys.exc_info()[1]
                
        #Observed Examples Info Begin
        try:
            t=listaw[i].getElementsByTagName('Observed_Example_Description')
            if (len(t)>0):
                aux=''
                for j in range(0,len(t)):
                    try:
                        aux+=' '+t[j].firstChild.data
                        aux=aux.replace('\n\t\t\t\t\t',' ')
                        aux=aux.replace('\t',' ')
                        aux=aux.replace('\"','\'')
                    except:
                        wObsExaDes+=''
                wObsExaDes+=aux
            else:
                wObsExaDes+=''
        except:
            print "Observed_Example_Description error: ", i, wId
            wObsExaDes+=''
            print "Sorry:", sys.exc_info()[1]
        #Observed Examples Info End
            
        try:
            tmp=[]
            
            tmp.append(wId.encode('ascii','ignore')+' '+wName.encode('ascii','ignore'))
            tmp.append(wDesSum.encode('ascii','ignore'))
            tmp.append(wExtDes.encode('ascii','ignore'))
            
            if (len(wLang)>=1):
                #aux+='::'+wLang
                tmp.append(wLang.encode('ascii','ignore'))
            else:
                #aux+=''
                tmp.append('')
            
            if (len(wOS)>=1):
                #aux+='::'+wLang
                tmp.append(wOS.encode('ascii','ignore'))
            else:
                #aux+=''
                tmp.append('')                

            if (len(wConSco)>=1):
                #aux+='::'+wConSco
                tmp.append(wConSco.encode('ascii','ignore'))
            else:
                #aux+=''
                tmp.append('')
                
            if (len(wConTecImp)>=1):
                #aux+='::'+wConTecImp
                tmp.append(wConTecImp.encode('ascii','ignore'))
            else:
                #aux+=''
                tmp.append('')
                
            if (len(wConNot)>=1):
                #aux+='::'+wConNot
                tmp.append(wConNot.encode('ascii','ignore'))
            else:
                #aux+=''
                tmp.append('')
                
            if (len(wMapNodNam)>=1):
                #aux+='::'+wMapNodNam
                tmp.append(wMapNodNam.encode('ascii','ignore'))
            else:
                #aux+=''
                tmp.append('')
            #if (len(wMitDes)>=1):
            #        aux+='::'+wMitDes
            #else:
            #    aux+=''
            if (len(wRel)>=1):
                #aux+='::'+wRel
                tmp.append(wRel.encode('ascii','ignore'))                   
            else:
                #aux+=''
                tmp.append('')
                
            if (len(wObsExaDes)>=1):
                #aux+='::'+wObsExaDes
                tmp.append(wObsExaDes.encode('ascii','ignore'))
            else:
                #aux+=''
                tmp.append('')
            
            if (wId=='89' or wId=='78' or wId=='120' or wId=='79' or wId=='306' or wId=='862' or wId=='798' or wId=='311' or wId=='434' or wId=='807' or wId=='250' or wId=='352' or wId=='22' or wId=='494' or wId=='863' or wId=='829' or wId=='732' or wId=='676' or wId=='327' or wId=='131' or wId=='307' or wId=='601' or wId=='134' or wId=='190' or wId=='759'):                
                tmp.append('top25')
            else:
                tmp.append('')
            
            weaknessTag.append(tmp)
          
        except:
            print '-'*60
            print "FATAL ERROR: ", i, wId
            print "Sorry:", sys.exc_info()
            print traceback.print_exc(file=sys.stdout)
            print '-'*60

    return weaknessTag


def searchCWE(a,lista,umbral):
#Function to search related system attributes to the weaknesses
    salida=[]
    for i in range(0,3):
        result=[]
        aux=0
        for k in range(0,len(lista)):            
            cont=0
            for j in range(0,10):                
                if ((lista[k] in a[i][j].split()) or (lista[k].capitalize() in a[i][j].split())):                                                            
                    cont+=1
                    aux+=1                                                                  
            #result.append(lista[k])
            #result.append(cont)
            #if (cont>=1):
                #print lista[k],':',cont
        if (aux>=umbral):
            salida.append([a[i][0].replace(',',''),a[i][3],a[i][10]])
        #salida.append(result)
                                            
    return salida

def manualCWE(a,lista,name):
#Function to search related system attributes to the weaknesses
    salida=[]
    
    f = open(name,"wb")
    
    for i in range(0,682):
        result=[]
        aux=0
        temp=[]
        for k in range(0,len(lista)):            
            cont=0                        
            for j in range(0,10):                                               
                if (lista[k] in a[i][j].split()):
                    temp.append(lista[k])
                    cont+=1
                    aux+=1                    
                elif (lista[k].capitalize() in a[i][j].split()):
                    temp.append(lista[k].capitalize())
                    cont+=1
                    aux+=1               
        
        print 'Total: ',i+1 
        for m in range(0,10):
            print m,
            for k in a[i][m].split():
                key=0
                for l in range(0,len(temp)):
                    if (temp[l]==k):                                                                                       
                        print bcolors.FAIL+k+bcolors.ENDC,
                        key=1
                if (key==0):
                    print bcolors.OKGREEN+k+bcolors.ENDC,
            print ""                                                                                                                                                                           
            #print m, a[i][m]
                    
        print bcolors.WARNING + "System Attributes scores: " + bcolors.ENDC,bcolors.WARNING+str(aux)+bcolors.ENDC 
        print lista 
        print bcolors.WARNING + "Must be related to CWE?" + bcolors.ENDC
        
        q=raw_input()                                                                  
        if (q=="y" or q=="Y"):
            aux+=100
            salida.append([a[i][0].replace(',',''),a[i][3],a[i][10]])
            pickle.dump([a[i][0].replace(',',''),a[i][3],a[i][10]],f)
                        
            print bcolors.OKBLUE+'',salida,'' + bcolors.ENDC,'CWE related to System Attribute!!!'                                                  
        
        #result.append(aux)
        #salida.append(result)                
        os.system('clear')
    
    f.close()                                        
    return salida

#a=fweaks()           
print "CWE Loaded!!!"            

wUser=['root','administrator','administrators','owner','ownership','actor','actors','username','privileges','attacker','attackers','permissions','account','accounts','user','users']
#cweUser=manualCWE(a,wUser,"cweUser.l")
###cweUser=cwe.searchCWE(lcwe,wUser,4)
wUIcom=['user','interface','UI','GUI','client-side','user-supplied','command','line']
#cweUIcom=manualCWE(a,wUIcom,"cweUIcom.l")
###cweUIcom=cwe.searchCWE(lcwe,wUIcom,3)

wSanit=['sanitize','encoding','escaping','sanitization','neutralize','neutralization','injection','malformed','filtering','pathname']
#cweSanit=manualCWE(a,wSanit,"cweSanit.l")
###cweSanit=cwe.searchCWE(lcwe,wSanit,2)

wTrans=['converting','transformation','conversion','modify','modifies','modification']
#deprecated --> added to tampering attribute
#cweTrans=manualCWE(a,wTrans,"cweTransfor.l")
###cweTrans=cwe.searchCWE(lcwe,wTrans,3)

wTransfer=['transfer','transfers','cross-boundary','cross-Boundary','sent','transmission','exchange','communication','communications','downstream','upstream']
#cweTransfer=manualCWE(a,wTransfer,"cweTransfer.l")
#cweTransf=cwe.searchCWE(lcwe,wTransf,2)

wTrust=['trust','trusted','untrusted','identity','receives','trusts','receives','ssl','certificate','credential','upstream']
#cweTrust=manualCWE(a,wTrust,"cweTrust.l")
#cweTrust=cwe.searchCWE(lcwe,wTrust,2)

wDBint=['database','databases','ldap','dns','firewall','POP3','mail','server','pop','ftp','injection','sql','web']
#cweDBint=manualCWE(a,wDBint,"cweDBint.l")
#cweDBint=cwe.searchCWE(lcwe,wDBint,3)

wTime=['timeout','time','race','condition','deadlock','lock','unlock','dos','lifetime','denial','consumption','concurrent','synchronization','TOCTOU','threads','dos:','denial-of-service']
#cweTime=manualCWE(a,wTime,"cweTime.l")
#cweTime=cwe.searchCWE(lcwe,wTime,4)

wMaxmin=['maximum','minimum','size','length','width','height','truncation','overflow','underflow','range']
#cweMaxmin=manualCWE(a,wMaxmin,"cweMaxmin.l")
#cweMaxmin=cwe.searchCWE(lcwe,wMaxmin,3)

wCall3p=['third','party','parties','third-party','sphere','external','functionality','API','remote']
#cweCall3p=manualCWE(a,wCall3p,"cweCall3p.l")
#cweCall3p=cwe.searchCWE(lcwe,wCall3p,3)

wSpoof=['spoofing','phising','spoof','spoofed','authentication','identity']
#cweSpoof=manualCWE(a,wSpoof,"cweSpoof.l")
#cweSpoof=cwe.searchCWE(lcwe,wSpoof,3)

wTamper=['tampering','tamper','tampered','modify','integrity','converting','transformation','conversion','modify','modifies','modification','casting']
#cweTamper=manualCWE(a,wTamper,"cweTamper.l")
#cweTamper=cwe.searchCWE(lcwe,wTamper,3)

wEncryp=['encryption','encrypted','encrypting','ssl','certificate','confidentiality','password','cryptographic','seed','random','channel','ssl2','tls']
#cweEncryp=manualCWE(a,wEncryp,"cweEncryp.l")
#cweEncryp=cwe.searchCWE(lcwe,wEncryp,3)

wAttach=['attachment','attachments','upload']
#cweAttach=manualCWE(a,wAttach,"cweAttach.l")
#cweAttach=cwe.searchCWE(lcwe,wAttach,1)

wUError=['unexpected','error','handling','undefined','unchecked','checked']
#cweUError=manualCWE(a,wUError,"cweUError.l")
#cweUError=cwe.searchCWE(lcwe,wUError,4)

wCliSer=['client','client-based','client-Based','client-side','client-Side','client/server','server-side','server-Side']
#cweCliSer=manualCWE(a,wCliSer,"cweCliSer.l")
#cweCliSer=cwe.searchCWE(lcwe,wCliSer,2)

wWeb=['web','xss','site','service','html','tags','scripting','IIS','apache','domain','SOAP','xml','XML','DTD','url','URL','URI','javascript','browser','J2EE','ASP','PHP']
#cweWeb=manualCWE(a,wWeb,"cweWeb.l")
#cweWeb=cwe.searchCWE(lcwe,wWeb,3)

wLogB=['log','backup','logging']
#cweLogB=manualCWE(a,wLogB,"cweLogB.l")
#cweLogB=cwe.searchCWE(lcwe,wLogB,1)  
