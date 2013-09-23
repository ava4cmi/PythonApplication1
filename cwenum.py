from xml.dom import minidom
import MySQLdb, sys, traceback

#The Research View CWE-1000 in XML format

xmlFile='1000.xml'
xmlDoc = minidom.parse(xmlFile)

rootNode = xmlDoc.firstChild

#The tree of weaknesses in XML format
weaks = rootNode.childNodes[2]

#Search Function

#Function to extract the useful and comparable XML information about weaknesses
def fweaks():
    
##    db = MySQLdb.connect(host='localhost',user='root',passwd='',db='test')
##    cursor =db.cursor()

    listaw = weaks.getElementsByTagName('Weakness')
    weaknessTag = []
     
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

        sql=''

        #Basic Info Begin
        try:
            wId = listaw[i].attributes.get('ID').value
            wName = listaw[i].attributes.get('Name').value
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
                        aux+='::'+t1[j].attributes.get('Language_Name').value
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
                        aux+='::'+t2[j].attributes.get('Language_Class_Description').value
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
                        aux+='::'+t3[j].attributes.get('Language_Class_Description').value
                wLang+=aux
        except:
            print "Prog. Language error 3: ", i, wId
            wLang+=''
            print "Sorry:", sys.exc_info()[1]
        #Programming Language End

        #Relationship Begin
        try:
            t=listaw[i].getElementsByTagName('Relationship')
            aux=''
            for j in range(0,len(t)):
                if (t[j].childNodes[1].childNodes[1].firstChild.data == '1000' and t[j].childNodes[5].firstChild.data == 'ChildOf'):
                    aux+='::'+t[j].childNodes[7].firstChild.data
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
                aux+='::'+t[j].firstChild.data
            wConSco+=aux
        except:
            print "Cons. Scope error: ", i, wId
            wConSco+=''
            print "Sorry:", sys.exc_info()[1]

        try:
            t=listaw[i].getElementsByTagName('Consequence_Technical_Impact')
            aux=''
            for j in range(0,len(t)):
                aux+='::'+t[j].firstChild.data
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
                aux+='::'+t[j].childNodes[1].firstChild.data
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
                    aux+='::'+t[j].firstChild.data
                    aux=aux.replace('\n\t\t\t\t\t\t',' ')
                    aux=aux.replace('\"','\'')
                except:
                    wMapNodNam+=''
            wMapNodNam+=aux
        except:
            print "Mapped_Node_Name error: ", i, wId
            wMapNodNam+=''
            print "Sorry:", sys.exc_info()[1]
        #Taxonomy Mappings End

        #Mitigation Info Begin
        try:
            t=listaw[i].getElementsByTagName('Mitigation_Description')
            aux=''
            for j in range(0,len(t)):
                try:
                    aux+='::'+t[j].childNodes[1].firstChild.data
                    aux=aux.replace('\n\t\t\t\t\t\t\t',' ')
                    aux=aux.replace('\"','\'')
                except:
                    wMitDes+=''
            wMitDes+=aux                
        except:
            print "Mitigation error: ", i, wId
            wMitDes+=''
            print "Sorry:", sys.exc_info()[1]
            
        #Mitigation Info End
        
        #Observed Examples Info Begin
        try:
            t=listaw[i].getElementsByTagName('Observed_Example_Description')
            if (len(t)>0):
                aux=''
                for j in range(0,len(t)):
                    try:
                        aux+='::'+t[j].firstChild.data
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
            aux=''
            aux=wId+'::'+wName+'::'+wDesSum+'::'+wExtDes
            if (len(wLang)>=1):
                aux+='::'+wLang
            else:
                aux+=''
            if (len(wConSco)>=1):
                aux+='::'+wConSco
            else:
                aux+=''
            if (len(wConTecImp)>=1):
                aux+='::'+wConTecImp
            else:
                aux+=''
            if (len(wConNot)>=1):
                aux+='::'+wConNot
            else:
                aux+=''
            if (len(wMapNodNam)>=1):
                aux+='::'+wMapNodNam
            else:
                aux+=''
            if (len(wMitDes)>=1):
                    aux+='::'+wMitDes
            else:
                aux+=''
            if (len(wRel)>=1):
                aux+='::'+wRel
            else:
                aux+=''
            if (len(wObsExaDes)>=1):
                aux+='::'+wObsExaDes
            else:
                aux+=''

            weaknessTag.append(aux)

            sql = """ INSERT INTO python VALUES ("%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s")"""%(wId,wName,wDesSum,wExtDes,wLang,wConSco,wConTecImp,wConNot,wMapNodNam,wMitDes,wRel,wObsExaDes)
            
        except:
            print '-'*60
            print "FATAL ERROR: ", i, wId
            print "Sorry:", sys.exc_info()
            print traceback.print_exc(file=sys.stdout)
            print '-'*60

##        try:
##            cursor.execute(sql)
##        except MySQLdb.Error, e:
##            print "\n Error %d: %s" % (e.args[0], e.args[1])
##            print sql

##    db.commit()     

    return weaknessTag

def busca(a, oper, s1, s2):

    result=[]

    cont = 0
    for i in range(0,682):
        if (oper=='or'):
            if (a[i].find(s1) > -1 or a[i].find(s1.capitalize()) > -1):
                cont=cont+1
                result.append(a[i].split('::')[0].encode('ascii','ignore'))
        elif (oper=='and'):
            if (a[i].find(s1) > -1 and a[i].find(s2) > -1):
                cont=cont+1
                result.append(a[i].split('::')[0].encode('ascii','ignore'))                
            elif (a[i].find(s1.capitalize()) > -1 and a[i].find(s2) > -1):
                cont=cont+1
                #print cont, 'la 1a may -> ',a[i].split('::')[0]
                result.append(a[i].split('::')[0].encode('ascii','ignore'))
            elif (a[i].find(s1) > -1 and a[i].find(s2.capitalize()) > -1):
                cont=cont+1
                #print cont, 'la 2da may -> ', a[i].split('::')[0]
                result.append(a[i].split('::')[0].encode('ascii','ignore'))
            elif (a[i].find(s1.capitalize()) > -1 and a[i].find(s2.capitalize()) > -1):
                cont=cont+1
                #print cont, 'ambas may -> ', a[i].split('::')[0]
                result.append(a[i].split('::')[0].encode('ascii','ignore'))
    return result

def combina(a,n):

    lista=[]
    result=[]
    for z in range(0,n):
        lista.append(raw_input('Elemento '+str(z)+': '))

    #lista=['sanitize','transform','transfer','database','trust','timeout','maximum']
    temp=0
    for x in range(0,len(lista)):
        for y in range(1,len(lista)):
            cont=0
            if (lista[x]!=lista[y] and x<y):
                temp=temp+1
                for i in range(0,682):
                    if (a[i].find(lista[x]) > -1 and a[i].find(lista[y]) > -1):
                        cont=cont+1
                        print temp, cont, lista[x], lista[y], a[i].split('::')[0]
                        result.append(a[i].split('::')[0].encode('ascii','ignore'))
                    elif (a[i].find(lista[x].capitalize()) > -1 and a[i].find(lista[y]) > -1):
                        cont=cont+16
                        print temp, cont, lista[x], lista[y],a[i].split('::')[0]
                        result.append(a[i].split('::')[0].encode('ascii','ignore'))
                    elif (a[i].find(lista[x]) > -1 and a[i].find(lista[y].capitalize()) > -1):
                        cont=cont+1
                        print temp, cont, lista[x], lista[y], a[i].split('::')[0]
                        result.append(a[i].split('::')[0].encode('ascii','ignore'))
                    elif (a[i].find(lista[x].capitalize()) > -1 and a[i].find(lista[y].capitalize()) > -1):
                        cont=cont+1
                        print temp, cont, lista[x], lista[y], a[i].split('::')[0]
                        result.append(a[i].split('::')[0].encode('ascii','ignore'))
    return result
