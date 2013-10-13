import os, sys, traceback, pprint
from xml.dom import minidom
from sets import Set
import constants, utils

print "Loading Post..."
#Constants
CONST=constants._Const()
top25 = CONST.top25
names = CONST.names
cwebase=constants.cwebase()

#Global Vars
salida=[]
maxp0, maxp1, maxp2, maxp3, maxp4, maxp5, maxp6, maxp7, maxp8, maxp9, maxp10 = ({} for i in range(11))
maxph0, maxph1, maxph2, maxph3, maxph4, maxph5, maxph6, maxph7, maxph8, maxph9, maxph10 = ({} for i in range(11))
maxi0, maxi1, maxi2, maxi3, maxi4, maxi5, maxi6, maxi7, maxi8, maxi9, maxi10 = ({} for i in range(11))
medg0, medg1, medg2, medg3, medg4, medg5, medg6, medg7, medg8, medg9, medg10 = ({} for i in range(11))

cwe, maxp, maxph, maxi, medg = ({} for i in range(5))

def makePost(dir):
    #Leemos los datos del XML para el/los Vector(es) de Ataque             
    
    for filename in os.listdir('workspace/'+dir+'/xml/'):
        if not (filename.split('.')[1] == 'graphml' ):
            data,dataux = av2data(dir,filename)                
            #Itero sobre cada weakness con sus atributos evaluados
            for d in data.items():                
                name = d[0]        
                cweid=name.split()[0]                                       
                id = cweid.split("-")[1]    
                cwe[name]=name                        
                #Llamamos la funcion para crear el fichero gnuplot DATA con los datos de la weakness y sus atributos puntuados
                gnuplotdata(d,cweid,dir,filename)        
                #numero de atributos de la weakness 
                n=len(d[1].items())       
                #Separamos por weakness base
                for base in range(12):              
                    if (id in cwebase[base]) and (base in names):                                                   
                        #Llamamos la funcion para crear el fichero gnuplot POST con los datos de la weakness y su prioridad por atributos                        
                        post=gnuplotpost(names[base],name,cweid,dir,filename)                                                       
                        #if the weakness belong to top25 the top25 priority p0 will be equal "1".#p is the sum of all priorities
                        p=0
                        p0=(0)                                
                        if (id in top25):
                            p0=1                 
                        for i in d[1].items():                    
                            #Calculamos el score minimo (aux) para el atributo en el AV, la prioridad de la weakness segun los atributos y la weakness base.                    
                            try:                        
                                aux, temp = clasifica(base,id,i)
                            except:
                                print "Error:",base, id, i
                            ""       
                            p+=temp                                
                            aux="%.2f"%aux
                            post.write(i[0])            
                            post.write(" "+aux+"\n")                              
                        #Genero un diccionario con el weakness name y le asigno la prioridad "totalp" obtenida normalizada por el numero de atributos "n".
                        totalp=(p+p0)/n                
                        maxbase(base, name, totalp,"all")                    
                        post.close()                                                
                        
            dmaxph={0:dict(maxph0), 1:dict(maxph1), 2:dict(maxph2), 3:dict(maxph3), 4:dict(maxph4), 5:dict(maxph5), 6:dict(maxph6), 7:dict(maxph7), 8:dict(maxph8), 9:dict(maxph9), 10:dict(maxph10), 11:dict(maxph)}
            dmaxp={0:dict(maxp0), 1:dict(maxp1), 2:dict(maxp2), 3:dict(maxp3), 4:dict(maxp4), 5:dict(maxp5), 6:dict(maxp6), 7:dict(maxp7), 8:dict(maxp8), 9:dict(maxp9), 10:dict(maxp10), 11:dict(maxp)}
            ##
            ### AGREGO LOS HIJOS CON SUS PRIORIDADES Y CALCULAR EL MAXIMO, MEDIAG, Y CUARTILES???
            insertSubcwe(dataux,dmaxph,dmaxp)    
            ### CALCULAR EL MAXIMO, MEDIAG, Y CUARTILES por categoria???            
            evalMMQ(data,dmaxph)  
            #Ordeno el Listado de Weaknesses teniendo en cuenta el valor de las clases hijas y tomando el maximo    
            postOrder(maxi, cwe, 11,"maxi",0,dir,filename)
            #Ordeno el Listado de Weaknesses teniendo en cuenta el valor de las clases hijas y tomando la mediag
            postOrder(medg, cwe, 11,"medg",0,dir,filename)    
            #Ordeno el Listado de Weaknesses sin tener en cuenta el valor de las clases hijas
            postOrder(maxp, cwe,11,"all", dataux,dir,filename)
        
            rOrder("all", dataux,dir,filename)    
            rOrder("maxi", 0,dir,filename)    
            rOrder("medg", 0,dir,filename)        

    return 0

def evalMMQ(data,dmaxph):
    #Calculamos el max y medg
    for d in data.items():                                 
        id = d[0].split()[0].split("-")[1]          
        for base in range(12):                        
            if id in cwebase[base]:                
                try:                                                         
                    if (d[0] in dmaxph[base]):                                     
                        maxbase(base, d[0],max(dmaxph[base][d[0]]),"maxi")
                        maxbase(base, d[0],utils.mediag(dmaxph[base][d[0]]),"medg")                                                          
                except:
                    print "evalMMQ-Error:", base, d
                    print "Sorry:", sys.exc_info()
                    raw_input()

    return 0

def insertSubcwe(dataux,dmaxph,dmaxp):
    #dataux tiene los cwe-id de las subclases directas de cada cwe-id en maxp    
    for parent in maxp.items():        
        parentid=parent[0].split("-")[1].split()[0]        
        for child in dataux.items():                    
            childid=child[0].split("-")[1].split()[0]        
            if parentid in child[1].split():
                for base in range(12):
                    if (parentid in cwebase[base]) and (childid in cwebase[base]):   
                        try:                            
                            dmaxph[base][parent[0]]+=[dmaxp[base][child[0]]]                            
                        except:
                            print "insertSubcwe-Error:", base, parentid, child
                            print "Sorry:", sys.exc_info()
    return 0                  

def maxbase(base, name, totalp, type):    
    #Genero un Diccionario por cada weakness base con las weakness hijas y su prioridad
    if type=="all":
        if base==0:
            maxp0[name]=totalp            
            maxph0[name]=[totalp]            
        if base==1:
            maxp1[name]=totalp
            maxph1[name]=[totalp]
        if base==2:
            maxp2[name]=totalp
            maxph2[name]=[totalp]
        if base==3:
            maxp3[name]=totalp
            maxph3[name]=[totalp]
        if base==4:
            maxp4[name]=totalp
            maxph4[name]=[totalp]
        if base==5:
            maxp5[name]=totalp
            maxph5[name]=[totalp]
        if base==6:
            maxp6[name]=totalp
            maxph6[name]=[totalp]
        if base==7:
            maxp7[name]=totalp
            maxph7[name]=[totalp]
        if base==8:
            maxp8[name]=totalp
            maxph8[name]=[totalp]
        if base==9:
            maxp9[name]=totalp
            maxph9[name]=[totalp]
        if base==10:
            maxp10[name]=totalp            
            maxph10[name]=[totalp]            
        if base==11:
            maxp[name]=totalp
            maxph[name]=[totalp]                  

    if type=="maxi":
        if base==0:
            maxi0[name]=totalp            
        if base==1:
            maxi1[name]=totalp
        if base==2:
            maxi2[name]=totalp
        if base==3:
            maxi3[name]=totalp
        if base==4:
            maxi4[name]=totalp
        if base==5:
            maxi5[name]=totalp
        if base==6:
            maxi6[name]=totalp
        if base==7:
            maxi7[name]=totalp
        if base==8:
            maxi8[name]=totalp
        if base==9:
            maxi9[name]=totalp
        if base==10:
            maxi10[name]=totalp        
        if base==11:
            maxi[name]=totalp 

    if type=="medg":
        if base==0:
            medg0[name]=totalp            
        if base==1:
            medg1[name]=totalp
        if base==2:
            medg2[name]=totalp
        if base==3:
            medg3[name]=totalp
        if base==4:
            medg4[name]=totalp
        if base==5:
            medg5[name]=totalp
        if base==6:
            medg6[name]=totalp
        if base==7:
            medg7[name]=totalp
        if base==8:
            medg8[name]=totalp
        if base==9:
            medg9[name]=totalp
        if base==10:
            medg10[name]=totalp
        if base==11:
            medg[name]=totalp   

def postOrder(maxprio,cwe,base,type, child,dir,filename):    
    ""   
    dirfname=filename.split('.')[0]
    dmaxi={0:dict(maxi0), 1:dict(maxi1), 2:dict(maxi2), 3:dict(maxi3), 4:dict(maxi4), 5:dict(maxi5), 6:dict(maxi6), 7:dict(maxi7), 8:dict(maxi8), 9:dict(maxi9), 10:dict(maxi10), 11:dict(maxi)}
    dmedg={0:dict(medg0), 1:dict(medg1), 2:dict(medg2), 3:dict(medg3), 4:dict(medg4), 5:dict(medg5), 6:dict(medg6), 7:dict(medg7), 8:dict(medg8), 9:dict(medg9), 10:dict(medg10), 11:dict(medg)}

    #Tercer Cuartil
    Q3=int(round((len(maxprio)+1)/4.0))    
             
    if base==11:
        fprior=open("workspace/"+dir+"/"+dir+"finalCWElist_"+type+".txt","w")            

    for i in range(12):        
        if (i==base) and (i in names):            
            #utils.makepath("workspace/"+dir)
            #utils.makepath("workspace/"+dir+"/"+dirfname)
            utils.makepath("workspace/"+dir+"/"+dirfname+"/post")
            utils.makepath("workspace/"+dir+"/"+dirfname+"/post/"+names[i])

            fprior=open("workspace/"+dir+"/"+dirfname+"/post/"+names[i]+"/"+"finalCWE-"+names[i]+"_"+type+".txt","w")
            
    cont=0
    #Buscamos el valor del 3er Quartil
    for key,value in sorted(maxprio.iteritems(), key=lambda (k,v):(v,k), reverse=True):                      
        cont+=1        
        if cont==Q3:
            Q3val=value
    
    #Reiniciamos el contador del Quartil y Ordenamos por prioridad las weaknesses
    if type=="all":
        cont=0
        for key,value in sorted(maxprio.iteritems(), key=lambda (k,v):(v,k), reverse=True):                        
            x=cwe[key]                         
            x=x.rstrip('\n')                            
            cont+=1                    
            fprior.write(str(cont)+"., "+x+": "+",Sp=, "+str(value)+", Max=, "+str(dmaxi[base][key])+"\n")            
            #fprior.write(str(cont)+". "+x+": "+",Sp=, "+str(value)+", Max=, "+str(dmaxi[base][key])+", Meg= "+str(dmedg[base][key])+"; Q3= "+str(Q3val)+")\n")            
            #Miro si id es weakness padre es decir pertenece a l[1] 
            id=key.split()[0].split("-")[1]            
            for l in child.iteritems():
                if id in l[1].split():
                    lid=l[0].split()[0].split("-")[1]
                    y=cwe[l[0]]                                        
                    y=y.rstrip('\n')
                    fprior.write("  |\n")                    
                    if (id in cwebase[base]) and (lid in cwebase[base]):                        
                        fprior.write("  -->"+y+": "+"(Sp= "+str(maxprio[l[0]])+"; Max= "+str(dmaxi[base][l[0]])+"; Meg= "+str(dmedg[base][l[0]])+")\n")                    
                        fprior.write("\n")                        
        fprior.close()
    else:
        cont=0
        for key,value in sorted(maxprio.iteritems(), key=lambda (k,v):(v,k), reverse=True):
            x=cwe[key]             
            x=x.rstrip('\n')                            
            cont+=1                    
            fprior.write(str(cont)+"., "+x+":,"+str(value)+"\n")            
        fprior.close()

    return 0

def rOrder(type,child,dir,filename):
    ""    
    if type=="all":
        postOrder(maxp0, cwe,0,type, child,dir,filename)
        postOrder(maxp1, cwe,1,type, child,dir,filename)
        postOrder(maxp2, cwe,2,type, child,dir,filename)
        postOrder(maxp3, cwe,3,type, child,dir,filename)
        postOrder(maxp4, cwe,4,type, child,dir,filename)
        postOrder(maxp5, cwe,5,type, child,dir,filename)
        postOrder(maxp6, cwe,6,type, child,dir,filename)
        postOrder(maxp7, cwe,7,type, child,dir,filename)
        postOrder(maxp8, cwe,8,type, child,dir,filename)
        postOrder(maxp9, cwe,9,type, child,dir,filename)
        postOrder(maxp10, cwe,10,type, child,dir,filename)
        #postOrder(maxp, cwe,11,type, child)
    if type=="maxi":
        postOrder(maxi0, cwe,0,type, child,dir,filename)
        postOrder(maxi1, cwe,1,type, child,dir,filename)
        postOrder(maxi2, cwe,2,type, child,dir,filename)
        postOrder(maxi3, cwe,3,type, child,dir,filename)
        postOrder(maxi4, cwe,4,type, child,dir,filename)
        postOrder(maxi5, cwe,5,type, child,dir,filename)
        postOrder(maxi6, cwe,6,type, child,dir,filename)
        postOrder(maxi7, cwe,7,type, child,dir,filename)
        postOrder(maxi8, cwe,8,type, child,dir,filename)
        postOrder(maxi9, cwe,9,type, child,dir,filename)
        postOrder(maxi10, cwe,10,type, child,dir,filename)
        #postOrder(maxi, cwe,11,type, child)
    if type=="medg":
        postOrder(medg0, cwe,0,type, child,dir,filename)
        postOrder(medg1, cwe,1,type, child,dir,filename)
        postOrder(medg2, cwe,2,type, child,dir,filename)
        postOrder(medg3, cwe,3,type, child,dir,filename)
        postOrder(medg4, cwe,4,type, child,dir,filename)
        postOrder(medg5, cwe,5,type, child,dir,filename)
        postOrder(medg6, cwe,6,type, child,dir,filename)
        postOrder(medg7, cwe,7,type, child,dir,filename)
        postOrder(medg8, cwe,8,type, child,dir,filename)
        postOrder(medg9, cwe,9,type, child,dir,filename)
        postOrder(medg10, cwe,10,type, child,dir,filename)
        #postOrder(medg, cwe,11,type, child)

    return 0

def clasifica(base, id, i):
    ""               
    #Initialize the others priority vars    
    p1=0
    p2=0
    p3=0    
    #Segun la weakness base determino los levels y por ende su prioridad:    
    #Obtengo los atributos por niveles segun a la weakness base a la que corresponde la weakness (id)
    Level1, Level2, Level3 = constants.levels(base)        
    #aux=mediag([float(x) for x in i[1]])            
    #Seleccionamos el menor score entre los componentes del vector de ataque y acumulamos los minimos segun pertenezcan a un nivel       
    aux=min([float(x) for x in i[1]])
    #Preguntamos por la relevancia del atributo (en que nivel esta) para la weakness base
    if (i[0] in Level1):
        p1+=aux 
        p = (p1*0.75)
        return aux, p                   
    elif (i[0] in Level2):
        p2+=aux       
        p = (p2*0.5)
        return aux, p         
    elif (i[0] in Level3):
        p3+=aux       
        p = (p3*0.25)
        return aux, p               

def av2data(dir,filename):
    ## Cargamos el vector de ataque XML 
    ## Aqui debemos pasar un listado completo de los AV (iterar por cada AV.xml)
        
    print "Attack vector: ", filename, "is being loaded!!!"
        
    avxml='workspace/'+dir+'/xml/'+filename
    dirfname=filename.split('.')[0]
    xmlDoc = minidom.parse(avxml)
    rootNode = xmlDoc.firstChild
    avcomp=rootNode.getElementsByTagName('Component')
    ""
    match={}
    matchaux={}
    ""
    #childof={}
    ""
    gnuplot="Attributes"
    
    cont=0      
    for i in avcomp:                
        #Recorro (los datos XML) para cada componente (i) del vector de ataque (avcomp)
        gnuplot+=" "+i.attributes.get('name').value.capitalize()       
        cwe=i.getElementsByTagName('CWE')                                            
        cont+=1        
        for j in cwe:                                                             
            #Recorro cada Weakness (j) del componente (cwe)
            cweid=j.attributes.get('id').value 
            id=cweid.split("-")[1]            
            cwename=j.attributes.get('name').value            
            cwename=cwename.lstrip()            
            cweatt=j.getElementsByTagName('Attribute')
            cwe=cweid+" "+cwename            
            child=j.attributes.get('childof').value                                               
            ""            
            utils.makepath("workspace/"+dir)
            utils.makepath("workspace/"+dir+"/"+dirfname)
            utils.makepath("workspace/"+dir+"/"+dirfname+"/data")
         
            try:
                data=open("workspace/"+dir+"/"+dirfname+"/data/"+cweid+".data","wb")                           
                data.write("#"+cwe+"\n")                           
                data.write(gnuplot+"\n")
                data.close()               
            except IOError as e:
                print "I/O error({0}): {1}".format(e.errno, e.strerror)                
                
            ""
            att=[]
            #Creo un diccionaro de weakness con sus atributos y sus valores
            if cwe in match:                
                for k in cweatt[0].attributes.keys():
                    att.append(k)                                    
                    try:
                        aux=cweatt[0].attributes.get(k).value                        
                    except:
                        aux=0
                    match[cwe][k]+=[aux]                                                            
            else:                                
                match[cwe]={}          
                matchaux[cwe]={}                                                                               
                for k in cweatt[0].attributes.keys():                    
                    att.append(k)                    
                    try:
                        aux=cweatt[0].attributes.get(k).value                        
                    except:
                        aux=0                 
                    match[cwe][k]=[aux]                                
                #Creo un match auxiliar con los hijos,
                matchaux[cwe]=child                                
                    
    return match, matchaux    

def gnuplotdata(d,cweid,dir,filename):
    ""
    #Here we create the headers for gnuplot file to see graphical interpretation        
    dirfname=filename.split('.')[0]
    datos=open("workspace/"+dir+"/"+dirfname+"/data/"+cweid+".data","a")     
    for i in d[1].items():                                              
        plot=''                          
        for j in i[1]:                                
            plot=plot+" "+j
            plot=plot.lstrip() 
        datos.write(i[0]+" "+plot+"\n") 
    datos.close()       
    return 0

def gnuplotpost(names,name,cweid,dir,filename):
    ""
    dirfname=filename.split('.')[0]
    utils.makepath("workspace/"+dir+"/"+dirfname+"/post")
    utils.makepath("workspace/"+dir+"/"+dirfname+"/post/"+names)
    post=open("workspace/"+dir+"/"+dirfname+"/post/"+names+"/"+cweid+".post","w")                
    #Here we create the headers for gnuplot file to see graphical interpretation        
    post.write("#"+name+"\n")
    post.write("Attributes"+" "+"Value\n")                                      
    return post      
    
dir1="crossbroker"
dir2="wms"

makePost(dir2)

print "Post Loaded!!!"
raw_input()
sys.exit(0)