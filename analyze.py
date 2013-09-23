'''
Created on 26/09/2011

@author: Jairo
'''
print "Loading Analyze..."

from xml.dom.minidom import Document, parse

import rules
import static
import xml, sys, os, errno
import constants, utils 
CONST=constants._Const()

cweAtts = CONST.cweAtts
listOS = CONST.listOS
listWEB = CONST.listWeb

#function analyze attack vector
def analyzeAV(arch,av,os,web,dir):
                            
    # rav[] store CWSS values from rules
    rav=[]

    for comp in av:         
        #attributesbyrules               
        rav.append(rules.rules(comp))      
        
    #loadAttCWE has new features
    CWE=static.loadAttCWE()
    
    # sav[] store individual attribute scores from rav[]
    sav=[]
    
    #create the minidom document
    doc = Document()
    #create the <root> base element
    root = doc.createElement("Attack_Vector")
    doc.appendChild(root)    
    
    for j in range(0,len(av)):
        ""                     
        sav.append(rav[j])
        #Scores for non top25 weaknesses
        s = [sav[j][0],sav[j][1],sav[j][2],sav[j][3],sav[j][4],sav[j][5],sav[j][6],sav[j][7],sav[j][8],sav[j][9],sav[j][10],\
            sav[j][11],sav[j][12],sav[j][13],sav[j][14],sav[j][15],sav[j][16],sav[j][17],sav[j][18]]
        #Scores for top25 weaknesses
        s25 = [sav[j][19],sav[j][20],sav[j][21],sav[j][22],sav[j][23],sav[j][24],sav[j][25],sav[j][26],sav[j][27],sav[j][28],\
            sav[j][29],sav[j][30],sav[j][31],sav[j][32],sav[j][33],sav[j][34],sav[j][35],sav[j][36],sav[j][37]]
        #
        s = ["%.2f"%elem for elem in s]
        s25 = ["%.2f"%elem for elem in s25]                
        #        
        match={}  
        ntchos={}             
        match,ntchos=subAV(av[j].cLang,s,s25,CWE)                        
        #        
        component = doc.createElement("Component")
        component.setAttribute("name",av[j].cName)             
        for k in match.keys():             
            elemcwe = doc.createElement("CWE")            
            id="CWE-"+k                            
            #We select weaknesses related to the operating system involved ("Unix Linux Mac"), so far!            
            if (os=="ULM" and (k not in listOS)):                
                #We select weaknesses NOT related to web applications or services here
                if ((not web) and (k not in listWEB)): 
                    elemcwe.setAttribute("id",id)                    
                    name=ntchos[k][0]                       
                    elemcwe.setAttribute("name",name)  
                    elemcwe.setAttribute("top25",ntchos[k][1])
                    elemcwe.setAttribute("childof",ntchos[k][2])                                            
                    elemcwe.setAttribute("os",ntchos[k][3])
                    component.appendChild(elemcwe)
                    ""                    
                    attrib = doc.createElement("Attribute")  
                    for l in range(0,len(match[k])):                                    
                        if ((l%2)==0):
                            safeatt=match[k][l]                    
                        else:
                            valueatt=match[k][l]                    
                            attrib.setAttribute(safeatt,valueatt)
                            elemcwe.appendChild(attrib)            
                    component.appendChild(elemcwe)

            root.appendChild(component)        
        avfile="workspace/"+dir+"/xml/"+arch+".xml"
        file = open(avfile,"wb")
        try:
            file.write(doc.toprettyxml(indent="  "))
        finally:
            file.close()

    return 0

def subAV(lang, s, s25, CWE):
    ""            
    #Based on the programming language a filter is applied to remove weaknesses that does not belong to the component
    ""   
    match={} 
    ntchos={}          
    for i in range(0,len(CWE)):        
        for x in range(0,len(CWE[i])):                       
            langs=lang.split("/")            
            try:                 
                if len(langs)==2:           
                    if ((langs[0] in CWE[i][x][2].split()) or (langs[1] in CWE[i][x][2].split()) or ("Language-independent" in CWE[i][x][2].split()) or ("All" in CWE[i][x][2].split()) or (lang=='')):                
                        if (CWE[i][x][0] in match):
                            if (CWE[i][x][3]=='top25'):
                                match[CWE[i][x][0]]+=[cweAtts[i],s25[i]]                                                
                                ntchos[CWE[i][x][0]]+=[CWE[i][x][1],CWE[i][x][3],CWE[i][x][4],CWE[i][x][5]]
                            else:
                                match[CWE[i][x][0]]+=[cweAtts[i],s[i]]
                                ntchos[CWE[i][x][0]]+=[CWE[i][x][1],CWE[i][x][3],CWE[i][x][4],CWE[i][x][5]] 
                        else:
                            if (CWE[i][x][3]=='top25'):
                                match.update([(CWE[i][x][0],[cweAtts[i],s25[i]])])
                                ntchos.update([(CWE[i][x][0],[CWE[i][x][1],CWE[i][x][3],CWE[i][x][4],CWE[i][x][5]])])
                            else:                        
                                match.update([(CWE[i][x][0],[cweAtts[i],s[i]])])
                                ntchos.update([(CWE[i][x][0],[CWE[i][x][1],CWE[i][x][3],CWE[i][x][4],CWE[i][x][5]])])
                        #print "match= ",match
                        #print "ntchos= ",ntchos
                        #raw_input()
                elif len(langs)==1:
                    if ((langs[0] in CWE[i][x][2].split()) or ("Language-independent" in CWE[i][x][2].split()) or ("All" in CWE[i][x][2].split()) or (lang=='')):
                        if (CWE[i][x][0] in match):
                            if (CWE[i][x][3]=='top25'):
                                match[CWE[i][x][0]]+=[cweAtts[i],s25[i]]                                                
                                ntchos[CWE[i][x][0]]+=[CWE[i][x][1],CWE[i][x][3],CWE[i][x][4],CWE[i][x][5]]
                            else:
                                match[CWE[i][x][0]]+=[cweAtts[i],s[i]]
                                ntchos[CWE[i][x][0]]+=[CWE[i][x][1],CWE[i][x][3],CWE[i][x][4],CWE[i][x][5]] 
                        else:
                            if (CWE[i][x][3]=='top25'):
                                match.update([(CWE[i][x][0],[cweAtts[i],s25[i]])])
                                ntchos.update([(CWE[i][x][0],[CWE[i][x][1],CWE[i][x][3],CWE[i][x][4],CWE[i][x][5]])])
                            else:                        
                                match.update([(CWE[i][x][0],[cweAtts[i],s[i]])])
                                ntchos.update([(CWE[i][x][0],[CWE[i][x][1],CWE[i][x][3],CWE[i][x][4],CWE[i][x][5]])])
                        #print "match= ",match
                        #print "ntchos= ",ntchos
                        #raw_input()

            except IndexError as E:
                print "IndexError error: ", (E.args)
                raw_input()
                

    return match,ntchos

# replace minidom's function with ours
xml.dom.minidom.Element.writexml = utils.fixed_writexml
#

print "Analyze Loaded!!!"