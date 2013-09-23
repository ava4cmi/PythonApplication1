import sys, traceback
from xml.dom.minidom import Document

#CWSS.py includes the Common Weakness Scoring System

   
##  Each metric is composed by: ["Value", "Code", Weight]
##  Base Finding Metric Group:
    
TI = {"Critical":1.0,"High":0.9,"Medium":0.6,"Low":0.3,"None":0,"Default":0.6,"Unknown":0.5,"Not Applicable":1.0}
AP = {"Administrator":1.0,"Partially-Privileged User":0.9,"Regular User":0.7,"Guest":0.6,"None":0.1,"Default":0.7,"Unknown":1.0,"Not Applicable":1.0}
AL = {"Application":1.0,"System":0.9,"Network":0.7,"Enterprise":1.0,"Default":0.9,"Unknown":0.5,"Not Applicable":1.0}
IC = {"None":1.0,"Limited":0.9,"Moderate":0.7,"Indirect":0.5,"Best-Available":0.3,"Complete":0,"Default":0.6,"Unknown":0.5,"Not Applicable":1.0}
FC = {"Proven True":1.0,"Proven Locally True":0.8,"Proven False":0,"Default":0.8,"Unknown":0.5,"Not Applicable":1.0}

##  Attack Surface Metric Group:

RP = {"None":1.0,"Guest":0.9,"Regular User":0.7,"Partially-Privileged User":0.6,"Administrator":0.1,"Default":0.7,"Unknown":0.5,"Not Applicable":1.0}
RL = {"System":0.9,"Application":1.0,"Network":0.7,"Enterprise":1.0,"Default":0.9,"Unknown":0.5,"Not Applicable":1.0}
AV = {"Internet":1.0,"Intranet":0.8,"Private Network":0.8,"Adjacent Network":0.7,"Local":0.5,"Physical":0.2,"Default":0.75,"Unknown":0.5,"Not Applicable":1.0}
AS = {"Strong":0.7,"Moderate":0.8,"Weak":0.9,"None":1.0,"Default":0.85,"Unknown":0.5,"Not Applicable":1.0}
AI = {"None":1.0,"Single":0.8,"Multiple":0.5,"Default":0.8,"Unknown":0.5,"Not Applicable":1.0}
IN = {"Automated":1.0,"Limited/Typical":0.9,"Opportunistic":0.3,"High":0.1,"No Interaction":0,"Default":0.55,"Unknown":0.5,"Not Applicable":1.0}
SC = {"All":1.0,"Moderate":0.9,"Rare":0.5,"Potentially Reachable":0.1,"Default":0.7,"Unknown":0.5,"Not Applicable":1.0}

## Environmental Metric Group:
    
BI = {"Critical":1.0,"High":0.9,"Medium":0.6,"Low":0.3,"None":0,"Default":0.6,"Unknown":0.5,"Not Applicable":1.0}
DI = {"High":1.0,"Medium":0.6,"Low":0.2,"Default":0.6,"Unknown":0.5,"Not Applicable":1.0}
EX = {"High":1.0,"Medium":0.6,"Low":0.2,"None":0,"Default":0.6,"Unknown":0.5,"Not Applicable":1.0}
EC = {"None":1.0,"Limited":0.9,"Moderate":0.7,"Indirect":0.5,"Best-Available":0.3,"Complete":0.1,"Default":0.6,"Unknown":0.5,"Not Applicable":1.0}
RE = {"Extensive":1.0,"Moderate":0.9,"Limited":0.8,"Default":0.9,"Unknown":0.5,"Not Applicable":1.0}
P  = {"Widespread":1.0,"High":0.9,"Common":0.8,"Limited":0.7,"Default":0.85,"Unknown":0.5,"Not Applicable":1.0}

cweOwner = ["Administrator","Partially-Privileged User","Regular User","Guest","None","Default","Unknown","Not Applicable"]
cweUser = ["Administrator","Partially-Privileged User","Regular User","Guest","None","Default","Unknown","Not Applicable"]

#http://www.tiobe.com/index.php/content/paperinfo/tpci/index.html
cweLang = ["C/C++","Java","Visual Basic","C#",".NET","Fortran","PHP","Python","Bash","Ruby","Perl","Javascript","PL/SQL","Matlab"]

cweUIcom = ["Yes","No"]
cweSanit = ["Yes","No"]
cweTrans = ["Yes","No"]
cweTransf = ["Yes","No"]
cweTrust = ["Yes","No"]
cweDBint = ["Yes","No"]
cweTime = ["Yes","No"]
cweMaxmin = ["Yes","No"]
cweCalltpf = ["Yes","No"]
cweSpoof = ["Yes","No"]
cweTamper = ["Yes","No"]
cweEncryp = ["Yes","No"]
cweAttach = ["Yes","No"]
cweDataf = ["JDL","RSL","ClassAdd","Submit","SQL","XML","PDF","DOC","XLS","TXT","CSV","RTF","HTML","Binary"]
cweUError = ["Yes","No"]
cweRemote = ["Yes","No"]
cweClient = ["Yes","No"]
cwePrecedents = []

cweAtts = {"Owner":cweOwner,"User":cweUser,"Programming Language":cweLang,"User Interface":cweUIcom,"Sanitize":cweSanit,\
    "Transform Data":cweTrans,"Transfering Data":cweTransf,"Trust":cweTrust,"Database Interaction":cweDBint,\
    "Timeout Operations":cweTime,"Max/Min Operations":cweMaxmin,"Thirdparty Operations":cweCalltpf,"Spoofing":cweSpoof,\
    "Tampering":cweTamper,"Encryption":cweEncryp,"Attachment":cweAttach,"Data/File Format":cweDataf,\
    "Unexpected Error handling":cweUError,"Remote/External Operation":cweRemote,"Client/Server Installation":cweClient}

def reglas(attrib,value):

    ## Evaluating Owner attribute
    if (attrib=="Owner"):
        if (value=='Administrator'):
            metrics = [["Technical Impact","Critical", TI.get("Critical")], ["Acquired Privilege","Administrator",AP.get("Administrator")],["Acquired Privilege Layer","Enterprise",AL.get("Enterprise")],["Business Impact","Critical",BI.get("Critical")]]
        elif (value=='Partially-Privileged User'):
            metrics = [["Technical Impact","High", TI.get("High")], ["Acquired Privilege","Partially-Privileged User",AP.get("Partially-Privileged User")],["Acquired Privilege Layer","System",AL.get("System")],["Business Impact","High",BI.get("High")]]
        elif (value=='Regular User'):
            metrics = [["Technical Impact","Medium", TI.get("Medium")], ["Acquired Privilege","Regular User",AP.get("Regular User")],["Acquired Privilege Layer","Network",AL.get("Network")],["Business Impact","Medium",BI.get("Medium")]]
        elif (value=='Guest'):
            metrics = [["Technical Impact","Low", TI.get("Low")], ["Acquired Privilege","Guest",AP.get("Guest")],["Acquired Privilege Layer","Unknown",AL.get("Unknown")],["Business Impact","Low",BI.get("Low")]]
        elif (value=='None'):
            metrics = [["Technical Impact","None", TI.get("None")], ["Acquired Privilege","None",AP.get("None")],["Acquired Privilege Layer","Unknown",AL.get("Unknown")],["Business Impact","None",BI.get("None")]]
        elif (value=='Default'):
            metrics = [["Technical Impact","Default", TI.get("Default")], ["Acquired Privilege","Default",AP.get("Default")],["Acquired Privilege Layer","Default",AL.get("Default")],["Business Impact","Default",BI.get("Default")]]
        elif (value=='Unknown'):
            metrics = [["Technical Impact","Unknown", TI.get("Unknown")], ["Acquired Privilege","Unknown",AP.get("Unknown")],["Acquired Privilege Layer","Unknown",AL.get("Unknown")],["Business Impact","Unknown",BI.get("Unknown")]]
        elif (value=='Not Applicable'):
            metrics = [["Technical Impact","Not Applicable", TI.get("Not Applicable")], ["Acquired Privilege","Not Applicable",AP.get("Not Applicable")],["Acquired Privilege Layer","Not Applicable",AL.get("Not Applicable")],["Business Impact","Not Applicable",BI.get("Not Applicable")]]
         
    ## Evaluating User attribute
    
    #if (value=='Administrator'):
#        print RP.get("Administrator"), AV.get("Physical"), BI.get("Critical")

#    elif (value=='Partially-Privileged User'):
 #       print RP.get("Partially-Privileged User"), AV.get("Local"), BI.get("High") 

  #  elif (value=='Regular User'):
   #     print RP.get("Regular User"), AV.get("Private Network"), AV.get("Adjacent Network"), BI.get("Medium")

    #elif (value=='Guest'):
     #   print RP.get("Guest"), AV.get("Internet"), AV.get("Intranet"), BI.get("Low")  

    #elif (value=='None'):
     #   print RP.get("None"), AV.get("Unknown"), BI.get("None") 

    #elif (value=='Default'):
     #   print RP.get("Default"), AV.get("Default"), BI.get("Default") 

    #elif (value=='Unknown'):
     #   print RP.get("Unknown"), AV.get("Unknown"), BI.get("Unknown")

    #elif (value=='Not Applicable'):
     #   print RP.get("Not Applicable"), AV.get("Not Applicable"), BI.get("Not Applicable")
    
    ## Required Layer should be always set up to "Application"
    #print RL.get("Application")

    print 'reglas'
    raw_input()

    return metrics


#create the minidom document
doc = Document()

#create the <static> base element
rules = doc.createElement("rules")
doc.appendChild(rules)

for i in cweAtts.keys():
    safetyatt = doc.createElement("SafetyAttribute")
    nameatt = doc.createElement("Name")
    nameatt.setAttribute("name",i)    
    safetyatt.appendChild(nameatt)
    
    aux = cweAtts.get(i)
    
    for j in range(0,len(aux)):
        tmp=""
        tmp += aux[j]
        valueatt = doc.createElement("Value")    
        valueatt.setAttribute("value",tmp)
        if (i=="Owner"):
            metricas=reglas(i,tmp)
            for k in range(0,len(metricas)):
                metrics = doc.createElement("Metric")
                metrics.setAttribute("metric",metricas[k][0])
                metrics.setAttribute("value",metricas[k][1])
                metrics.setAttribute("score",str(metricas[k][2]))
                valueatt.appendChild(metrics)
                            
        safetyatt.appendChild(valueatt)

    rules.appendChild(safetyatt)

file = open("rules.xml","wb")
try:
    file.write(doc.toprettyxml(indent="  ",encoding="UTF-8"))
finally:
    file.close()


