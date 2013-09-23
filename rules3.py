import sys, traceback

#rules.py 
#""" Includes the Rules about the Common Weakness Scoring System and the CWE related to safety attributes

##  Each metric is composed by: ["Value", Weight]
##  Base Finding Metric Group:
    
TI = {"Critical":1.0,"High":0.9,"Medium":0.6,"Low":0.3,"None":0,"Default":0.6,"Unknown":0.5,"Not Applicable":0}
AP = {"Administrator":1.0,"Partially-Privileged User":0.9,"Regular User":0.7,"Guest":0.6,"None":0.1,"Default":0.7,"Unknown":1.0,"Not Applicable":0}
AL = {"Application":1.0,"System":0.9,"Network":0.7,"Enterprise":1.0,"Default":0.9,"Unknown":0.5,"Not Applicable":0}
IC = {"None":1.0,"Limited":0.9,"Moderate":0.7,"Indirect":0.5,"Best-Available":0.3,"Complete":0,"Default":0.6,"Unknown":0.5,"Not Applicable":0.3}
FC = {"Proven True":1.0,"Proven Locally True":0.8,"Proven False":0,"Default":0.8,"Unknown":0.5,"Not Applicable":0}

##  Attack Surface Metric Group:

RP = {"None":1.0,"Guest":0.9,"Regular User":0.7,"Partially-Privileged User":0.6,"Administrator":0.1,"Default":0.7,"Unknown":0.5,"Not Applicable":0}
RL = {"System":0.9,"Application":1.0,"Network":0.7,"Enterprise":1.0,"Default":0.9,"Unknown":0.5,"Not Applicable":0}
AV = {"Internet":1.0,"Intranet":0.8,"Private Network":0.8,"Adjacent Network":0.7,"Local":0.5,"Physical":0.2,"Default":0.75,"Unknown":0.5,"Not Applicable":0}
AS = {"Strong":0.7,"Moderate":0.8,"Weak":0.9,"None":1.0,"Default":0.85,"Unknown":0.5,"Not Applicable":0}
AI = {"None":1.0,"Single":0.8,"Multiple":0.5,"Default":0.8,"Unknown":0.5,"Not Applicable":0}
IN = {"Automated":1.0,"Limited/Typical":0.9,"Opportunistic":0.3,"High":0.1,"No Interaction":0,"Default":0.55,"Unknown":0.5,"Not Applicable":0}
SC = {"All":1.0,"Moderate":0.9,"Rare":0.5,"Potentially Reachable":0.1,"Default":0.7,"Unknown":0.5,"Not Applicable":0}

## Environmental Metric Group:
    
BI = {"Critical":1.0,"High":0.9,"Medium":0.6,"Low":0.3,"None":0,"Default":0.6,"Unknown":0.5,"Not Applicable":0}
DI = {"High":1.0,"Medium":0.6,"Low":0.2,"Default":0.6,"Unknown":0.5,"Not Applicable":0}
EX = {"High":1.0,"Medium":0.6,"Low":0.2,"None":0,"Default":0.6,"Unknown":0.5,"Not Applicable":0}
EC = {"None":1.0,"Limited":0.9,"Moderate":0.7,"Indirect":0.5,"Best-Available":0.3,"Complete":0.1,"Default":0.6,"Unknown":0.5,"Not Applicable":0.3}
RE = {"Extensive":1.0,"Moderate":0.9,"Limited":0.8,"Default":0.9,"Unknown":0.5,"Not Applicable":0}
P = {"Widespread":1.0,"High":0.9,"Common":0.8,"Limited":0.7,"Default":0.85,"Unknown":0.5,"Not Applicable":0}

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

def reglas(cOwner,cUser,cLang,cUIcom,cSanit,cTrans,cTransf,cTrust,cDBint,cTime,cMaxmin,cCalltpf,cSpoof,cTamper,cEncryp,cAttach,cDataf,cUError,cRemote,cCliSer):
    
    ## RL = 1 = Application, The entity must be able to have access to an affected application.
    ## or RL = 1 = Enterprise, The entity must have access to a critical piece of enterprise infrastructure, such as a router, switch, DNS, domain controller, firewall, identity server, etc.  
    ## Variable key2 stores RL value
    
    key="Not Applicable"
    key1="Default"
    key2="Application"

    ## Evaluating Owner attribute  
    
    if (cOwner=='Administrator'):

        oTI1 = ["Technical Impact","Critical", TI.get("Critical")] 
        oAP1 = ["Acquired Privilege","Administrator",RP.get("Administrator")]
        oAL1 = ["Acquired Privilege Layer","Enterprise",AL.get("Enterprise")]
        oBI1 = oTI1

    elif (cOwner=='Partially-Privileged User'):

        oTI1 = ["Technical Impact","High", TI.get("High")]
        oAP1= ["Acquired Privilege","Partially-Privileged User",RP.get("Partially-Privileged User")]
        oAL1 = ["Acquired Privilege Layer","System",AL.get("System")]
        oBI1 = oTI1

    elif (cOwner=='Regular User'):
        oTI1 = ["Technical Impact","Medium", TI.get("Medium")]
        oAP1 = ["Acquired Privilege","Regular User",RP.get("Regular User")]
        oAL1 = ["Acquired Privilege Layer","Network",AL.get("Network")]
        oBI1 = oTI1

    elif (cOwner=='Guest'):

        oTI1 = ["Technical Impact","Low", TI.get("Low")]
        oAP1 = ["Acquired Privilege","Guest",RP.get("Guest")]
        oAL1 = ["Acquired Privilege Layer","Unknown",AL.get("Unknown")]
        oBI1 = oTI1

    elif (cOwner=='None'):

        oTI1 = ["Technical Impact","None", TI.get("None")]
        oAP1 = ["Acquired Privilege","None",RP.get("None")]
        oAL1 = ["Acquired Privilege Layer","Unknown",AL.get("Unknown")]
        oBI1 = oTI1

    elif (cOwner=='Default'):

        oTI1 = ["Technical Impact","Default", TI.get("Default")]
        oAP1 = ["Acquired Privilege","Default",RP.get("Default")]
        oAL1 = ["Acquired Privilege Layer","Default",AL.get("Default")]
        oBI1 = oTI1

    elif (cOwner=='Unknown'):

        oTI1 = ["Technical Impact","Unknown", TI.get("Unknown")]
        oAP1 = ["Acquired Privilege","Unknown",RP.get("Unknown")]
        oAL1 = ["Acquired Privilege Layer","Unknown",AL.get("Unknown")]
        oBI1 = oTI1

    elif (cOwner=='Not Applicable'):

        oTI1 = ["Technical Impact","Not Applicable", TI.get("Not Applicable")]
        oAP1 = ["Acquired Privilege","Not Applicable",RP.get("Not Applicable")]
        oAL1 = ["Acquired Privilege Layer","Not Applicable",AL.get("Not Applicable")]
        oBI1 = oTI1
        
    cwssOwner=cwssBaseF(oTI1[2],oAP1[2],oAL1[2],IC[key1],FC[key1])*cwssAttackS(oAP1[2],RL[key2],AV[key],AS[key],AI[key],IN[key],SC[key])*cwssEnv(oBI1[2],DI[key],EX[key],EC[key1],RE[key],P[key])
    
    ## Evaluating User attribute
    
    if (cUser=='Administrator'):
        
        oTI2 = ["Technical Impact","Critical", TI.get("Critical")] 
        oAP2 = ["Acquired Privilege","Administrator",RP.get("Administrator")]
        oRP = ["Required Privilege","Administrator",RP.get("Administrator")]
        oAL2 = ["Acquired Privilege Layer","Enterprise",AL.get("Enterprise")]
        oBI2 = oTI2

    elif (cUser=='Partially-Privileged User'):

        oTI2 = ["Technical Impact","High", TI.get("High")]
        oAP2 = ["Acquired Privilege","Partially-Privileged User",RP.get("Partially-Privileged User")]
        oRP = ["Required Privilege","Partially-Privileged User",RP.get("Partially-Privileged User")]
        oAL2 = ["Acquired Privilege Layer","System",AL.get("System")]
        oBI2 = oTI2

    elif (cUser=='Regular User'):

        oTI2 = ["Technical Impact","Medium", TI.get("Medium")]
        oAP2 = ["Acquired Privilege","Regular User",RP.get("Regular User")]
        oRP = ["Required Privilege","Regular User",RP.get("Regular User")]
        oAL2 = ["Acquired Privilege Layer","Network",AL.get("Network")]
        oBI2 = oTI2

    elif (cUser=='Guest'):

        oTI2 = ["Technical Impact","Low", TI.get("Low")]
        oAP2 = ["Acquired Privilege","Guest",RP.get("Guest")]
        oRP = ["Required Privilege","Guest",RP.get("Guest")]
        oAL2 = ["Acquired Privilege Layer","Unknown",AL.get("Unknown")]
        oBI2 = oTI2

    elif (cUser=='None'):

        oTI2 = ["Technical Impact","None", TI.get("None")]
        oAP2 = ["Acquired Privilege","None",RP.get("None")]
        oRP = ["Required Privilege","None",RP.get("None")]
        oAL2 = ["Acquired Privilege Layer","Unknown",AL.get("Unknown")]
        oBI2 = oTI2

    elif (cUser=='Default'):

        oTI2 = ["Technical Impact","Default", TI.get("Default")]
        oAP2 = ["Acquired Privilege","Default",RP.get("Default")]
        oRP = ["Required Privilege","Default",RP.get("Default")]
        oAL2 = ["Acquired Privilege Layer","Default",AL.get("Default")]
        oBI2 = oTI2

    elif (cUser=='Unknown'):

        oTI2 = ["Technical Impact","Unknown", TI.get("Unknown")]
        oAP2 = ["Acquired Privilege","Unknown",RP.get("Unknown")]
        oRP = ["Required Privilege","Unknown",RP.get("Unknown")]
        oAL2 = ["Acquired Privilege Layer","Unknown",AL.get("Unknown")]
        oBI2 = oTI2

    elif (cUser=='Not Applicable'):

        oTI2 = ["Technical Impact","Not Applicable", TI.get("Not Applicable")]
        oAP2 = ["Acquired Privilege","Not Applicable",RP.get("Not Applicable")]
        oRP = ["Required Privilege","Not Applicable",RP.get("Not Applicable")]
        oAL2 = ["Acquired Privilege Layer","Not Applicable",AL.get("Not Applicable")]
        oBI2 = oTI2
        
    cwssUser=cwssBaseF(oTI2[2],oAP2[2],oAL2[2],IC[key1],FC[key1])*cwssAttackS(oRP[2],RL[key2],AV[key],AS[key],AI[key],IN[key],SC[key])*cwssEnv(oBI2[2],DI[key],EX[key],EC[key1],RE[key],P[key])
    
    ## Evaluating Programming Language attribute

    if (cLang=="C/C++" or cLang=="Java" or cLang=="Fortran" or cLang=="Visual Basic" or cLang=="C#" or cLang==".NET" or cLang=="Matlab"):
        
        oSC1 = ["Deployment Scope","Moderate",SC.get("Moderate")]
        oDI4 = ["Likelihood of Discovery","Low",DI.get("Low")] 
        oEX4 = ["Likelihood of Exploit","Low",DI.get("Low")]
        oRE3 = ["Remediation Effort","Moderate",RE.get("Moderate")]
        
    elif (cLang=="Bash" or cLang=="Python" or cLang=="Javascript" or cLang=="PHP" or cLang=="PL/SQL" or cLang=="Ruby"):
        
        oSC1 = ["Deployment Scope","Rare",SC.get("Rare")]
        oDI4 = ["Likelihood of Discovery","Medium",DI.get("Medium")]
        oEX4 = ["Likelihood of Exploit","Medium",DI.get("Medium")]
        oRE3 = ["Remediation Effort","Limited",RE.get("Limited")]
        
    else:
        
        oSC1 = ["Deployment Scope","Unknown",SC.get("Unknown")]
        oDI4 = ["Likelihood of Discovery","Unknown",DI.get("Unknown")] 
        oEX4 = ["Likelihood of Exploit","Unknown",DI.get("Unknown")]
        oRE3 = ["Remediation Effort","Unknown",RE.get("Unknown")]
    
    cwssLang=cwssBaseF(TI[key1],oAP2[2],oAL2[2],IC[key1],FC[key1])*cwssAttackS(oRP[2],RL[key2],AV[key],AS[key1],AI[key],IN[key],oSC1[2])*cwssEnv(TI[key1],oDI4[2],oEX4[2],EC[key1],oRE3[2],P[key])
    
    ## Evaluating User Interface Command attribute

    if (cUIcom=="Yes"):
        
        oAV1 = ["Access Vector","Local",AV.get("Local")] 
        oIN1 = ["Level of Interaction","Opportunistic",IN.get("Opportunistic")]
        oDI2 = ["Likelihood of Discovery","High",DI.get("High")] 
        oEX2 = ["Likelihood of Exploit","High",DI.get("High")]
    
    else:
        
        oAV1 = ["Access Vector","Adjacent Network",AV.get("Adjacent Network")] 
        oIN1 = ["Level of Interaction","Automated",IN.get("Automated")]
        oDI2 = ["Likelihood of Discovery","Medium",DI.get("Medium")] 
        oEX2 = ["Likelihood of Exploit","Medium",DI.get("Medium")]

    cwssUIcom=cwssBaseF(TI[key1],oAP2[2],oAL2[2],IC[key1],FC[key])*cwssAttackS(oRP[2],RL[key2],oAV1[2],AS[key1],AI[key1],oIN1[2],SC[key1])*cwssEnv(TI[key1],oDI2[2],oEX2[2],EC[key1],RE[key],P[key])
    
    ## Evaluating Sanitize data attribute

    if (cSanit=="Yes"):
        
        oIC1 = ["Internal Control Effectiveness","Moderate",IC.get("Moderate")]
        oDI1 = ["Likelihood of Discovery","Low",DI.get("Low")] 
        oEX1 = ["Likelihood of Exploit","Low",DI.get("Low")]
        
    else:
        
        oIC1 = ["Internal Control Effectiveness","Limited",IC.get("Limited")]
        oDI1 = ["Likelihood of Discovery","High",DI.get("High")] 
        oEX1 = ["Likelihood of Exploit","High",DI.get("High")]
    
    cwssSanit=cwssBaseF(TI[key1],oAP2[2],oAL2[2],oIC1[2],FC[key1])*cwssAttackS(oRP[2],RL[key2],AV[key],AS[key],AI[key],IN[key],SC[key1])*cwssEnv(TI[key1],oDI1[2],oEX1[2],EC[key1],RE[key],P[key])
    
    ## Evaluating Transform data attribute

    if (cTrans=="Yes"):
        
        oIC2 = ["Internal Control Effectiveness","Moderate",IC.get("Moderate")]
        
    else:
        
        oIC2 = ["Internal Control Effectiveness","Limited",IC.get("Limited")]
        
    cwssTrans=cwssBaseF(TI[key1],oAP2[2],oAL2[2],oIC2[2],FC[key1])*cwssAttackS(oRP[2],RL[key2],AV[key],AS[key],AI[key],IN[key],SC[key])*cwssEnv(TI[key1],DI[key1],EX[key1],EC[key1],RE[key],P[key])        
    
    ## Evaluating Transfering data attribute
    
    if (cTransf=="Yes"):
        
        oIC3 = ["Internal Control Effectiveness","Moderate",IC.get("Moderate")]
        
    else:
        
        oIC3 = ["Internal Control Effectiveness","Limited",IC.get("Limited")]
    
    cwssTransf=cwssBaseF(TI[key1],oAP2[2],oAL2[2],oIC3[2],FC[key1])*cwssAttackS(oRP[2],RL[key2],AV[key],AS[key],AI[key],IN[key],SC[key])*cwssEnv(TI[key1],DI[key1],EX[key1],EC[key1],RE[key],P[key])        
    
    ## Evaluating Trust in data attribute
    
    if (cTrust=="Yes"):
        
        #oIC4 = ["Internal Control Effectiveness","Moderate",IC.get("Moderate")]
        oAS1 = ["Authentication Strength","Weak",AS.get("Weak")]
        oAI1 = ["Authentication Instances","Single",AI.get("Single")]
        
    else:
        
        #oIC4 = ["Internal Control Effectiveness","Limited",IC.get("Limited")]
        oAS1 = ["Authentication Strength","Moderate",AS.get("Moderate")]
        oAI1 = ["Authentication Instances","Multiple",AI.get("Multiple")]
    
    cwssTrust=cwssBaseF(TI[key1],oAP2[2],oAL2[2],IC[key],FC[key1])*cwssAttackS(oRP[2],RL[key2],AV[key],oAS1[2],oAI1[2],IN[key],SC[key])*cwssEnv(TI[key1],DI[key1],EX[key1],EC[key1],RE[key],P[key])
        
    ## Evaluating Database Interaction attribute 

    if (cDBint=="Yes"):
        
        oAV2 = ["Access Vector","Private Network",AV.get("Private Network")] 
        #oBI1 = ["Business Impact","High",BI.get("High")]
        oDI3 = ["Likelihood of Discovery","High",DI.get("High")] 
        oEX3 = ["Likelihood of Exploit","High",DI.get("High")]
        
    else:
        
        oAV2 = oAV1
        #oBI1 = ["Business Impact","Low",BI.get("Low")]
        oDI3 = ["Likelihood of Discovery","Low",DI.get("Low")] 
        oEX3 = ["Likelihood of Exploit","Low",DI.get("Low")]
    
    cwssDBint=cwssBaseF(TI[key1],oAP2[2],oAL2[2],IC[key1],FC[key])*cwssAttackS(oRP[2],RL[key2],oAV2[2],AS[key1],AI[key1],IN[key],SC[key])*cwssEnv(TI[key1],oDI3[2],oEX3[2],EC[key1],RE[key1],P[key])

    ## Evaluating Timeout operations attribute

    if (cTime=="Yes"):
        
        oDI9 = ["Likelihood of Discovery","High",DI.get("High")] 
        oEX9 = ["Likelihood of Exploit","High",DI.get("High")]
        
    else:
        
        oDI9 = ["Likelihood of Discovery","Low",DI.get("Low")] 
        oEX9 = ["Likelihood of Exploit","Low",DI.get("Low")]
    
    cwssTime=cwssBaseF(TI[key1],oAP2[2],oAL2[2],oIC3[2],FC[key1])*cwssAttackS(oRP[2],RL[key2],AV[key],AS[key],AI[key],IN[key],SC[key])*cwssEnv(TI[key1],oDI9[2],oEX9[2],EC[key1],RE[key],P[key])
    
    ## Evaluating Max/Min operations attribute

    if (cMaxmin=="Yes"):
        
        oDI10 = ["Likelihood of Discovery","High",DI.get("High")] 
        oEX10 = ["Likelihood of Exploit","High",DI.get("High")]
        
    else:
        
        oDI10 = ["Likelihood of Discovery","Low",DI.get("Low")] 
        oEX10 = ["Likelihood of Exploit","Low",DI.get("Low")]
    
    cwssMaxmin=cwssBaseF(TI[key1],oAP2[2],oAL2[2],oIC3[2],FC[key1])*cwssAttackS(oRP[2],RL[key2],AV[key],AS[key],AI[key],IN[key],SC[key])*cwssEnv(TI[key1],oDI10[2],oEX10[2],EC[key1],RE[key],P[key])
    
    ## Evaluating Call Local Third-party Functions attribute

    if (cCalltpf=="Yes"):
        
        oAV3 = ["Access Vector","Private Network",AV.get("Private Network")] 
        oAS2 = ["Authentication Strength","Moderate",AS.get("Moderate")]
        oAI2 = ["Authentication Instances","Multiple",AI.get("Multiple")]
        oEC1 = ["External Control Effectiveness","Limited",EC.get("Limited")]
        oRE1 = ["Remediation Effort","Extensive",RE.get("Extensive")]
        
    else:
        
        oAV3 = oAV1
        oAS2 = oAS1
        oAI2 = oAI1
        oEC1 = ["External Control Effectiveness","Moderate",EC.get("Moderate")]
        oRE1 = ["Remediation Effort","Moderate",RE.get("Moderate")]
    
    cwssCalltpf=cwssBaseF(TI[key1],oAP2[2],oAL2[2],IC[key1],FC[key])*cwssAttackS(oRP[2],RL[key2],oAV3[2],oAS2[2],oAI2[2],IN[key],SC[key])*cwssEnv(TI[key1],DI[key],EX[key],oEC1[2],oRE1[2],P[key])
    
    ## Evaluating Spoofing Protection attribute

    if (cSpoof=="Yes"):
        
        #oBI2 = ["Business Impact","Low",BI.get("Low")]
        oDI5 = ["Likelihood of Discovery","Low",DI.get("Low")] 
        oEX5 = ["Likelihood of Exploit","Low",DI.get("Low")]
        
    else:
        
        #oBI2 = ["Business Impact","High",BI.get("High")]
        oDI5 = ["Likelihood of Discovery","High",DI.get("High")] 
        oEX5 = ["Likelihood of Exploit","High",DI.get("High")]
    
    cwssSpoof=cwssBaseF(TI[key1],oAP2[2],oAL2[2],oIC3[2],FC[key])*cwssAttackS(oRP[2],RL[key2],AV[key],AS[key],AI[key],IN[key],SC[key])*cwssEnv(TI[key1],oDI5[2],oEX5[2],EC[key1],RE[key],P[key])
    
    ## Evaluating Tampering Protection attribute
    if (cTamper=="Yes"):
        
        #oBI3 = ["Business Impact","Low",BI.get("Low")]
        oDI6 = ["Likelihood of Discovery","Low",DI.get("Low")] 
        oEX6 = ["Likelihood of Exploit","Low",DI.get("Low")]
        
    else:
        
        #oBI3 = ["Business Impact","High",BI.get("High")]
        oDI6 = ["Likelihood of Discovery","High",DI.get("High")] 
        oEX6 = ["Likelihood of Exploit","High",DI.get("High")]
    
    cwssTamper=cwssBaseF(TI[key1],oAP2[2],oAL2[2],oIC3[2],FC[key])*cwssAttackS(oRP[2],RL[key2],AV[key],AS[key],AI[key],IN[key],SC[key])*cwssEnv(TI[key1],oDI6[2],oEX6[2],EC[key1],RE[key],P[key])
    
    ## Evaluating Encryption Protection attribute

    if (cEncryp=="Yes"):
        
        #oBI4 = ["Business Impact","Low",BI.get("Low")]
        oDI7 = ["Likelihood of Discovery","Low",DI.get("Low")] 
        oEX7 = ["Likelihood of Exploit","Low",DI.get("Low")]
        
    else:
        
        #oBI4 = ["Business Impact","High",BI.get("High")]
        oDI7 = ["Likelihood of Discovery","High",DI.get("High")] 
        oEX7 = ["Likelihood of Exploit","High",DI.get("High")]
    
    cwssEncryp=cwssBaseF(TI[key1],oAP2[2],oAL2[2],oIC3[2],FC[key])*cwssAttackS(oRP[2],RL[key2],AV[key],AS[key],AI[key],IN[key],SC[key])*cwssEnv(TI[key1],oDI7[2],oEX7[2],EC[key1],RE[key],P[key])
    
    ## Evaluating Attachments attribute
    
    if (cAttach=="Yes"):
        
        oIN2 = ["Level of Interaction","Automated",IN.get("Automated")]
        oDI8 = ["Likelihood of Discovery","High",DI.get("High")] 
        oEX8 = ["Likelihood of Exploit","High",DI.get("High")]
        
    else:
        
        oIN2 = oIN1
        oDI8 = ["Likelihood of Discovery","Low",DI.get("Low")] 
        oEX8 = ["Likelihood of Exploit","Low",DI.get("Low")]

    cwssAttach=cwssBaseF(TI[key1],oAP2[2],oAL2[2],oIC3[2],FC[key])*cwssAttackS(oRP[2],RL[key2],AV[key],AS[key],AI[key],oIN2[2],SC[key])*cwssEnv(TI[key1],oDI8[2],oEX8[2],EC[key1],RE[key],P[key])    
    
    ## Evaluating Data/File format attribute

    if (cDataf=="DOC" or cDataf=="XLS" or cDataf=="EXE" or cDataf=="SQL" or cDataf=="PDF"):
        
        oSC2 = ["Deployment Scope","Moderate",SC.get("Moderate")]
        oDI_1= ["Likelihood of Discovery","High",DI.get("High")]
        oEX_1= ["Likelihood of Exploit","High",DI.get("High")]  
        
    else:
        
        oSC2 = ["Deployment Scope","Rare",SC.get("Rare")]
        oDI_1 = ["Likelihood of Discovery","Low",DI.get("Low")] 
        oEX_1 = ["Likelihood of Exploit","Low",DI.get("Low")]        

    cwssDataf=cwssBaseF(TI[key1],oAP2[2],oAL2[2],IC[key1],FC[key])*cwssAttackS(oRP[2],RL[key2],AV[key],AS[key],AI[key],IN[key],oSC2[2])*cwssEnv(TI[key1],oDI_1[2],oEX_1[2],EC[key1],RE[key],P[key])

    ## Evaluating Unexpected Error Handling attribute

    if (cUError=="Yes"):
        
        oDI11 = ["Likelihood of Discovery","Low",DI.get("Low")] 
        oEX11 = ["Likelihood of Exploit","Low",DI.get("Low")]
        
    else:
        
        oDI11 = ["Likelihood of Discovery","High",DI.get("High")] 
        oEX11 = ["Likelihood of Exploit","High",DI.get("High")]
    
    cwssUError=cwssBaseF(TI[key1],oAP2[2],oAL2[2],oIC3[2],FC[key])*cwssAttackS(oRP[2],RL[key2],AV[key],AS[key],AI[key],IN[key],SC[key])*cwssEnv(TI[key1],oDI11[2],oEX11[2],EC[key1],RE[key],P[key])
    
    ## Evaluating Call Remote Third-party Functions attribute

    if (cRemote=="Yes"):
        
        oAV4 = ["Access Vector","Internet",AV.get("Internet")] 
        oAS3 = ["Authentication Strength","Moderate",AS.get("Moderate")]
        oAI3 = ["Authentication Instances","Multiple",AI.get("Multiple")]
        oEC2 = ["External Control Effectiveness","None",EC.get("None")]
        oRE2 = ["Remediation Effort","Extensive",RE.get("Extensive")]
        
    else:
        
        oAV4 = oAV1
        oAS3 = oAS1
        oAI3 = oAI1
        oEC2 = ["External Control Effectiveness","Moderate",EC.get("Moderate")]
        oRE2 = ["Remediation Effort","Unknown",RE.get("Unknown")]
    
    cwssRemote=cwssBaseF(TI[key1],oAP2[2],oAL2[2],IC[key1],FC[key])*cwssAttackS(oRP[2],RL[key2],oAV4[2],oAS3[2],oAI3[2],IN[key],SC[key])*cwssEnv(TI[key1],DI[key],EX[key],oEC2[2],oRE2[2],P[key])
    
    ## Evaluating Client/Server installation attribute

    if (cCliSer=="Client"):
        
        oDI12 = ["Likelihood of Discovery","High",DI.get("High")] 
        oEX12 = ["Likelihood of Exploit","High",DI.get("High")]
        oRE4 = ["Remediation Effort","Limited",RE.get("Limited")]
        
    else:
        
        oDI12 = ["Likelihood of Discovery","Low",DI.get("Low")] 
        oEX12 = ["Likelihood of Exploit","Low",DI.get("Low")]
        oRE4 = ["Remediation Effort","Extensive",RE.get("Extensive")]
    
    cwssCliSer=cwssBaseF(TI[key1],oAP2[2],oAL2[2],IC[key],FC[key])*cwssAttackS(oRP[2],RL[key2],AV[key],AS[key],AI[key],IN[key],SC[key])*cwssEnv(TI[key1],oDI12[2],oEX12[2],EC[key1],oRE4[2],P[key])
    
    score = [cwssOwner,cwssUser,cwssLang,cwssUIcom,cwssSanit,cwssTrans,cwssTransf,cwssTrust,cwssDBint,cwssTime,cwssMaxmin,cwssCalltpf,cwssSpoof,cwssTamper,cwssEncryp,cwssAttach,cwssDataf,cwssUError,cwssRemote,cwssCliSer]

    return score

def cwssBaseF(TI,AP,AL,IC,FC):
    
    if (TI > 0):
        fTI=1
        score = (((10 * TI) + (5 * (AP + AL)) + (5 * FC)) * fTI) * 4
    else:
        fTI=0
        score = (((10 * TI) + (5 * (AP + AL)) + (5 * FC)) * fTI) * 4
    
    return score

def cwssAttackS(RP,RL,AV,AS,AI,IN,SC):

    score = ((20 * (RP + RL + AV)) + (20 * SC) + (10 * IN) + (5 * (AS + AI))) / 100

    return score

def cwssEnv(BI,DI,EX,EC,RE,P):

    if (BI>0):
        fBI=1
        score = ((((10 * BI) + (3 * (DI + EX)) + (3 * P) + RE) * fBI) * EC) / 20
    else:
        fBI=0
        score = ((((10 * BI) + (3 * (DI + EX)) + (3 * P) + RE) * fBI) * EC) / 20

    return score



