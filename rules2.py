import logging, sys, traceback

print "Loading Rules..."
#rules.py 
#""" Includes the Rules about the Common Weakness Scoring System and the CWE related to safety attributes

##  Each metric is composed by: ["Value", Weight]
##  Base Finding Metric Group:

TI = {"Critical":1.0,"High":0.9,"Medium":0.6,"Low":0.3,"None":0,"Default":0.6,"Unknown":0.5,"Not Applicable":0.3}
AP = {"Administrator":1.0,"Partially-Privileged User":0.9,"Regular User":0.7,"Guest":0.6,"None":0.1,"Default":0.7,"Unknown":1.0,"Not Applicable":0.1}
AL = {"Application":1.0,"System":0.9,"Network":0.7,"Enterprise":1.0,"Default":0.9,"Unknown":0.5,"Not Applicable":0.5}
IC = {"None":1.0,"Limited":0.9,"Moderate":0.7,"Indirect":0.5,"Best-Available":0.3,"Complete":0,"Default":0.6,"Unknown":0.5,"Not Applicable":0.3}
FC = {"Proven True":1.0,"Proven Locally True":0.8,"Proven False":0,"Default":0.8,"Unknown":0.5,"Not Applicable":1.0}

##  Attack Surface Metric Group:

RP = {"None":1.0,"Guest":0.9,"Regular User":0.7,"Partially-Privileged User":0.6,"Administrator":0.1,"Default":0.7,"Unknown":0.5,"Not Applicable":0.1}
RL = {"System":0.9,"Application":1.0,"Network":0.7,"Enterprise":1.0,"Default":0.9,"Unknown":0.5,"Not Applicable":0.5}
AV = {"Internet":1.0,"Intranet":0.8,"Private Network":0.8,"Adjacent Network":0.7,"Local":0.5,"Physical":0.2,"Default":0.75,"Unknown":0.5,"Not Applicable":0.2}
AS = {"Strong":0.7,"Moderate":0.8,"Weak":0.9,"None":1.0,"Default":0.85,"Unknown":0.5,"Not Applicable":0.5}
AI = {"None":1.0,"Single":0.8,"Multiple":0.5,"Default":0.8,"Unknown":0.5,"Not Applicable":0.5}
IN = {"Automated":1.0,"Limited/Typical":0.9,"Opportunistic":0.3,"High":0.1,"No Interaction":0,"Default":0.55,"Unknown":0.5,"Not Applicable":0.1}
SC = {"All":1.0,"Moderate":0.9,"Rare":0.5,"Potentially Reachable":0.1,"Default":0.7,"Unknown":0.5,"Not Applicable":0.1}

## Environmental Metric Group:

BI = {"Critical":1.0,"High":0.9,"Medium":0.6,"Low":0.3,"None":0,"Default":0.6,"Unknown":0.5,"Not Applicable":0.3}
DI = {"High":1.0,"Medium":0.6,"Low":0.2,"Default":0.6,"Unknown":0.5,"Not Applicable":0.2}
EX = {"High":1.0,"Medium":0.6,"Low":0.2,"None":0,"Default":0.6,"Unknown":0.5,"Not Applicable":0.2}
EC = {"None":1.0,"Limited":0.9,"Moderate":0.7,"Indirect":0.5,"Best-Available":0.3,"Complete":0.1,"Default":0.6,"Unknown":0.5,"Not Applicable":0.1}
RE = {"Extensive":1.0,"Moderate":0.9,"Limited":0.8,"Default":0.9,"Unknown":0.5,"Not Applicable":0.5}
P = {"Widespread":1.0,"High":0.9,"Common":0.8,"Limited":0.7,"Default":0.85,"Unknown":0.5,"Not Applicable":0.5}

cweOwner = ["Administrator","Partially-Privileged User","Regular User","Guest","None","Default","Unknown","Not Applicable"]
cweUser = ["Administrator","Partially-Privileged User","Regular User","Guest","None","Default","Unknown","Not Applicable"]

#http://www.tiobe.com/index.php/content/paperinfo/tpci/index.html
#cweLang = ["C/C++","Java","Visual Basic","C#",".NET","Fortran","PHP","Python","Bash","Ruby","Perl","Javascript","PL/SQL","Matlab"]

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
#cweDataf = ["JDL","RSL","ClassAdd","Submit","SQL","XML","PDF","DOC","XLS","TXT","CSV","RTF","HTML","Binary"]
cweUError = ["Yes","No"]
#cweRemote = ["Yes","No"]
cweClient = ["Yes","No"]
cweWeb = ["Yes","No"]
cweLogB = ["Yes","No"]
cwePrecedents = []

cweAtts = {"Owner":cweOwner,"User":cweUser,"User Interface":cweUIcom,"Sanitize":cweSanit,\
    "Transform Data":cweTrans,"Transfering Data":cweTransf,"Trust":cweTrust,"Database Interaction":cweDBint,\
    "Timeout Operations":cweTime,"Max/Min Operations":cweMaxmin,"Thirdparty Operations":cweCalltpf,"Spoofing":cweSpoof,\
    "Tampering":cweTamper,"Encryption":cweEncryp,"Attachment":cweAttach,\
    "Unexpected Error handling":cweUError,"Client/Server Installation":cweClient, "Web App Service":cweWeb,"Log_Operations":cweLogB}

#logging.basicConfig(filename='reglas.log',level=logging.DEBUG)


def reglas(c):
    
    ## RL = 1 = Application, The entity must be able to have access to an affected application.
    ## or RL = 1 = Enterprise, The entity must have access to a critical piece of enterprise infrastructure, such as a router, switch, DNS, domain controller, firewall, identity server, etc.  
    ## Variable APP stores RL value
    
    NA="Not Applicable"
    DEF="Default"
    APP="Application"

    ## Evaluating Owner attribute  
    
    if (c.cOwner=='Administrator'):

        oTI1 = ["Technical Impact","Critical", TI.get("Critical")] 
        oAP1 = ["Acquired Privilege","Administrator",AP.get("Administrator")]
        oAL1 = ["Acquired Privilege Layer","Enterprise",AL.get("Enterprise")]
        oAV  = ["Access Vector","Intranet",AV.get("Intranet")]
        #oRP1 = ["Required Privilege","Administrator",RP.get("Administrator")]
        oBI1 = oTI1

    elif (c.cOwner=='Partially-Privileged User'):

        oTI1 = ["Technical Impact","High", TI.get("High")]
        oAP1= ["Acquired Privilege","Partially-Privileged User",AP.get("Partially-Privileged User")]
        oAL1 = ["Acquired Privilege Layer","System",AL.get("System")]
        oAV  = ["Access Vector","Private Network",AV.get("Private Network")]
        #oRP1 = ["Required Privilege","Partially-Privileged User",RP.get("Partially-Privileged User")]
        oBI1 = oTI1

    elif (c.cOwner=='Regular User'):
        oTI1 = ["Technical Impact","Medium", TI.get("Medium")]
        oAP1 = ["Acquired Privilege","Regular User",AP.get("Regular User")]
        oAL1 = ["Acquired Privilege Layer","Network",AL.get("Network")]
        oAV  = ["Access Vector","Local",AV.get("Local")]
        #oRP1 = ["Required Privilege","Regular User",RP.get("Regular User")]
        oBI1 = oTI1

    elif (c.cOwner=='Guest'):

        oTI1 = ["Technical Impact","Low", TI.get("Low")]
        oAP1 = ["Acquired Privilege","Guest",AP.get("Guest")]
        oAL1 = ["Acquired Privilege Layer","Unknown",AL.get("Unknown")]
        oAV  = ["Access Vector","Local",AV.get("Local")]
        #oRP1 = ["Required Privilege","Guest",RP.get("Guest")]
        oBI1 = oTI1

    elif (c.cOwner=='None'):

        oTI1 = ["Technical Impact","None", TI.get("None")]
        oAP1 = ["Acquired Privilege","None",AP.get("None")]
        oAL1 = ["Acquired Privilege Layer","Unknown",AL.get("Unknown")]
        oAV  = ["Access Vector","Local",AV.get("Local")]
        #oRP1 = ["Required Privilege","None",RP.get("None")]
        oBI1 = oTI1

    elif (c.cOwner=='Default'):

        oTI1 = ["Technical Impact","Default", TI.get("Default")]
        oAP1 = ["Acquired Privilege","Default",AP.get("Default")]
        oAL1 = ["Acquired Privilege Layer","Default",AL.get("Default")]
        oAV  = ["Access Vector","Local",AV.get("Local")]
        #oRP1 = ["Required Privilege","Default",RP.get("Default")]
        oBI1 = oTI1

    elif (c.cOwner=='Unknown'):

        oTI1 = ["Technical Impact","Unknown", TI.get("Unknown")]
        oAP1 = ["Acquired Privilege","Unknown",AP.get("Unknown")]
        oAL1 = ["Acquired Privilege Layer","Unknown",AL.get("Unknown")]
        oAV  = ["Access Vector","Local",AV.get("Local")]
        #oRP1 = ["Required Privilege","Unknown",RP.get("Unknown")]
        oBI1 = oTI1

    elif (c.cOwner=='Not Applicable'):

        oTI1 = ["Technical Impact","Not Applicable", TI.get("Not Applicable")]
        oAP1 = ["Acquired Privilege","Not Applicable",AP.get("Not Applicable")]
        oAL1 = ["Acquired Privilege Layer","Not Applicable",AL.get("Not Applicable")]
        oAV  = ["Access Vector","Local",AV.get("Local")]
        #oRP1 = ["Required Privilege","Not Applicable",RP.get("Not Applicable")]
        oBI1 = oTI1
        
    #logging.warning('cName= %s, cOwner= %s', c.cName, c.cOwner)
    #logging.warning('Base Finding Group:')
    #logging.warning('TI= %s, AP= %s, AL= %s, IC= %s',oTI1[2],oAP1[2],oAL1[2],1)
    #logging.warning('Base Subscore: %s',cwssBaseF(oTI1[2],oAP1[2],oAL1[2],1,0))
    #logging.warning('--')
    #logging.warning('Attack Surface Group:')
    #logging.warning('RP= %s, RL= %s, AV= %s, AS= %s, AI= %s, IN= %s, SC= %s',RP[NA],RL[APP],oAV[2],AS[NA],AI[NA],IN[NA],SC[NA])
    #logging.warning('AS Subscore: %s',cwssAttackS(RP[NA],RL[APP],oAV[2],AS[NA],AI[NA],IN[NA],SC[NA]))
    #logging.warning('--')
    #logging.warning('Environmental Group:')
    #logging.warning('BI= %s, DI= %s, EX= %s, EC= %s, RE= %s, P= %s',oBI1[2],DI[DEF],EX[DEF],EC[NA],0,P[NA])
    #logging.warning('ENV Subscore: %s',cwssEnv(oBI1[2],DI[DEF],EX[DEF],EC[NA],0,P[NA]))
    #logging.warning('--')
    
                     
    #logging.warning('--')                
    #logging.warning('cUser= %s,cLang= %s,cUIcom= %s,cSanit= %s,cTrans= %s,cTransf= %s,cTrust= %s,cDBint= %s,cTime= %s,cMaxmin= %s,cCalltpf= %s,cSpoof= %s,cTamper= %s,cEncryp= %s,cAttach= %s,cDataf= %s,cUError= %s,cRemote= %s,cCliSer= %s',c.cUser,c.cLang,c.cUIcom,c.cSanit,c.cTrans,c.cTransf,c.cTrust,c.cDBint,c.cTime,c.cMaxmin,c.cCalltpf,c.cSpoof,c.cTamper,c.cEncryp,c.cAttach,c.cDataf,c.cUError,c.cRemote,c.cCliSer)    
    cwssOwner = cwssBaseF(oTI1[2],oAP1[2],oAL1[2],1,0) * cwssAttackS(RP[NA],RL[APP],oAV[2],AS[NA],AI[NA],IN[NA],SC[NA]) * cwssEnv(oBI1[2],DI[DEF],EX[DEF],EC[NA],0,P[NA])
    #if the CWE belong to top25 DI and EX are equal to 1.
    cwssOwner25 = cwssBaseF(oTI1[2],oAP1[2],oAL1[2],1,0) * cwssAttackS(RP[NA],RL[APP],oAV[2],AS[NA],AI[NA],IN[NA],SC[NA]) * cwssEnv(oBI1[2],1,1,EC[NA],0,P[NA])
    #logging.warning('Total Owner Score: %s',cwssOwner)
    #logging.warning('--')
    #logging.warning('--')
    
    ## Evaluating User attribute
    
    if (c.cUser=='Administrator'):
        
        oTI2 = ["Technical Impact","Critical", TI.get("Critical")] 
        #oAP2 = ["Acquired Privilege","Administrator",AP.get("Administrator")]
        oAL2 = ["Acquired Privilege Layer","Enterprise",AL.get("Enterprise")]
        oRP2 = ["Required Privilege","Administrator",RP.get("Administrator")]
        oAV  = ["Access Vector","Intranet",AV.get("Intranet")]
        oAS  = ["Authentication Strength","Moderate",AS.get("Moderate")]
        oAI  = ["Authentication Instances","Single",AI.get("Single")]
        oBI2 = oTI2

    elif (c.cUser=='Partially-Privileged User'):

        oTI2 = ["Technical Impact","High", TI.get("High")]
        #oAP2 = ["Acquired Privilege","Partially-Privileged User",AP.get("Partially-Privileged User")]
        oAL2 = ["Acquired Privilege Layer","System",AL.get("System")]
        oRP2 = ["Required Privilege","Partially-Privileged User",RP.get("Partially-Privileged User")]
        oAV  = ["Access Vector","Private Network",AV.get("Private Network")]
        oAS  = ["Authentication Strength","Moderate",AS.get("Moderate")]
        oAI  = ["Authentication Instances","Single",AI.get("Single")]        
        oBI2 = oTI2

    elif (c.cUser=='Regular User'):

        oTI2 = ["Technical Impact","Medium", TI.get("Medium")]
        #oAP2 = ["Acquired Privilege","Regular User",AP.get("Regular User")]
        oAL2 = ["Acquired Privilege Layer","Network",AL.get("Network")]
        oRP2 = ["Required Privilege","Regular User",RP.get("Regular User")]
        oAV  = ["Access Vector","Local",AV.get("Local")]        
        oAS  = ["Authentication Strength","Moderate",AS.get("Moderate")]
        oAI  = ["Authentication Instances","Single",AI.get("Single")]
        oBI2 = oTI2

    elif (c.cUser=='Guest'):

        oTI2 = ["Technical Impact","Low", TI.get("Low")]
        #oAP2 = ["Acquired Privilege","Guest",AP.get("Guest")]
        oAL2 = ["Acquired Privilege Layer","Unknown",AL.get("Unknown")]
        oRP2 = ["Required Privilege","Guest",RP.get("Guest")]  
        oAV  = ["Access Vector","Local",AV.get("Local")]      
        oAS  = ["Authentication Strength","Moderate",AS.get("Moderate")]
        oAI  = ["Authentication Instances","Multiple",AI.get("Multiple")]
        oBI2 = oTI2

    elif (c.cUser=='None'):

        oTI2 = ["Technical Impact","None", TI.get("None")]
        #oAP2 = ["Acquired Privilege","None",AP.get("None")]
        oAL2 = ["Acquired Privilege Layer","Unknown",AL.get("Unknown")]
        oRP2 = ["Required Privilege","None",RP.get("None")]
        oAV  = ["Access Vector","Local",AV.get("Local")]        
        oAS  = ["Authentication Strength","Moderate",AS.get("Moderate")]
        oAI  = ["Authentication Instances","Multiple",AI.get("Multiple")]
        oBI2 = oTI2

    elif (c.cUser=='Default'):

        oTI2 = ["Technical Impact","Default", TI.get("Default")]
        #oAP2 = ["Acquired Privilege","Default",AP.get("Default")]
        oAL2 = ["Acquired Privilege Layer","Default",AL.get("Default")]
        oRP2 = ["Required Privilege","Default",RP.get("Default")]     
        oAV  = ["Access Vector","Local",AV.get("Local")]
        oAS  = ["Authentication Strength","Moderate",AS.get("Moderate")] 
        oAI  = ["Authentication Instances","Multiple",AI.get("Multiple")]  
        oBI2 = oTI2

    elif (c.cUser=='Unknown'):

        oTI2 = ["Technical Impact","Unknown", TI.get("Unknown")]
        #oAP2 = ["Acquired Privilege","Unknown",AP.get("Unknown")]
        oAL2 = ["Acquired Privilege Layer","Unknown",AL.get("Unknown")]
        oRP2 = ["Required Privilege","Unknown",RP.get("Unknown")]     
        oAV  = ["Access Vector","Local",AV.get("Local")]   
        oAS  = ["Authentication Strength","Moderate",AS.get("Moderate")]
        oAI  = ["Authentication Instances","Multiple",AI.get("Multiple")]
        oBI2 = oTI2

    elif (c.cUser=='Not Applicable'):

        oTI2 = ["Technical Impact","Not Applicable", TI.get("Not Applicable")]
        #oAP2 = ["Acquired Privilege","Not Applicable",AP.get("Not Applicable")]
        oAL2 = ["Acquired Privilege Layer","Not Applicable",AL.get("Not Applicable")]
        oRP2 = ["Required Privilege","Not Applicable",RP.get("Not Applicable")]       
        oAV  = ["Access Vector","Local",AV.get("Local")] 
        oAS  = ["Authentication Strength","Not Applicable",AS.get("Not Applicable")]
        oAI  = ["Authentication Instances","Not Applicable",AI.get("Not Applicable")]
        oBI2 = oTI2

    #logging.warning('cName= %s, cUser= %s, ', cName, cUser)
    #logging.warning('Base Finding Group:')
    #logging.warning('TI= %s, AP= %s, AL= %s, IC= %s',oTI2[2],AP[NA],oAL2[2],IC[NA])
    #logging.warning('Base Subscore: %s',cwssBaseF(oTI1[2],AP[NA],oAL2[2],IC[NA],0))
    #logging.warning('--')
    #logging.warning('Attack Surface Group:')
    #logging.warning('RP= %s, RL= %s, AV= %s, AS= %s, AI= %s, IN= %s, SC= %s',oRP2[2],RL[APP],oAV[2],oAS[2],oAI[2],IN[NA],SC[NA])
    #logging.warning('AS Subscore: %s',cwssAttackS(oRP2[2],RL[APP],oAV[2],oAS[2],oAI[2],IN[NA],SC[NA]))
    #logging.warning('--')
    #logging.warning('Environmental Group:')
    #logging.warning('BI= %s, DI= %s, EX= %s, EC= %s, RE= %s, P= %s',oBI1[2],DI[DEF],EX[DEF],EC[NA],RE[NA],P[NA])
    #logging.warning('ENV Subscore: %s',cwssEnv(oBI1[2],DI[DEF],EX[DEF],EC[NA],RE[NA],P[NA]))
    #logging.warning('--')                   
    #logging.warning('--')              
    #logging.warning('cUser= %s,cLang= %s,cUIcom= %s,cSanit= %s,cTrans= %s,cTransf= %s,cTrust= %s,cDBint= %s,cTime= %s,cMaxmin= %s,cCalltpf= %s,cSpoof= %s,cTamper= %s,cEncryp= %s,cAttach= %s,cDataf= %s,cUError= %s,cRemote= %s,cCliSer= %s',,cUser,cLang,cUIcom,cSanit,cTrans,cTransf,cTrust,cDBint,cTime,cMaxmin,cCalltpf,cSpoof,cTamper,cEncryp,cAttach,cDataf,cUError,cRemote,cCliSer)    
    cwssUser=cwssBaseF(oTI2[2],AP[NA],oAL2[2],1,0) * cwssAttackS(oRP2[2],RL[APP],oAV[2],oAS[2],oAI[2],IN[NA],SC[NA]) * cwssEnv(oBI2[2],DI[DEF],EX[DEF],EC[NA],0,P[NA])
    #if the CWE belong to top25 DI and EX are equal to 1.
    cwssUser25=cwssBaseF(oTI2[2],AP[NA],oAL2[2],1,0) * cwssAttackS(oRP2[2],RL[APP],oAV[2],oAS[2],oAI[2],IN[NA],SC[NA]) * cwssEnv(oBI2[2],1,1,EC[NA],0,P[NA])
    #logging.warning('Total User Score: %s',cwssUser)
    #logging.warning('--')
    #logging.warning('--') 
        
    ## Evaluating Programming Language attribute

    #if (cLang=="C/C++" or cLang=="Java" or cLang=="Fortran" or cLang=="Visual Basic" or cLang=="C#" or cLang==".NET" or cLang=="Matlab"):
        
        #oTI  = ["Technical Impact","Critical", TI.get("Critical")]
        #oSC1 = ["Deployment Scope","Moderate",SC.get("Moderate")]
        #oDI4 = ["Likelihood of Discovery","Low",DI.get("Low")] 
        #oEX4 = ["Likelihood of Exploit","Low",DI.get("Low")]
        #oRE3 = ["Remediation Effort","Moderate",RE.get("Moderate")]
        
    #elif (cLang=="Bash" or cLang=="Python" or cLang=="Javascript" or cLang=="PHP" or cLang=="PL/SQL" or cLang=="Ruby"):
        
        #oTI  = ["Technical Impact","High", TI.get("High")]
        #oSC1 = ["Deployment Scope","Rare",SC.get("Rare")]
        #oDI4 = ["Likelihood of Discovery","Medium",DI.get("Medium")]
        #oEX4 = ["Likelihood of Exploit","Medium",DI.get("Medium")]
        #oRE3 = ["Remediation Effort","Limited",RE.get("Limited")]
        
    #else:
        
        #oTI  = ["Technical Impact","Default", TI.get("Default")]
        #oSC1 = ["Deployment Scope","Unknown",SC.get("Unknown")]
        #oDI4 = ["Likelihood of Discovery","Unknown",DI.get("Unknown")] 
        #oEX4 = ["Likelihood of Exploit","Unknown",DI.get("Unknown")]
        #oRE3 = ["Remediation Effort","Unknown",RE.get("Unknown")]
    
    #cwssLang=cwssBaseF(oTI[2],AP[NA],AL[NA],IC[DEF],0)*cwssAttackS(RP[NA],RL[APP],AV[NA],AS[DEF],AI[NA],IN[NA],oSC1[2])*cwssEnv(oTI[2],oDI4[2],oEX4[2],EC[DEF],oRE3[2],P[NA])
    
    ## Evaluating User Interface Command attribute

    if (c.cUIcom=="Yes"):
        
        oTI  = ["Technical Impact","Critical", TI.get("Critical")]
        oAV1 = ["Access Vector","Local",AV.get("Local")] 
        oIN1 = ["Level of Interaction","Opportunistic",IN.get("Opportunistic")]
        oDI2 = ["Likelihood of Discovery","High",DI.get("High")] 
        oEX2 = ["Likelihood of Exploit","High",DI.get("High")]
        oAS  = ["Authentication Strength","Moderate",AS.get("Moderate")]
        oAI  = ["Authentication Instances","Single",AI.get("Single")]
        oRE  = ["Remediation Effort","Limited",RE.get("Limited")]
    
    else:
        
        oTI  = ["Technical Impact","High", TI.get("High")]
        oAV1 = ["Access Vector","Adjacent Network",AV.get("Adjacent Network")] 
        oIN1 = ["Level of Interaction","Automated",IN.get("Automated")]
        oDI2 = ["Likelihood of Discovery","Medium",DI.get("Medium")] 
        oEX2 = ["Likelihood of Exploit","Medium",DI.get("Medium")]
        oAS  = ["Authentication Strength","Strong",AS.get("Strong")]
        oAI  = ["Authentication Instances","Single",AI.get("Single")]
        oRE  = ["Remediation Effort","Moderate",RE.get("Moderate")]

    cwssUIcom=cwssBaseF(oTI[2],AP[NA],AL[NA],IC[DEF],0)*cwssAttackS(RP[NA],RL[APP],oAV1[2],oAS[2],oAI[2],oIN1[2],SC[DEF])*cwssEnv(oTI[2],DI[DEF],EX[DEF],EC[DEF],0,P[NA])
    #if the CWE belong to top25 DI and EX are equal to 1.
    cwssUIcom25=cwssBaseF(oTI[2],AP[NA],AL[NA],IC[DEF],0)*cwssAttackS(RP[NA],RL[APP],oAV1[2],oAS[2],oAI[2],oIN1[2],SC[DEF])*cwssEnv(oTI[2],1,1,EC[DEF],0,P[NA])
    
    ## Evaluating Sanitize data attribute

    if (c.cSanit=="Yes"):
        
        oTI  = ["Technical Impact","Low", TI.get("Low")]
        oIC1 = ["Internal Control Effectiveness","Moderate",IC.get("Moderate")]
        oDI1 = ["Likelihood of Discovery","Low",DI.get("Low")] 
        oEX1 = ["Likelihood of Exploit","Low",DI.get("Low")]
        
    else:
        
        oTI  = ["Technical Impact","High", TI.get("High")]
        oIC1 = ["Internal Control Effectiveness","Limited",IC.get("Limited")]
        oDI1 = ["Likelihood of Discovery","High",DI.get("High")] 
        oEX1 = ["Likelihood of Exploit","High",DI.get("High")]
    
    cwssSanit=cwssBaseF(oTI[2],AP[NA],AL[NA],oIC1[2],0)*cwssAttackS(RP[DEF],RL[APP],AV[NA],AS[NA],AI[NA],IN[NA],SC[DEF])*cwssEnv(oTI[2],DI[DEF],EX[DEF],EC[DEF],0,P[NA])
    #if the CWE belong to top25 DI and EX are equal to 1.
    cwssSanit25=cwssBaseF(oTI[2],AP[NA],AL[NA],oIC1[2],0)*cwssAttackS(RP[DEF],RL[APP],AV[NA],AS[NA],AI[NA],IN[NA],SC[DEF])*cwssEnv(oTI[2],1,1,EC[DEF],0,P[NA])
    
    ## Evaluating Transform data attribute

    if (c.cTrans=="Yes"):
        
        oTI  = ["Technical Impact","High", TI.get("High")]
        oIC2 = ["Internal Control Effectiveness","Moderate",IC.get("Moderate")]
        
    else:
        
        oTI  = ["Technical Impact","Low", TI.get("Low")]
        oIC2 = ["Internal Control Effectiveness","Limited",IC.get("Limited")]
        
    cwssTrans=cwssBaseF(oTI[2],AP[NA],AL[NA],oIC2[2],0)*cwssAttackS(RP[NA],RL[APP],AV[NA],AS[NA],AI[NA],IN[NA],SC[NA])*cwssEnv(oTI[2],DI[DEF],EX[DEF],EC[NA],0,P[NA])        
    #if the CWE belong to top25 DI and EX are equal to 1.
    cwssTrans25=cwssBaseF(oTI[2],AP[NA],AL[NA],oIC2[2],0)*cwssAttackS(RP[NA],RL[APP],AV[NA],AS[NA],AI[NA],IN[NA],SC[NA])*cwssEnv(oTI[2],1,1,EC[NA],0,P[NA])
    ## Evaluating Transfering data attribute
    
    if (c.cTransf=="Yes"):
        
        oTI  = ["Technical Impact","High", TI.get("High")]
        oIC3 = ["Internal Control Effectiveness","Moderate",IC.get("Moderate")]
        
    else:
        
        oTI  = ["Technical Impact","Low", TI.get("Low")]
        oIC3 = ["Internal Control Effectiveness","Limited",IC.get("Limited")]
    
    cwssTransf=cwssBaseF(oTI[2],AP[NA],AL[NA],oIC3[2],0)*cwssAttackS(RP[NA],RL[APP],AV[NA],AS[NA],AI[NA],IN[NA],SC[NA])*cwssEnv(oTI[2],DI[DEF],EX[DEF],EC[NA],0,P[NA])        
    #if the CWE belong to top25 DI and EX are equal to 1.
    cwssTransf25=cwssBaseF(oTI[2],AP[NA],AL[NA],oIC3[2],0)*cwssAttackS(RP[NA],RL[APP],AV[NA],AS[NA],AI[NA],IN[NA],SC[NA])*cwssEnv(oTI[2],1,1,EC[NA],0,P[NA])
    
    ## Evaluating Trust in data attribute
    
    if (c.cTrust=="Yes"):
        
        oTI  = ["Technical Impact","Low", TI.get("Low")]
        oIC4 = ["Internal Control Effectiveness","Moderate",IC.get("Moderate")]
        oAS1 = ["Authentication Strength","Weak",AS.get("Weak")]
        oAI1 = ["Authentication Instances","Single",AI.get("Single")]
               
    else:
        
        oTI  = ["Technical Impact","High", TI.get("High")]
        oIC4 = ["Internal Control Effectiveness","Limited",IC.get("Limited")]
        oAS1 = ["Authentication Strength","Moderate",AS.get("Moderate")]
        oAI1 = ["Authentication Instances","Multiple",AI.get("Multiple")]
            
    cwssTrust=cwssBaseF(oTI[2],AP[NA],AL[NA],oIC4[2],0)*cwssAttackS(RP[NA],RL[APP],AV[NA],oAS1[2],oAI1[2],IN[NA],SC[NA])*cwssEnv(oTI[2],DI[DEF],EX[DEF],EC[NA],0,P[NA])
    #if the CWE belong to top25 DI and EX are equal to 1.
    cwssTrust25=cwssBaseF(oTI[2],AP[NA],AL[NA],oIC4[2],0)*cwssAttackS(RP[NA],RL[APP],AV[NA],oAS1[2],oAI1[2],IN[NA],SC[NA])*cwssEnv(oTI[2],1,1,EC[NA],0,P[NA])
        
    ## Evaluating Database Interaction attribute 

    if (c.cDBint=="Yes"):
        
        oTI  = ["Technical Impact","High", TI.get("High")]
        oAV2 = ["Access Vector","Private Network",AV.get("Private Network")] 
        oDI3 = ["Likelihood of Discovery","High",DI.get("High")] 
        oEX3 = ["Likelihood of Exploit","High",DI.get("High")]
        #oIN  = ["Level of Interaction","Automated",IN.get("Automated")]
        
    else:
        
        oTI  = ["Technical Impact","Low", TI.get("Low")]
        oAV2 = oAV1
        oDI3 = ["Likelihood of Discovery","Low",DI.get("Low")] 
        oEX3 = ["Likelihood of Exploit","Low",DI.get("Low")]
        #oIN  = ["Level of Interaction","Unknown",IN.get("Unknown")]
    
    cwssDBint=cwssBaseF(oTI[2],AP[NA],oAL2[2],IC[DEF],0)*cwssAttackS(oRP2[2],RL[APP],oAV2[2],AS[DEF],AI[DEF],IN[DEF],SC[NA])*cwssEnv(oTI[2],DI[DEF],EX[DEF],EC[DEF],0,P[NA])
    #if the CWE belong to top25 DI and EX are equal to 1.
    cwssDBint25=cwssBaseF(oTI[2],AP[NA],oAL2[2],IC[DEF],0)*cwssAttackS(oRP2[2],RL[APP],oAV2[2],AS[DEF],AI[DEF],IN[DEF],SC[NA])*cwssEnv(oTI[2],1,1,EC[DEF],0,P[NA])

    ## Evaluating Timeout operations attribute

    if (c.cTime=="Yes"):
        
        oTI  = ["Technical Impact","High", TI.get("High")]
        oDI9 = ["Likelihood of Discovery","High",DI.get("High")] 
        oEX9 = ["Likelihood of Exploit","High",DI.get("High")]
        oIN  = ["Level of Interaction","Automated",IN.get("Automated")]
        #oIC  = oIC3
        
    else:
        
        oTI  = ["Technical Impact","Low", TI.get("Low")]
        oDI9 = ["Likelihood of Discovery","Low",DI.get("Low")] 
        oEX9 = ["Likelihood of Exploit","Low",DI.get("Low")]
        oIN  = ["Level of Interaction","Unknown",IN.get("Unknown")]
        #oIC  = oIC3
    
    cwssTime=cwssBaseF(oTI[2],AP[NA],AL[NA],oIC3[2],0)*cwssAttackS(RP[NA],RL[APP],AV[NA],AS[NA],AI[NA],oIN[2],SC[NA])*cwssEnv(oTI[2],DI[DEF],EX[DEF],EC[DEF],0,P[NA])
    #if the CWE belong to top25 DI and EX are equal to 1.
    cwssTime25=cwssBaseF(oTI[2],AP[NA],AL[NA],oIC3[2],0)*cwssAttackS(RP[NA],RL[APP],AV[NA],AS[NA],AI[NA],oIN[2],SC[NA])*cwssEnv(oTI[2],1,1,EC[DEF],0,P[NA])
    
    ## Evaluating Max/Min operations attribute

    if (c.cMaxmin=="Yes"):
        
        oTI  = ["Technical Impact","High", TI.get("High")]
        oDI10 = ["Likelihood of Discovery","High",DI.get("High")] 
        oEX10 = ["Likelihood of Exploit","High",DI.get("High")]
        oIN  = ["Level of Interaction","Automated",IN.get("Automated")]
        
    else:
        
        oTI  = ["Technical Impact","Low", TI.get("Low")]
        oDI10 = ["Likelihood of Discovery","Low",DI.get("Low")] 
        oEX10 = ["Likelihood of Exploit","Low",DI.get("Low")]
        oIN  = ["Level of Interaction","Unknown",IN.get("Unknown")]
    
    cwssMaxmin=cwssBaseF(oTI[2],AP[NA],AL[NA],oIC3[2],0)*cwssAttackS(RP[NA],RL[APP],AV[NA],AS[NA],AI[NA],oIN[2],SC[NA])*cwssEnv(oTI[2],DI[DEF],EX[DEF],EC[DEF],0,P[NA])
    #if the CWE belong to top25 DI and EX are equal to 1.
    cwssMaxmin25=cwssBaseF(oTI[2],AP[NA],AL[NA],oIC3[2],0)*cwssAttackS(RP[NA],RL[APP],AV[NA],AS[NA],AI[NA],oIN[2],SC[NA])*cwssEnv(oTI[2],1,1,EC[DEF],0,P[NA])
    
    ## Evaluating Call Local Third-party Functions attribute

    if (c.cCalltpf=="Yes"):
        
        oTI  = ["Technical Impact","High", TI.get("High")]
        oAV3 = ["Access Vector","Private Network",AV.get("Private Network")] 
        oAS2 = ["Authentication Strength","Moderate",AS.get("Moderate")]
        oAI2 = ["Authentication Instances","Multiple",AI.get("Multiple")]
        oEC1 = ["External Control Effectiveness","Limited",EC.get("Limited")]
        oRE1 = ["Remediation Effort","Extensive",RE.get("Extensive")]
        oIN  = ["Level of Interaction","Automated",IN.get("Automated")]
        
    else:
        
        oTI  = ["Technical Impact","Low", TI.get("Low")]
        oAV3 = oAV1
        oAS2 = oAS1
        oAI2 = oAI1
        oEC1 = ["External Control Effectiveness","Moderate",EC.get("Moderate")]
        oRE1 = ["Remediation Effort","Moderate",RE.get("Moderate")]
        oIN  = ["Level of Interaction","No Interaction",IN.get("No Interaction")]
    
    cwssCalltpf=cwssBaseF(oTI[2],AP[NA],AL[NA],IC[DEF],0)*cwssAttackS(oRP2[2],RL[APP],oAV3[2],oAS2[2],oAI2[2],oIN[2],SC[NA])*cwssEnv(oTI[2],DI[DEF],EX[DEF],oEC1[2],0,P[NA])
    #if the CWE belong to top25 DI and EX are equal to 1.
    cwssCalltpf25=cwssBaseF(oTI[2],AP[NA],AL[NA],IC[DEF],0)*cwssAttackS(oRP2[2],RL[APP],oAV3[2],oAS2[2],oAI2[2],oIN[2],SC[NA])*cwssEnv(oTI[2],1,1,oEC1[2],0,P[NA])
    
    ## Evaluating Spoofing Protection attribute

    if (c.cSpoof=="Yes"):
        
        oTI  = ["Technical Impact","Low", TI.get("Low")]
        oDI5 = ["Likelihood of Discovery","Low",DI.get("Low")] 
        oEX5 = ["Likelihood of Exploit","Low",DI.get("Low")]
        oAP  = ["Acquired Privilege","Not Applicable",AP.get("Not Applicable")]
         
    else:
        
        oTI  = ["Technical Impact","High", TI.get("High")]
        oDI5 = ["Likelihood of Discovery","High",DI.get("High")] 
        oEX5 = ["Likelihood of Exploit","High",DI.get("High")]
        oAP  = oAP1
    
    cwssSpoof=cwssBaseF(oTI[2],oAP[2],AL[NA],oIC3[2],0)*cwssAttackS(RP[NA],RL[APP],AV[NA],AS[NA],AI[NA],IN[NA],SC[NA])*cwssEnv(oTI[2],DI[DEF],EX[DEF],EC[NA],0,P[NA])
    #if the CWE belong to top25 DI and EX are equal to 1.
    cwssSpoof25=cwssBaseF(oTI[2],oAP[2],AL[NA],oIC3[2],0)*cwssAttackS(RP[NA],RL[APP],AV[NA],AS[NA],AI[NA],IN[NA],SC[NA])*cwssEnv(oTI[2],1,1,EC[NA],0,P[NA])
    
    ## Evaluating Tampering Protection attribute
    if (c.cTamper=="Yes"):
        
        oTI  = ["Technical Impact","Low", TI.get("Low")]
        oDI6 = ["Likelihood of Discovery","Low",DI.get("Low")] 
        oEX6 = ["Likelihood of Exploit","Low",DI.get("Low")]
        
    else:
        
        oTI  = ["Technical Impact","High", TI.get("High")]
        oDI6 = ["Likelihood of Discovery","High",DI.get("High")] 
        oEX6 = ["Likelihood of Exploit","High",DI.get("High")]
    
    cwssTamper=cwssBaseF(oTI[2],AP[NA],AL[NA],oIC3[2],0)*cwssAttackS(RP[NA],RL[APP],AV[NA],AS[NA],AI[NA],IN[NA],SC[NA])*cwssEnv(oTI[2],DI[DEF],EX[DEF],EC[NA],0,P[NA])
    #if the CWE belong to top25 DI and EX are equal to 1.
    cwssTamper25=cwssBaseF(oTI[2],AP[NA],AL[NA],oIC3[2],0)*cwssAttackS(RP[NA],RL[APP],AV[NA],AS[NA],AI[NA],IN[NA],SC[NA])*cwssEnv(oTI[2],1,1,EC[NA],0,P[NA])
    
    ## Evaluating Encryption Protection attribute

    if (c.cEncryp=="Yes"):
        
        oTI  = ["Technical Impact","Low", TI.get("Low")]
        oDI7 = ["Likelihood of Discovery","Low",DI.get("Low")] 
        oEX7 = ["Likelihood of Exploit","Low",DI.get("Low")]
        
    else:
        
        oTI  = ["Technical Impact","High", TI.get("High")]
        oDI7 = ["Likelihood of Discovery","High",DI.get("High")] 
        oEX7 = ["Likelihood of Exploit","High",DI.get("High")]
    
    cwssEncryp=cwssBaseF(oTI[2],AP[DEF],AL[DEF],oIC3[2],0)*cwssAttackS(RP[NA],RL[APP],AV[NA],AS[NA],AI[NA],IN[NA],SC[NA])*cwssEnv(oTI[2],DI[DEF],EX[DEF],EC[NA],0,P[NA])
    #if the CWE belong to top25 DI and EX are equal to 1.
    cwssEncryp25=cwssBaseF(oTI[2],AP[DEF],AL[DEF],oIC3[2],0)*cwssAttackS(RP[NA],RL[APP],AV[NA],AS[NA],AI[NA],IN[NA],SC[NA])*cwssEnv(oTI[2],1,1,EC[NA],0,P[NA])
    
    ## Evaluating Attachments attribute
    
    if (c.cAttach=="Yes"):
        
        oTI  = ["Technical Impact","High", TI.get("High")]
        oIN2 = ["Level of Interaction","Automated",IN.get("Automated")]
        oDI8 = ["Likelihood of Discovery","High",DI.get("High")] 
        oEX8 = ["Likelihood of Exploit","High",DI.get("High")]
        
    else:
        
        oTI  = ["Technical Impact","Low", TI.get("Low")]
        oIN2 = ["Level of Interaction","High",IN.get("High")]
        oDI8 = ["Likelihood of Discovery","Low",DI.get("Low")] 
        oEX8 = ["Likelihood of Exploit","Low",DI.get("Low")]

    cwssAttach=cwssBaseF(oTI[2],AP[NA],AL[NA],oIC3[2],0)*cwssAttackS(RP[NA],RL[APP],AV[NA],AS[NA],AI[NA],oIN2[2],SC[NA])*cwssEnv(oTI[2],DI[DEF],EX[DEF],EC[NA],0,P[NA])    
    #if the CWE belong to top25 DI and EX are equal to 1.
    cwssAttach25=cwssBaseF(oTI[2],AP[NA],AL[NA],oIC3[2],0)*cwssAttackS(RP[NA],RL[APP],AV[NA],AS[NA],AI[NA],oIN2[2],SC[NA])*cwssEnv(oTI[2],1,1,EC[NA],0,P[NA])
    

    ## Evaluating Unexpected Error Handling attribute

    if (c.cUError=="Yes"):
        
        oTI   = ["Technical Impact","Low", TI.get("Low")]
        oDI11 = ["Likelihood of Discovery","Low",DI.get("Low")] 
        oEX11 = ["Likelihood of Exploit","Low",DI.get("Low")]
        oIC   = ["Internal Control Effectiveness", "Moderate", IC.get("Moderate")] 
        
    else:
        
        oTI  = ["Technical Impact","High", TI.get("High")]
        oDI11 = ["Likelihood of Discovery","High",DI.get("High")] 
        oEX11 = ["Likelihood of Exploit","High",DI.get("High")]
        oIC   = ["Internal Control Effectiveness", "Limited", IC.get("Limited")]
    
    cwssUError=cwssBaseF(oTI[2],AP[NA],AL[NA],oIC[2],0)*cwssAttackS(RP[NA],RL[APP],AV[NA],AS[NA],AI[NA],IN[NA],SC[NA])*cwssEnv(oTI[2],DI[DEF],EX[DEF],EC[DEF],0,P[NA])
    #if the CWE belong to top25 DI and EX are equal to 1.
    cwssUError25=cwssBaseF(oTI[2],AP[NA],AL[NA],oIC[2],0)*cwssAttackS(RP[NA],RL[APP],AV[NA],AS[NA],AI[NA],IN[NA],SC[NA])*cwssEnv(oTI[2],1,1,EC[DEF],0,P[NA])
   
    ## Evaluating Client/Server installation attribute

    if (c.cCliSer=="Client"):
        
        oTI  = ["Technical Impact","Low", TI.get("Low")]
        oDI12 = ["Likelihood of Discovery","High",DI.get("High")] 
        oEX12 = ["Likelihood of Exploit","High",DI.get("High")]
        oRE4 = ["Remediation Effort","Limited",RE.get("Limited")]
        # AL == AL for USER
        oAL = oAL2
        oAV = ["Access Vector","Local",AV.get("Local")] 
        
    else:
        
        oTI  = ["Technical Impact","High", TI.get("High")]
        oDI12 = ["Likelihood of Discovery","Low",DI.get("Low")] 
        oEX12 = ["Likelihood of Exploit","Low",DI.get("Low")]
        oRE4 = ["Remediation Effort","Extensive",RE.get("Extensive")]
        oAL = oAL2
        oAV = ["Access Vector","Intranet",AV.get("Intranet")] 
    
    cwssCliSer=cwssBaseF(oTI[2],AP[NA],oAL[2],IC[NA],0)*cwssAttackS(RP[NA],RL[APP],AV[NA],AS[NA],AI[NA],IN[NA],SC[NA])*cwssEnv(oTI[2],DI[DEF],EX[DEF],EC[DEF],0,P[NA])
    #if the CWE belong to top25 DI and EX are equal to 1.
    cwssCliSer25=cwssBaseF(oTI[2],AP[NA],oAL[2],IC[NA],0)*cwssAttackS(RP[NA],RL[APP],AV[NA],AS[NA],AI[NA],IN[NA],SC[NA])*cwssEnv(oTI[2],1,1,EC[DEF],0,P[NA])

    ## Evaluating Web attribute

    if (c.cWeb=="Yes"):
        
        oTI  = ["Technical Impact","High", TI.get("High")]
        oAV4 = ["Access Vector","Internet",AV.get("Internet")] 
        oAS3 = ["Authentication Strength","Moderate",AS.get("Moderate")]
        oAI3 = ["Authentication Instances","Multiple",AI.get("Multiple")]
        oEC2 = ["External Control Effectiveness","None",EC.get("None")]
        oRE2 = ["Remediation Effort","Extensive",RE.get("Extensive")]
        # RP == RP for User
        oRP = oRP2 
        
    else:
        
        oTI  = ["Technical Impact","Low", TI.get("Low")]
        oAV4 = oAV1
        oAS3 = oAS1
        oAI3 = oAI1
        oEC2 = ["External Control Effectiveness","Moderate",EC.get("Moderate")]
        oRE2 = ["Remediation Effort","Unknown",RE.get("Unknown")]
        # RP == RP for User
        oRP = oRP2 
    
    cwssWeb=cwssBaseF(oTI[2],AP[NA],AL[NA],IC[DEF],0)*cwssAttackS(oRP[2],RL[APP],oAV4[2],oAS3[2],oAI3[2],IN[NA],SC[NA])*cwssEnv(oTI[2],DI[DEF],EX[DEF],oEC2[2],0,P[NA])
    #if the CWE belong to top25 DI and EX are equal to 1.
    cwssWeb25=cwssBaseF(oTI[2],AP[NA],AL[NA],IC[DEF],0)*cwssAttackS(oRP[2],RL[APP],oAV4[2],oAS3[2],oAI3[2],IN[NA],SC[NA])*cwssEnv(oTI[2],1,1,oEC2[2],0,P[NA])

## Evaluating Log/Backup attribute

    if (c.cLogB=="Yes"):
        
        oTI  = ["Technical Impact","High", TI.get("High")]
        oAV4 = ["Access Vector","Local",AV.get("Local")] 
        oAS3 = ["Authentication Strength","Moderate",AS.get("Moderate")]
        oAI3 = ["Authentication Instances","Multiple",AI.get("Multiple")]
        oEC2 = ["External Control Effectiveness","None",EC.get("None")]
        oRE2 = ["Remediation Effort","Extensive",RE.get("Extensive")]
        # RP == RP for User
        oRP = oRP2 
        
    else:
        
        oTI  = ["Technical Impact","Low", TI.get("Low")]
        oAV4 = oAV1
        oAS3 = oAS1
        oAI3 = oAI1
        oEC2 = ["External Control Effectiveness","Moderate",EC.get("Moderate")]
        oRE2 = ["Remediation Effort","Unknown",RE.get("Unknown")]
        # RP == RP for User
        oRP = oRP2 
    
    cwssLogB=cwssBaseF(oTI[2],AP[NA],AL[NA],IC[DEF],0)*cwssAttackS(oRP[2],RL[APP],oAV4[2],oAS3[2],oAI3[2],IN[NA],SC[NA])*cwssEnv(oTI[2],DI[DEF],EX[DEF],oEC2[2],0,P[NA])
    #if the CWE belong to top25 DI and EX are equal to 1.
    cwssLogB25=cwssBaseF(oTI[2],AP[NA],AL[NA],IC[DEF],0)*cwssAttackS(oRP[2],RL[APP],oAV4[2],oAS3[2],oAI3[2],IN[NA],SC[NA])*cwssEnv(oTI[2],1,1,oEC2[2],0,P[NA])
        
    score = [cwssOwner,cwssUser,cwssUIcom,cwssSanit,cwssTrans,cwssTransf,cwssTrust,cwssDBint,cwssTime,cwssMaxmin,cwssCalltpf,cwssSpoof,cwssTamper,cwssEncryp,cwssAttach,cwssUError,cwssCliSer,cwssWeb,cwssLogB,\
             cwssOwner25,cwssUser25,cwssUIcom25,cwssSanit25,cwssTrans25,cwssTransf25,cwssTrust25,cwssDBint25,cwssTime25,cwssMaxmin25,cwssCalltpf25,cwssSpoof25,cwssTamper25,cwssEncryp25,cwssAttach25,cwssUError25,\
             cwssCliSer25,cwssWeb25,cwssLogB25]

    return score

def cwssBaseF(TI,AP,AL,IC,FC):
    
    if (TI > 0):
        fTI=1
        score = ((12.5 * TI) + (6.25 * (AP + AL))) * fTI * IC * 4
    else:
        score = 0
    
    return score

def cwssAttackS(RP,RL,AV,AS,AI,IN,SC):
    
    score = (20 * (RP + RL + AV) + (20 * SC) + (10 * IN) + (5 * (AS + AI))) / 100

    return score

def cwssEnv(BI,DI,EX,EC,RE,P):

    if (BI>0):
        fBI=1
        score = (((10.25 * BI) + (3.25 * (DI + EX)) + (3.25 * P)) * fBI * EC) / 20
    else:        
        score = 0

    return score

print "Rules Loaded!!!"
#raw_input()