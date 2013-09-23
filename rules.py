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
#FC = {"Proven True":1.0,"Proven Locally True":0.8,"Proven False":0,"Default":0.8,"Unknown":0.5,"Not Applicable":1.0}

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
#RE = {"Extensive":1.0,"Moderate":0.9,"Limited":0.8,"Default":0.9,"Unknown":0.5,"Not Applicable":0.5}
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
cweClient = ["Client","Server"]
cweWeb = ["Yes","No"]
cweLogB = ["Yes","No"]
cwePrecedents = []

cweAtts = {"Owner":cweOwner,"User":cweUser,"User Interface":cweUIcom,"Sanitize":cweSanit,\
    "Transform Data":cweTrans,"Transfering Data":cweTransf,"Trust":cweTrust,"Database Interaction":cweDBint,\
    "Timeout Operations":cweTime,"Maxmin Operations":cweMaxmin,"Thirdparty Operations":cweCalltpf,"Spoofing":cweSpoof,\
    "Tampering":cweTamper,"Encryption":cweEncryp,"Attachment":cweAttach,\
    "Unexpected Error handling":cweUError,"Client_Server Installation":cweClient, "Web App Service":cweWeb,"Log_Operations":cweLogB}

logging.basicConfig(filename='reglas.log',level=logging.DEBUG)

def log(c,att, B,A,E):
    logging.warning('cName= %s cAtt= %s', c.cName, att)
    logging.warning('Base Finding Group:')
    logging.warning('TI= %s, AP= %s, AL= %s, IC= %s',B[0],B[1],B[2],B[3])
    logging.warning('Base Subscore: %s',cwssBaseF(B[0],B[1],B[2],B[3]))
    base=cwssBaseF(B[0],B[1],B[2],B[3])

    logging.warning('--')
    logging.warning('Attack Surface Group:')
    logging.warning('RP= %s, RL= %s, AV= %s, AS= %s, AI= %s, IN= %s, SC= %s',A[0],A[1],A[2],A[3],A[4],A[5],A[6])
    logging.warning('AS Subscore: %s',cwssAttackS(A[0],A[1],A[2],A[3],A[4],A[5],A[6]))
    attack=cwssAttackS(A[0],A[1],A[2],A[3],A[4],A[5],A[6])

    logging.warning('--')
    logging.warning('Environmental Group:')
    logging.warning('BI= %s, DI= %s, EX= %s, EC= %s, P= %s',E[0],E[1],E[2],E[3],E[4])
    logging.warning('ENV Subscore: %s',cwssEnv(E[0],E[1],E[2],E[3],E[4]))
    env=cwssEnv(E[0],E[1],E[2],E[3],E[4])

    logging.warning('Environmental Group TOP25:')
    logging.warning('BI= %s, DI= %s, EX= %s, EC= %s, P= %s',E[0],1,1,E[3],E[4])
    logging.warning('ENV Subscore: %s',cwssEnv(E[0],1,1,E[3],E[4]))
    env25=cwssEnv(E[0],1,1,E[3],E[4])
    
    logging.warning('--')
    score=base*attack*env
    score25=base*attack*env25
    logging.warning('Total Score: %s',score)
    logging.warning('Total Score TOP25: %s',score25)
    logging.warning('\n')
    #logging.warning('--')
    #logging.warning('cUser= %s,cLang= %s,cUIcom= %s,cSanit= %s,cTrans= %s,cTransf= %s,cTrust= %s,cDBint= %s,cTime= %s,cMaxmin= %s,cCalltpf= %s,cSpoof= %s,cTamper= %s,cEncryp= %s,cAttach= %s,cDataf= %s,cUError= %s,cRemote= %s,cCliSer= %s',c.cUser,c.cLang,c.cUIcom,c.cSanit,c.cTrans,c.cTransf,c.cTrust,c.cDBint,c.cTime,c.cMaxmin,c.cCalltpf,c.cSpoof,c.cTamper,c.cEncryp,c.cAttach,c.cDataf,c.cUError,c.cRemote,c.cCliSer)    
    return 0


def rules(c):
    
    ## RL = 1 = Application, The entity must be able to have access to an affected application.
    ## or RL = 1 = Enterprise, The entity must have access to a critical piece of enterprise infrastructure, such as a router, switch, DNS, domain controller, firewall, identity server, etc.  
    ## Variable APP stores RL value           

    NA="Not Applicable"
    DEF="Default"
    APP="Application"
    TI1=[]
    TI2=[]
    ## Evaluating Owner attribute  
    
    if (c.cOwner=='Administrator'):

        TI1 = ["Technical Impact","Critical", TI.get("Critical")] 
        AP1 = ["Acquired Privilege","Administrator",AP.get("Administrator")]
        AL1 = ["Acquired Privilege Layer","Enterprise",AL.get("Enterprise")]
        AV1 = ["Access Vector","Intranet",AV.get("Intranet")]
        #RP1 = ["Required Privilege","Administrator",RP.get("Administrator")]
        BI1 = TI1

    elif (c.cOwner=='Partially-Privileged User'):

        TI1 = ["Technical Impact","High", TI.get("High")]
        AP1 = ["Acquired Privilege","Partially-Privileged User",AP.get("Partially-Privileged User")]
        AL1 = ["Acquired Privilege Layer","System",AL.get("System")]
        AV1 = ["Access Vector","Private Network",AV.get("Private Network")]
        #oRP1 = ["Required Privilege","Partially-Privileged User",RP.get("Partially-Privileged User")]
        BI1 = TI1

    elif (c.cOwner=='Regular User'):
        TI1 = ["Technical Impact","Medium", TI.get("Medium")]
        AP1 = ["Acquired Privilege","Regular User",AP.get("Regular User")]
        AL1 = ["Acquired Privilege Layer","Network",AL.get("Network")]
        AV1 = ["Access Vector","Local",AV.get("Local")]
        #RP1 = ["Required Privilege","Regular User",RP.get("Regular User")]
        BI1 = TI1

    elif (c.cOwner=='Guest'):

        TI1 = ["Technical Impact","Low", TI.get("Low")]
        AP1 = ["Acquired Privilege","Guest",AP.get("Guest")]
        AL1 = ["Acquired Privilege Layer","Unknown",AL.get("Unknown")]
        AV1 = ["Access Vector","Local",AV.get("Local")]
        #oRP1 = ["Required Privilege","Guest",RP.get("Guest")]
        BI1 = TI1

    elif (c.cOwner=='None'):

        TI1 = ["Technical Impact","None", TI.get("None")]
        AP1 = ["Acquired Privilege","None",AP.get("None")]
        AL1 = ["Acquired Privilege Layer","Unknown",AL.get("Unknown")]
        AV1 = ["Access Vector","Local",AV.get("Local")]
        #oRP1 = ["Required Privilege","None",RP.get("None")]
        BI1 = TI1

    elif (c.cOwner=='Default'):

        TI1 = ["Technical Impact","Default", TI.get("Default")]
        AP1 = ["Acquired Privilege","Default",AP.get("Default")]
        AL1 = ["Acquired Privilege Layer","Default",AL.get("Default")]
        AV1 = ["Access Vector","Local",AV.get("Local")]
        #oRP1 = ["Required Privilege","Default",RP.get("Default")]
        BI1 = TI1

    elif (c.cOwner=='Unknown'):

        TI1 = ["Technical Impact","Unknown", TI.get("Unknown")]
        AP1 = ["Acquired Privilege","Unknown",AP.get("Unknown")]
        AL1 = ["Acquired Privilege Layer","Unknown",AL.get("Unknown")]
        AV1 = ["Access Vector","Local",AV.get("Local")]
        #oRP1 = ["Required Privilege","Unknown",RP.get("Unknown")]
        BI1 = TI1

    elif (c.cOwner=='Not Applicable'):

        TI1 = ["Technical Impact","Not Applicable", TI.get("Not Applicable")]
        AP1 = ["Acquired Privilege","Not Applicable",AP.get("Not Applicable")]
        AL1 = ["Acquired Privilege Layer","Not Applicable",AL.get("Not Applicable")]
        AV1  = ["Access Vector","Local",AV.get("Local")]
        #oRP1 = ["Required Privilege","Not Applicable",RP.get("Not Applicable")]
        BI1 = TI1
                                       
    B=[TI1[2],AP1[2],AL1[2],1]
    A=[RP[NA],RL[APP],AV1[2],AS[NA],AI[NA],IN[NA],SC[NA]]
    E=[BI1[2],DI[DEF],EX[DEF],EC[NA],P[NA]]
    #log(c,"Owner",B,A,E)
    
    cwssOwner = cwssBaseF(TI1[2],AP1[2],AL1[2],1) * cwssAttackS(RP[NA],RL[APP],AV1[2],AS[NA],AI[NA],IN[NA],SC[NA]) * cwssEnv(BI1[2],DI[DEF],EX[DEF],EC[NA],P[NA])
    #if the CWE belong to top25 DI and EX are equal to 1.
    cwssOwner25 = cwssBaseF(TI1[2],AP1[2],AL1[2],1) * cwssAttackS(RP[NA],RL[APP],AV1[2],AS[NA],AI[NA],IN[NA],SC[NA]) * cwssEnv(BI1[2],1,1,EC[NA],P[NA])
        
    ## Evaluating User attribute

    if (c.cUser=='Administrator'):
        
        TI2 = ["Technical Impact","Critical", TI.get("Critical")] 
        #oAP2 = ["Acquired Privilege","Administrator",AP.get("Administrator")]
        AL2 = ["Acquired Privilege Layer","Enterprise",AL.get("Enterprise")]
        RP2 = ["Required Privilege","Administrator",RP.get("Administrator")]
        AV2  = ["Access Vector","Intranet",AV.get("Intranet")]
        AS2  = ["Authentication Strength","Moderate",AS.get("Moderate")]
        AI2  = ["Authentication Instances","Single",AI.get("Single")]
        BI2 = TI2

    elif (c.cUser=='Partially-Privileged User'):

        TI2 = ["Technical Impact","High", TI.get("High")]
        #oAP2 = ["Acquired Privilege","Partially-Privileged User",AP.get("Partially-Privileged User")]
        AL2 = ["Acquired Privilege Layer","System",AL.get("System")]
        RP2 = ["Required Privilege","Partially-Privileged User",RP.get("Partially-Privileged User")]
        AV2  = ["Access Vector","Private Network",AV.get("Private Network")]
        AS2  = ["Authentication Strength","Moderate",AS.get("Moderate")]
        AI2  = ["Authentication Instances","Single",AI.get("Single")]        
        BI2 = TI2

    elif (c.cUser=='Regular User'):

        TI2 = ["Technical Impact","Medium", TI.get("Medium")]
        #oAP2 = ["Acquired Privilege","Regular User",AP.get("Regular User")]
        AL2 = ["Acquired Privilege Layer","Network",AL.get("Network")]
        RP2 = ["Required Privilege","Regular User",RP.get("Regular User")]
        AV2  = ["Access Vector","Local",AV.get("Local")]        
        AS2  = ["Authentication Strength","Moderate",AS.get("Moderate")]
        AI2  = ["Authentication Instances","Single",AI.get("Single")]
        BI2 = TI2

    elif (c.cUser=='Guest'):

        TI2 = ["Technical Impact","Low", TI.get("Low")]
        #oAP2 = ["Acquired Privilege","Guest",AP.get("Guest")]
        AL2 = ["Acquired Privilege Layer","Unknown",AL.get("Unknown")]
        RP2 = ["Required Privilege","Guest",RP.get("Guest")]  
        AV2  = ["Access Vector","Local",AV.get("Local")]      
        AS2  = ["Authentication Strength","Moderate",AS.get("Moderate")]
        AI2  = ["Authentication Instances","Multiple",AI.get("Multiple")]
        BI2 = TI2

    elif (c.cUser=='None'):

        TI2 = ["Technical Impact","None", TI.get("None")]
        #oAP2 = ["Acquired Privilege","None",AP.get("None")]
        AL2 = ["Acquired Privilege Layer","Unknown",AL.get("Unknown")]
        RP2 = ["Required Privilege","None",RP.get("None")]
        AV2  = ["Access Vector","Local",AV.get("Local")]        
        AS2  = ["Authentication Strength","Moderate",AS.get("Moderate")]
        AI2  = ["Authentication Instances","Multiple",AI.get("Multiple")]
        BI2 = TI2

    elif (c.cUser=='Default'):

        TI2 = ["Technical Impact","Default", TI.get("Default")]
        #oAP2 = ["Acquired Privilege","Default",AP.get("Default")]
        AL2 = ["Acquired Privilege Layer","Default",AL.get("Default")]
        RP2 = ["Required Privilege","Default",RP.get("Default")]     
        AV2  = ["Access Vector","Local",AV.get("Local")]
        AS2  = ["Authentication Strength","Moderate",AS.get("Moderate")] 
        AI2  = ["Authentication Instances","Multiple",AI.get("Multiple")]  
        BI2 = TI2

    elif (c.cUser=='Unknown'):

        TI2 = ["Technical Impact","Unknown", TI.get("Unknown")]
        #oAP2 = ["Acquired Privilege","Unknown",AP.get("Unknown")]
        AL2 = ["Acquired Privilege Layer","Unknown",AL.get("Unknown")]
        RP2 = ["Required Privilege","Unknown",RP.get("Unknown")]     
        AV2  = ["Access Vector","Local",AV.get("Local")]   
        AS2  = ["Authentication Strength","Moderate",AS.get("Moderate")]
        AI2  = ["Authentication Instances","Multiple",AI.get("Multiple")]
        BI2 = TI2

    elif (c.cUser=='Not Applicable'):

        TI2 = ["Technical Impact","Not Applicable", TI.get("Not Applicable")]
        #oAP2 = ["Acquired Privilege","Not Applicable",AP.get("Not Applicable")]
        AL2 = ["Acquired Privilege Layer","Not Applicable",AL.get("Not Applicable")]
        RP2 = ["Required Privilege","Not Applicable",RP.get("Not Applicable")]       
        AV2  = ["Access Vector","Local",AV.get("Local")] 
        AS2  = ["Authentication Strength","Not Applicable",AS.get("Not Applicable")]
        AI2  = ["Authentication Instances","Not Applicable",AI.get("Not Applicable")]
        BI2 = TI2
    
    B=[TI2[2],AP[NA],AL2[2],1]
    A=[RP2[2],RL[APP],AV2[2],AS2[2],AI2[2],IN[NA],SC[NA]]
    E=[BI2[2],DI[DEF],EX[DEF],EC[NA],P[NA]]
    #log(c,"User",B,A,E)
    
    cwssUser=cwssBaseF(TI2[2],AP[NA],AL2[2],1) * cwssAttackS(RP2[2],RL[APP],AV2[2],AS2[2],AI2[2],IN[NA],SC[NA]) * cwssEnv(BI2[2],DI[DEF],EX[DEF],EC[NA],P[NA])
    #if the CWE belong to top25 DI and EX are equal to 1.
    cwssUser25=cwssBaseF(TI2[2],AP[NA],AL2[2],1) * cwssAttackS(RP2[2],RL[APP],AV2[2],AS2[2],AI2[2],IN[NA],SC[NA]) * cwssEnv(BI2[2],1,1,EC[NA],P[NA])
        
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
        
        TI3 = ["Technical Impact","Critical", TI.get("Critical")]
        AV3 = ["Access Vector","Local",AV.get("Local")] 
        IN3 = ["Level of Interaction","Automated",IN.get("Automated")]        
        DI3 = ["Likelihood of Discovery","High",DI.get("High")] 
        EX3 = ["Likelihood of Exploit","High",DI.get("High")]
        AS3 = ["Authentication Strength","Moderate",AS.get("Moderate")]
        #oAI3 = ["Authentication Instances","Single",AI.get("Single")]        
        BI3 = TI3
    
    else:
        
        TI3 = ["Technical Impact","High", TI.get("High")]
        AV3 = ["Access Vector","Adjacent Network",AV.get("Adjacent Network")]         
        IN3 = ["Level of Interaction","Opportunistic",IN.get("Opportunistic")]
        DI3 = ["Likelihood of Discovery","Medium",DI.get("Medium")] 
        EX3 = ["Likelihood of Exploit","Medium",DI.get("Medium")]
        AS3 = ["Authentication Strength","Strong",AS.get("Strong")]
        #oAI3  = ["Authentication Instances","Single",AI.get("Single")]
        BI3 = TI3

    B=[TI3[2],AP[NA],AL[NA],IC[DEF]]
    A=[RP[NA],RL[APP],AV3[2],AS3[2],AI[DEF],IN3[2],SC[DEF]]
    E=[BI3[2],DI[DEF],EX[DEF],EC[NA],P[NA]]
    #log(c,"User Interface",B,A,E)

    cwssUIcom=cwssBaseF(TI3[2],AP[NA],AL[NA],IC[DEF])*cwssAttackS(RP[NA],RL[APP],AV3[2],AS3[2],IN3[2],IN3[2],SC[DEF])*cwssEnv(BI3[2],DI[DEF],EX[DEF],EC[NA],P[NA])
    #if the CWE belong to top25 DI and EX are equal to 1.
    cwssUIcom25=cwssBaseF(TI3[2],AP[NA],AL[NA],IC[DEF])*cwssAttackS(RP[NA],RL[APP],AV3[2],AS3[2],IN3[2],IN3[2],SC[DEF])*cwssEnv(BI3[2],1,1,EC[NA],P[NA])
    
    ## Evaluating Sanitize data attribute

    if (c.cSanit=="Yes"):
        
        TI4 = ["Technical Impact","Medium", TI.get("Medium")]
        IC4 = ["Internal Control Effectiveness","Moderate",IC.get("Moderate")]        
        BI4=TI4
    else:
        
        TI4 = ["Technical Impact","Critical", TI.get("Critical")]
        IC4 = ["Internal Control Effectiveness","Limited",IC.get("Limited")]        
        BI4=TI4

    B=[TI4[2],AP[NA],AL[NA],IC4[2]]
    A=[RP[NA],RL[APP],AV[DEF],AS[NA],AI[NA],IN[NA],SC[NA]]
    E=[BI4[2],DI[DEF],EX[DEF],EC[NA],P[NA]]
    #log(c,"Sanitize",B,A,E)

    cwssSanit=cwssBaseF(TI4[2],AP[NA],AL[NA],IC4[2])*cwssAttackS(RP[NA],RL[APP],AV[DEF],AS[NA],AI[NA],IN[NA],SC[NA])*cwssEnv(BI4[2],DI[DEF],EX[DEF],EC[NA],P[NA])
    #if the CWE belong to top25 DI and EX are equal to 1.
    cwssSanit25=cwssBaseF(TI4[2],AP[NA],AL[NA],IC4[2])*cwssAttackS(RP[NA],RL[APP],AV[DEF],AS[NA],AI[NA],IN[NA],SC[NA])*cwssEnv(BI4[2],1,1,EC[NA],P[NA])
    
    ## Evaluating Transform data attribute

    if (c.cTransform=="Yes"):
        
        TI5 = ["Technical Impact","Critical", TI.get("Critical")]
        IC5 = ["Internal Control Effectiveness","Moderate",IC.get("Moderate")]
        BI5 = TI5
    else:
        
        TI5  = ["Technical Impact","Low", TI.get("Low")]
        IC5 = ["Internal Control Effectiveness","Limited",IC.get("Limited")]
        BI5 = TI5

    B=[TI5[2],AP[NA],AL[NA],IC5[2]]
    A=[RP[NA],RL[APP],AV[DEF],AS[NA],AI[NA],IN[NA],SC[NA]]
    E=[BI5[2],DI[DEF],EX[DEF],EC[NA],P[NA]]
    #log(c,"Transformation",B,A,E)    

    cwssTrans=cwssBaseF(TI5[2],AP[NA],AL[NA],IC5[2])*cwssAttackS(RP[NA],RL[APP],AV[DEF],AS[NA],AI[NA],IN[NA],SC[NA])*cwssEnv(BI5[2],DI[DEF],EX[DEF],EC[NA],P[NA])        
    #if the CWE belong to top25 DI and EX are equal to 1.
    cwssTrans25=cwssBaseF(TI5[2],AP[NA],AL[NA],IC5[2])*cwssAttackS(RP[NA],RL[APP],AV[DEF],AS[NA],AI[NA],IN[NA],SC[NA])*cwssEnv(BI5[2],1,1,EC[NA],P[NA])
    ## Evaluating Transfering data attribute
    
    if (c.cTransfer=="Yes"):
        
        TI6 = ["Technical Impact","Critical", TI.get("Critical")]
        IC6 = ["Internal Control Effectiveness","Moderate",IC.get("Moderate")]        
        BI6 = TI6
    else:
        
        TI6 = ["Technical Impact","Low", TI.get("Low")]
        IC6 = ["Internal Control Effectiveness","Limited",IC.get("Limited")]
        BI6 = TI6

    B=[TI6[2],AP[NA],AL[NA],IC6[2]]
    A=[RP[NA],RL[APP],AV[DEF],AS[NA],AI[NA],IN[NA],SC[NA]]
    E=[BI6[2],DI[DEF],EX[DEF],EC[NA],P[NA]]
    #log(c,"Transfering",B,A,E)    

    cwssTransf=cwssBaseF(TI6[2],AP[NA],AL[NA],IC5[2])*cwssAttackS(RP[NA],RL[APP],AV[DEF],AS[NA],AI[NA],IN[NA],SC[NA])*cwssEnv(BI6[2],DI[DEF],EX[DEF],EC[NA],P[NA])        
    #if the CWE belong to top25 DI and EX are equal to 1.
    cwssTransf25=cwssBaseF(TI6[2],AP[NA],AL[NA],IC5[2])*cwssAttackS(RP[NA],RL[APP],AV[DEF],AS[NA],AI[NA],IN[NA],SC[NA])*cwssEnv(BI6[2],1,1,EC[NA],P[NA])
    
    ## Evaluating Trust in data attribute
    
    if (c.cTrust=="Yes"):
        
        TI7  = ["Technical Impact","Medium", TI.get("Medium")]
        IC7 = ["Internal Control Effectiveness","Moderate",IC.get("Moderate")]
        AS7 = ["Authentication Strength","Weak",AS.get("Weak")]
        AI7 = ["Authentication Instances","Single",AI.get("Single")]
        BI7 = TI7       
    else:
        
        TI7  = ["Technical Impact","Critical", TI.get("Critical")]
        IC7 = ["Internal Control Effectiveness","Limited",IC.get("Limited")]
        AS7 = ["Authentication Strength","Moderate",AS.get("Moderate")]
        AI7 = ["Authentication Instances","Multiple",AI.get("Multiple")]
        BI7 = TI7

    B=[TI7[2],AP[NA],AL[NA],IC7[2]]
    A=[RP[NA],RL[APP],AV[NA],AS7[2],AI[NA],IN[NA],SC[NA]]
    E=[BI7[2],DI[DEF],EX[DEF],EC[NA],P[NA]]
    #log(c,"Trust",B,A,E)            

    cwssTrust=cwssBaseF(TI7[2],AP[NA],AL[NA],IC7[2])*cwssAttackS(RP[NA],RL[APP],AV[NA],AS7[2],AI7[2],IN[NA],SC[NA])*cwssEnv(BI7[2],DI[DEF],EX[DEF],EC[NA],P[NA])
    #if the CWE belong to top25 DI and EX are equal to 1.
    cwssTrust25=cwssBaseF(TI7[2],AP[NA],AL[NA],IC7[2])*cwssAttackS(RP[NA],RL[APP],AV[NA],AS7[2],AI7[2],IN[NA],SC[NA])*cwssEnv(BI7[2],1,1,EC[NA],P[NA])
        
    ## Evaluating Database Interaction attribute 

    if (c.cDBint=="Yes"):
        
        TI8  = ["Technical Impact","Critical", TI.get("Critical")]
        AV8 = ["Access Vector","Private Network",AV.get("Private Network")]         
        RP8 = ["Required Privilege","Partially-Privileged User",RP.get("Partially-Privileged User")]
        #oIN  = ["Level of Interaction","Automated",IN.get("Automated")]
        BI8 = TI8
    else:
        
        TI8  = ["Technical Impact","Low", TI.get("Low")]
        AV8 = ["Access Vector","Not Applicable",AV.get("Not Applicable")]         
        RP8 = ["Required Privilege","Not Applicable",RP.get("Not Applicable")]
        #oIN  = ["Level of Interaction","Unknown",IN.get("Unknown")]
        BI8 = TI8

    B=[TI8[2],AP[DEF],AL[DEF],IC[DEF]]
    A=[RP8[2],RL[APP],AV8[2],AS[DEF],AI[DEF],IN[DEF],SC[NA]]
    E=[BI8[2],DI[DEF],EX[DEF],EC[NA],P[NA]]
    #log(c,"DB_DNS_LDAP_FW",B,A,E)            

    cwssDBint=cwssBaseF(TI8[2],AP[DEF],AL[DEF],IC[DEF])*cwssAttackS(RP8[2],RL[APP],AV8[2],AS[DEF],AI[DEF],IN[DEF],SC[NA])*cwssEnv(BI8[2],DI[DEF],EX[DEF],EC[NA],P[NA])
    #if the CWE belong to top25 DI and EX are equal to 1.
    cwssDBint25=cwssBaseF(TI8[2],AP[DEF],AL[DEF],IC[DEF])*cwssAttackS(RP8[2],RL[APP],AV8[2],AS[DEF],AI[DEF],IN[DEF],SC[NA])*cwssEnv(BI8[2],1,1,EC[NA],P[NA])

    ## Evaluating Timeout operations attribute

    if (c.cTime=="Yes"):
        
        TI9 = ["Technical Impact","Critical", TI.get("Critical")]
        BI9 = TI9
    else:
        
        TI9  = ["Technical Impact","Low", TI.get("Low")]
        BI9 = TI9

    B=[TI9[2],AP[NA],AL[NA],IC[DEF]]
    A=[RP[NA],RL[APP],AV[NA],AS[NA],AI[NA],IN[NA],SC[NA]]
    E=[BI9[2],DI[DEF],EX[DEF],EC[NA],P[NA]]
    #log(c,"Timeout Operations",B,A,E) 
               
    cwssTime=cwssBaseF(TI9[2],AP[NA],AL[NA],IC[DEF])*cwssAttackS(RP[NA],RL[APP],AV[NA],AS[NA],AI[NA],IN[NA],SC[NA])*cwssEnv(BI9[2],DI[DEF],EX[DEF],EC[NA],P[NA])
    #if the CWE belong to top25 DI and EX are equal to 1.
    cwssTime25=cwssBaseF(TI9[2],AP[NA],AL[NA],IC[DEF])*cwssAttackS(RP[NA],RL[APP],AV[NA],AS[NA],AI[NA],IN[NA],SC[NA])*cwssEnv(BI9[2],1,1,EC[NA],P[NA])
    
    ## Evaluating Max/Min operations attribute

    if (c.cMaxmin=="Yes"):
        
        TI10 = ["Technical Impact","Critical", TI.get("Critical")]
        BI10 = TI10        
    else:
        
        TI10 = ["Technical Impact","Low", TI.get("Low")]
        BI10 = TI10

    B=[TI10[2],AP[NA],AL[NA],IC[DEF]]
    A=[RP[NA],RL[APP],AV[NA],AS[NA],AI[NA],IN[NA],SC[NA]]
    E=[BI10[2],DI[DEF],EX[DEF],EC[NA],P[NA]]
    #log(c,"MaxMin Operations",B,A,E) 

    cwssMaxmin=cwssBaseF(TI10[2],AP[NA],AL[NA],IC[DEF])*cwssAttackS(RP[NA],RL[APP],AV[NA],AS[NA],AI[NA],IN[NA],SC[NA])*cwssEnv(BI10[2],DI[DEF],EX[DEF],EC[NA],P[NA])
    #if the CWE belong to top25 DI and EX are equal to 1.
    cwssMaxmin25=cwssBaseF(TI10[2],AP[NA],AL[NA],IC[DEF])*cwssAttackS(RP[NA],RL[APP],AV[NA],AS[NA],AI[NA],IN[NA],SC[NA])*cwssEnv(BI10[2],1,1,EC[NA],P[NA])
    
    ## Evaluating Call Local Third-party Functions attribute

    if (c.cCalltpf=="Yes"):
        
        TI11 = ["Technical Impact","Critical", TI.get("Critical")]
        RP11 = ["Required Privilege","Partially-Privileged User",RP.get("Partially-Privileged User")]
        AV11 = ["Access Vector","Private Network",AV.get("Private Network")] 
        BI11 = TI11        
    else:
        
        TI11  = ["Technical Impact","Low", TI.get("Low")]
        RP11 = ["Required Privilege","Not Applicable",RP.get("Not Applicable")]
        AV11 = ["Access Vector","Not Applicable",AV.get("Not Applicable")]
        BI11 = TI11        

    B=[TI11[2],AP[NA],AL[NA],IC[DEF]]
    A=[RP11[2],RL[APP],AV11[2],AS[DEF],AI[DEF],IN[DEF],SC[NA]]
    E=[BI11[2],DI[DEF],EX[DEF],EC[NA],P[NA]]
    #log(c,"Thirdparty Operations",B,A,E) 

    cwssCalltpf=cwssBaseF(TI11[2],AP[NA],AL[NA],IC[DEF])*cwssAttackS(RP11[2],RL[APP],AV11[2],AS[DEF],AI[DEF],IN[DEF],SC[NA])*cwssEnv(BI11[2],DI[DEF],EX[DEF],EC[NA],P[NA])
    #if the CWE belong to top25 DI and EX are equal to 1.
    cwssCalltpf25=cwssBaseF(TI11[2],AP[NA],AL[NA],IC[DEF])*cwssAttackS(RP11[2],RL[APP],AV11[2],AS[DEF],AI[DEF],IN[DEF],SC[NA])*cwssEnv(BI11[2],1,1,EC[NA],P[NA])
    
    ## Evaluating Spoofing Protection attribute

    if (c.cSpoof=="Yes"):
        
        TI12 = ["Technical Impact","Low", TI.get("Low")]
        DI12 = ["Likelihood of Discovery","Low",DI.get("Low")] 
        EX12 = ["Likelihood of Exploit","Low",EX.get("Low")]
        IC12 = ["Internal Control Effectiveness","Indirect",IC.get("Indirect")]         
        BI12 = TI12
    else:
        
        TI12  = ["Technical Impact","Critical", TI.get("Critical")]
        DI12 = ["Likelihood of Discovery","High",DI.get("High")] 
        EX12 = ["Likelihood of Exploit","High",EX.get("High")]
        IC12 = ["Internal Control Effectiveness","Limited",IC.get("Limited")]
        BI12 = TI12

    B=[TI12[2],AP[NA],AL[NA],IC12[2]]
    A=[RP[NA],RL[APP],AV[NA],AS[NA],AI[NA],IN[NA],SC[NA]]
    E=[BI12[2],DI12[2],EX12[2],EC[NA],P[NA]]
    #log(c,"Spoofing",B,A,E) 

    cwssSpoof=cwssBaseF(TI12[2],AP[NA],AL[NA],IC12[2])*cwssAttackS(RP[NA],RL[APP],AV[NA],AS[NA],AI[NA],IN[NA],SC[NA])*cwssEnv(BI12[2],DI12[2],EX12[2],EC[NA],P[NA])
    #if the CWE belong to top25 DI and EX are equal to 1.
    cwssSpoof25=cwssBaseF(TI12[2],AP[NA],AL[NA],IC12[2])*cwssAttackS(RP[NA],RL[APP],AV[NA],AS[NA],AI[NA],IN[NA],SC[NA])*cwssEnv(BI12[2],1,1,EC[NA],P[NA])
    
    ## Evaluating Tampering Protection attribute
    if (c.cTamper=="Yes"):
        
        TI13 = ["Technical Impact","Low", TI.get("Low")]
        DI13 = ["Likelihood of Discovery","Low",DI.get("Low")] 
        EX13 = ["Likelihood of Exploit","Low",EX.get("Low")]
        IC13 = ["Internal Control Effectiveness","Indirect",IC.get("Indirect")]         
        BI13 = TI13
    else:
        
        TI13 = ["Technical Impact","Critical", TI.get("Critical")]
        DI13 = ["Likelihood of Discovery","High",DI.get("High")] 
        EX13 = ["Likelihood of Exploit","High",EX.get("High")]
        IC13 = ["Internal Control Effectiveness","Limited",IC.get("Limited")]
        BI13 = TI13

    B=[TI13[2],AP[NA],AL[NA],IC13[2]]
    A=[RP[NA],RL[APP],AV[NA],AS[NA],AI[NA],IN[NA],SC[NA]]
    E=[BI13[2],DI13[2],EX13[2],EC[NA],P[NA]]
    #log(c,"Tampering",B,A,E)     

    cwssTamper=cwssBaseF(TI13[2],AP[NA],AL[NA],IC13[2])*cwssAttackS(RP[NA],RL[APP],AV[NA],AS[NA],AI[NA],IN[NA],SC[NA])*cwssEnv(BI13[2],DI13[2],EX13[2],EC[NA],P[NA])
    #if the CWE belong to top25 DI and EX are equal to 1.
    cwssTamper25=cwssBaseF(TI13[2],AP[NA],AL[NA],IC13[2])*cwssAttackS(RP[NA],RL[APP],AV[NA],AS[NA],AI[NA],IN[NA],SC[NA])*cwssEnv(BI13[2],1,1,EC[NA],P[NA])
    
    ## Evaluating Encryption Protection attribute

    if (c.cEncryp=="Yes"):
        
        TI14 = ["Technical Impact","Low", TI.get("Low")]
        DI14 = ["Likelihood of Discovery","Low",DI.get("Low")] 
        EX14 = ["Likelihood of Exploit","Low",EX.get("Low")]
        IC14 = ["Internal Control Effectiveness","Indirect",IC.get("Indirect")]         
        BI14 = TI14
    else:
        
        TI14 = ["Technical Impact","Critical", TI.get("Critical")]
        DI14 = ["Likelihood of Discovery","High",DI.get("High")] 
        EX14 = ["Likelihood of Exploit","High",EX.get("High")]
        IC14 = ["Internal Control Effectiveness","Limited",IC.get("Limited")]
        BI14 = TI14

    B=[TI14[2],AP[NA],AL[NA],IC14[2]]
    A=[RP[NA],RL[APP],AV[NA],AS[NA],AI[NA],IN[NA],SC[NA]]
    E=[BI14[2],DI14[2],EX14[2],EC[NA],P[NA]]
    #log(c,"Encryption",B,A,E)     
    
    cwssEncryp=cwssBaseF(TI14[2],AP[NA],AL[NA],IC14[2])*cwssAttackS(RP[NA],RL[APP],AV[NA],AS[NA],AI[NA],IN[NA],SC[NA])*cwssEnv(BI14[2],DI14[2],EX14[2],EC[NA],P[NA])
    #if the CWE belong to top25 DI and EX are equal to 1.
    cwssEncryp25=cwssBaseF(TI14[2],AP[NA],AL[NA],IC14[2])*cwssAttackS(RP[NA],RL[APP],AV[NA],AS[NA],AI[NA],IN[NA],SC[NA])*cwssEnv(BI14[2],1,1,EC[NA],P[NA])
    
    ## Evaluating Attachments attribute
    
    if (c.cAttach=="Yes"):
        
        TI15 = ["Technical Impact","Critical", TI.get("Critical")]
        IC15 = ["Internal Control Effectiveness","Moderate",IC.get("Moderate")]
        IN15 = ["Level of Interaction","Automated",IN.get("Automated")]
        DI15 = ["Likelihood of Discovery","Medium",DI.get("Medium")] 
        EX15 = ["Likelihood of Exploit","Medium",EX.get("Medium")]
        BI15 = TI15
    else:
        
        TI15 = ["Technical Impact","Low", TI.get("Low")]
        IC15 = ["Internal Control Effectiveness","Indirect",IC.get("Indirect")]
        IN15 = ["Level of Interaction","Not Applicable",IN.get("Not Applicable")]
        DI15 = ["Likelihood of Discovery","Not Applicable",DI.get("Not Applicable")] 
        EX15 = ["Likelihood of Exploit","Not Applicable",EX.get("Not Applicable")]
        BI15 = TI15

    B=[TI15[2],AP[NA],AL[NA],IC15[2]]
    A=[RP[NA],RL[APP],AV[NA],AS[NA],AI[NA],IN15[2],SC[NA]]
    E=[BI15[2],DI15[2],EX15[2],EC[NA],P[NA]]
    #log(c,"Attachment",B,A,E)     

    cwssAttach=cwssBaseF(TI15[2],AP[NA],AL[NA],IC15[2])*cwssAttackS(RP[NA],RL[APP],AV[NA],AS[NA],AI[NA],IN15[2],SC[NA])*cwssEnv(BI15[2],DI15[2],EX15[2],EC[NA],P[NA])    
    #if the CWE belong to top25 DI and EX are equal to 1.
    cwssAttach25=cwssBaseF(TI15[2],AP[NA],AL[NA],IC15[2])*cwssAttackS(RP[NA],RL[APP],AV[NA],AS[NA],AI[NA],IN15[2],SC[NA])*cwssEnv(BI15[2],DI15[2],EX15[2],EC[NA],P[NA])
    
    ## Evaluating Unexpected Error Handling attribute

    if (c.cUError=="Yes"):
        TI16 = ["Technical Impact","Low", TI.get("Low")]
        IC16 = ["Internal Control Effectiveness","Indirect",IC.get("Indirect")]
        BI16 = TI16        
    else:
        
        TI16 = ["Technical Impact","Critical", TI.get("Critical")]
        IC16 = ["Internal Control Effectiveness","Moderate",IC.get("Moderate")]
        BI16 = TI16

    B=[TI16[2],AP[NA],AL[NA],IC16[2]]
    A=[RP[NA],RL[APP],AV[NA],AS[NA],AI[NA],IN[NA],SC[NA]]
    E=[BI16[2],DI[DEF],EX[DEF],EC[NA],P[NA]]
    #log(c,"Unexpected Error",B,A,E)     

    cwssUError=cwssBaseF(TI16[2],AP[NA],AL[NA],IC16[2])*cwssAttackS(RP[NA],RL[APP],AV[NA],AS[NA],AI[NA],IN[NA],SC[NA])*cwssEnv(BI16[2],DI[DEF],EX[DEF],EC[NA],P[NA])
    #if the CWE belong to top25 DI and EX are equal to 1.
    cwssUError25=cwssBaseF(TI16[2],AP[NA],AL[NA],IC16[2])*cwssAttackS(RP[NA],RL[APP],AV[NA],AS[NA],AI[NA],IN[NA],SC[NA])*cwssEnv(BI16[2],1,1,EC[NA],P[NA])
   
    ## Evaluating Client/Server installation attribute

    if (c.cCliSer=="Client"):
        
        TI17  = ["Technical Impact","Medium", TI.get("Medium")]
        DI17 = ["Likelihood of Discovery","Medium",DI.get("Medium")] 
        EX17 = ["Likelihood of Exploit","Medium",EX.get("Medium")]
        # AL == Application
        AV17 = ["Access Vector","Local",AV.get("Local")]         
        BI17 = TI17
    else:
        #("c.CliSer==Server"):
        TI17  = ["Technical Impact","Critical", TI.get("Critical")]
        DI17 = ["Likelihood of Discovery","Not Applicable",DI.get("Not Applicable")] 
        EX17 = ["Likelihood of Exploit","Not Applicable",EX.get("Not Applicable")]
        # AL == Application
        AV17 = ["Access Vector","Intranet",AV.get("Intranet")] 
        BI17 = TI17

    B=[TI17[2],AP[NA],AL[APP],IC[NA]]
    A=[RP[NA],RL[APP],AV17[2],AS[NA],AI[NA],IN[NA],SC[NA]]
    E=[BI17[2],DI17[2],EX17[2],EC[NA],P[NA]]
    #log(c,"Client or Server",B,A,E)     

    cwssCliSer=cwssBaseF(TI17[2],AP[NA],AL[APP],IC[NA])*cwssAttackS(RP[NA],RL[APP],AV17[2],AS[NA],AI[NA],IN[NA],SC[NA])*cwssEnv(BI17[2],DI17[2],EX17[2],EC[NA],P[NA])
    #if the CWE belong to top25 DI and EX are equal to 1.
    cwssCliSer25=cwssBaseF(TI17[2],AP[NA],AL[APP],IC[NA])*cwssAttackS(RP[NA],RL[APP],AV17[2],AS[NA],AI[NA],IN[NA],SC[NA])*cwssEnv(BI17[2],DI17[2],EX17[2],EC[NA],P[NA])

    ## Evaluating Web attribute

    if (c.cWeb=="Yes"):
        
        TI18 = ["Technical Impact","Critical", TI.get("Critical")]
        AL18 = ["Acquired Privilege Layer","Application",AL.get("Application")]
        AV18 = ["Access Vector","Internet",AV.get("Internet")] 
        DI18 = ["Likelihood of Discovery","Medium",DI.get("Medium")] 
        EX18 = ["Likelihood of Exploit","Medium",EX.get("Medium")]
        BI18 = TI18        
    else:
        
        TI18 = ["Technical Impact","Low", TI.get("Low")]
        AL18 = ["Acquired Privilege Layer","Not Applicable",AL.get("Not Applicable")]
        AV18 = ["Access Vector","Local",AV.get("Local")] 
        DI18 = ["Likelihood of Discovery","Not Applicable",DI.get("Not Applicable")] 
        EX18 = ["Likelihood of Exploit","Not Applicable",EX.get("Not Applicable")]
        BI18 = TI18

    B=[TI18[2],AP[NA],AL18[2],IC[NA]]
    A=[RP[NA],RL[APP],AV18[2],AS[NA],AI[NA],IN[NA],SC[NA]]
    E=[BI18[2],DI18[2],EX18[2],EC[NA],P[NA]]
    #log(c,"Web Service/App",B,A,E)    
     
    cwssWeb=cwssBaseF(TI18[2],AP[NA],AL18[2],IC[NA])*cwssAttackS(RP[NA],RL[APP],AV18[2],AS[NA],AI[NA],IN[NA],SC[NA])*cwssEnv(BI18[2],DI18[2],EX18[2],EC[NA],P[NA])
    #if the CWE belong to top25 DI and EX are equal to 1.
    cwssWeb25=cwssBaseF(TI18[2],AP[NA],AL18[2],IC[NA])*cwssAttackS(RP[NA],RL[APP],AV18[2],AS[NA],AI[NA],IN[NA],SC[NA])*cwssEnv(BI18[2],1,1,EC[NA],P[NA])

## Evaluating Log/Backup attribute

    if (c.cLogB=="Yes"):
        
        TI19 = ["Technical Impact","High", TI.get("High")]
        IC19 = ["Internal Control Effectiveness","Limited",IC.get("Limited")]        
        DI19 = ["Likelihood of Discovery","Medium",DI.get("Medium")] 
        EX19 = ["Likelihood of Exploit","Medium",EX.get("Medium")]
        BI19 = TI19
    else:
        
        TI19 = ["Technical Impact","Critical", TI.get("Critical")]
        IC19 = ["Internal Control Effectiveness","Not Applicable",IC.get("Not Applicable")]
        DI19 = ["Likelihood of Discovery","Not Applicable",DI.get("Not Applicable")] 
        EX19 = ["Likelihood of Exploit","Not Applicable",EX.get("Not Applicable")]
        BI19 = TI19

    B=[TI19[2],AP[NA],AL[NA],IC19[2]]
    A=[RP[NA],RL[APP],AV[NA],AS[NA],AI[NA],IN[NA],SC[NA]]
    E=[BI19[2],DI19[2],EX19[2],EC[NA],P[NA]]
    #log(c,"Log-Backup Operations",B,A,E)    
    
    cwssLogB=cwssBaseF(TI19[2],AP[NA],AL[NA],IC19[2])*cwssAttackS(RP[NA],RL[APP],AV[NA],AS[NA],AI[NA],IN[NA],SC[NA])*cwssEnv(BI19[2],DI19[2],EX19[2],EC[NA],P[NA])
    #if the CWE belong to top25 DI and EX are equal to 1.
    cwssLogB25=cwssBaseF(TI19[2],AP[NA],AL[NA],IC19[2])*cwssAttackS(RP[NA],RL[APP],AV[NA],AS[NA],AI[NA],IN[NA],SC[NA])*cwssEnv(BI19[2],1,1,EC[NA],P[NA])
        
    score = [cwssOwner,cwssUser,cwssUIcom,cwssSanit,cwssTrans,cwssTransf,cwssTrust,cwssDBint,cwssTime,cwssMaxmin,cwssCalltpf,cwssSpoof,cwssTamper,cwssEncryp,cwssAttach,cwssUError,cwssCliSer,cwssWeb,cwssLogB,\
             cwssOwner25,cwssUser25,cwssUIcom25,cwssSanit25,cwssTrans25,cwssTransf25,cwssTrust25,cwssDBint25,cwssTime25,cwssMaxmin25,cwssCalltpf25,cwssSpoof25,cwssTamper25,cwssEncryp25,cwssAttach25,cwssUError25,cwssCliSer25,cwssWeb25,cwssLogB25]
    
    return score

def cwssBaseF(TI,AP,AL,IC):
    
    if (TI > 0):
        fTI=1
        score = ((12.5 * TI) + (6.25 * (AP + AL))) * fTI * IC * 4
    else:
        score = 0
    
    return score

def cwssAttackS(RP,RL,AV,AS,AI,IN,SC):
    
    score = (20 * (RP + RL + AV) + (20 * SC) + (10 * IN) + (5 * (AS + AI))) / 100

    return score

def cwssEnv(BI,DI,EX,EC,P):

    if (BI>0):
        fBI=1
        score = (((10.25 * BI) + (3.25 * (DI + EX)) + (3.25 * P)) * fBI * EC) / 20
    else:        
        score = 0

    return score

print "Rules Loaded!!!"
#raw_input()