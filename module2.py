import analyze

print "Loading Start..."

def start(dir):
    
    av=[]

    middleware='workspace/'+dir+'/xml/'+dir+'.graphml'
    #Extract the attack vectors paths  and stores in "attvec"
    attvec,nodes=graphml.loadGraphML(middleware)
    
    #Load the component of the middleware and their attributes
    comp=graphml.getComps(nodes)
    
    for i in attvec:               
                    
        arch='av'  
        av=[]       
        
        for j in i.split(','):
            arch=arch+"_"+j                
            for k in comp:
                if j==k.cId:                                                      
                    av.append(k)                                               
        os="ULM"
        web=False 
        
        try:                      
            analyze.analyzeAV(arch,av,os,web,dir)
            print "Analyzed: %s, OK!"%i
        except:
            print "Sorry:", sys.exc_info()
            print traceback.print_exc(file=sys.stdout)
