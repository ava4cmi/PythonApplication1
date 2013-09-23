'''
Created on 26/09/2011
Updated on 18/08/2012
Updated on 01/02/2013

@author: Jairo
'''
#Vulnerability Graph Analyzer: Main 
''
import start, utils
import sys, traceback, time


if __name__ == '__main__':
    
    ti = time.time()

    dir1="crossbroker"
    dir2="wms"
    #print "Select a middleware:..."
    #dir=raw_input()
    #if (dir=="middleware_name"):
    
    start.start(dir2)
                          
    tf = time.time()
    print (tf-ti)
    raw_input()
    sys.exit(0)

