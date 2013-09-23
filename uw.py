from xml.dom import minidom
import sys, traceback

#The Research View CWE-1000 in XML format

xmlFile='1000.xml'
xmlDoc = minidom.parse(xmlFile)

rootNode = xmlDoc.firstChild

#The tree of weaknesses in XML format
weaks = rootNode.childNodes[2]
