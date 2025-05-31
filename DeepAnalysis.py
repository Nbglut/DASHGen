"""
DeepAnalysis.py

This class is meant to use do a Deep Analysis of an SBOM.
The Analysis goes up the chain of dependencies to check all transient dependencies exist

@Author Nicolette Glut
File Created On 2-25-2025
"""





import os
import requests
import json
import argparse
import sys
from deepdiff import DeepDiff
import copy
import random
import re
from SBOM import SBOM
from CompareSBOMs import CompareSBOMs
import asyncio
import aiohttp
import xml.etree.ElementTree as ET
import chardet
import git

lock = asyncio.Lock()
missed_items=0


def getProperties(xml,space):
  properties_dict={}
  properties=xml.find('properties', space)
  if properties is None:
       properties=xml.find('properties')

  if properties is not None:
    for prop in properties:
       properties_dict[prop.tag.split('}')[-1]] = prop.text  
 
  parent=xml
  if xml.find('parent', space) is not None:
      parent=xml.find('parent', space)
    
  if parent.find('groupId',space) is not None:
      properties_dict['project.groupId']=parent.find('groupId',space).text
  if parent.find('artifactId',space) is not None:
     properties_dict['project.artifactId']= parent.find('artifactId',space).text
  if parent.find('version',space) is not None:
     properties_dict['project.version']=parent.find('version',space).text
  
       
#find project version, project.groupId, 
       
       
  return properties_dict




async def get_json_from_link(link):
        """
               Gets the Json of a given link
        """
        
        async with aiohttp.ClientSession() as session:
            async with session.get(link) as response:  # Non-blocking
               return await response.json()  
       # response = requests.get(link)
        #print(response.status_code) # Print the status code
        #return response.json() 
        
        
async def get_XML_from_link(link):
        """
               Gets the XML of a given link
        """
        global missed_items

        async with aiohttp.ClientSession() as session:
            async with session.get(link) as response:  # Non-blocking
               try:
               #detect encoding
                  raw= await response.read()
                  detect=chardet.detect(raw)
                  encoding=detect.get('encoding','utf-8')
                  content=raw.decode(encoding,errors='replace')
                  pkg_xml= ET.fromstring(content)
                  namespace = {'': 'http://maven.apache.org/POM/4.0.0'}
                  prop_list=getProperties(pkg_xml,namespace)
                  return pkg_xml, prop_list
               except ET.ParseError as e:
                #print(link)
                missed_items+=1
               # print("UNABLE TO GET .POM OF DEPENDENCY") 
       # response = requests.get(link)
        #print(response.status_code) # Print the status code
        #return response.json() 


class DeepAnalysis:
    """
      DeepAnalysis is the cass that analyzes the SBOM.
      It is given the SBOM content
    """
    def __init__(self, SBOM1, owner, repo):
        self.SBOMContents= SBOM1
        self.missing_packs={}
        self.missingdirect=[]
        self.relationships={}
        self.checked_packs={}
        self.licenses={}
        self.owner=owner
        self.repo=repo
   
    def getMissingPacks(self):
        """
               Returns the missingpacks
        """
        return self.missing_packs 
        
        
        
        
        
    def getMissingDirectPacks(self):
        """
               Returns the directmissingpacks
        """
        return self.missingdirect 


    async def add_to_missing_packs(self,pac,missing_packs):
      async with lock:  # Ensures that only one task can modify the list at a time
            missing_packs.add(pac)
            
            
    async def add_to_relationships(self,pac,newpac,relationships):
      async with lock:  # Ensures that only one task can modify the list at a time
            if pac not in relationships:
                
                relationships[pac]= {newpac}
            else:            
                relationships[pac].add( newpac)
            #print(relationships[pac])

            
            
            
            
    async def add_to_checked_packs(self,pac,checked_packs):
      async with lock:  # Ensures that only one task can modify the list at a time
            checked_packs.add(pac)
        
        
    

    def analyzeDirect(self):
     repo=self.repo
     owner=self.owner
     repo_url = f"https://github.com/{owner}/{repo}.git"
     local_path = f"./{repo}"
     filesfound=[]
     directdeps=[]
     if os.path.exists(local_path):
        repo=git.Repo(local_path)
     else:
        repo =git.Repo.clone_from(repo_url, local_path)
     for root, dirs,files in os.walk(local_path):
         if "pom.xml" in files:
           print("Pom.xml found")
           full_path = os.path.join(root, "pom.xml")
           filesfound.append(full_path)
         if "build.gradle" in files:
           print("gradle.build found")
           full_path = os.path.join(root, "build.gradle")
           filesfound.append(full_path)
     for item in filesfound:
       with open(item, 'r', encoding='utf-8') as f:
          content = f.read()
          if "gradle" in item:
            dependencies = re.findall(r'^\s*(?:classpath|implementation|api|compile|compileOnly|runtimeOnly|testImplementation|testCompile)\s+[\'"]([^\'"]+)[\'"]', content,re.MULTILINE)
            
            
            for dep in dependencies:
              #in form "group:artificat:version"
              splitdep=dep.split(":")
              groupID=splitdep[0]
              artificatID=splitdep[1]
              version=splitdep[-1]
              dependency=groupID+"/"+artificatID
              if version !="":
                   dependency+="@"+ version
              directdeps.append(dependency)
          
          
          
          
          
          #POM FILE
          if ".xml" in item:
            pkg_xml= ET.fromstring(content)
            namespace = {'': 'http://maven.apache.org/POM/4.0.0'}
            prop_dict=getProperties(pkg_xml,namespace)
            if pkg_xml.find('dependencyManagement',namespace) is not None:
                pkg_xml=pkg_xml.find('dependencyManagement',namespace)
            
            dependencies= pkg_xml.find('dependencies',namespace)
            if dependencies is None:
                  dependencies=pkg_xml.find('dependencies')
                  if dependencies is not None:
                       namespace={'':''}
                  prop_dict=getProperties(pkg_xml,namespace)

                  #if dependecies exist, get dependencies

            if dependencies is not None:
                for dependency in dependencies.findall('dependency',namespace):
                    if dependency is not None:   
                     groupID=dependency.find('groupId',namespace).text
                     artificatID=dependency.find('artifactId',namespace).text
                     version=""
                     if dependency.find('version',namespace) is not None:
                         version=dependency.find('version',namespace).text
                         
                     for key, value in prop_dict.items():
                             if value is None:
                                value = version      
                             version = version.replace(f"${{{key}}}", value)
                             artificatID = artificatID.replace(f"${{{key}}}", value)
                             groupID = groupID.replace(f"${{{key}}}", value)

                     dependency=groupID+"/"+artificatID
                     if version !="":
                        dependency+="@"+ version
                     directdeps.append(dependency)                     


                       
     return directdeps




    async def MavenAnalyzeTransient(self, need_to_check, checked_packages, missing_packs, relationships, present_packs):
               """
                   Recursive function that goes up the chain of a package pac and finds all of the missing packages (recorded in missing_pack) 
                   by checking pacakges against present_packs and avoids checking the same package twice by using checked_packages  for Java Maven Projects
                  
               """
               tasks=[]
               

               while need_to_check:
                  pac=need_to_check.pop()
                 #Split by "/" and [0] is group [1] is artificat
                  pacsplit=pac.split("/")
                  pacGroup=pacsplit[0]
                  pacArtificat=pacsplit[1]
                  pacVersion=""
                  files={}
                  if len(pacArtificat.split("@")) >1:
                     pacsplit2=pacArtificat.split("@")
                     pacArtificat=pacsplit2[0]
                     pacVersion=pacsplit2[1]
                  if "-SNAPSHOT" in pacVersion:
                      pacVersion=pacVersion.replace("-SNAPSHOT","")
                                 
                  #Use https://repo1.maven.org/maven2/[group_path]/[artifact]/[version]/[artifact]-[version].pom
                  #Save all dependencies as [groupid]/[artificat]@[verison] if version exists
                  #Else just [groupid]/[artificat]
                  linkPart1=f"https://repo1.maven.org/maven2"
                  pacGroupSplit= pacGroup.split(".")
                  for item in pacGroupSplit:
                       linkPart1 += "/" + item
                  if pacVersion != "":
                   tasks.append( get_XML_from_link(linkPart1 + "/" +pacArtificat + "/" +pacVersion + "/" + pacArtificat + "-" +pacVersion + ".pom"))
                  else: 
                   tasks.append( get_XML_from_link(linkPart1 + "/" +pacArtificat +  ".pom"))

                
                  if pac not in missing_packs and pac not in present_packs and add:
                         #print("Adding " + pac + " to missing packs")
                         await self.add_to_missing_packs(pac, missing_packs)
                 #add to checked_pacs
                  await self.add_to_checked_packs(pac,checked_packages)  
                  
               #asynch get all xmls
               results = await asyncio.gather(*tasks)
               #for all packages' xml
               for tup in results:
                if isinstance(tup, tuple) and len(tup) == 2:
                        pkg_xml, properties_dict = tup
                else:
                        pkg_xml, properties_dict = tup, None  # Default to None if missing
                if pkg_xml is not None:
                #get properties in case there are variables in xml
                  #properties_dict = {}
                  #properties_dict= getProperties(pkg_xml,'http://maven.apache.org/POM/4.0.0')
                 #Get all dependencies using XML
                  #dependencies are found in <dependency> and 
                  namespace = {'': 'http://maven.apache.org/POM/4.0.0'}
                  dependencies= pkg_xml.find('dependencies',namespace)
                  properties= pkg_xml.find('properties',namespace)
                       
                  if pkg_xml.find('dependencyManagement',namespace) is not None:
                      pkg_xml=pkg_xml.find('dependencyManagement',namespace)
                  version=''
                  if dependencies is None:
                    dependencies=pkg_xml.find('dependencies')
                    if dependencies is not None:
                       namespace={'':''}
                  #if dependecies exist, get dependencies
                  if dependencies is not None:

                   for dependency in dependencies.findall('dependency',namespace):
                   # print(ET.tostring(dependencies,encoding="unicode"))          

                    if dependency is not None:   
                  #dependency name found in <groupID> and then <artificatID> groupID/artificatID@<version>
                     groupID=dependency.find('groupId',namespace).text
                     artificatID=dependency.find('artifactId',namespace).text
                     version=""
                     if dependency.find('version',namespace) is not None:
                        version=dependency.find('version',namespace).text
                     if version=="": #likely a managed dependency
                          continue
                     #if any part of the dependecy has a variable, replace it
                                         
                     if properties_dict is not None:
                       #print(version)
                       for key, value in properties_dict.items():
                             if value is None:
                                value = version
                                
                                
                             version = version.replace(f"${{{key}}}", value)
                             artificatID = artificatID.replace(f"${{{key}}}", value)
                             groupID = groupID.replace(f"${{{key}}}", value)
                   
                          
                #newpac=   groupID/artificatID@<version>
                     newpac= groupID + "/" +artificatID
                     if version != "":
                         newpac+="@" + version
                         
                 
                  #if newpac not in present_packs 
                     if newpac not in missing_packs and newpac not in present_packs:
                            #print("Adding to missing packs " + newpac)
                            #print("PAC:" + pac + " newpac: " + newpac)  
                            
                            #NEWPAC DEPENDS ON PAC 
                            await self.add_to_relationships(pac,newpac,relationships)
                            await self.add_to_missing_packs(newpac, missing_packs)
                   # If newpac not in checked
                     if newpac not in checked_packages and newpac not in need_to_check:
                         #print(newpac)
                         await self.add_to_checked_packs(newpac,need_to_check)
                      
                  if len(need_to_check) >0:
                     
                     await self.MavenAnalyzeTransient(need_to_check, checked_packages, missing_packs, relationships, present_packs)
      
               return missing_packs, relationships

               

















    async def PythonAnalyzeTransient(self, present_packs, checked_packages, missing_packs):
               """
                   Recursive function that goes up the chain of a package pac and finds all of the missing packages (recorded in missing_pack) 
                   by checking pacakges against present_packs and avoids checking the same package twice by using checked_packages 
                  
               """
               tasks=[]
               
               need_to_check= set(present_packs)

               while need_to_check:
                  pac=need_to_check.pop()
                  paclower=pac.lower()
                  if pac not in missing_packs and pac not in present_packs and pac.lower() not in present_packs:
                         #print("\nMissing package "+ pac )
                         await self.add_to_missing_packs(pac)
                  if paclower not in checked_packages:
                  #ALSO Check if sbom[package][homepage] exists and is a github link 
                      if "com.git" in paclower and pac!= self.SBOMContents['name'] and paclower not in checked_packages:
                               tasks.append(get_json_from_link(f"https://api.github.com/repos/" + pac.split(".")[2] +"/dependency-graph/sbom"))
                      elif "github.com" in paclower:
                              tasks.append(get_json_from_link("https://api.github.com/repos/" + pac.split("/")[3] + "/" + pac.split("/")[4] +"/dependency-graph/sbom" ))
                      elif "https://" not in paclower and "/" not in paclower:
                        tasks.append(get_json_from_link(f"https://pypi.org/pypi/{pac}/json"))

                  await self.add_to_checked_packs(paclower,checked_packages)  
               results = await asyncio.gather(*tasks)
               #print(tasks)
               missing_packs_lower=[item.lower() for item in missing_packs]
               for pkg_json in results:
                  if 'sbom' in pkg_json:
                     pkg_json=pkg_json['sbom']
               #if [message] exists in json, the json does not exist and we continue 
                  if "message"  not in pkg_json and  "info" in pkg_json and 'requires_dist' in  pkg_json['info'] and  pkg_json['info']['requires_dist']!=None:
               #req_pack=data['info']['requires_dist'] has all required packages 
                      req_packetsunformated=pkg_json['info']['requires_dist']
                      for item in req_packetsunformated: 
                         nextpac=re.split(r"([=<>; ~)(?!])", item)[0]
                         nextpaclower=nextpac.lower()
                         if nextpaclower not in checked_packages  and nextpac not in need_to_check:
                                  need_to_check.add(nextpac)
                         if (nextpac not in present_packs and nextpaclower not in present_packs ):
                                   #print("\nMissing package "+ nextpac  )
                                   await self.add_to_missing_packs(nextpaclower, missing_packs)
                              #TO ADD-RELATIONSHIP ADDDITION for restoring
                              #pkg_json['info']['name']=pac depends on nextpac
                              
                    
                  else:
                 #else if not in pypi form we can find sbom directly
                     #for all packages in the SBOM, analyze the packages dependencies
                     
                     #Eventually, remove if sbom
                        if 'packages' in pkg_json:
                           for packs in pkg_json['packages']:
                            # print("GITHUB FOUND")
                             nextpac= packs['name']
                             nextpaclower=nextpac.lower()
                             if nextpaclower not in checked_packages and nextpac not in need_to_check:
                                  if 'homepage' in packs and "github" in packs['homepage']:
                                      need_to_check.add(packs['homepage'])
                                  else:
                                      need_to_check.add(nextpaclower)
                             if nextpac not in missing_packs and nextpaclower not in missing_packs:
                                   # print("\nMissing package "+ nextpac  )
                                    await self.add_to_missing_packs(nextpac, missing_packs)
                
                 # if len(need_to_check) >0:
                     
                   #  await self.PythonAnalyzeTransient(need_to_check, checked_packages, missing_packs)
               #print("\nWe checked " + str(len(checked_packages)))
               return missing_packs

               
                  
    async def Analyze(self):
       """
          Function which calls analyzeTransient 
       """
       checked_pks=set()
       req_packs=[]
       present_packs=[]
       missing_packs=set()
       relationships={}
       #print(self.SBOMContents)
       pks=self.SBOMContents["packages"]
       python = input("Is this a Python Project? True or False")
       if python=="True":
          for package in pks:
             if package['name'] != self.SBOMContents['name']:
            
                present_packs.append(package['name'])
       #Assume maven
       else:
          for package in pks:
             if package['name'] != self.SBOMContents['name']:
               if 'externalRefs' in package:
                pac=package['externalRefs']
                pac=pac[-1]['referenceLocator']
                pacsplit=pac.split("/")
                pacGroup=""
                pacArtificat=""
                if len(pacsplit)>=3:
                  pacGroup=pacsplit[1]
                  pacArtificat=pacsplit[2]
            
 #eles if gradle
                else:
                  pacsplit=pac.split(":")
                  pacGroup=pacsplit[3]
                  pacArtificat=pacsplit[4]
                  pacArtificat+="@"+pacsplit[5]
                
                if "swid" in pacsplit[0]:
                    pacArtificat=pacsplit[3]
                    pacGroup= "org." +pacGroup
                    continue
                pac=pacGroup+ "/" +pacArtificat
                present_packs.append(pac)
            
              
                
       global missed_items   
       print("Checking Direct Dependencies...")
       directdeps=self.analyzeDirect()
       for item in directdeps:
            if item not in present_packs:
                self.missingdirect.append(item)
                present_packs.append(item)

       if python=="True":
          print("Checking Transitive Dependencies...")
          await self.PythonAnalyzeTransient( set(present_packs), checked_pks, missing_packs)
       else:
          print("Checking Transitive Dependencies...")
          await self.MavenAnalyzeTransient( set(present_packs), checked_pks, missing_packs, relationships, set(present_packs))
       percent=0
       if len(checked_pks) + missed_items >0:
        percent= missed_items/(len(checked_pks) +missed_items) 
       print("There have been " + str(missed_items) + " packages whose pom cannot be found\n")
       print("There have been " + str(len(checked_pks)) + " checked dependencies/transitive dependencies.\nMissing packages found with " + str(percent*100) + "% of packages being unable to resolve a .pom." )
       self.missing_packs=missing_packs
       self.relationships=relationships
       for item in self.relationships:
             for i in self.relationships[item]:
                print(i + " depeneds on " + item)
       if len(self.missingdirect)>0:
          print("MISSING " + str(len(self.missingdirect)) + " DIRECT DEPENDENCIES IN SBOM:")
          print(self.missingdirect)

               
                   
               

              
    
    



#What about restoring??
#Another Python file
#Add to [package] 
#Add to [relationships] 

   
async def main():
    if len(sys.argv) <= 1:
         print("No file or remote given")
    fileOrRemote= args.filename
    fileContents=""
    if args.file=="True":
      with open(fileOrRemote, 'r') as file:
                fileContents = json.load(file)
                if 'sbom' in fileContents:
                    fileContents= fileContents['sbom']
    else:
       SBOM1=SBOM(fileOrRemote)
       fileContents=SBOM1.getJson()
    #print(fileContents)
    owner = input("Enter the owner: ").strip()
    repo = input("Enter the repo: ").strip()

    SBOMAnalysis=DeepAnalysis(fileContents, owner, repo)
    await SBOMAnalysis.Analyze()
    missing_packs=SBOMAnalysis.getMissingPacks()
    missing_pack_list=list(missing_packs)
    missing_pack_list.sort()
    print("Missing Transitive Dependencies:")
    print(missing_pack_list)     
    print(str(len(missing_packs)) + " MISSING TRANSIENT DEPENDENCIES\n")
 

   

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Deep Analysis')

    parser.add_argument('--file', default='True', type=str, help='file (True) or remote (False)')
    parser.add_argument('filename')  
    args = parser.parse_args()
    asyncio.run(main())
     
   