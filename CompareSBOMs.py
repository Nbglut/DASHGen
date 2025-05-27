"""
CompareSBOMs.py

This class simply is a Toy Example of Comparing


@Author Nicolette Glut
File Created On 2-18-2025
"""

import os
import requests
import json
import sys
from deepdiff import DeepDiff
import copy
import random
from SBOM import SBOM
import re 


def normalize_name(name):
    # Strip group prefixes like org.mockito or com.example 
       if len(name.split('.')) >1:
          return name.split('.')[-1]
          
       return name.split(':')[-1]
       
class CompareSBOMs:
    """

    """
    def __init__(self, repo):
        self.TruthSBOM= SBOM(repo)
        self.SBOMjsonTruth={}
        self.SBOMjsonNonTruth={}
        self.added_pack={}
        self.removed_pack={}


 




    def findTruthSBOMs(self):
        """
                Finds the Truth SBOM and puts it in the  self.SBOMjsonTruth
        """
        self.TruthSBOM.findJson()
        self.SBOMjsonTruth= self.TruthSBOM.getJson()
        if 'sbom' in  self.SBOMjsonTruth:
          self.SBOMjsonTruth=self.SBOMjsonTruth['sbom']
        for item in self.SBOMjsonTruth.get('packages', []):
            if 'name' in item:
              item['name'] = normalize_name(item['name'])
           



    def setTruth(self, truth):
        """
                Sets the self.SBOMjsonTruth
        """
        self.SBOMjsonTruth=truth
        if 'sbom' in  self.SBOMjsonTruth:
          self.SBOMjsonTruth=self.SBOMjsonTruth['sbom']
        for item in self.SBOMjsonTruth['packages']:
           item['name'] = normalize_name(item['name'])



    def setNonTruth(self, nontruth):
        """
                Sets the self.SBOMjsonNonTruth
        """
        self.SBOMjsonNonTruth=nontruth
        if 'sbom' in  self.SBOMjsonNonTruth:
          self.SBOMjsonNonTruth=self.SBOMjsonNonTruth['sbom']
        #print("Dependencies present in generated SBOM")
        for item in self.SBOMjsonNonTruth['packages']:
           item['name'] = normalize_name(item['name'])
          # print(item['name'])
           
           
    def RandomizeNonTruth(self):
        """
                Makes random changes to  self.SBOMjsonTruth and saves it to self.SBOMjsonNonTruth
        """
        self.findTruthSBOMs()
        self.SBOMjsonNonTruth= copy.deepcopy(self.SBOMjsonTruth) #copy of truth
            
        packagename_remove="transformers"   #placeholder  for package to remove
        packagename_change="transformers"   #placeholder  for package to change
        numpackages=len(self.SBOMjsonNonTruth['packages'])-1
        packagename_remove=self.SBOMjsonNonTruth['packages'][random.randint(0, numpackages)]['name']  #random package


        print("\nChanges between Truth and Non Truth:\n")
	
	#random chance to remove  
        if(random.choice([0, 1])):
           self.SBOMjsonNonTruth["sbom"]["packages"] = [pkg for pkg in self.SBOMjsonNonTruth["sbom"]["packages"] if pkg["name"] != packagename_remove]
           print("Removed " +  str(packagename_remove) + "\n")
        
        #update numbers just in case packages removed
        numpackages=len(self.SBOMjsonNonTruth['packages'])-1
        #if numpackages <=0, packagename_change should be NONE
        if numpackages <=0:
           packagename_change="None"
        else : #else, get random package like normal
           packagename_change=self.SBOMjsonNonTruth['packages'][random.randint(0, numpackages)]['name']  #random package

#random chance to change  
        if(random.choice([0, 1]) and packagename_change != "None"):
           for package in self.SBOMjsonNonTruth['packages']:
               if package['name'] == packagename_change:
                   package['filesAnalyzed'] = True  
           print("Changed " +  str(packagename_change) + "\n")

        #Random chance to change  licensing
        if(random.choice([0, 1])):
           self.SBOMjsonNonTruth["sbom"]["dataLicense"]="MIT" 
           print("Changed License\n\n\n\n")
     



        
    def getTruthSBOM(self):
        """
        Retrieves the truth SBOM

        Returns:
            self.SBOMjsonTruth: string name of the file
        """
        return self.SBOMjsonTruth

    def returnAddedItems(self):
        """
        Retrieves the added packages between SBOMs

        Returns:
            self.add_packages: string name of the file
        """
        return self.add_packages
        
    def returnRemovedItems(self):
        """
        Retrieves the removed packages between SBOMs

        Returns:
            self.removed_packages: string name of the file
        """
        return self.removed_packages
   
    def compareSBOMs(self, onlypack=False, printDiffs=True):
        """
           Uses the nonTruthSBOmjson and the TruthSBOMjson and compares the two 
        """
        output=""
   
  

        
        
        
        
        difference = DeepDiff(self.SBOMjsonTruth,self.SBOMjsonNonTruth, ignore_order=True)   
        '''print("\nDifferences found by DeepDiff\n")

        self.removed_packages = []
        self.add_packages = []
        changed_items=[]
        differences=1
        if difference:
             if 'iterable_item_removed' in difference:
                for key, package in difference['iterable_item_removed'].items():
                   # Check if 'name' key exists in the package
                    if 'name' in package:
                      pack_name=package['name']
                      if 'versionInfo' in package:
                         pack_name=package['name']+ "@" + package['versionInfo']
                      self.removed_packages.append(pack_name)
                for item in self.removed_packages:
                
                    output= output + str(differences) +". "+ item + " present in truth but not nonTruth\n"
                    differences=differences+1
             if 'iterable_item_added' in difference:
                for key, package in difference['iterable_item_added'].items():
                   # Check if 'name' key exists in the package
                    if 'name' in package:
                      pack_name=package['name']
                      if 'versionInfo' in package:
                         pack_name=package['name']+ "@" + package['versionInfo']

                      self.add_packages.append(pack_name)
                for item in self.add_packages:
                    output= output + str(differences) + ". " + item + " not present in truth but present in nonTruth\n"
                    differences=differences +1



             if 'values_changed' in difference and not onlypack:
                for key, package in difference['values_changed'].items():
                   # Check if 'package' is part of key
                    if 'packages' in key:   
                      index=2
                      if key.split(']')[2]=='':
                         index=1
                      package_index = int(key.split(']')[index][1:])  # Extract index of the package
                      package_name = self.SBOMjsonTruth['packages'][package_index ]['name']  
                      output= output + str(differences)  +  ". The information about package/dependency " + package_name + " is not equal\n"
                      differences=differences+1
                      changed_items.append(package_name)
                    elif 'root'  not in key:
                     key_parts= key.split(']')
                     changed_type=key
                     if len(key_parts) >2:
                        changed_type= key_parts[1][1:]
                        changed_type=changed_type.replace("'", "")
             
                     if changed_type=="creationInfo" or changed_type=="documentNamespace":
                        continue
                     output= output + str(differences)  + ". The " +changed_type + " is " + str(self.SBOMjsonTruth[changed_type])
                     output= output + " in the truth SBOM and " +  str(self.SBOMjsonNonTruth[changed_type]) 
                     output= output + " in the nontruth SBOM\n"
                     differences=differences +1

                     changed_items.append(changed_type)  
                       





             if printDiffs:
                print( str(differences-1)  + " difference(s) found:\n")
             #print(difference)
                print(output)
        else:
           if printDiffs:
              print("No differences found.")


        '''
        packs_in_Truth=[]
        packs_in_NonTruth=[]
        print("\n\nDependencies in Ground Truth missing from Generated SBOM:\n")
        for item in self.SBOMjsonTruth.get('packages', []): 
          if 'name' in item:
              addname=normalize_name(item['name'])
              if 'versionInfo' in item:
                addname+= "@"+ item[ 'versionInfo']
              packs_in_Truth.append(addname)
        for item in self.SBOMjsonNonTruth.get('packages', []): 
          if 'name' in item:
              addname=normalize_name(item['name'])
              if 'versionInfo' in item:
                addname+= "@"+ item[ 'versionInfo']
              packs_in_NonTruth.append(addname)
        missing_from_nontruth = [item for item in packs_in_Truth if item not in packs_in_NonTruth]
        print("There are " + str(len(missing_from_nontruth)) + " missing.")
        print(missing_from_nontruth)
        missing_from_truth= [item for item in packs_in_NonTruth if item not in packs_in_Truth]
        falsepos=len(missing_from_truth)
        falseneg=len(missing_from_nontruth)
        print("\nThere are " + str(falsepos) + " present that are not in the truth.")
        
        truepositive=len(packs_in_Truth)-len(missing_from_nontruth)
        precision=truepositive/(falsepos+truepositive)
        recall=truepositive/(truepositive+falseneg)
        
        accuracy=(truepositive)/(truepositive+falsepos+falseneg)  
        print("\n\nPrecision: " + str(precision) +"\nRecall: " + str(recall) + "\nAccuracy: " + str(accuracy))      
        
        #Print precision, recall, accuracy, etc/
        
        

      


if __name__ == "__main__":
    if len(sys.argv) <= 1:
         print("No repo given")
    test_SBOM = CompareSBOMs(sys.argv[1])
    test_SBOM.findTruthSBOMs()
    test_SBOM.RandomizeNonTruth()

    test_SBOM.compareSBOMs()

    #print(test_SBOM.getTruthSBOM())

