from SBOM_generate import SBOM_generate
from DeepAnalysis import DeepAnalysis
from CompareSBOMs import CompareSBOMs
from CompareLocalSBOMWithRemote import CompareLocalSBOMWithRemote
import json
import asyncio
import aiohttp
import sys  
  
def restoreSBOM(fileContents, missing_packs):
           for item in missing_packs:
              version= item.split('@')[-1]
              itemlocator= item.split('@')[0]
              itemname=itemlocator.replace("/",".")
              new_package = {
               "SPDXID": "SPDXRef-Package-" + itemlocator.replace(".","") +version,
               "name": itemname,
               "versionInfo": version,
               "packageFileName": itemname.split(".")[-1] + "-" +version +".jar",
               "supplier": "NOASSERTION",
               "downloadLocation": "NOASSERTION",
               "filesAnalyzed": False,
               "checksums": [],
               "homepage": "NOASSERTION",
               "licenseConcluded": "NOASSERTION",
               "licenseDeclared": "NOASSERTION",
               "copyrightText": "NOASSERTION",
               "externalRefs": [
                   {
                       "referenceCategory": "PACKAGE-MANAGER",
                       "referenceType": "purl",
                       "referenceLocator": "pkg:maven/" + item
                   }
                 ]
               }  
              fileContents["packages"].append(new_package)       
           return fileContents


    






async def main():
          file=sys.argv[1]

          with open(file, 'r') as file:
                fileContents = json.load(file)
          if 'sbom' in fileContents:
                fileContents=fileContents['sbom']
          analyzer=DeepAnalysis(fileContents)
          await analyzer.Analyze()
          missing_packs=analyzer.getMissingPacks()         
          print("\nDeep Analysis Results:\n\nThe SBOM was missing " + str(len(missing_packs)) + " transitive dependencies of dependencies already present in it.\n")
          newfileContents=restoreSBOM(fileContents, missing_packs)
     

          with open('restored.json', 'w') as file:
             json.dump(newfileContents, file, indent=4)

      
       
       
        
if __name__ == "__main__":
        asyncio.run(main())
