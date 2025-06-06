# DASHGen
Deep Analysis SBOM Helper Generator

This project, is designed to automate the creation of SBOMs, including transitvie dependencies and dependency relationships. 

Currently, the focus of DASHGen is Maven/Gradle projects that are available on GitHub.

# How it Works

First, DASHGen retrieves the current SBOM that GitHub automatically creates. This SBOM will have basic information about the project, but will often be missing both transtivie, and sometimes even direct, dependencies of the project. 

Then, DASHGen uses Maven or Gradle files to traverse the dependency trees and gather all depnendencies, as well as their relationships. In other words, DASHGen supplements the built-in GitHub SBOM Generator.



# How to Use

Using DASHGen at the moment is relaitvely simple. 

python ./RestoreSBOM.py 

This script then asks for the GitHub owner and name, and then completes the SBOM


# What's Next?

The creation of a better GUI and executable would be the next steps. Additionally, DASHGen takes the GitHub SBOM automatically created and supplements it, however, an option to create an SBOM from complete scratch could easily be implemented if demand arises.
