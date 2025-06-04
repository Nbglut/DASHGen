# DASHGen
Deep Analysis SBOM Helper Generator

This project, is designed to automate the creation of SBOMs, including transitvie dependencies and dependency relationships. 

Currently, the focus of DASHGen is Maven/Gradle projects that are available on GitHub.

#How it Works

First, DASHGen retrieves the current SBOM that GitHub automatically creates. This SBOM will have basic information about the project, but will often be missing both transtivie, and sometimes even direct, dependencies of the project. Then DASHGen uses Maven or Gradle files to traverse the dependency trees and gather all depnendencies, as well as their relationships. In other words, DASHGen supplements the built-in GitHub SBOM Generator.

WORK IN PROGRESS
