# Reportero: TOMCAT:cat2: Beamtime report generator
___
Generate reports for your beamtimes from the terminal.

## Features:
- List acquired datasets and show relevant information
- Compute relevant statistics
- Throw warnings if the file structure is not expected
- Get the report in your terminal, json format


## Usage

Install the tool (recommended to install it in a separate venv or conda env):
```
pip install git+https://github.com/dveni/reportero.git
```
Run the tool on one of your beamtime folders:
```
reportero -p <PATH TO BEAMTIME FOLDER> -o test.csv
```
This will create two files:
- test.csv: Contains a list with all the scans done during the beamtime, along with relevant information. The output file can be named differently. 
- test.log: Log file showing warnings that could be potential issues (e.g.: Missing flat images files, duplicated files, etc)

## Conventions
- First level folders are independent acquisitions
- Subsequent levels of folders contain in their name the parent folder name (e.g.: parent_name+suffix)
- Creating a report with `csv` format outputs a specific set of columns. Only available in the TOMCAT ecosystem (should be easy to generalize).

## Acknowledgments
- Hongjian Wang for beta testing the tool