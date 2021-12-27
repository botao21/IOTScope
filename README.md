### Introduction

Our artifact main include scripts and prepared data.

Operating environment: Python 3.6 & Linux system

### Enumerating Interfaces

We have unpacked the firmware and the extracted files are located in `firmware` directory.

All the firmware could be downloaded from Google Drive:

https://drive.google.com/file/d/1h2iLZ-QlUXrDkeDPhbTjS23SPjBhlEcJ/view?usp=sharing

After executing, we get a path list in each directory, whoes name format is "{vendor}_{model}.txt".

The results are listed in `Table 3`(Columns: #Path, #File, #URL).

### Delivering Probing Requests

We send HTTP requests to real and emulation devices and store the results in the SQLite database.

You need to change this Boolean Variable `firmadyne` to store data in different database.

Especially, each device has different login credits, which need some manual work.

We upload the response databases to Google Drive:

https://drive.google.com/file/d/1-g9Jb7HZs05gR9eDYtv5Foot8-NueEKY/view?usp=sharing

### Identifying Unprotected Interfaces

We extract the response data from databases and classify the URLs through similarity.

Before running this script, we need to put `dbs` directory in the same path.

In this script, you should set the Boolean `firmadyne` to choose the parsing model, and you can change the similar threshold.

The results are listed in `Table 3`(Columns: #Cluster).

### Identifying Hidden Interfaces

In this subprocess, we need to find the pages which can leak sensitive information or change router's settings.

We extract page response content from Sqlite databases and file content from `firmware` directory.

At last we get results in "./infoLeakPages.csv" and """./{vendor}/{model}/unauthSetting.log.txt"

