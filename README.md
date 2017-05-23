# Virus Total Monitor

Virus Total Monitor will create a base list of current running processes, then will start to check the task list every second. If any new process is created, `VTMonitor` will get the signature of it and submitted to Virus Total.

## Installation
`VTMonitor` required Python 2.7, moreover there are a couple of external library required. You can easily install them using pip:  
```
pip install -r requirements.txt
```

## Setup
Before running `VTMonitor` you have to copy the file `settings-dist.json` to `settings.json`.  
Inside it you'll have to save your Virus Total API key; moreover you can specify if you want to use the private (billed) API or the public ones.

## Usage
Simply launch the script, at the moment there aren't any extra arguments available.
```
python vtmonitor.py
```
