import requests


def GetResponsefromAPICall(url,headers={"Content-Type":"application/json"}):
    print (url)
    result = requests.get(url,headers=headers)
    status_code = result.status_code
    if result.status_code == 200:
        return status_code, result.json()   
    else:
        return status_code

