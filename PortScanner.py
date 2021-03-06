import nmap

def callback_result(host, scan_result):
    check = 0
    print('Scan complete!')
    print('*'*50)
    #TCP
    if 'tcp' in scan_result['scan'][ipaddr].keys():
        check = 1
        print('Protocol : TCP')
        for port in scan_result['scan'][ipaddr]['tcp']:
            if scan_result['scan'][ipaddr]['tcp'][port]['name'] == '' :
                print(f"Port : {port}\tService : unknown\tState : {scan_result['scan'][ipaddr]['tcp'][port]['state']}")
            else:
                print(f"Port : {port}\tService : {scan_result['scan'][ipaddr]['tcp'][port]['name']}\tState : {scan_result['scan'][ipaddr]['tcp'][port]['state']}")

    #No ports open
    if check == 0 :
        print('No ports open!')

print('*'*50)
print(' '*12+'python-nmap port scanner')
print('*'*50)
ipaddr = input('Enter IP address:')
print('*'*50)
print('Options:')
print('1 : Scan the important ports (0-1000)')
print('2 : Scan all 65536 ports')


nm = nmap.PortScanner()
nma = nmap.PortScannerAsync()

counter = 0

while counter == 0:
    print('*'*50)
    choice = input('Enter choice number : ')
    print('*'*50)

    if choice == '1':
        check=0
        ports = '0-1000'
        print(f'Scanning ports {ports} on {ipaddr}')
        nm.scan(ipaddr, ports,timeout=240)
        print('Scan complete!')
        print('*'*50)
        #TCP
        if 'tcp' in nm[ipaddr].all_protocols():
            check=1
            print('Protocol : TCP')
            for port in nm[ipaddr].all_tcp() :
                print(f"Port : {port}\tService : {nm[ipaddr]['tcp'][port]['name']}\tState : {nm[ipaddr]['tcp'][port]['state']}")
        
        #No ports open
        if check == 0 :
            print('No ports open')

    elif choice == '2' :
        ports = '0-65535'
        print(f'Scanning ports {ports} on {ipaddr}')
        nma.scan(hosts=ipaddr,arguments='-p 0-65535',callback=callback_result,timeout=240)
        while nma.still_scanning():
            nma.wait(2)
    
    else:
        print('Incorrect choice. Enter again : ')
        continue
    
    counter = 1

print('*'*50)

