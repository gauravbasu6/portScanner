import nmap

print('*'*50)
print(' '*12+'python-nmap port scanner')
print('*'*50)
ipaddr = input('Enter IP address:')
print('*'*50)
print('Options:')
print('1 : Scan the important ports (0-1000)')
# print('2 : Scan all 65536 ports')


nm = nmap.PortScanner()
counter = 0

while counter == 0:
    print('*'*50)
    choice = input('Enter choice number : ')
    print('*'*50)

    if choice == '1':
        ports = '0-1000'
    # elif choice == '2':
    #     ports = '0-65535'
    else:
        print('Incorrect choice! Enter again : ')
        continue

    print(f'Scanning ports {ports} on {ipaddr}')
    nm.scan(ipaddr, ports)
    print('*'*50)
    print(nm.command_line())    
    #TCP
    if 'tcp' in nm[ipaddr].all_protocols():
        print('Protocol : TCP')
        for port in nm[ipaddr].all_tcp() :
            print(f"Port : {port}\tService : {nm[ipaddr]['tcp'][port]['name']}\tState : {nm[ipaddr]['tcp'][port]['state']}")
        
    #UDP
    if 'udp' in nm[ipaddr].all_protocols():
        print('Protocol : UDP')
        for port in nm[ipaddr].all_udp() :
            print(f"Port : {port}\tService : {nm[ipaddr]['udp'][port]['name']}\tState : {nm[ipaddr]['udp'][port]['state']}")

    #IP
    if 'ip' in nm[ipaddr].all_protocols():
        print('Protocol : IP')
        for port in nm[ipaddr].all_ip() :
            print(f"Port : {port}\tService : {nm[ipaddr]['ip'][port]['name']}\tState : {nm[ipaddr]['ip'][port]['state']}")
    
    #SCTP
    if 'sctp' in nm[ipaddr].all_protocols():
        print('Protocol : SCTP')
        for port in nm[ipaddr].all_sctp() :
            print(f"Port : {port}\tService : {nm[ipaddr]['sctp'][port]['name']}\tState : {nm[ipaddr]['sctp'][port]['state']}")

    counter = 1

print('*'*50)

