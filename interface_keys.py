import psutil
interfaces = psutil.net_if_addrs()
print(interfaces.keys())
