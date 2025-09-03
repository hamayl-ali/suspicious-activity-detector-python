import os
import psutil
import socket
import time
import json

# scanning the process
def scan():
    sus=["keylogger","logger","monitor","spy"]
    flagged=[]
    for proc in psutil.process_iter(["pid","name"]):#itrates over everty running process but only conider ***pid,name***
        try:#using try cathch because there are some process that require permission so the cannot be reached
            pname=proc.info["name"]#we did not use pid because we dont need their id right now but if we want to kill the process or log which process is sus we need it later
    
            for keyword in sus:
                if keyword in pname:
                    flagged.append(proc.info)
        except (psutil.NoSuchProcess,psutil.AccessDenied):
            continue
    return flagged

# scanning the files

def scan_file():
    sus_files=[]
    search=["/tmp",os.path.expanduser("~")]
    keywords=["log","record","key","keys"]

    for dir in search:
        try:
            for root, _,files in os.walk(dir):
                for f in files:
                    if any (k in f.lower() for k in keywords):
                        sus_files.append(os.path.join(root,f))
        except Exception:
            continue
    return sus_files

#network scanning 

def scan_net():
    sus_conns=[]
    for conn in psutil.net_connections(kind="inet"):
        if conn.raddr and conn.status=="Established":
            sus_conns.append({
                "local": f"{conn.laddr.ip}:{conn.laddr.port}",
                "remote": f"{conn.raddr.ip}:{conn.raddr.port}",
                "pid": conn.pid
            })
    return sus_conns
# generating the report here as json ...
def gen_report(processes,files,conns):

    report={
        "time": time.ctime(),
        "suspicious_processes": processes,
        "suspicious_files": files,
        "suspicious_connections": conns
    }
    with open("detector_report.json", "w") as f:
        json.dump(report, f, indent=4)
    print("Report saved as detector_report.json")


def main():
    print("The keylogger detector is running...")
    processes=scan()
    files=scan_file()
    conns=scan_net()

    if not processes and not files and not conns :
        print (" ...there is no suspecious activity detected... ")

    else:
        print(" there are potential threats here ")
        if processes: 
            print( f"[processes]{len(processes)} flagged")
        if files:
            print (f"[Files] {len(files)} suspicious files")
        if conns: 
            print(f"[Connections] {len(conns)} suspicious network conns")


    gen_report(processes,files,conns)


if __name__=="__main__":
    main()
    
            