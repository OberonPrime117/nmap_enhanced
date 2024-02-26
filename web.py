from concurrent.futures import ThreadPoolExecutor
import glob
import shutil
import time
from flask import Flask, render_template, request
from threading import Timer
import webbrowser
import subprocess
import ipaddress
import os
import numpy as np
import pandas as pd
import glob
import os
import csv
from datetime import datetime
import csv
import sys
import xml.etree.ElementTree as ET
from tqdm import tqdm

app = Flask(__name__)

# OPENS A NEW TAB OPENING THE PAGE FOR NMAP FORM


def openBrowser():
    if os.path.exists("port.txt"):
        with open('port.txt', 'r') as file:
            contents = file.read()
            port = str(contents)
    else:
        port = "5000"
    ip = "http://127.0.0.1:"+str(port)
    webbrowser.open(ip, new=2)


def worker(filename, params):

    with open(filename, newline='') as csvfile:
        reader = csv.reader(csvfile)
        first_column = [row[0] for row in reader]

    ip_addr_list = []

    for ip in first_column:
        ip = str(ip).strip()
        if "-" in ip:
            ip_addr_list.extend(rangeExtract(ip))
        elif "/" in ip:
            ip_addr_list.extend(subnetExtract(ip))
        else:
            ip_addr_list.append(ip)

    if len(ip_addr_list) > 1000000:
        print("YOU HAVE ENTERED OVER 1 LAKH IP ADDRESSES. SHUTTING DOWN !!!")
        time.sleep(60)
        os._exit(0)
        sys.exit()

    if len(str(params["Extra"])) > 0:
        if params["Ping"] == "ping":
            customNMAP(params, ip_addr_list, True)
            current_datetime = datetime.now()
            current_time = current_datetime.strftime("%Y_%m_%d_%H_%M_%S")
            if os.path.exists("live_ip_addresses.csv"):
                new_name = "live_ip_addresses_"+str(current_time)+".csv"
                os.rename("live_ip_addresses.csv", new_name)
        else:
            customNMAP(params, ip_addr_list, False)
            current_datetime = datetime.now()
            current_time = current_datetime.strftime("%Y_%m_%d_%H_%M_%S")
            if os.path.exists("live_ip_addresses.csv"):
                new_name = "live_ip_addresses_"+str(current_time)+".csv"
                os.rename("live_ip_addresses.csv", new_name)
    else:
        parseNMAP(params, ip_addr_list)
        current_datetime = datetime.now()
        current_time = current_datetime.strftime("%Y_%m_%d_%H_%M_%S")
        if os.path.exists("live_ip_addresses.csv"):
            new_name = "live_ip_addresses_"+str(current_time)+".csv"
            os.rename("live_ip_addresses.csv", new_name)


def customNMAP(params, ip_addr_list, pingval):
    params = changeParams(params)
    start_time = time.time()
    futures = []
    nmap_futures = []
    new_ip_addr_list = []
    executor = ThreadPoolExecutor(max_workers=int(params["Batches"]))
    executor2 = ThreadPoolExecutor(max_workers=int(params["Batches"]))

    if pingval == True:
        # print("123")
        with tqdm(total=len(ip_addr_list), desc="PING PROGRESS", unit="ip") as pbar:
            for ip in ip_addr_list:
                future = executor.submit(pingme, ip)
                futures.append(future)

            for future, ip in zip(futures, ip_addr_list):
                result = future.result()
                post_proc_func(ip, result)
                if result[0] == True:
                    new_ip_addr_list.append(str(ip))
                pbar.update(1)

        with tqdm(total=len(new_ip_addr_list), desc="NMAP PROGRESS", unit="ip") as pbar:
            for ip in new_ip_addr_list:
                future2 = executor2.submit(custom_nmapfunc, ip, params)
                nmap_futures.append(future2)

            for future2, ip in zip(nmap_futures, new_ip_addr_list):
                result = future2.result()
                post_proc_func(ip, result)
                pbar.update(1)
    else:
        # print("456")
        with tqdm(total=len(ip_addr_list), desc="NMAP", unit="ip") as pbar:
            for ip in ip_addr_list:
                future = executor.submit(custom_nmapfunc, ip, params)
                futures.append(future)

            for future, ip in zip(futures, ip_addr_list):
                result = future.result()
                post_proc_func(ip, result)
                pbar.update(1)


def custom_nmapfunc(ip, params):
    direct = str(ip).replace(":", "_")
    try:
        os.mkdir(os.path.join("results", str(direct)))
    except:
        pass

    command = str(params["Extra"]) + " -oA results/" + \
        str(direct)+"/"+str(direct)+" "+str(ip)
    process = subprocess.run(command, capture_output=True, text=True)
    a = process.stdout
    return (True, "port")


def changeParams(params):
    params["Extra"] = emptyval(params["Extra"])
    if str(params["Extra"]) == "":
        params["Zombie"] = emptyval(params["Zombie"])
        params["Vulners"] = emptyval(params["Vulners"])
        params["FTP"] = emptyval(params["FTP"])
        params["UDP"] = emptyval(params["UDP"])
        params["Basic"] = emptyval(params["Basic"])
        params["SCTP_INIT"] = emptyval(params["SCTP_INIT"])
        params["SCTP_COOKIE"] = emptyval(params["SCTP_COOKIE"])
        params["HOST_DISCO"] = emptyval(params["HOST_DISCO"])
        params["PortTechnique"] = emptyval(params["PortTechnique"])
        params["PortText"] = emptyval(params["PortText"])

        params["Timing"] = emptyval(params["Timing"])
        if params["PortTechnique"] == "-p":
            params["PortText"] = params["PortText"].replace(' ', '')
        if params["Vulners"] == "True":
            params["Vulners"] = "--script=vulners"
        else:
            params["Vulners"] = ""
    else:
        pass
    return params

# REMOVE ARGUMENTS THAT HAVE NONE AS VALUE


def emptyval(val):
    if val == None or val == "None":
        return ""
    else:
        return val

# FORM PAGE


@app.route('/')
def formPage():
    return render_template('index.html')

# EXTRACT INDIVIDUAL IP ADDRESSES FROM SUBNET


def subnetExtract(line):
    # print("EXTRACTING IP ADDRESSES FROM SUBNETS")
    ip_addr_list = []

    if ':' in str(line):
        subnet = ipaddress.IPv6Network(str(line).strip(), False)
        # print(str(line).strip())
        for ip in subnet.hosts():
            # print(ip)
            ip_addr_list.append(ip)
    else:
        subnet = ipaddress.ip_network(str(line).strip(), False)
        for ip in subnet.hosts():
            ip_addr_list.append(ip)

    return ip_addr_list

# EXTRACT INDIVIDUAL IP ADDRESSES FROM RANGE


def rangeExtract(line):
    # print("EXTRACTING IP ADDRESSES FROM RANGE")
    ip_addr_list = []
    rangeList = line.split("-")

    if ipaddress.ip_address(str(rangeList[1]).strip()).version == 4 or ipaddress.ip_address(str(rangeList[0]).strip()).version == 4:
        start_ip = ipaddress.ip_address(str(rangeList[0]).strip())
        end_ip = ipaddress.ip_address(str(rangeList[1]).strip())
        for ip_int in range(int(start_ip), int(end_ip)+1):
            ip_addr = str(ipaddress.ip_address(ip_int))
            ip_addr_list.append(ip_addr)
    elif ipaddress.ip_address(str(rangeList[1]).strip()).version == 6 or ipaddress.ip_address(str(rangeList[0]).strip()).version == 6:
        start_ip = ipaddress.IPv6Address(str(rangeList[0]).strip())
        end_ip = ipaddress.IPv6Address(str(rangeList[1]).strip())
        for ip_int in range(int(start_ip), int(end_ip)+1):
            ip_addr = str(ipaddress.IPv6Address(ip_int))
            ip_addr_list.append(ip_addr)
    return ip_addr_list

# THE BACKEND THAT ACTIVATES AFTER FILLING FORM


@app.route('/backend', methods=['POST'])
def backendPage():

    file = request.files['inputFile']
    filename = file.filename
    file.save(file.filename)
    if len(str(request.values.get('extra'))) > 0:
        params = {
            'Batches': request.values.get('power'),
            'Extra': request.values.get('extra'),
            'Choice': request.values.get('choice'),
            'Ping': request.values.get('customping')
        }
        # print(params["Extra"])
    else:
        # print("ACTUAL PARAMS")
        params = {
            'Technique': request.values.get('scanme'),
            'Zombie': request.values.get('zombieName'),
            'FTP': request.values.get('ftpHost'),
            'UDP': request.values.get('udp'),
            'Basic': request.values.get('basic'),
            'SCTP_INIT': request.values.get('sctp-init'),
            'SCTP_COOKIE': request.values.get('sctp-cookie'),
            'HOST_DISCO': request.values.get('host-discovery'),
            'PortTechnique': request.values.get('portscan'),
            'PortText': request.values.get('ports'),
            'Timing': request.values.get('quantity'),
            'Batches': request.values.get('power'),
            'Vulners': request.values.get('vuln'),
            'Extra': request.values.get('extra'),
            'Choice': request.values.get('choice'),
            'Ping': request.values.get('customping')
        }

    if os.path.exists("output.csv"):
        os.remove("output.csv")
    if os.path.exists("live_ip_addresses.csv"):
        os.remove("live_ip_addresses.csv")
    if os.path.exists("offline_ip_addresses.csv"):
        os.remove("offline_ip_addresses.csv")

    executor2 = ThreadPoolExecutor(max_workers=40)
    future = executor2.submit(removeRESULT)
    future.result()

    worker(filename, params)

    os._exit(0)
    sys.exit()

    return render_template('loading.html')


def removeRESULT():
    if os.path.exists("results"):
        shutil.rmtree("results")
        os.mkdir("results")
    else:
        os.mkdir("results")

# def threadme(ip_addr_list,params):
#     with tqdm(total=len(ip_addr_list), desc="Nmap Progress", unit="ip") as pbar:

#         futures = [ for ip in ip_addr_list]

#         for future in futures:
#             result = future.result()
#             pbar.update(1)


def post_proc_func(ip, result):
    if result[0] == None or str(result[0]) == "None":
        pass
    else:
        if result[0] == False and result[1] == "ping":
            if os.path.exists("offline_ip_addresses.csv"):
                data = {'IP Address': [str(ip)]}
                df = pd.DataFrame(data)
                df.to_csv('offline_ip_addresses.csv',
                          mode='a', index=False, header=False)
            else:
                data = {'IP Address': [str(ip)]}
                df = pd.DataFrame(data)
                df.to_csv('offline_ip_addresses.csv', index=False)

        elif result[0] == True and result[1] == "ping":
            if os.path.exists("live_ip_addresses.csv"):
                data = {'IP Address': [str(ip)]}
                df = pd.DataFrame(data)
                df.to_csv('live_ip_addresses.csv', mode='a',
                          index=False, header=False)
            else:
                data = {'IP Address': [str(ip)]}
                df = pd.DataFrame(data)
                df.to_csv('live_ip_addresses.csv', index=False)
        # print(result[1])
        if result[0] == True and result[1] == "port":
            direct = str(ip).replace(":", "_")
            csv_direct = str(direct) + ".csv"
            try:
                xml_direct = str(direct) + ".xml"
                nmap_xml_file = os.path.join(
                    "results", str(direct), str(xml_direct))
                csv_file = os.path.join("results", str(csv_direct))
                csv_xml_switch(nmap_xml_file, csv_file)
                convert(ip)
            except Exception as e:
                os.remove(os.path.join("results", str(csv_direct)))

# NMAP PARSING FUNCTION


def parseNMAP(params, ip_addr_list):

    params = changeParams(params)
    start_time = time.time()
    futures = []
    new_ip_addr_list = []
    executor = ThreadPoolExecutor(max_workers=int(params["Batches"]))
    executor2 = ThreadPoolExecutor(max_workers=int(params["Batches"]))

    if params["Choice"] == "direct":
        # print("WHY")
        with tqdm(total=len(ip_addr_list), desc="NMAP", unit="ip") as pbar:

            for ip in ip_addr_list:
                future = executor.submit(proc, ip, params)
                futures.append(future)

            for future, ip in zip(futures, ip_addr_list):
                result = future.result()
                post_proc_func(ip, result)
                pbar.update(1)

    elif params["Choice"] == "both":
        with tqdm(total=len(ip_addr_list), desc="PING PROGRESS", unit="ip") as pbar:
            for ip in ip_addr_list:
                future = executor.submit(pingme, ip)
                futures.append(future)

            for future, ip in zip(futures, ip_addr_list):
                result = future.result()
                post_proc_func(ip, result)
                if result[0] == True:
                    new_ip_addr_list.append(str(ip))
                pbar.update(1)

        futures = []
        with tqdm(total=len(new_ip_addr_list), desc="NMAP PROGRESS", unit="ip") as pbar:
            for ip in new_ip_addr_list:
                future = executor2.submit(nmapfunc, ip, params)
                futures.append(future)

            for future, ip in zip(futures, new_ip_addr_list):
                result = future.result()
                post_proc_func(ip, result)
                pbar.update(1)

    end_time = time.time()
    time_taken = end_time - start_time
    # print("TOTAL TIME FOR PROCESSING - "+str(time_taken))


def pingme(ip):
    # print("YO")
    if ipaddress.ip_address(str(ip).strip()).version == 4:
        command = "nmap -sn "+str(ip)
    if ipaddress.ip_address(str(ip).strip()).version == 6:
        command = "nmap -sn -6 "+str(ip)
    process = subprocess.run(
        command, capture_output=True, shell=True, text=True)
    if "down" in str(process.stdout).split() or "down" in str(process.stdout):
        return (False, "ping")
    elif "Host is up" in str(process.stdout).split() or "Host is up" in str(process.stdout) or "1 host up" in str(process.stdout):
        return (True, "ping")
    else:
        return (False, "ping")


def nmapfunc(ip, params):
    # print("WHYYYYYYYY")
    direct = str(ip).replace(":", "_")
    try:
        os.mkdir(os.path.join("results", str(direct)))
    except:
        pass
    big_statement = str(params["Basic"])+" "+str(params["Technique"])+" "+str(params["Zombie"])+str(params["FTP"])+" "+str(
        params["UDP"])+" "+str(params["SCTP_INIT"])+" "+str(params["SCTP_COOKIE"])+" "+str(params["HOST_DISCO"])

    if ipaddress.ip_address(str(ip).strip()).version == 4:
        command = "nmap -n "+str(params["Vulners"])+" --open --min-parallelism 10 "+" -sV -Pn "+str(params["Timing"])+" "+str(
            big_statement)+" "+str(params["PortTechnique"])+" "+str(params["PortText"])+" -oA "+str(direct)+" " + str(ip)
    if ipaddress.ip_address(str(ip).strip()).version == 6:
        command = "nmap -6 -n "+str(params["Vulners"])+" --open --min-parallelism 10 "+" -sV -Pn "+str(params["Timing"])+" "+str(
            big_statement)+" "+str(params["PortTechnique"])+" "+str(params["PortText"])+" -oA "+str(direct)+" " + str(ip)

    process = subprocess.run(
        command, capture_output=True, text=True, cwd="results")
    a = process.stdout
    if "down" in str(a).split() or "down" in str(a):
        return (False, "port")
    elif "Host is up" in str(a).split() or "Host is up" in str(a) or "1 host up" in str(a):
        return (True, "port")
    else:
        return (False, "port")


def proc(ip, params):
    direct = str(ip).replace(":", "_")
    big_statement = str(params["Basic"])+" "+str(params["Technique"])+" "+str(params["Zombie"])+str(params["FTP"])+" "+str(
        params["UDP"])+" "+str(params["SCTP_INIT"])+" "+str(params["SCTP_COOKIE"])+" "+str(params["HOST_DISCO"])
    # print(big_statement)
    if len(str(big_statement).strip()) == 0 or big_statement == "None" or str(big_statement) == "None":
        if ipaddress.ip_address(str(ip).strip()).version == 4:
            command = "nmap -sn "+str(ip)
        if ipaddress.ip_address(str(ip).strip()).version == 6:
            command = "nmap -sn -6 "+str(ip)
        process = subprocess.run(
            command, capture_output=True, shell=True, text=True)
        if "down" in str(process.stdout).split() or "down" in str(process.stdout):
            return (False, "ping")
        elif "Host is up" in str(process.stdout).split() or "Host is up" in str(process.stdout) or "1 host up" in str(process.stdout):
            return (True, "ping")
        else:
            return (False, "ping")

    else:
        try:
            os.mkdir(os.path.join("results", str(direct)))
        except:
            pass
        # loc = str(direct)+"/"+str(direct)
        loc = os.path.join(str(direct),str(direct))
        if ipaddress.ip_address(str(ip).strip()).version == 4:
            command = ["nmap", "-n", str(params["Vulners"]), "--open", "--min-parallelism", "10", "-sV", "-Pn", str(
                params["Timing"]), str(big_statement), str(params["PortTechnique"]), str(params["PortText"]), "-oA", str(loc), str(ip)]
        if ipaddress.ip_address(str(ip).strip()).version == 6:
            command = ["nmap", "-6", "-n", str(params["Vulners"]), "--open", "--min-parallelism", "10", "-sV", "-Pn", str(params["Timing"]), str(
                big_statement), str(params["PortTechnique"]), str(params["PortText"]), "-oA", str(loc), str(ip)]
        process = subprocess.run(
            command, capture_output=True, text=True, cwd="results")
        a = process.stdout
        if "down" in str(a).split() or "down" in str(a):
            return (False, "port")
        elif "Host is up" in str(a).split() or "Host is up" in str(a) or "1 host up" in str(a):
            return (True, "port")
        else:
            return (False, "port")


def convert(ip):
    direct = str(ip).replace(":", "_")
    path = "results"
    files = glob.glob(path + "/*.csv")
    data_frame = pd.DataFrame()
    content = []

    for filename in files:
        df = pd.read_csv(filename)
        if os.stat(filename).st_size == 0 or df.empty or np.isnan(df.iloc[0]['PORT']):
            data = {'IP': [str(ip)], 'PORT': ['-'], 'PROTOCOL': ['-'], 'SERVICE': ['-'], 'VERSION': ['-'], 'STATE': ['IP is live but ports are closed/filtered'],
                    'TYPE': ['-'], 'CVSS': ['-'], 'ID': ['-'], 'IS EXPLOIT AVAILABLE?': ['-'], 'TIME WHEN SCAN FINISHED': ''}
            df = pd.DataFrame(data)
        content.append(df)

    if os.path.exists("output.csv"):
        data_frame = pd.concat(content)
        data_frame.to_csv('output.csv', mode='a', index=False, header=False)
    else:
        data_frame = pd.concat(content)
        data_frame.to_csv('output.csv', index=False)

    csv_direct = str(direct)+".csv"
    os.remove(os.path.join("results", str(csv_direct)))


def csv_xml_switch(nmap_xml_file, csv_output_file):

    with open(csv_output_file, "w", newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["IP", "PORT", "PROTOCOL", "SERVICE", "VERSION", "STATE",
                        'TYPE', 'CVSS', 'ID', 'IS EXPLOIT AVAILABLE?', 'TIME WHEN SCAN FINISHED'])

        tree = ET.parse(nmap_xml_file)
        root = tree.getroot()

        for t in root.findall("finished"):
            timerec = t.get("timestr")
        
        try:
            if timerec:
                pass
            else:
                timerec = '-'
        except:
            time.sleep(2)
            try:
                for t in root.findall("finished"):
                    timerec = t.get("timestr")
            except Exception as e:
                print(e)
                timerec = '-'

        for host in root.findall("host"):
            ip_address = ""
            for address in host.findall("address"):
                if address.get("addrtype") == "ipv4":
                    ip_address = address.get("addr")
                elif address.get("addrtype") == "ipv6":
                    ip_address = address.get("addr")

            for port in host.findall("ports/port"):
                cve = {}
                if port.find("state").get("state") == "open" or port.find("state").get("state") == "open|filtered":
                    if str(port.find("service").get("product")) == "None" or str(port.find("service").get("product")) == None:
                        product = " "
                    else:
                        product = str(port.find("service").get("product"))

                    if str(port.find("service").get("version")) == "None" or str(port.find("service").get("version")) == None:
                        version = " "
                    else:
                        version = str(port.find("service").get("version"))
                    try:
                        script_tag = port.findall(".//elem")
                        i = 0
                        if len(script_tag) > 0:
                            for c in script_tag:
                                try:
                                    val = c.get("key")
                                    if val in ["id", "cvss", "type", "is_exploit"]:
                                        if i % 4 == 0 and i != 0:
                                            writer.writerow([ip_address, port.get("portid"), port.get("protocol"), port.find("service").get("name"), str(
                                                product) + " " + str(version), port.find("state").get("state"), cve["type"], cve["cvss"], cve["id"], cve["is_exploit"], timerec])
                                            cve = {}
                                            i = 0
                                        val = c.get("key")
                                        if val == "type":
                                            cve["type"] = str(c.text)
                                        if val == "cvss":
                                            cve["cvss"] = str(c.text)
                                        if val == "id":
                                            cve["id"] = str(c.text)
                                        if val == "is_exploit":
                                            cve["is_exploit"] = str(c.text)
                                        i = i+1
                                except:
                                    pass
                        else:
                            writer.writerow([ip_address, port.get("portid"), port.get("protocol"), port.find("service").get(
                                "name"), str(product) + " " + str(version), port.find("state").get("state"), '-', '-', '-', '-', timerec])
                    except:
                        writer.writerow([ip_address, port.get("portid"), port.get("protocol"), port.find("service").get(
                            "name"), str(product) + " " + str(version), port.find("state").get("state"), '-', '-', '-', '-', timerec])


if __name__ == '__main__':
    Timer(0.5, openBrowser).start()
    if os.path.exists("port.txt"):
        with open('port.txt', 'r') as file:
            contents = file.read()
            port = str(contents)
    else:
        port = "5000"
    app.run(debug=False, port=port)
