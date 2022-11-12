from netaddr import *
import logging
import csv
import re


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s :: [%(module)s] :: [%(levelname)s] :: %(message)s",
    handlers=[
        logging.FileHandler("analysis.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('log')

subnet_file = input("Please input the CSV file path : ")

logger.info(f"Started to read file {subnet_file}")

def cleanup_ips(ip):

    if (re.search('[a-zA-Z]', ip)):
        return False

    # check for ips with subnet mask- Eg "10.2.0.0/24"
    elif (re.search('[/]', ip)):

        if (len(ip.split("/")) > 2):               
            ip = f"{ip.split('/')[0]}/{ip.split('/')[1]}"

        if (re.search('[_]', ip)):
            ip = ip.replace(f"_{ip.split('_')[1]}", "")

        try:
            return(IPNetwork(ip))
        except:
            return False

    # check for ips with range - Eg "10.1.0.0 - 10.2.0.0"
    elif ((re.search('[-]', ip)) or (re.search('[_]', ip))):
        ip = ip.replace("_", "-")

        # check which is greatet
        if (IPAddress(ip.split("-")[0]) < IPAddress(ip.split("-")[1])):
            high = ip.split("-")[1]
            low = ip.split("-")[0]

        else:
            high = ip.split("-")[0]
            low = ip.split("-")[1]

        try:
            return (IPRange(low, high))
        except:
            return False
            
    # normal ip
    else:
        try:
            return IPAddress(ip)
        except:
            return False


def filter(ips):

    eligible_ip = []
    in_eligible_ip = []

    while(len(ips)>0):

        if(len(ips)==1):

            if(cleanup_ips(ips[0])):
                eligible_ip.append(ips[0])
            else:
                in_eligible_ip.append(ips[0])

            break
            
        check_ip = ips[0]
        ips.remove(check_ip)
        
        new_ips = ips.copy()
        
        for ip in new_ips:
            flag=0
            logger.info(f"Comparing {check_ip} against {ip}")
            if (cleanup_ips(check_ip)):

                if(cleanup_ips(ip)):
                    try:
                        if(cleanup_ips(check_ip) in cleanup_ips(ip)):
                            in_eligible_ip.append(check_ip)
                            flag=1
                            break
                        elif(cleanup_ips(ip) in cleanup_ips(check_ip)):
                            in_eligible_ip.append(ip)
                            ips.remove(ip)
                    except:
                        try:
                            if(cleanup_ips(ip) in cleanup_ips(check_ip)):
                                in_eligible_ip.append(ip)
                                ips.remove(ip)
                        except Exception as e:
                            logger.error(e)

                else:
                    in_eligible_ip.append(ip)
                    ips.remove(ip)   
                    logger.info(f"Removing {ip} and {ips}")
                    continue
            else:
                in_eligible_ip.append(check_ip)
                flag=1
                break

        if(flag==0):
            logger.info(f"Adding {check_ip} to eligible list")
            eligible_ip.append(check_ip)

    return(eligible_ip,in_eligible_ip)


with open(subnet_file) as file:
    csv_reader = csv.DictReader(file, delimiter=',')
    count = 1

    write_row = []

    for row in csv_reader:

        count += 1
        logger.info(f"Working on the row no : {count}")

        ips = (row['rule.source']).split(",")
        source_ips = filter(ips)

        dest_ips = (row['rule.destination']).split(",")
        destination_ips = filter(dest_ips)
        
        row['finalized_source_ips'] = ','.join(list(set(source_ips[0])))
        row['removed_source_ips'] = ','.join(list(set(source_ips[1])))

        row['finalized_destination_ips'] = ','.join(list(set(destination_ips[0])))
        row['removed_destination_ips'] = ','.join(list(set(destination_ips[1])))

        write_row.append(row)

if (len(write_row) > 0):

    headers = write_row[0].keys()
    with open('filtered.csv', 'w', encoding='UTF8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(write_row)
