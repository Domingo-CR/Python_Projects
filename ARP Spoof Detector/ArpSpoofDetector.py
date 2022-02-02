import os, re, datetime

endpoints = dict()
susmachine = dict()


# Prints ARP table
def printARPTable():
    os.system("arp -a")


# Parses ARP table to store IP:MAC in a dictionary as a key:value pair
def parseARPTable():
    with os.popen('arp -a') as f:
        data = f.read()

    # Regex looks for IP and Mac in the 'arp -a' output and stores them as a tuple
    for line in re.findall('([-.0-9]+)\s+([-0-9a-f]{17})',data):
        # Exclude broadcast addresses from the list
        if line[1] != "ff-ff-ff-ff-ff-ff":
            endpoints[line[0]] = line[1]

    # Uncomment line below to display the key:value in the 'endpoint' dictionary | POC for this function
    # print(endpoints)
    return endpoints


# Goes through dictionary looking for duplicate MAC addresses
def duplicateMACAddr():
    while len(endpoints) != 0:
        machine = endpoints.popitem()
        if machine[1] in endpoints.values():
            susmachine[machine[0]] = machine[1]

    return susmachine


# Generate a report if duplicate MAC addresses are found
def reportSusActivity():
    now = datetime.datetime.now()
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")

    g = open("report.txt", "a")
    g.write(f"These machines have been reported for suspicion [{dt_string}]:\n{susmachine}")
    g.close()


def main():
    printARPTable()

    endpoints = parseARPTable()
    susmachine = duplicateMACAddr()

    reportSusActivity() if len(susmachine) != 0 else print("\n~~All Clear!~~")


if __name__ == "__main__":
    main()